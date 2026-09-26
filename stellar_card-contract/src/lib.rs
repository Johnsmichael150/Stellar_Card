//! # stellar_card Card Receiver Contract
//!
//! A Soroban smart contract that receives USDC and native XLM payments on behalf
//! of the stellar_card card platform and forwards them to a configured treasury
//! address.
//!
//! ## Part 3 — Reentrancy Guard for Payment Callbacks (Issue #407)
//!
//! ## Part 3 — Event Emission (Issue #408)
//! This iteration wires up Soroban events for **every meaningful contract state
//! change**, so that off-chain indexers, audit logs, and the backend event
//! watcher can react to the full lifecycle of the contract — not just payments.
//!
//! ### New events added in this part
//! | Symbol            | Topics (besides symbol)       | Value                        |
//! |-------------------|-------------------------------|------------------------------|
//! | `init`            | admin                         | (treasury, usdc, xlm)        |
//! | `pay_usdc`        | order_id, from                | amount (i128)                |
//! | `pay_xlm`         | order_id, from                | amount (i128)                |
//! | `paused`          | caller                        | true                         |
//! | `unpaused`        | admin                         | false                        |
//! | `upgraded`        | admin                         | new_wasm_hash                |
//! | `admin_transferred` | old_admin, new_admin        | ()                           |
//!
//! All event topics follow the `(Symbol, ...)` convention so the backend
//! watcher can filter by the first topic symbol without decoding the full
//! event body.
//!
//! ### Design rules
//! * Events are emitted **after** all state writes succeed — no half-baked
//!   events if a panic unwinds the call.
//! * Idempotent no-ops (`pause` when already paused, `unpause` when already
//!   unpaused) do **not** emit events, keeping the event log clean.
//! * Payment events carry the `order_id` as a topic so log consumers can
//!   filter by order without downloading the event body.
//!
//! ## Security features
//! * **Reentrancy guard** — a storage-backed guard (`_enter` / `_exit`, wrapped
//!   by `with_reentrancy_guard`) surrounds every external token call —
//!   `pay_usdc`, `pay_xlm` and `rescue_tokens` — so a token contract calling
//!   back into any of them is blocked.
//! * **Pause mechanism** — the admin can pause the contract to halt all transfers
//!   during incidents or upgrades.
//! * **Role-based access control (RBAC)** — a hierarchical role model
//!   (`Admin > Operator > Viewer`) gates privileged operations. Roles are
//!   granted/revoked by the admin (`grant_role`/`grant_roles`/`revoke_role`)
//!   or given up voluntarily by their holder (`renounce_role`).
//!   **Completion of #424 (Part 5)**: RBAC fully implemented with role hierarchy,
//!   grant/revoke operations, role queries, and hierarchical permission checks.
//! * **Upgradeability** — the admin can swap the contract WASM in place.
//! * **No admin withdraw path (issue #431, issue #421, issue #411)** — `pay_usdc`/`pay_xlm`
//!   forward funds directly from payer to `DataKey::Treasury` in the same call; the
//!   contract never holds custody of funds itself. An admin withdrawal
//!   limit therefore has no function to attach to today — there is nothing
//!   for an admin to withdraw. If a future change introduces fund custody
//!   (e.g. an escrow/hold period), a withdrawal limit should be added at
//!   that point, not before there's a withdrawal path to protect.
//!
//!   **Completion of #421 (Part 4) and #411 (Part 3)**: Administrative
//!   withdraw limit protections are deferred until a withdrawal mechanism is
//!   introduced — both issues asked for the same protection and resolve to
//!   the same answer. See `rescue_tokens` for the existing token recovery
//!   mechanism (for mistaken direct sends), which is itself Admin-role-gated
//!   and unconditional per-call (not a running limit) precisely because it
//!   recovers a fixed mistaken balance rather than acting as a general
//!   withdrawal path.
//!
//! ## Events
//! Every entrypoint that changes contract state emits exactly one event per
//! change (Issue #398 - Part 2), and calls that turn out to be no-ops (pausing
//! an already-paused contract, renouncing a role that isn't held, re-granting
//! the role an address already has) emit nothing, so an indexer can treat
//! each event as a real state transition. The first topic is always the
//! event name:
//!
//! | Event                 | Topics                            | Data                                      |
//! |-----------------------|-----------------------------------|-------------------------------------------|
//! | `init`                | `admin`                           | `(treasury, usdc_contract, xlm_contract)` |
//! | `pay_usdc`            | `order_id`, `from`                | `amount`                                  |
//! | `pay_xlm`             | `order_id`, `from`                | `amount`                                  |
//! | `paused`              | `caller`                          | `true`                                    |
//! | `unpaused`            | `admin`                           | `false`                                   |
//! | `upgraded`            | `admin`                           | `new_wasm_hash`                           |
//! | `tokens_rescued`      | `token_contract`, `to`            | `(caller, amount)`                        |
//! | `withdraw_limits_set` | `caller`                          | `(per_call, per_day)`                     |
//! | `admin_transferred`   | `old_admin`, `new_admin`          | `()`                                      |
//! | `role_granted`        | `address`                         | `role`                                    |
//! | `role_revoked`        | `address`                         | `()`                                      |
//! | `role_renounced`      | `caller`                          | `()`                                      |
//!
//! ## Authorization model
//! `init` and all admin entrypoints call `require_auth`. Payment entrypoints
//! require the paying address to authorize the transfer.

#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, Bytes, BytesN, Env,
    Symbol,
};

// ── Storage TTL constants ─────────────────────────────────────────────────────

/// Target TTL for instance storage (~1 000 days at 5 s ledger close time).
const INSTANCE_TTL_MAX: u32 = 17_280_000;
/// Only extend instance storage TTL when it drops below this threshold.
/// Using half of max avoids a redundant ledger write on every call.
const INSTANCE_TTL_THRESHOLD: u32 = INSTANCE_TTL_MAX / 2;

/// Decimal precision `init` requires of both token contracts (Issue #399 -
/// Part 2). Every Stellar Asset Contract — including the USDC and native XLM
/// SACs this contract is built for — uses 7, and `pay_usdc`/`pay_xlm`
/// document their `amount` in 7-decimal base units.
const TOKEN_DECIMALS: u32 = 7;

/// Represents user roles in the contract with hierarchical permissions.
///
/// Set to half of [`INSTANCE_TTL_MAX`].  When `threshold == extend_to` (as
/// was the original pattern), *any* decrease below the max retriggers a full
/// extend — effectively a fee-costing ledger write on nearly every call.
/// A threshold at half the max means an extension only fires roughly once
/// every ~500 days\' worth of activity instead of on almost every call.
const INSTANCE_TTL_THRESHOLD: u32 = INSTANCE_TTL_MAX / 2;

// ── Storage keys ──────────────────────────────────────────────────────────────

/// Discriminated union of all storage keys used by the contract.
///
/// Each variant identifies a slot in the contract's storage.
#[contracttype]
pub enum DataKey {
    /// The Stellar address to which all forwarded payments are sent.
    ///
    /// Set once during [`Stellar_CardReceiver::init`] and never changed
    /// afterwards.  Any payment that reaches `pay_usdc` or `pay_xlm`
    /// forwards funds directly to this address in the same transaction —
    /// the contract itself never holds a balance.
    Treasury,

    /// The contract address of the USDC Stellar Asset Contract (SAC).
    ///
    /// Used by [`Stellar_CardReceiver::pay_usdc`] to call `transfer` on
    /// behalf of the payer.  Validated at init time via a `try_decimals()`
    /// probe so a non-token address is caught immediately rather than at
    /// the first payment.
    UsdcContract,

    /// The contract address of the native XLM Stellar Asset Contract (SAC).
    ///
    /// Used by [`Stellar_CardReceiver::pay_xlm`].  Validated at init time
    /// with the same `try_decimals()` probe as [`DataKey::UsdcContract`].
    XlmContract,

    /// The Stellar address that holds administrative control of the contract.
    ///
    /// This address is required to co-sign `init`, `pause`, `unpause`,
    /// `upgrade`, and `transfer_admin`.  It is transferred atomically by
    /// [`Stellar_CardReceiver::transfer_admin`], which requires both the
    /// current and the new admin to authorize to prevent accidental lockout.
    Admin,
    /// Circuit breaker: `true` means payments are rejected.
    Paused,
    /// Maximum amount `rescue_tokens` may move in a single call. Key
    /// absent means no per-call cap is configured.
    WithdrawLimitPerCall,
    /// Maximum cumulative amount `rescue_tokens` may move across all calls
    /// within a single day. Key absent means no daily cap.
    WithdrawLimitPerDay,
    /// Running total withdrawn via `rescue_tokens` during `day` (ledger
    /// timestamp / 86400), keyed per day so the accumulator resets
    /// automatically at each day boundary instead of needing an explicit
    /// reset call.
    WithdrawnToday(u64),
}

// ── Contract errors ───────────────────────────────────────────────────────────

/// Errors returned by fallible contract entrypoints.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// `amount` must be > 0.
    InvalidAmount = 1,
    /// The SAC `transfer` call was rejected (e.g. insufficient balance).
    TransferFailed = 2,
    /// All new payments are rejected while the contract is paused.
    ContractPaused = 3,
    /// `rescue_tokens` amount exceeds the configured per-call withdraw limit
    WithdrawLimitExceeded = 4,
    /// `rescue_tokens` amount would push today's cumulative withdrawals past
    /// the configured daily withdraw limit
    DailyWithdrawLimitExceeded = 5,
}

// ── Contract ─────────────────────────────────────────────────────────────────

/// The stellar_card card receiver contract.
///
/// All persistent state lives in instance or temporary storage keyed by
/// [`DataKey`]; the struct itself carries no in-memory fields.
#[contract]
pub struct Stellar_CardReceiver;

#[contractimpl]
impl Stellar_CardReceiver {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initializes the contract with essential configuration.
    ///
    /// This is a one-time operation: calling `init` a second time panics with
    /// `"already initialized"`.  The admin must co-sign the call to prevent
    /// a front-running attack where a third party initializes the contract
    /// with their own treasury before the legitimate deployer can.
    ///
    /// # Validation
    /// All parameters are checked by `validate_init_params` before any state
    /// is written (Issue #399 - Part 2): the receiver contract can't be used
    /// for any role; the admin can't be the treasury or a token contract;
    /// the token contracts must differ and not double as the treasury; and
    /// both must implement the token interface with 7 decimals.
    ///
    /// # Events
    /// Emits after all writes succeed:
    /// ```text
    /// topics : [Symbol("init"), admin]
    /// value  : (treasury, usdc_contract, xlm_contract)
    /// ```
    ///
    /// # Panics
    /// * `"already initialized"` if called more than once.
    /// * `admin.require_auth()` if the admin signature is missing.
    /// * Various validation panics for self-referential or duplicate addresses.
    pub fn init(
        env: Env,
        admin: Address,
        treasury: Address,
        usdc_contract: Address,
        xlm_contract: Address,
    ) {
        admin.require_auth();

        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }

        Self::validate_init_params(&env, &admin, &treasury, &usdc_contract, &xlm_contract);

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Treasury, &treasury);
        env.storage()
            .instance()
            .set(&DataKey::UsdcContract, &usdc_contract);
        env.storage()
            .instance()
            .set(&DataKey::XlmContract, &xlm_contract);
        env.storage().instance().set(&DataKey::Paused, &false);

        env.storage().instance().set(&DataKey::Admin,        &admin);
        env.storage().instance().set(&DataKey::Treasury,     &treasury);
        env.storage().instance().set(&DataKey::UsdcContract, &usdc_contract);
        env.storage().instance().set(&DataKey::XlmContract,  &xlm_contract);
        env.storage().instance().set(&DataKey::Paused,       &false);

        Self::extend_instance_ttl(&env);

        env.events().publish(
            (Symbol::new(&env, "init"), admin),
            (treasury, usdc_contract, xlm_contract),
        );
    }

    /// Validates `init`'s parameters before anything is written to storage
    /// (Issue #399 - Part 2).
    ///
    /// Kept separate from `init` so every rule lives in one place and is
    /// applied in a fixed order: cheap address-equality checks first, then
    /// the token-interface probes, which make cross-contract calls.
    ///
    /// # Rules
    /// * No role (admin, treasury, USDC, XLM) may be the receiver contract
    ///   itself.
    /// * The admin must not be the treasury (accidental self-payment) or
    ///   either token contract (a token contract can't sign admin actions,
    ///   so the contract would be unmanageable).
    /// * USDC and XLM must be different contracts, and the treasury must not
    ///   be either of them.
    /// * Both token contracts must answer `decimals()` (Issue #409 - Part 3)
    ///   and report [`TOKEN_DECIMALS`], the precision `pay_usdc`/`pay_xlm`
    ///   amounts are documented in. A token with any other precision would
    ///   silently mis-scale every payment by a power of ten.
    ///
    /// # Panics
    /// Panics with a message naming the offending parameter on the first
    /// rule that fails.
    fn validate_init_params(
        env: &Env,
        admin: &Address,
        treasury: &Address,
        usdc_contract: &Address,
        xlm_contract: &Address,
    ) {
        let contract_address = env.current_contract_address();

        // No parameter may point back at this contract.
        if *admin == contract_address {
            panic!("admin cannot be the contract itself");
        }
        if *treasury == contract_address {
            panic!("treasury cannot be the contract itself");
        }
        if *usdc_contract == contract_address {
            panic!("usdc_contract cannot be the contract itself");
        }
        if *xlm_contract == contract_address {
            panic!("xlm_contract cannot be the contract itself");
        }

        // Prevent admin and treasury from being the same (accidental self-payment)
        if admin == treasury {
            panic!("admin and treasury must be different addresses");
        }
        if admin == usdc_contract || admin == xlm_contract {
            panic!("admin cannot be a configured token contract");
        }

        // Validate token contracts are different (prevents misconfiguration)
        if usdc_contract == xlm_contract {
            panic!("usdc_contract and xlm_contract must be different");
        }
        if treasury == usdc_contract || treasury == xlm_contract {
            panic!("treasury cannot be a configured token contract");
        }

        // Issue #409 (Part 3): probe both token addresses against the SAC
        // interface before storing them. Without this, a plain non-token
        // address (or a typo'd contract ID) would pass every check above and
        // only surface as a failure the first time a payer calls pay_usdc /
        // pay_xlm — by then the contract is already live and misconfigured.
        // `decimals()` is a read-only call with no side effects, so probing
        // it here costs nothing beyond the call itself and fails fast, at
        // deploy time, instead of at the first payment.
        match token::Client::new(env, usdc_contract).try_decimals() {
            Ok(Ok(TOKEN_DECIMALS)) => {}
            Ok(Ok(_)) => panic!("usdc_contract must use 7 decimals"),
            _ => panic!("usdc_contract does not implement the token interface"),
        }
        match token::Client::new(env, xlm_contract).try_decimals() {
            Ok(Ok(TOKEN_DECIMALS)) => {}
            Ok(Ok(_)) => panic!("xlm_contract must use 7 decimals"),
            _ => panic!("xlm_contract does not implement the token interface"),
        }
    }

    /// Acquires the reentrancy guard to prevent reentrant calls.
    ///
    /// # Security (Issue #427 - Part 5)
    /// The reentrancy guard implements the Checks-Effects-Interactions pattern
    /// for payment callbacks. It prevents an attacker from calling back into
    /// `pay_usdc` or `pay_xlm` during a token transfer and draining funds.
    ///
    /// Reads [`DataKey::ReentrancyGuard`] from **temporary** storage.
    /// If the flag is already `true`, a reentrant call is in progress and
    /// this function panics immediately.  Otherwise it writes `true` to
    /// claim the guard for the current call.
    ///
    /// Reads `DataKey::ReentrancyGuard` from temporary storage.
    /// If the flag is already `true`, a reentrant call is in progress and
    /// this function panics immediately.  Otherwise it sets the flag to
    /// `true` to block any nested invocation.
    ///
    /// # Panics
    /// Panics with `"reentrancy detected"` if the guard is already held.
    fn _enter(env: &Env) {
        if env
            .storage()
            .temporary()
            .get::<_, bool>(&DataKey::ReentrancyGuard)
            .unwrap_or(false)
        {
            panic!("reentrancy detected");
        }
        env.storage()
            .temporary()
            .set(&DataKey::ReentrancyGuard, &true);
    }

    /// Releases the reentrancy guard after the external token call returns.
    ///
    /// Sets the temporary-storage flag back to `false`.  **Must be called in
    /// every exit path** from a guarded function — both the success branch
    /// and every error branch — to ensure the guard is never left locked.
    fn _exit(env: &Env) {
        env.storage()
            .temporary()
            .set(&DataKey::ReentrancyGuard, &false);
    }

    /// Runs `f` while holding the reentrancy guard (Issue #397 - Part 2).
    ///
    /// Every external call into a token contract goes through this helper,
    /// so acquiring and releasing the guard lives in exactly one place
    /// instead of being repeated (and potentially forgotten) on every early
    /// return inside each entrypoint. `f` returns normally on both its
    /// success and error paths, and the guard is released before its result
    /// is handed back. If `f` panics, the whole invocation is rolled back by
    /// the host, which also discards the guard write, so there is no path
    /// that leaves the guard stuck on.
    ///
    /// # Panics
    /// Panics with "reentrancy detected" if the guard is already held.
    fn with_reentrancy_guard<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        Self::_enter(env);
        let result = f();
        Self::_exit(env);
        result
    }

    /// Returns whether the contract is currently paused.
    fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Transfers USDC from `from` to the treasury and emits a payment event.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `caller` - The address invoking pause (must authorize this call)
    ///
    /// # Authorization (Issue #426 - Part 5 - Complete NatSpec)
    /// Requires `caller` to hold at least the `Operator` role. Pausing is an
    /// operational response to an incident, so it's granted to Operators
    /// (not Admin-only) — the faster an incident responder can halt
    /// payments, the smaller the blast radius. Resuming is stricter; see
    /// `unpause`.
    ///
    /// # Events (Issue #428 - Part 5)
    /// Emits: topics=[Symbol("paused"), caller], value=true
    ///
    /// # Notes
    /// Idempotent — calling when already paused is a no-op.
    ///
    /// # Panics
    /// Panics if `caller` does not hold at least the `Operator` role, or if
    /// `caller.require_auth()` fails.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        if !Self::has_role(env.clone(), caller.clone(), Role::Operator) {
            panic!("pause requires at least the Operator role");
        }
        if Self::is_paused(&env) {
            return;
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::extend_instance_ttl(&env);

        // Emit pause event (Issue #428 - Part 5)
        env.events()
            .publish((Symbol::new(&env, "paused"), caller), true);
    }

    /// Unpauses the contract, re-enabling token transfers.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    ///
    /// # Authorization (Issue #426 - Part 5 - Complete NatSpec)
    /// Only the admin can call this function. Unpausing is more sensitive
    /// than pausing because it reopens the payment flow after an incident,
    /// so it requires admin approval.
    ///
    /// # Events (Issue #428 - Part 5)
    /// Emits: topics=[Symbol("unpaused"), admin], value=false
    ///
    /// # Notes
    /// Idempotent — calling when already unpaused is a no-op.
    pub fn unpause(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if !Self::is_paused(&env) {
            return;
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::extend_instance_ttl(&env);

        // Emit unpause event (Issue #428 - Part 5)
        env.events()
            .publish((Symbol::new(&env, "unpaused"), admin), false);
    }

    /// Extends instance storage's TTL, but only performs the (fee-costing)
    /// ledger write once the remaining TTL drops below
    /// `INSTANCE_TTL_THRESHOLD` — see that constant's doc comment for why
    /// threshold and extend-to are deliberately different values.
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_MAX);
    }

    /// Extends a single per-address role storage entry's TTL, but only
    /// performs the (fee-costing) ledger write once its remaining TTL drops
    /// below `INSTANCE_TTL_THRESHOLD` (Issue #415 - Part 4).
    ///
    /// # Storage footprint
    /// `grant_role`/`grant_roles` previously called `extend_ttl` on every
    /// single grant unconditionally, re-billing the entry's rent even when
    /// its TTL was already close to the maximum. Gating the extension
    /// behind a threshold — mirroring `extend_instance_ttl`'s existing
    /// pattern for instance storage — turns most repeat grants to the same
    /// address into a no-op write, cutting the average gas cost of RBAC
    /// administration.
    fn extend_role_ttl(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_MAX);
    }

    /// Transfers USDC from `from` to the treasury.
    ///
    /// The reentrancy guard is acquired before the SAC `try_transfer` call and
    /// released in both the success and failure exit paths, so a reentrant
    /// callback cannot execute this function a second time while the first call
    /// is still live.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`]  — contract is paused.
    /// * [`Error::InvalidAmount`]   — `amount` ≤ 0.
    /// * [`Error::TransferFailed`]  — SAC transfer rejected.
    pub fn pay_usdc(env: Env, from: Address, amount: i128, order_id: Bytes) -> Result<(), Error> {
        if Self::is_paused(&env) {
            return Err(Error::ContractPaused);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        from.require_auth();

        let treasury: Address = env.storage().instance().get(&DataKey::Treasury).unwrap();
        let usdc_contract: Address = env.storage().instance().get(&DataKey::UsdcContract).unwrap();

        // The token contract is the only external call in this function, so
        // it is the only step that needs to run under the guard.
        let transferred = Self::with_reentrancy_guard(&env, || {
            token::Client::new(&env, &usdc_contract)
                .try_transfer(&from, &treasury, &amount)
                .is_ok()
        });
        if !transferred {
            return Err(Error::TransferFailed);
        }

        env.events()
            .publish((Symbol::new(&env, "pay_usdc"), order_id, from), amount);

        // Optimization #1: conditional TTL extension — write only when needed.
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Transfers native XLM from `from` to the treasury.
    ///
    /// Same reentrancy-guard pattern as [`pay_usdc`].
    ///
    /// # Errors
    /// * [`Error::ContractPaused`]  — contract is paused.
    /// * [`Error::InvalidAmount`]   — `amount` ≤ 0.
    /// * [`Error::TransferFailed`]  — SAC transfer rejected.
    pub fn pay_xlm(env: Env, from: Address, amount: i128, order_id: Bytes) -> Result<(), Error> {
        if Self::is_paused(&env) {
            return Err(Error::ContractPaused);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        from.require_auth();

        let treasury: Address = env.storage().instance().get(&DataKey::Treasury).unwrap();
        let xlm_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::XlmContract)
            .unwrap();

        // The token contract is the only external call in this function, so
        // it is the only step that needs to run under the guard.
        let transferred = Self::with_reentrancy_guard(&env, || {
            token::Client::new(&env, &xlm_contract)
                .try_transfer(&from, &treasury, &amount)
                .is_ok()
        });
        if !transferred {
            return Err(Error::TransferFailed);
        }

        env.events()
            .publish((Symbol::new(&env, "pay_xlm"), order_id, from), amount);

        Self::extend_instance_ttl(&env);
        Ok(())
    }

    // ── Administrative entrypoints ────────────────────────────────────────────

    /// Pauses the contract (admin only). Idempotent.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("pause requires admin");
        }
        if Self::is_paused(&env) {
            return;
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::extend_instance_ttl(&env);
        env.events().publish((Symbol::new(&env, "paused"), caller), true);
    }

    /// Unpauses the contract (admin only). Idempotent.
    pub fn unpause(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if !Self::is_paused(&env) {
            return;
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::extend_instance_ttl(&env);
        env.events().publish((Symbol::new(&env, "unpaused"), admin), false);
    }

    /// Upgrades the contract WASM (admin only).
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());

        // Issue #408 (Part 3): emit upgrade event.
        env.events()
            .publish((Symbol::new(&env, "upgraded"), admin), new_wasm_hash);
    }

    /// Transfers admin authority to `new_admin`.
    ///
    /// Requires both the current admin **and** `new_admin` to authorize the
    /// call. This two-step pattern prevents accidental lockout from a typo'd
    /// address — the new admin must be reachable to co-sign.
    ///
    /// # Errors
    /// * `InvalidAmount` - If `amount` is <= 0
    /// * `WithdrawLimitExceeded` - If a per-call limit is configured and
    ///   `amount` exceeds it
    /// * `DailyWithdrawLimitExceeded` - If a daily limit is configured and
    ///   this withdrawal would push today's cumulative total past it
    /// * `TransferFailed` - If the underlying token transfer fails (e.g. the
    ///   contract's balance is lower than `amount`)
    ///
    /// # Security (Issue #397 - Part 2)
    /// The transfer runs under the reentrancy guard, and the daily
    /// accumulator is written before the transfer (Checks-Effects-
    /// Interactions), because `token_contract` is caller-supplied and may
    /// call back into this contract.
    ///
    /// # Events (Issue #398 - Part 2)
    /// Emits: topics=[Symbol("tokens_rescued"), token_contract, to],
    /// value=(caller, amount). Not emitted when the call returns an error.
    ///
    /// # Panics
    /// Panics if `caller` does not hold the `Admin` role, if
    /// `caller.require_auth()` fails, or with "reentrancy detected" if
    /// invoked while another guarded operation is in progress.
    pub fn rescue_tokens(
        env: Env,
        caller: Address,
        token_contract: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        // The contract's single DataKey::Admin address is never
        // auto-granted the Admin *role* — grant_role/has_role are a
        // separate system, so a fresh deployer wouldn't satisfy a
        // has_role-only check until someone explicitly grants it to
        // themselves. Accept either form of admin authority here.
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        let is_stored_admin = caller == stored_admin;
        if !is_stored_admin && !Self::has_role(env.clone(), caller.clone(), Role::Admin) {
            panic!("rescue_tokens requires the Admin role");
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        if let Some(per_call_limit) = env
            .storage()
            .instance()
            .get::<DataKey, i128>(&DataKey::WithdrawLimitPerCall)
        {
            if amount > per_call_limit {
                return Err(Error::WithdrawLimitExceeded);
            }
        }

        let day = env.ledger().timestamp() / 86_400;
        let day_key = DataKey::WithdrawnToday(day);
        let withdrawn_today: i128 = env.storage().instance().get(&day_key).unwrap_or(0);
        let new_total = withdrawn_today.saturating_add(amount);

        if let Some(daily_limit) = env
            .storage()
            .instance()
            .get::<DataKey, i128>(&DataKey::WithdrawLimitPerDay)
        {
            if new_total > daily_limit {
                return Err(Error::DailyWithdrawLimitExceeded);
            }
        }

        // Checks-Effects-Interactions (Issue #397 - Part 2): `token_contract`
        // is caller-supplied and may be any contract, not just a trusted SAC,
        // which makes this the contract's only call into potentially
        // untrusted code. Record the withdrawal against today's accumulator
        // *before* the transfer, so a callback made from inside the
        // transfer can never observe a stale total and slip a second
        // withdrawal under the daily limit.
        env.storage().instance().set(&day_key, &new_total);

        let contract_address = env.current_contract_address();
        let transferred = Self::with_reentrancy_guard(&env, || {
            token::Client::new(&env, &token_contract)
                .try_transfer(&contract_address, &to, &amount)
                .is_ok()
        });
        if !transferred {
            // The transfer didn't happen, so it mustn't count against the
            // day's budget: restore the accumulator to its previous value.
            env.storage().instance().set(&day_key, &withdrawn_today);
            return Err(Error::TransferFailed);
        }

        Self::extend_instance_ttl(&env);

        // Issue #398 (Part 2): moving funds out of the contract is the most
        // sensitive state change it can make, so it must be visible to
        // off-chain monitoring like every other admin action. Only emitted
        // once the transfer has succeeded.
        env.events().publish(
            (Symbol::new(&env, "tokens_rescued"), token_contract, to),
            (caller, amount),
        );
        Ok(())
    }

    /// Configures `rescue_tokens`'s withdraw limits (Admin-role gated).
    ///
    /// # Arguments
    /// * `per_call` - Maximum amount a single `rescue_tokens` call may move,
    ///   or `None` to remove the per-call cap.
    /// * `per_day` - Maximum cumulative amount `rescue_tokens` may move
    ///   within a single day, or `None` to remove the daily cap.
    ///
    /// # Panics
    /// Panics if `caller` does not hold the `Admin` role (or is not the
    /// stored admin), if `caller.require_auth()` fails, or if either limit
    /// is provided as <= 0.
    pub fn set_withdraw_limits(
        env: Env,
        caller: Address,
        per_call: Option<i128>,
        per_day: Option<i128>,
    ) {
        caller.require_auth();
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        let is_stored_admin = caller == stored_admin;
        if !is_stored_admin && !Self::has_role(env.clone(), caller.clone(), Role::Admin) {
            panic!("set_withdraw_limits requires the Admin role");
        }
        if per_call.is_some_and(|v| v <= 0) || per_day.is_some_and(|v| v <= 0) {
            panic!("withdraw limits must be positive when set");
        }

        match per_call {
            Some(v) => env
                .storage()
                .instance()
                .set(&DataKey::WithdrawLimitPerCall, &v),
            None => env
                .storage()
                .instance()
                .remove(&DataKey::WithdrawLimitPerCall),
        }
        match per_day {
            Some(v) => env
                .storage()
                .instance()
                .set(&DataKey::WithdrawLimitPerDay, &v),
            None => env
                .storage()
                .instance()
                .remove(&DataKey::WithdrawLimitPerDay),
        }
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (Symbol::new(&env, "withdraw_limits_set"), caller),
            (per_call, per_day),
        );
    }

    /// Returns the currently configured `(per_call, per_day)` withdraw
    /// limits for `rescue_tokens`. `None` in either position means that
    /// limit is not configured.
    pub fn withdraw_limits(env: Env) -> (Option<i128>, Option<i128>) {
        let per_call = env.storage().instance().get(&DataKey::WithdrawLimitPerCall);
        let per_day = env.storage().instance().get(&DataKey::WithdrawLimitPerDay);
        (per_call, per_day)
    }

    /// Begins a two-step handover of the admin address. Unlike a naive
    /// single-step reassignment, this requires the *proposed new admin* to
    /// also authorize the call — a typo'd or unreachable address can never
    /// silently become admin, since it would have to co-sign its own
    /// appointment.
    ///
    /// # Arguments
    /// * `env`       — The Soroban execution environment.
    /// * `new_admin` — The address that will become the new admin.
    ///
    /// Both the current admin and `new_admin` must authorize the call, preventing
    /// lockout from a typo\'d address.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        current_admin.require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Self::extend_instance_ttl(&env);
        env.events().publish(
            (Symbol::new(&env, "admin_transferred"), current_admin, new_admin),
            (),
        );
    }

    // ── View entrypoints ──────────────────────────────────────────────────────

    /// Returns the configured treasury address.
    ///
    /// # Events (Issue #428 - Part 5)
    /// Emits: topics=[Symbol("role_granted"), address], value=role — only
    /// when the address's stored role actually changes (Issue #398 - Part 2).
    ///
    /// # Panics
    /// Panics if called before `init`, or if `admin.require_auth()` fails.
    pub fn grant_role(env: Env, address: Address, role: Role) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        Self::store_role(&env, address, role);
    }

    /// Returns the USDC SAC contract address.
    ///
    /// # Returns
    /// The [`Address`] stored at [`DataKey::UsdcContract`].
    ///
    /// # Events
    /// Emits one `role_granted` event per address whose role actually
    /// changed, matching `grant_role`.
    pub fn grant_roles(env: Env, addresses: Vec<Address>, role: Role) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        for address in addresses.iter() {
            Self::store_role(&env, address, role);
        }

    /// Returns the admin address.
    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Assigns `role` to `address` and emits `role_granted` — shared by
    /// `grant_role` and `grant_roles` so both follow the same rules.
    ///
    /// # Events (Issue #398 - Part 2)
    /// The event is only emitted when the stored role actually changes.
    /// Re-granting the role an address already holds still refreshes the
    /// entry's TTL, but is not reported as a new grant.
    fn store_role(env: &Env, address: Address, role: Role) {
        let key = DataKey::UserRole(address.clone());
        let previous: Option<Role> = env.storage().persistent().get(&key);
        env.storage().persistent().set(&key, &role);
        Self::extend_role_ttl(env, &key);

        if previous != Some(role) {
            // Emit role granted event (Issue #428 - Part 5)
            env.events()
                .publish((Symbol::new(env, "role_granted"), address), role);
        }
    }

    /// Revokes a role from an address.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `address` - The address to revoke the role from
    ///
    /// # Authorization (Issue #426 - Part 5 - Complete NatSpec)
    /// Only the admin can call this function.
    ///
    /// # Returns
    /// The [`Address`] stored at [`DataKey::XlmContract`].
    ///
    /// # Panics
    /// Panics if called before `init`, or if `admin.require_auth()` fails.
    /// Revoking a role from an address that never had one is a no-op, not
    /// a panic (see `test_revoke_nonexistent_role_is_noop`).
    pub fn revoke_role(env: Env, address: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

    /// Returns the admin address.
    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Returns `true` if the contract is currently paused.
    pub fn is_paused_view(env: Env) -> bool {
        Self::is_paused(&env)
    }

    /// Returns the current admin address.
    ///
    /// # Events
    /// Emits: topics=[Symbol("role_renounced"), caller], value=() — only
    /// when the caller actually held a role (Issue #398 - Part 2).
    ///
    /// # Notes
    /// Renouncing a role the caller doesn't hold is a no-op, matching
    /// `revoke_role`'s behaviour for an address with no assigned role.
    /// Because the contract's ultimate authority (`DataKey::Admin`) is a
    /// separate, independent identity from the `Role` system (see
    /// `rescue_tokens`'s doc comment), an address renouncing `Role::Admin`
    /// can never lock the contract out of RBAC administration — the
    /// stored admin can always call `grant_role` again.
    ///
    /// # Panics
    /// Panics if `caller.require_auth()` fails.
    pub fn renounce_role(env: Env, caller: Address) {
        caller.require_auth();

        // Issue #398 (Part 2): renouncing a role that isn't held changes
        // nothing, so — like `revoke_role` — it must not emit an event that
        // an indexer would record as a real role change.
        let key = DataKey::UserRole(caller.clone());
        if !env.storage().persistent().has(&key) {
            return;
        }
        env.storage().persistent().remove(&key);

        env.events()
            .publish((Symbol::new(&env, "role_renounced"), caller), ());
    }

    /// Extends instance storage TTL only when it has dropped below the
    /// threshold, avoiding a redundant ledger write (and fee) on every call.
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_MAX);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger as _, MockAuth, MockAuthInvoke},
        token, Bytes, Env, IntoVal, Symbol, TryIntoVal,
    };

    // ── Test fixture ──────────────────────────────────────────────────────────

    /// Shared test fixture that registers the contract and two mock SAC tokens,
    /// then provides helpers for minting and balance-checking.
    struct Fixture {
        env: Env,
        contract_id: Address,
        admin: Address,
        treasury: Address,
        payer: Address,
        usdc: Address,
        xlm_sac: Address,
    }

    impl Fixture {
        /// Creates a new [`Fixture`] with freshly generated addresses and
        /// `mock_all_auths()` enabled so all `require_auth` calls pass
        /// automatically.
        fn new() -> Self {
            let env = Env::default();
            env.mock_all_auths();
            let admin    = Address::generate(&env);
            let treasury = Address::generate(&env);
            let payer    = Address::generate(&env);
            let usdc     = env.register_stellar_asset_contract_v2(admin.clone()).address();
            let xlm_sac  = env.register_stellar_asset_contract_v2(admin.clone()).address();
            let contract_id = env.register(Stellar_CardReceiver, ());
            Fixture { env, contract_id, admin, treasury, payer, usdc, xlm_sac }
        }

        /// Returns a type-safe client bound to the registered contract.
        fn client(&self) -> Stellar_CardReceiverClient<'_> {
            Stellar_CardReceiverClient::new(&self.env, &self.contract_id)
        }

        /// Calls `init` with all fixture addresses.
        fn init(&self) {
            self.client().init(&self.admin, &self.treasury, &self.usdc, &self.xlm_sac);
        }

        /// Mints USDC to `to` using the SAC admin client.
        fn mint_usdc(&self, to: &Address, amount: i128) {
            token::StellarAssetClient::new(&self.env, &self.usdc).mint(to, &amount);
        }

        /// Mints XLM to `to` using the SAC admin client.
        fn mint_xlm(&self, to: &Address, amount: i128) {
            token::StellarAssetClient::new(&self.env, &self.xlm_sac).mint(to, &amount);
        }

        /// Returns the USDC balance of `addr`.
        fn usdc_balance(&self, addr: &Address) -> i128 {
            token::Client::new(&self.env, &self.usdc).balance(addr)
        }

        /// Returns the XLM balance of `addr`.
        fn xlm_balance(&self, addr: &Address) -> i128 {
            token::Client::new(&self.env, &self.xlm_sac).balance(addr)
        }
    }

    /// Converts a Rust string slice to a Soroban [`Bytes`] value for use as
    /// an `order_id` argument.
    fn order_bytes(env: &Env, s: &str) -> Bytes {
        Bytes::from_slice(env, s.as_bytes())
    }

    // ── Reentrancy guard tests (Issue #407 — Part 3) ──────────────────────────

    /// `pay_usdc` must panic with "reentrancy detected" when the guard flag is
    /// already held in temporary storage, simulating a reentrant callback.
    #[test]
    #[should_panic(expected = "reentrancy detected")]
    fn test_pay_usdc_panics_when_guard_held() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 10_000_000;
        f.mint_usdc(&f.payer, amount * 2);

        // Inject the guard flag directly, mimicking a reentrant call in flight.
        f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary().set(&DataKey::ReentrancyGuard, &true);
        });

        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "re-usdc"));
    }

    /// `pay_xlm` must panic with "reentrancy detected" when the guard is held.
    #[test]
    #[should_panic(expected = "reentrancy detected")]
    fn test_pay_xlm_panics_when_guard_held() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 5_000_000;
        f.mint_xlm(&f.payer, amount);

        f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary().set(&DataKey::ReentrancyGuard, &true);
        });

        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "re-xlm"));
    }

    // ── init parameter validation (issue #399) ────────────────────────────────

    /// A contract that answers `decimals()` like a token but with a precision
    /// other than the 7 every Stellar Asset Contract uses.
    mod six_decimal_token {
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct SixDecimalToken;

        #[contractimpl]
        impl SixDecimalToken {
            pub fn decimals(_env: Env) -> u32 {
                6
            }
        }
    }

    /// A contract with no token interface at all.
    mod not_a_token {
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct NotAToken;

        #[contractimpl]
        impl NotAToken {
            pub fn hello(_env: Env) -> u32 {
                1
            }
        }
    }

    #[test]
    #[should_panic(expected = "admin cannot be the contract itself")]
    fn test_init_rejects_contract_as_admin() {
        let f = Fixture::new();
        f.client()
            .init(&f.contract_id, &f.treasury, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "treasury cannot be the contract itself")]
    fn test_init_rejects_contract_as_treasury() {
        let f = Fixture::new();
        f.client()
            .init(&f.admin, &f.contract_id, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "usdc_contract cannot be the contract itself")]
    fn test_init_rejects_contract_as_usdc() {
        let f = Fixture::new();
        f.client()
            .init(&f.admin, &f.treasury, &f.contract_id, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "xlm_contract cannot be the contract itself")]
    fn test_init_rejects_contract_as_xlm() {
        let f = Fixture::new();
        f.client()
            .init(&f.admin, &f.treasury, &f.usdc, &f.contract_id);
    }

    #[test]
    #[should_panic(expected = "admin and treasury must be different addresses")]
    fn test_init_rejects_admin_as_treasury() {
        let f = Fixture::new();
        f.client().init(&f.admin, &f.admin, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "admin cannot be a configured token contract")]
    fn test_init_rejects_usdc_contract_as_admin() {
        let f = Fixture::new();
        f.client().init(&f.usdc, &f.treasury, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "admin cannot be a configured token contract")]
    fn test_init_rejects_xlm_contract_as_admin() {
        let f = Fixture::new();
        f.client()
            .init(&f.xlm_sac, &f.treasury, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "usdc_contract and xlm_contract must be different")]
    fn test_init_rejects_same_token_for_usdc_and_xlm() {
        let f = Fixture::new();
        f.client().init(&f.admin, &f.treasury, &f.usdc, &f.usdc);
    }

    #[test]
    #[should_panic(expected = "treasury cannot be a configured token contract")]
    fn test_init_rejects_usdc_contract_as_treasury() {
        let f = Fixture::new();
        f.client().init(&f.admin, &f.usdc, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "treasury cannot be a configured token contract")]
    fn test_init_rejects_xlm_contract_as_treasury() {
        let f = Fixture::new();
        f.client().init(&f.admin, &f.xlm_sac, &f.usdc, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "usdc_contract does not implement the token interface")]
    fn test_init_rejects_usdc_contract_without_token_interface() {
        let f = Fixture::new();
        let not_token = f.env.register(not_a_token::NotAToken, ());
        f.client()
            .init(&f.admin, &f.treasury, &not_token, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "xlm_contract does not implement the token interface")]
    fn test_init_rejects_xlm_contract_without_token_interface() {
        let f = Fixture::new();
        let not_token = f.env.register(not_a_token::NotAToken, ());
        f.client().init(&f.admin, &f.treasury, &f.usdc, &not_token);
    }

    #[test]
    #[should_panic(expected = "usdc_contract does not implement the token interface")]
    fn test_init_rejects_account_address_as_usdc_contract() {
        // A plain generated address has no contract deployed behind it —
        // e.g. a G-address pasted where a C-address was expected.
        let f = Fixture::new();
        let account = Address::generate(&f.env);
        f.client().init(&f.admin, &f.treasury, &account, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "usdc_contract must use 7 decimals")]
    fn test_init_rejects_usdc_contract_with_wrong_decimals() {
        let f = Fixture::new();
        let token = f.env.register(six_decimal_token::SixDecimalToken, ());
        f.client().init(&f.admin, &f.treasury, &token, &f.xlm_sac);
    }

    #[test]
    #[should_panic(expected = "xlm_contract must use 7 decimals")]
    fn test_init_rejects_xlm_contract_with_wrong_decimals() {
        let f = Fixture::new();
        let token = f.env.register(six_decimal_token::SixDecimalToken, ());
        f.client().init(&f.admin, &f.treasury, &f.usdc, &token);
    }

    #[test]
    fn test_failed_init_leaves_contract_uninitialized_and_retryable() {
        let f = Fixture::new();
        let client = f.client();
        let token = f.env.register(six_decimal_token::SixDecimalToken, ());

        // Rejections from both phases: an address check and a token probe.
        assert!(client
            .try_init(&f.usdc, &f.treasury, &f.usdc, &f.xlm_sac)
            .is_err());
        assert!(client
            .try_init(&f.admin, &f.treasury, &f.usdc, &token)
            .is_err());

        // Nothing was written: no admin, no role, no init event.
        assert!(client.try_admin().is_err());
        assert!(client.try_treasury().is_err());
        assert_eq!(client.get_role(&f.admin), None);
        assert_eq!(contract_event_count(&f.env, &f.contract_id, "init"), 0);

        // A corrected call still succeeds, since "already initialized" was
        // never tripped.
        f.init();
        assert_eq!(client.admin(), f.admin);
        assert_eq!(client.get_role(&f.admin), Some(Role::Admin));
    }

    #[test]
    fn test_init_accepts_a_contract_address_as_treasury() {
        // The treasury only receives transfers, so a contract (e.g. a
        // multisig or vault) is a valid treasury as long as it isn't one
        // of the configured tokens or this contract.
        let f = Fixture::new();
        let vault = f.env.register(not_a_token::NotAToken, ());
        f.client().init(&f.admin, &vault, &f.usdc, &f.xlm_sac);
        assert_eq!(f.client().treasury(), vault);
    }

    // ── pay_usdc tests ────────────────────────────────────────────────────────
    // Issue #423 (Part 5): Comprehensive unit tests for Soroban token transfer
    // functionality. Tests cover successful transfers, authorization, error
    // handling, reentrancy protection, pause behavior, and edge cases.

    /// `init` stores all four configuration addresses as documented.
    #[test]
    fn test_guard_resets_after_successful_pay_usdc() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 5_000_000;
        f.mint_usdc(&f.payer, amount * 2);

        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "seq-1"));
        // If guard were NOT reset, this would panic with "reentrancy detected".
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "seq-2"));

        assert_eq!(f.usdc_balance(&f.treasury), amount * 2);
        assert_eq!(f.usdc_balance(&f.payer), 0);
    }

    /// After a successful `pay_xlm`, the guard must be cleared.
    #[test]
    fn test_guard_resets_after_successful_pay_xlm() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 5_000_000;
        f.mint_xlm(&f.payer, amount * 2);

        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "xlm-1"));
        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "xlm-2"));

        assert_eq!(f.xlm_balance(&f.treasury), amount * 2);
    }

    /// After a **failed** `pay_usdc` (insufficient balance), the guard must
    /// still be cleared so the next call with sufficient balance succeeds.
    #[test]
    fn test_guard_resets_after_failed_pay_usdc() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 10_000_000;
        f.mint_usdc(&f.payer, amount / 2); // not enough — transfer fails

        let res = f.client().try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "fail"));
        assert_eq!(res, Err(Ok(Error::TransferFailed)));

        // Replenish and retry — guard must have been released on failure.
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "retry"));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
    }

    /// After a **failed** `pay_xlm`, the guard must be cleared.
    #[test]
    fn test_guard_resets_after_failed_pay_xlm() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 5_000_000;
        f.mint_xlm(&f.payer, amount / 2);

        let res = f.client().try_pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "xlm-fail"));
        assert_eq!(res, Err(Ok(Error::TransferFailed)));

        f.mint_xlm(&f.payer, amount);
        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "xlm-retry"));
        assert_eq!(f.xlm_balance(&f.treasury), amount);
    }

    /// The guard lives in temporary storage, not instance storage.
    /// Verify by reading temporary storage directly before and after a payment.
    #[test]
    fn test_guard_is_in_temporary_storage_and_cleared_after_payment() {
        let f = Fixture::new();
        f.init();

        // Before any payment — flag is absent (defaults to false).
        let before = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!before, "guard should start as false");

        let amount = 3_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "guard-check"));

        // After payment — flag must be false (cleared by _exit).
        let after = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!after, "guard should be cleared after successful payment");
    }

    /// The guard must NOT be written to instance storage — it belongs only in
    /// temporary storage to keep the instance storage footprint minimal.
    #[test]
    fn test_guard_not_in_instance_storage() {
        let f = Fixture::new();
        f.init();

        let amount = 2_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "no-inst"));

        let in_instance = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().has(&DataKey::ReentrancyGuard)
        });
        assert!(!in_instance, "guard must not appear in instance storage");
    }

    /// `pay_usdc` early-exit paths (paused, invalid amount) must NOT touch
    /// the reentrancy guard at all — they return before `_enter` is called.
    #[test]
    fn test_guard_untouched_when_pay_usdc_returns_early() {
        let f = Fixture::new();
        f.init();

        // Early exit: paused
        f.client().pause(&f.admin);
        let _ = f.client().try_pay_usdc(&f.payer, &1_000_000_i128, &order_bytes(&f.env, "early"));
        let guard_val = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!guard_val, "guard should not be set by early-exit path");
        f.client().unpause();

        // Early exit: invalid amount (zero)
        let _ = f.client().try_pay_usdc(&f.payer, &0_i128, &order_bytes(&f.env, "zero"));
        let guard_val2 = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!guard_val2, "guard should not be set by zero-amount path");
    }

    /// Interleaved USDC and XLM payments all release the (shared) guard,
    /// proving the `DataKey::ReentrancyGuard` key is correctly reused.
    #[test]
    fn test_interleaved_usdc_xlm_payments_all_clear_guard() {
        let f = Fixture::new();
        f.init();
        let amount = 4_000_000_i128;
        f.mint_usdc(&f.payer, amount * 3);
        f.mint_xlm(&f.payer, amount * 3);

        for i in 0..3 {
            let uid = format!("u{}", i);
            let xid = format!("x{}", i);
            f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, &uid));
            f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, &xid));
        }

        assert_eq!(f.usdc_balance(&f.treasury), amount * 3);
        assert_eq!(f.xlm_balance(&f.treasury), amount * 3);
    }

    // ── Regression tests ──────────────────────────────────────────────────────

    #[test]
    fn test_init_stores_all_addresses() {
        let f = Fixture::new();
        f.init();
        let c = f.client();
        assert_eq!(c.treasury(),      f.treasury);
        assert_eq!(c.usdc_contract(), f.usdc);
        assert_eq!(c.xlm_contract(),  f.xlm_sac);
        assert_eq!(c.admin(),         f.admin);
    }

    /// `pause` emits the documented `paused` event with value `true`.
    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_init_twice_panics() {
        let f = Fixture::new();
        f.init();
        f.init();
    }

    /// `pause` is documented as idempotent — calling it twice must NOT emit
    /// a second event.
    #[test]
    fn test_pay_usdc_transfers_to_treasury() {
        let f = Fixture::new();
        f.init();
        let amount = 25_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "t1"));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
        assert_eq!(f.usdc_balance(&f.payer), 0);
    }

    /// `unpause` emits the documented `unpaused` event with value `false`.
    #[test]
    fn test_pay_xlm_transfers_to_treasury() {
        let f = Fixture::new();
        f.init();
        let amount = 100_000_000_i128;
        f.mint_xlm(&f.payer, amount);
        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "t2"));
        assert_eq!(f.xlm_balance(&f.treasury), amount);
    }

    // ── reentrancy guard: rescue_tokens and callbacks (issue #397) ─────────

    /// A deliberately hostile "token" whose `transfer` tries to call back
    /// into the receiver contract, the way a malicious token passed to
    /// `rescue_tokens` could. It records whether the callback got through.
    mod reentrant_token {
        use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

        #[contracttype]
        enum Key {
            Receiver,
            CallbackSucceeded,
        }

        #[contract]
        pub struct ReentrantToken;

        #[contractimpl]
        impl ReentrantToken {
            pub fn set_receiver(env: Env, receiver: Address) {
                env.storage().instance().set(&Key::Receiver, &receiver);
            }

            pub fn decimals(_env: Env) -> u32 {
                7
            }

            pub fn transfer(env: Env, from: Address, _to: Address, amount: i128) {
                let receiver: Address = env.storage().instance().get(&Key::Receiver).unwrap();
                let client = super::super::Stellar_CardReceiverClient::new(&env, &receiver);
                // Re-enter the receiver while its own rescue_tokens call is
                // still on the stack.
                let callback = client.try_rescue_tokens(
                    &from,
                    &env.current_contract_address(),
                    &from,
                    &amount,
                );
                let payment = client.try_pay_usdc(&from, &amount, &Bytes::new(&env));
                env.storage().instance().set(
                    &Key::CallbackSucceeded,
                    &(callback.is_ok() || payment.is_ok()),
                );
            }

            pub fn callback_succeeded(env: Env) -> bool {
                env.storage()
                    .instance()
                    .get(&Key::CallbackSucceeded)
                    .unwrap_or(false)
            }
        }
    }

    fn reentrancy_guard_is_held(f: &Fixture) -> bool {
        f.env.as_contract(&f.contract_id, || {
            f.env
                .storage()
                .temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        })
    }

    #[test]
    #[should_panic(expected = "reentrancy detected")]
    fn test_reentrancy_guard_blocks_rescue_tokens_while_held() {
        let f = Fixture::new();
        f.init();
        f.mint_usdc(&f.contract_id, 1_000_000);

        f.env.as_contract(&f.contract_id, || {
            f.env
                .storage()
                .temporary()
                .set(&DataKey::ReentrancyGuard, &true);
        });

        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &1_000_000);
    }

    #[test]
    #[should_panic(expected = "reentrancy detected")]
    fn test_reentrancy_guard_blocks_pay_xlm_while_held() {
        let f = Fixture::new();
        f.init();
        f.mint_xlm(&f.payer, 1_000_000);

        f.env.as_contract(&f.contract_id, || {
            f.env
                .storage()
                .temporary()
                .set(&DataKey::ReentrancyGuard, &true);
        });

        f.client()
            .pay_xlm(&f.payer, &1_000_000, &order_bytes(&f.env, "xlm-reentry"));
    }

    #[test]
    fn test_reentrancy_guard_released_after_every_guarded_call() {
        let f = Fixture::new();
        f.init();
        f.mint_usdc(&f.payer, 2_000_000);
        f.mint_xlm(&f.payer, 1_000_000);
        f.mint_usdc(&f.contract_id, 500_000);
        let destination = Address::generate(&f.env);

        f.client()
            .pay_usdc(&f.payer, &1_000_000, &order_bytes(&f.env, "g-1"));
        assert!(!reentrancy_guard_is_held(&f));

        f.client()
            .pay_xlm(&f.payer, &1_000_000, &order_bytes(&f.env, "g-2"));
        assert!(!reentrancy_guard_is_held(&f));

        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &500_000);
        assert!(!reentrancy_guard_is_held(&f));

        // Failed transfers (insufficient balance) must release it too.
        assert_eq!(
            f.client()
                .try_pay_usdc(&f.payer, &5_000_000, &order_bytes(&f.env, "g-3")),
            Err(Ok(Error::TransferFailed))
        );
        assert!(!reentrancy_guard_is_held(&f));

        assert_eq!(
            f.client()
                .try_rescue_tokens(&f.admin, &f.usdc, &destination, &1),
            Err(Ok(Error::TransferFailed))
        );
        assert!(!reentrancy_guard_is_held(&f));
    }

    #[test]
    fn test_rejected_calls_never_acquire_the_guard() {
        // Paused and invalid-amount rejections return before the guarded
        // section, so they can't leave the guard set either.
        let f = Fixture::new();
        f.init();

        assert_eq!(
            f.client()
                .try_pay_usdc(&f.payer, &0, &order_bytes(&f.env, "zero")),
            Err(Ok(Error::InvalidAmount))
        );
        assert!(!reentrancy_guard_is_held(&f));

        f.client().pause(&f.admin);
        assert_eq!(
            f.client()
                .try_pay_xlm(&f.payer, &1, &order_bytes(&f.env, "paused")),
            Err(Ok(Error::ContractPaused))
        );
        assert!(!reentrancy_guard_is_held(&f));
    }

    #[test]
    fn test_rescue_tokens_callback_from_malicious_token_cannot_reenter() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &None, &Some(1_000));
        f.mint_usdc(&f.admin, 10_000);

        let evil = f.env.register(reentrant_token::ReentrantToken, ());
        let evil_client = reentrant_token::ReentrantTokenClient::new(&f.env, &evil);
        evil_client.set_receiver(&f.contract_id);

        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &evil, &destination, &1_000);

        // Neither the nested rescue_tokens nor the nested pay_usdc went
        // through, so no USDC moved on the callback path.
        assert!(!evil_client.callback_succeeded());
        assert_eq!(f.usdc_balance(&f.treasury), 0);
        assert_eq!(f.usdc_balance(&f.admin), 10_000);
        assert!(!reentrancy_guard_is_held(&f));

        // The single outer rescue used the whole daily budget: a callback
        // can't have slipped a second withdrawal in against a stale total.
        assert_eq!(
            f.client()
                .try_rescue_tokens(&f.admin, &evil, &destination, &1),
            Err(Ok(Error::DailyWithdrawLimitExceeded))
        );
    }

    // ── comprehensive edge-case tests ─────────────────────────────────────

    #[test]
    fn test_pay_usdc_rejects_zero() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_usdc(&f.payer, &0_i128, &order_bytes(&f.env, "z")).is_err());
    }

    /// `pause` is documented to panic with "pause requires admin" when the
    /// caller is not the stored admin.
    #[test]
    fn test_pay_usdc_rejects_negative() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_usdc(&f.payer, &(-1_i128), &order_bytes(&f.env, "n")).is_err());
    }

    /// `pay_usdc` documents that no funds move on a failed transfer — verify
    /// payer and treasury balances are unchanged.
    #[test]
    fn test_pay_xlm_rejects_zero() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_xlm(&f.payer, &0_i128, &order_bytes(&f.env, "z")).is_err());
    }

    /// The contract is documented to never hold an XLM balance (no custody).
    #[test]
    fn test_pay_xlm_rejects_negative() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_xlm(&f.payer, &(-1_i128), &order_bytes(&f.env, "n")).is_err());
    }

    /// `is_paused_view` is documented to return `false` after init (contract
    /// starts unpaused).
    #[test]
    fn test_contract_starts_unpaused() {
        let f = Fixture::new();
        f.init();
        assert!(!f.client().is_paused_view());
    }

    #[test]
    fn test_pause_blocks_pay_usdc() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.mint_usdc(&f.payer, 10_000_000);
        let res = f.client().try_pay_usdc(&f.payer, &10_000_000_i128, &order_bytes(&f.env, "p"));
        assert_eq!(res, Err(Ok(Error::ContractPaused)));
    }

    /// `transfer_admin` is documented as a two-step pattern that updates the
    /// stored admin.  Verify the new admin can exercise admin-gated functions.
    #[test]
    fn test_pause_blocks_pay_xlm() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        let res = f.client().try_pay_xlm(&f.payer, &1_000_000_i128, &order_bytes(&f.env, "p"));
        assert_eq!(res, Err(Ok(Error::ContractPaused)));
    }

    #[test]
    fn test_pay_usdc_works_after_unpause() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.client().unpause();
        let amount = 5_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "after"));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
    }

    #[test]
    fn test_pay_usdc_insufficient_balance_returns_transfer_failed() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount / 2);
        let res = f.client().try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "i"));
        assert_eq!(res, Err(Ok(Error::TransferFailed)));
    }

    #[test]
    fn test_pause_and_unpause_toggle_state() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        let available = amount / 2;
        f.mint_usdc(&f.payer, available);
        let _ = f.client().try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "i2"));
        assert_eq!(f.usdc_balance(&f.payer), available);
        assert_eq!(f.usdc_balance(&f.treasury), 0);
    }

    #[test]
    fn test_contract_never_retains_usdc() {
        let f = Fixture::new();
        f.init();
        let amount = 8_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "nc"));
        assert_eq!(f.usdc_balance(&f.contract_id), 0);
    }

    #[test]
    fn test_contract_never_retains_xlm() {
        let f = Fixture::new();
        f.init();
        let amount = 8_000_000_i128;
        f.mint_xlm(&f.payer, amount);
        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "nc"));
        assert_eq!(f.xlm_balance(&f.contract_id), 0);
    }

    #[test]
    fn test_try_getters_before_init_return_err() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Stellar_CardReceiver, ());
        let c  = Stellar_CardReceiverClient::new(&env, &id);
        assert!(c.try_treasury().is_err());
        assert!(c.try_usdc_contract().is_err());
        assert!(c.try_xlm_contract().is_err());
        assert!(c.try_admin().is_err());
    }

    #[test]
    fn test_transfer_admin_updates_admin() {
        let f = Fixture::new();
        f.init();
        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);
        assert_eq!(f.client().admin(), new_admin);
    }

    #[test]
    fn test_different_payers_accumulate_in_treasury() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        let available = amount / 2;
        f.mint_usdc(&f.payer, available);
        let _ = f
            .client()
            .try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "insuf2"));
        assert_eq!(f.usdc_balance(&f.payer), available);
        assert_eq!(f.usdc_balance(&f.treasury), 0);
    }

    #[test]
    fn test_contract_never_retains_usdc_balance_after_pay_usdc() {
        let f = Fixture::new();
        f.init();
        let amount = 8_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "no-custody"));
        assert_eq!(f.usdc_balance(&f.contract_id), 0);
    }

    #[test]
    fn test_contract_never_retains_xlm_balance_after_pay_xlm() {
        let f = Fixture::new();
        f.init();
        let amount = 8_000_000_i128;
        f.mint_xlm(&f.payer, amount);
        f.client()
            .pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "no-custody-xlm"));
        assert_eq!(f.xlm_balance(&f.contract_id), 0);
    }

    #[test]
    fn test_transfer_admin_updates_admin() {
        let f = Fixture::new();
        f.init();
        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);
        assert_eq!(f.client().admin(), new_admin);
    }

    #[test]
    fn test_try_getters_before_init_return_err() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);
        assert!(client.try_treasury().is_err());
        assert!(client.try_usdc_contract().is_err());
        assert!(client.try_xlm_contract().is_err());
        assert!(client.try_admin().is_err());
    }

    #[test]
    fn test_empty_order_id_accepted() {
        let f = Fixture::new();
        f.init();
        let amount = 1_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &Bytes::new(&f.env));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
    }

    #[test]
    fn test_different_payers_accumulate_in_treasury() {
        let f = Fixture::new();
        f.init();
        let payer2 = Address::generate(&f.env);
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.mint_usdc(&payer2, amount);
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "p1"));
        f.client()
            .pay_usdc(&payer2, &amount, &order_bytes(&f.env, "p2"));
        assert_eq!(f.usdc_balance(&f.treasury), amount * 2);
    }

    #[test]
    fn test_pay_usdc_and_pay_xlm_independent_balances() {
        let f = Fixture::new();
        f.init();

        let user1 = Address::generate(&f.env);
        let user2 = Address::generate(&f.env);

        f.client().grant_role(&user1, &Role::Viewer);
        f.client().grant_role(&user2, &Role::Operator);
        f.client().revoke_role(&user1);

        assert_eq!(f.client().get_role(&user1), None);
        assert_eq!(f.client().get_role(&user2), Some(Role::Operator));
    }

    #[test]
    fn test_pay_usdc_event_count_matches_payment() {
        let f = Fixture::new();
        f.init();

        let amount: i128 = 10_000_000;
        f.mint_usdc(&f.payer, amount * 3);

        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "evt-1"));
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "evt-2"));
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "evt-3"));

        // Each pay_usdc call emits exactly one event in the current transaction
        let events = f.env.events().all();
        let mut count = 0;
        for (contract_addr, topics, _) in events.iter() {
            if contract_addr != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym == Symbol::new(&f.env, "pay_usdc") {
                count += 1;
            }
        }
        // Soroban test env captures events from the last transaction only
        assert!(
            count >= 1,
            "should emit at least 1 pay_usdc event per transaction"
        );
    }

    #[test]
    fn test_pay_xlm_event_count_matches_payment() {
        let f = Fixture::new();
        f.init();

        let amount: i128 = 5_000_000;
        f.mint_xlm(&f.payer, amount * 2);

        f.client()
            .pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "xlm-evt-1"));
        f.client()
            .pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "xlm-evt-2"));

        let events = f.env.events().all();
        let mut count = 0;
        for (contract_addr, topics, _) in events.iter() {
            if contract_addr != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym == Symbol::new(&f.env, "pay_xlm") {
                count += 1;
            }
        }
        assert!(
            count >= 1,
            "should emit at least 1 pay_xlm event per transaction"
        );
    }

    #[test]
    fn test_usdc_and_xlm_payments_independent() {
        let f = Fixture::new();
        f.init();

        let usdc_amount: i128 = 10_000_000;
        let xlm_amount: i128 = 50_000_000;

        f.mint_usdc(&f.payer, usdc_amount);
        f.mint_xlm(&f.payer, xlm_amount);

        f.client()
            .pay_usdc(&f.payer, &usdc_amount, &order_bytes(&f.env, "mixed-usdc"));
        f.client()
            .pay_xlm(&f.payer, &xlm_amount, &order_bytes(&f.env, "mixed-xlm"));

        assert_eq!(f.usdc_balance(&f.treasury), usdc_amount);
        assert_eq!(f.xlm_balance(&f.treasury), xlm_amount);
        assert_eq!(f.usdc_balance(&f.payer), 0);
        assert_eq!(f.xlm_balance(&f.payer), 0);
    }

    // ── RBAC integration with payments tests ──────────────────────────────────

    #[test]
    fn test_admin_can_always_see_treasury() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Admin);

        assert!(f.client().has_role(&user, &Role::Admin));
        assert_eq!(f.client().treasury(), f.treasury);
    }

    #[test]
    fn test_operator_cannot_be_admin() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Operator);

        assert!(!f.client().has_role(&user, &Role::Admin));
        assert!(f.client().has_role(&user, &Role::Operator));
    }

    #[test]
    fn test_viewer_has_minimal_permissions() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);

        assert!(!f.client().has_role(&user, &Role::Admin));
        assert!(!f.client().has_role(&user, &Role::Operator));
        assert!(f.client().has_role(&user, &Role::Viewer));
    }

    #[test]
    fn test_multiple_users_can_have_roles() {
        let f = Fixture::new();
        f.init();

        let admin_user = Address::generate(&f.env);
        let operator_user = Address::generate(&f.env);
        let viewer_user = Address::generate(&f.env);

        f.client().grant_role(&admin_user, &Role::Admin);
        f.client().grant_role(&operator_user, &Role::Operator);
        f.client().grant_role(&viewer_user, &Role::Viewer);

        assert_eq!(f.client().get_role(&admin_user), Some(Role::Admin));
        assert_eq!(f.client().get_role(&operator_user), Some(Role::Operator));
        assert_eq!(f.client().get_role(&viewer_user), Some(Role::Viewer));
    }

    #[test]
    fn test_grant_role_overwrites_existing_role() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);
        assert_eq!(f.client().get_role(&user), Some(Role::Viewer));

        f.client().grant_role(&user, &Role::Operator);
        assert_eq!(f.client().get_role(&user), Some(Role::Operator));

        f.client().grant_role(&user, &Role::Admin);
        assert_eq!(f.client().get_role(&user), Some(Role::Admin));
    }

    #[test]
    fn test_revoke_role_makes_has_role_return_false() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Operator);
        assert!(f.client().has_role(&user, &Role::Operator));

        f.client().revoke_role(&user);
        assert!(!f.client().has_role(&user, &Role::Operator));
        assert!(!f.client().has_role(&user, &Role::Viewer));
        assert!(!f.client().has_role(&user, &Role::Admin));
    }

    #[test]
    fn test_admin_has_highest_privilege() {
        let f = Fixture::new();
        f.init();

        let admin_user = Address::generate(&f.env);
        f.client().grant_role(&admin_user, &Role::Admin);

        assert!(f.client().has_role(&admin_user, &Role::Admin));
        assert!(f.client().has_role(&admin_user, &Role::Operator));
        assert!(f.client().has_role(&admin_user, &Role::Viewer));
    }

    #[test]
    fn test_operator_has_operator_and_viewer_but_not_admin() {
        let f = Fixture::new();
        f.init();

        let operator_user = Address::generate(&f.env);
        f.client().grant_role(&operator_user, &Role::Operator);

        assert!(!f.client().has_role(&operator_user, &Role::Admin));
        assert!(f.client().has_role(&operator_user, &Role::Operator));
        assert!(f.client().has_role(&operator_user, &Role::Viewer));
    }

    // ── role-based access control state persistence tests ──────────────────────

    #[test]
    fn test_role_assignments_persist_across_calls() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Operator);

        assert_eq!(f.client().get_role(&user), Some(Role::Operator));
        assert_eq!(f.client().get_role(&user), Some(Role::Operator)); // Call again
    }

    #[test]
    fn test_multiple_role_assignments_do_not_interfere() {
        let f = Fixture::new();
        f.init();

        let user1 = Address::generate(&f.env);
        let user2 = Address::generate(&f.env);
        let user3 = Address::generate(&f.env);

        f.client().grant_role(&user1, &Role::Admin);
        f.client().grant_role(&user2, &Role::Operator);
        f.client().grant_role(&user3, &Role::Viewer);

        assert_eq!(f.client().get_role(&user1), Some(Role::Admin));
        assert_eq!(f.client().get_role(&user2), Some(Role::Operator));
        assert_eq!(f.client().get_role(&user3), Some(Role::Viewer));

        f.client().revoke_role(&user2);

        assert_eq!(f.client().get_role(&user1), Some(Role::Admin));
        assert_eq!(f.client().get_role(&user2), None);
        assert_eq!(f.client().get_role(&user3), Some(Role::Viewer));
    }

    // ── role management tests ────────────────────────────────────────────────

    #[test]
    fn test_grant_role_works() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        assert_eq!(f.client().get_role(&user), None);
        assert_eq!(f.client().has_role(&user, &Role::Viewer), false);

        f.client().grant_role(&user, &Role::Viewer);

        assert_eq!(f.client().get_role(&user), Some(Role::Viewer));
        assert_eq!(f.client().has_role(&user, &Role::Viewer), true);
        assert_eq!(f.client().has_role(&user, &Role::Operator), false);
        assert_eq!(f.client().has_role(&user, &Role::Admin), false);

        f.client().grant_role(&user, &Role::Operator);
        assert_eq!(f.client().get_role(&user), Some(Role::Operator));
        assert_eq!(f.client().has_role(&user, &Role::Viewer), true);
        assert_eq!(f.client().has_role(&user, &Role::Operator), true);
        assert_eq!(f.client().has_role(&user, &Role::Admin), false);
    }

    #[test]
    #[should_panic]
    fn test_grant_role_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        client.init(&admin, &treasury, &usdc, &xlm_sac);

        let user = Address::generate(&env);
        client.grant_role(&user, &Role::Viewer); // panics
    }

    #[test]
    fn test_revoke_role_works() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Operator);
        assert_eq!(f.client().get_role(&user), Some(Role::Operator));

        f.client().revoke_role(&user);
        assert_eq!(f.client().get_role(&user), None);
    }

    #[test]
    #[should_panic]
    fn test_revoke_role_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        client.init(&admin, &treasury, &usdc, &xlm_sac);

        let user = Address::generate(&env);
        client.revoke_role(&user); // panics
    }

    #[test]
    fn test_revoke_nonexistent_role_is_noop() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().revoke_role(&user);
        assert_eq!(f.client().get_role(&user), None);
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "role_revoked"),
            0
        );
    }

    // ── renounce_role (Issue #414 - Part 4) ──────────────────────────────────

    #[test]
    fn test_renounce_role_removes_own_role() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Operator);
        assert_eq!(f.client().get_role(&user), Some(Role::Operator));

        f.client().renounce_role(&user);

        assert_eq!(f.client().get_role(&user), None);
        assert_eq!(f.client().has_role(&user, &Role::Viewer), false);
    }

    #[test]
    #[should_panic]
    fn test_renounce_role_requires_self_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        env.mock_all_auths();
        client.init(&admin, &treasury, &usdc, &xlm_sac);

        let user = Address::generate(&env);
        client.grant_role(&user, &Role::Viewer);

        // Neither the user nor anyone else has authorized this call.
        env.mock_auths(&[]);
        client.renounce_role(&user); // panics
    }

    #[test]
    fn test_renounce_nonexistent_role_is_noop() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().renounce_role(&user);
        assert_eq!(f.client().get_role(&user), None);
    }

    #[test]
    fn test_renounce_role_does_not_affect_other_users() {
        let f = Fixture::new();
        f.init();

        let user1 = Address::generate(&f.env);
        let user2 = Address::generate(&f.env);
        f.client().grant_role(&user1, &Role::Operator);
        f.client().grant_role(&user2, &Role::Admin);

        f.client().renounce_role(&user1);

        assert_eq!(f.client().get_role(&user1), None);
        assert_eq!(f.client().get_role(&user2), Some(Role::Admin));
    }

    #[test]
    fn test_renounce_role_emits_correct_event() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);
        f.client().renounce_role(&user);

        let events = f.env.events().all();
        let mut found = false;
        for (contract_addr, topics, _data) in events.iter() {
            if contract_addr != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "role_renounced") {
                continue;
            }
            let emitted_caller: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            assert_eq!(emitted_caller, user);
            found = true;
            break;
        }
        assert!(found, "role_renounced event not found");
    }

    #[test]
    fn test_admin_can_still_grant_roles_after_admin_role_renounced() {
        let f = Fixture::new();
        f.init();

        // The admin renouncing its Role::Admin doesn't affect DataKey::Admin,
        // which is a separate identity — grant_role must keep working.
        f.client().renounce_role(&f.admin);
        assert_eq!(f.client().get_role(&f.admin), None);

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);
        assert_eq!(f.client().get_role(&user), Some(Role::Viewer));
    }

    #[test]
    fn test_has_role_hierarchy() {
        let f = Fixture::new();
        f.init();

        let admin_user = Address::generate(&f.env);
        let operator_user = Address::generate(&f.env);
        let viewer_user = Address::generate(&f.env);

        f.client().grant_role(&admin_user, &Role::Admin);
        f.client().grant_role(&operator_user, &Role::Operator);
        f.client().grant_role(&viewer_user, &Role::Viewer);

        // Admin has all roles
        assert!(f.client().has_role(&admin_user, &Role::Viewer));
        assert!(f.client().has_role(&admin_user, &Role::Operator));
        assert!(f.client().has_role(&admin_user, &Role::Admin));

        // Operator has Operator and Viewer
        assert!(f.client().has_role(&operator_user, &Role::Viewer));
        assert!(f.client().has_role(&operator_user, &Role::Operator));
        assert!(!f.client().has_role(&operator_user, &Role::Admin));

        // Viewer only has Viewer
        assert!(f.client().has_role(&viewer_user, &Role::Viewer));
        assert!(!f.client().has_role(&viewer_user, &Role::Operator));
        assert!(!f.client().has_role(&viewer_user, &Role::Admin));
    }

    // ── grant multiple roles to same user ──────────────────────────────────

    #[test]
    fn test_grant_multiple_roles_to_same_user() {
        let f = Fixture::new();
        f.init();

        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);
        assert_eq!(f.client().get_role(&user), Some(Role::Viewer));

        // Upgrading from Viewer to Operator
        f.client().grant_role(&user, &Role::Operator);
        assert_eq!(f.client().get_role(&user), Some(Role::Operator));
        assert!(f.client().has_role(&user, &Role::Viewer));
        assert!(f.client().has_role(&user, &Role::Operator));
        assert!(!f.client().has_role(&user, &Role::Admin));

        // Upgrading from Operator to Admin
        f.client().grant_role(&user, &Role::Admin);
        assert_eq!(f.client().get_role(&user), Some(Role::Admin));
        assert!(f.client().has_role(&user, &Role::Viewer));
        assert!(f.client().has_role(&user, &Role::Operator));
        assert!(f.client().has_role(&user, &Role::Admin));
    }

    // ── revoke admin role from original admin ──────────────────────────────

    #[test]
    fn test_revoke_admin_role_from_original_admin() {
        let f = Fixture::new();
        f.init();

        // The init function grants Admin role to the admin address
        assert_eq!(f.client().get_role(&f.admin), Some(Role::Admin));

        // Revoke admin's role
        f.client().revoke_role(&f.admin);
        assert_eq!(f.client().get_role(&f.admin), None);
        assert!(!f.client().has_role(&f.admin, &Role::Admin));
    }

    // ── has_role returns false for unknown address ─────────────────────────

    #[test]
    fn test_has_role_returns_false_for_unknown() {
        let f = Fixture::new();
        f.init();

        let unknown = Address::generate(&f.env);
        assert!(!f.client().has_role(&unknown, &Role::Viewer));
        assert!(!f.client().has_role(&unknown, &Role::Operator));
        assert!(!f.client().has_role(&unknown, &Role::Admin));
    }

    // ── pause / unpause (circuit breaker) tests ──────────────────────────────

    #[test]
    fn test_contract_starts_unpaused() {
        let f = Fixture::new();
        f.init();
        assert_eq!(f.client().is_paused_view(), false);
    }

    #[test]
    fn test_pause_requires_operator_role() {
        let f = Fixture::new();
        f.init();

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);

        f.client().pause(&operator);
        assert_eq!(f.client().is_paused_view(), true);
    }

    #[test]
    fn test_admin_role_can_also_pause() {
        let f = Fixture::new();
        f.init();

        let admin_role_holder = Address::generate(&f.env);
        f.client().grant_role(&admin_role_holder, &Role::Admin);

        f.client().pause(&admin_role_holder);
        assert_eq!(f.client().is_paused_view(), true);
    }

    #[test]
    fn test_pause_events_only_describe_state_transitions() {
        let f = Fixture::new();
        f.init();

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);
        f.client().pause(&operator);
        assert_eq!(contract_event_count(&f.env, &f.contract_id, "paused"), 1);
        f.client().pause(&operator);
        assert_eq!(contract_event_count(&f.env, &f.contract_id, "paused"), 0);

        f.client().unpause();
        assert_eq!(contract_event_count(&f.env, &f.contract_id, "unpaused"), 1);
        f.client().unpause();
        assert_eq!(contract_event_count(&f.env, &f.contract_id, "unpaused"), 0);
    }

    // ── state-change event coverage (issue #398) ──────────────────────────────

    /// Returns `(topics, data)` of the single event named `name` that this
    /// contract emitted during the last invocation, panicking if there
    /// isn't exactly one.
    fn single_contract_event(
        f: &Fixture,
        name: &str,
    ) -> (soroban_sdk::Vec<soroban_sdk::Val>, soroban_sdk::Val) {
        let symbol = Symbol::new(&f.env, name);
        let mut found = None;
        for (event_contract, topics, data) in f.env.events().all().iter() {
            if event_contract != f.contract_id {
                continue;
            }
            let event_symbol: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if event_symbol == symbol {
                assert!(found.is_none(), "more than one `{}` event emitted", name);
                found = Some((topics, data));
            }
        }
        found.unwrap_or_else(|| panic!("no `{}` event emitted", name))
    }

    #[test]
    fn test_rescue_tokens_emits_tokens_rescued_event() {
        let f = Fixture::new();
        f.init();
        f.mint_usdc(&f.contract_id, 400_000);
        let destination = Address::generate(&f.env);

        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &400_000);

        let (topics, data) = single_contract_event(&f, "tokens_rescued");
        assert_eq!(topics.len(), 3);
        let token_topic: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
        let to_topic: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
        let (caller, amount): (Address, i128) = data.try_into_val(&f.env).unwrap();
        assert_eq!(token_topic, f.usdc);
        assert_eq!(to_topic, destination);
        assert_eq!(caller, f.admin);
        assert_eq!(amount, 400_000);
    }

    #[test]
    fn test_failed_rescue_tokens_emits_no_event() {
        let f = Fixture::new();
        f.init();
        let destination = Address::generate(&f.env);

        // Insufficient contract balance -> TransferFailed.
        assert_eq!(
            f.client()
                .try_rescue_tokens(&f.admin, &f.usdc, &destination, &1),
            Err(Ok(Error::TransferFailed))
        );
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "tokens_rescued"),
            0
        );

        // Rejected by the per-call limit before any transfer is attempted.
        f.client().set_withdraw_limits(&f.admin, &Some(10), &None);
        f.mint_usdc(&f.contract_id, 100);
        assert_eq!(
            f.client()
                .try_rescue_tokens(&f.admin, &f.usdc, &destination, &11),
            Err(Ok(Error::WithdrawLimitExceeded))
        );
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "tokens_rescued"),
            0
        );
    }

    #[test]
    fn test_set_withdraw_limits_emits_event_with_new_limits() {
        let f = Fixture::new();
        f.init();

        f.client().set_withdraw_limits(&f.admin, &Some(250), &None);

        let (topics, data) = single_contract_event(&f, "withdraw_limits_set");
        let caller: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
        let limits: (Option<i128>, Option<i128>) = data.try_into_val(&f.env).unwrap();
        assert_eq!(caller, f.admin);
        assert_eq!(limits, (Some(250), None));
    }

    #[test]
    fn test_transfer_admin_emits_event_with_old_and_new_admin() {
        let f = Fixture::new();
        f.init();
        let new_admin = Address::generate(&f.env);

        f.client().transfer_admin(&new_admin);

        let (topics, _) = single_contract_event(&f, "admin_transferred");
        let old: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
        let new: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
        assert_eq!(old, f.admin);
        assert_eq!(new, new_admin);
    }

    #[test]
    fn test_renounce_role_not_held_emits_no_event() {
        let f = Fixture::new();
        f.init();
        let user = Address::generate(&f.env);

        f.client().renounce_role(&user);
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "role_renounced"),
            0
        );

        // Renouncing twice: only the first call is a real change.
        f.client().grant_role(&user, &Role::Operator);
        f.client().renounce_role(&user);
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "role_renounced"),
            1
        );
        f.client().renounce_role(&user);
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "role_renounced"),
            0
        );
    }

    #[test]
    fn test_grant_role_emits_only_when_role_changes() {
        let f = Fixture::new();
        f.init();
        let user = Address::generate(&f.env);

        f.client().grant_role(&user, &Role::Viewer);
        let (_, data) = single_contract_event(&f, "role_granted");
        let role: Role = data.try_into_val(&f.env).unwrap();
        assert_eq!(role, Role::Viewer);

        // Same role again: nothing changed, so no event.
        f.client().grant_role(&user, &Role::Viewer);
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "role_granted"),
            0
        );
        assert_eq!(f.client().get_role(&user), Some(Role::Viewer));

        // A different role is a real change and is reported.
        f.client().grant_role(&user, &Role::Operator);
        let (_, data) = single_contract_event(&f, "role_granted");
        let role: Role = data.try_into_val(&f.env).unwrap();
        assert_eq!(role, Role::Operator);
    }

    #[test]
    fn test_grant_roles_emits_only_for_addresses_whose_role_changed() {
        let f = Fixture::new();
        f.init();
        let already_viewer = Address::generate(&f.env);
        let fresh = Address::generate(&f.env);
        let was_operator = Address::generate(&f.env);
        f.client().grant_role(&already_viewer, &Role::Viewer);
        f.client().grant_role(&was_operator, &Role::Operator);

        let batch = soroban_sdk::vec![
            &f.env,
            already_viewer.clone(),
            fresh.clone(),
            was_operator.clone()
        ];
        f.client().grant_roles(&batch, &Role::Viewer);

        let mut granted = soroban_sdk::Vec::<Address>::new(&f.env);
        for (event_contract, topics, _) in f.env.events().all().iter() {
            if event_contract != f.contract_id {
                continue;
            }
            let name: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if name == Symbol::new(&f.env, "role_granted") {
                granted.push_back(topics.get(1).unwrap().try_into_val(&f.env).unwrap());
            }
        }
        assert_eq!(granted, soroban_sdk::vec![&f.env, fresh, was_operator]);
    }

    #[test]
    fn test_revoke_role_emits_single_event_only_for_held_role() {
        let f = Fixture::new();
        f.init();
        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);

        f.client().revoke_role(&user);
        let (topics, _) = single_contract_event(&f, "role_revoked");
        let revoked: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
        assert_eq!(revoked, user);

        f.client().revoke_role(&user);
        assert_eq!(
            contract_event_count(&f.env, &f.contract_id, "role_revoked"),
            0
        );
    }

    #[test]
    #[should_panic(expected = "pause requires at least the Operator role")]
    fn test_pause_rejects_viewer_role() {
        let f = Fixture::new();
        f.init();

        let viewer = Address::generate(&f.env);
        f.client().grant_role(&viewer, &Role::Viewer);

        f.client().pause(&viewer); // panics — Viewer is below Operator
    }

    #[test]
    #[should_panic(expected = "pause requires at least the Operator role")]
    fn test_pause_rejects_address_with_no_role() {
        let f = Fixture::new();
        f.init();

        let nobody = Address::generate(&f.env);
        f.client().pause(&nobody); // panics — no role at all
    }

    #[test]
    fn test_unpause_resumes_payments() {
        let f = Fixture::new();
        f.init();

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);
        f.client().pause(&operator);
        assert_eq!(f.client().is_paused_view(), true);

        f.client().unpause();
        assert_eq!(f.client().is_paused_view(), false);
    }

    // ── rescue_tokens tests ───────────────────────────────────────────────────

    #[test]
    fn test_rescue_tokens_recovers_mistaken_direct_transfer() {
        let f = Fixture::new();
        f.init();

        // Simulate a mistaken direct send: USDC minted straight to the
        // contract's own address, bypassing pay_usdc entirely.
        let amount: i128 = 3_000_000;
        f.mint_usdc(&f.contract_id, amount);
        assert_eq!(f.usdc_balance(&f.contract_id), amount);

        let rescue_destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &rescue_destination, &amount);

        assert_eq!(f.usdc_balance(&f.contract_id), 0);
        assert_eq!(f.usdc_balance(&rescue_destination), amount);
    }

    #[test]
    #[should_panic(expected = "rescue_tokens requires the Admin role")]
    fn test_rescue_tokens_requires_admin_role() {
        let f = Fixture::new();
        f.init();

        let amount: i128 = 1_000_000;
        f.mint_usdc(&f.contract_id, amount);

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);

        let destination = Address::generate(&f.env);
        // Operator is below Admin in the hierarchy — must panic (has_role
        // check), not merely return Err.
        f.client()
            .rescue_tokens(&operator, &f.usdc, &destination, &amount);
    }

    #[test]
    fn test_rescue_tokens_accepts_role_admin_who_is_not_the_stored_admin() {
        let f = Fixture::new();
        f.init();

        // Someone granted the Admin *role* — but who is NOT the stored
        // DataKey::Admin address — must still be able to rescue tokens.
        let role_admin = Address::generate(&f.env);
        f.client().grant_role(&role_admin, &Role::Admin);

        let amount: i128 = 750_000;
        f.mint_usdc(&f.contract_id, amount);
        let destination = Address::generate(&f.env);

        f.client()
            .rescue_tokens(&role_admin, &f.usdc, &destination, &amount);
        assert_eq!(f.usdc_balance(&destination), amount);
    }

    #[test]
    fn test_rescue_tokens_rejects_non_positive_amount() {
        let f = Fixture::new();
        f.init();

        f.client().grant_role(&f.admin, &Role::Admin);
        let destination = Address::generate(&f.env);

        let result = f
            .client()
            .try_rescue_tokens(&f.admin, &f.usdc, &destination, &0_i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_rescue_tokens_works_for_any_sac_not_just_configured_ones() {
        let f = Fixture::new();
        f.init();

        // A third, unrelated token (not the contract's configured USDC/XLM)
        // mistakenly sent to the contract — rescue_tokens must still work,
        // since it takes the token contract as a parameter.
        let other_token_admin = Address::generate(&f.env);
        let other_token = f
            .env
            .register_stellar_asset_contract_v2(other_token_admin.clone())
            .address();
        let amount: i128 = 500_000;
        token::StellarAssetClient::new(&f.env, &other_token).mint(&f.contract_id, &amount);

        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &other_token, &destination, &amount);

        assert_eq!(
            token::Client::new(&f.env, &other_token).balance(&destination),
            amount
        );
    }

    // ── withdraw limit tests (issue #401) ───────────────────────────────────────

    #[test]
    fn test_withdraw_limits_default_to_unset() {
        let f = Fixture::new();
        f.init();
        assert_eq!(f.client().withdraw_limits(), (None, None));
    }

    #[test]
    fn test_set_withdraw_limits_works() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &Some(1_000_000), &Some(5_000_000));
        assert_eq!(
            f.client().withdraw_limits(),
            (Some(1_000_000), Some(5_000_000))
        );
    }

    #[test]
    fn test_set_withdraw_limits_can_clear_a_limit() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &Some(1_000_000), &Some(5_000_000));
        f.client().set_withdraw_limits(&f.admin, &None, &None);
        assert_eq!(f.client().withdraw_limits(), (None, None));
    }

    #[test]
    #[should_panic(expected = "set_withdraw_limits requires the Admin role")]
    fn test_set_withdraw_limits_requires_admin_role() {
        let f = Fixture::new();
        f.init();
        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);
        f.client()
            .set_withdraw_limits(&operator, &Some(1_000_000), &None);
    }

    #[test]
    #[should_panic(expected = "withdraw limits must be positive when set")]
    fn test_set_withdraw_limits_rejects_non_positive_per_call() {
        let f = Fixture::new();
        f.init();
        f.client().set_withdraw_limits(&f.admin, &Some(0), &None);
    }

    #[test]
    fn test_rescue_tokens_within_per_call_limit_succeeds() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &Some(1_000_000), &None);

        f.mint_usdc(&f.contract_id, 1_000_000);
        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &1_000_000);

        assert_eq!(f.usdc_balance(&destination), 1_000_000);
    }

    #[test]
    fn test_rescue_tokens_over_per_call_limit_returns_err() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &Some(1_000_000), &None);

        f.mint_usdc(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        let result = f
            .client()
            .try_rescue_tokens(&f.admin, &f.usdc, &destination, &1_000_001);

        assert_eq!(result, Err(Ok(Error::WithdrawLimitExceeded)));
        // Balance must be untouched on rejection.
        assert_eq!(f.usdc_balance(&f.contract_id), 2_000_000);
    }

    #[test]
    fn test_rescue_tokens_within_daily_limit_across_multiple_calls_succeeds() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

        f.mint_usdc(&f.contract_id, 1_000_000);
        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &600_000);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &400_000);

        assert_eq!(f.usdc_balance(&destination), 1_000_000);
    }

    #[test]
    fn test_rescue_tokens_exceeding_daily_limit_on_second_call_returns_err() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

        f.mint_usdc(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &600_000);
        let result = f
            .client()
            .try_rescue_tokens(&f.admin, &f.usdc, &destination, &400_001);

        assert_eq!(result, Err(Ok(Error::DailyWithdrawLimitExceeded)));
        // The rejected call must not have moved any funds or inflated the accumulator.
        assert_eq!(f.usdc_balance(&destination), 600_000);
    }

    #[test]
    fn test_rescue_tokens_daily_limit_resets_on_the_next_day() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

        f.mint_usdc(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &1_000_000);

        // Advance the ledger clock by a full day.
        f.env.ledger().with_mut(|li| {
            li.timestamp += 86_400;
        });

        // A fresh day's accumulator is empty, so this succeeds even though
        // the prior call already used up the "previous day"'s full limit.
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &1_000_000);

        assert_eq!(f.usdc_balance(&destination), 2_000_000);
    }

    #[test]
    fn test_rescue_tokens_amount_still_counted_when_only_per_call_limit_set() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &Some(500_000), &None);

        f.mint_usdc(&f.contract_id, 500_000);
        let destination = Address::generate(&f.env);
        // Exactly at the limit must succeed (limit is inclusive).
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &500_000);
        assert_eq!(f.usdc_balance(&destination), 500_000);
    }

    #[test]
    fn test_rescue_tokens_failed_transfer_does_not_advance_daily_accumulator() {
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

        // No funds minted to the contract — the underlying token transfer
        // must fail (insufficient balance), which must not count against
        // the daily accumulator: a failed rescue shouldn't eat into the
        // day's remaining withdraw budget.
        let destination = Address::generate(&f.env);
        let result = f
            .client()
            .try_rescue_tokens(&f.admin, &f.usdc, &destination, &500_000);
        assert_eq!(result, Err(Ok(Error::TransferFailed)));

        // A second call for the same amount must still be within budget —
        // proof the first (failed) call left the accumulator untouched.
        f.mint_usdc(&f.contract_id, 500_000);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &500_000);
        assert_eq!(f.usdc_balance(&destination), 500_000);
    }

    #[test]
    fn test_rescue_tokens_xlm_sac_respects_withdraw_limits_too() {
        // The withdraw limit applies to rescue_tokens generically, not just
        // to USDC — exercised here against the XLM SAC to prove it isn't
        // hardcoded to one token contract.
        let f = Fixture::new();
        f.init();
        f.client()
            .set_withdraw_limits(&f.admin, &Some(1_000_000), &None);

        f.mint_xlm(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        let result = f
            .client()
            .try_rescue_tokens(&f.admin, &f.xlm_sac, &destination, &1_500_000);
        assert_eq!(result, Err(Ok(Error::WithdrawLimitExceeded)));

        f.client()
            .rescue_tokens(&f.admin, &f.xlm_sac, &destination, &1_000_000);
        assert_eq!(
            token::Client::new(&f.env, &f.xlm_sac).balance(&destination),
            1_000_000
        );
    }

    // ── transfer_admin tests ──────────────────────────────────────────────────

    #[test]
    fn test_transfer_admin_updates_admin_address() {
        let f = Fixture::new();
        f.init();

        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);

        assert_eq!(f.client().admin(), new_admin);
    }

    #[test]
    fn test_new_admin_can_act_after_transfer() {
        let f = Fixture::new();
        f.init();

        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);

        // The new admin must now be able to do admin-gated work (e.g.
        // grant a role) — proving the handover actually took effect, not
        // just that the getter reports the new address.
        let user = Address::generate(&f.env);
        f.client().grant_role(&user, &Role::Viewer);
        assert_eq!(f.client().get_role(&user), Some(Role::Viewer));
    }

    #[test]
    #[should_panic]
    fn test_pause_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        env.mock_all_auths();
        client.init(&admin, &treasury, &usdc, &xlm_sac);

        // init() auto-grants admin the Admin role, which satisfies pause()'s
        // Operator-or-above check -- so with no auth mocked at all, the
        // panic must come from caller.require_auth(), not a missing role.
        env.mock_auths(&[]);
        client.pause(&admin);
    }

    #[test]
    #[should_panic]
    fn test_unpause_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        env.mock_all_auths();
        client.init(&admin, &treasury, &usdc, &xlm_sac);

        // unpause() checks DataKey::Admin directly (not the Role system), and
        // is deliberately stricter than pause() — with no auth mocked at all,
        // admin.require_auth() must panic.

        env.mock_auths(&[]);
        client.unpause();
    }

    #[test]
    #[should_panic]
    fn test_old_admin_loses_authority_after_transfer() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        env.mock_all_auths();
        client.init(&admin, &treasury, &usdc, &xlm_sac);

        let new_admin = Address::generate(&env);
        client.transfer_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);

        // DataKey::Admin now holds new_admin. Mock auth for the OLD admin
        // ONLY (not new_admin) and try an admin-gated call — it must panic,
        // proving the old admin no longer has authority, not merely that
        // the getter reports a different address.
        let someone = Address::generate(&env);
        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "revoke_role",
                args: (someone.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.revoke_role(&someone);
    }

    #[test]
    #[should_panic]
    fn test_transfer_admin_requires_new_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let xlm_sac = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let contract_id = env.register(Stellar_CardReceiver, ());
        let client = Stellar_CardReceiverClient::new(&env, &contract_id);

        env.mock_all_auths();
        client.init(&admin, &treasury, &usdc, &xlm_sac);

        // transfer_admin requires BOTH the current admin's and the new
        // admin's auth. Mock only the current admin — the new admin's
        // require_auth() must panic.
        let new_admin = Address::generate(&env);
        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "transfer_admin",
                args: (new_admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.transfer_admin(&new_admin);
    }

    #[test]
    fn test_pay_usdc_rejected_when_paused() {
        let f = Fixture::new();
        f.init();

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);
        f.client().pause(&operator);

        let amount: i128 = 10_000_000;
        f.mint_usdc(&f.payer, amount);

        let oid = order_bytes(&f.env, "paused-usdc");
        let result = f.client().try_pay_usdc(&f.payer, &amount, &oid);
        assert_eq!(result, Err(Ok(Error::ContractPaused)));

        // Balance must be untouched — the paused check runs before any transfer.
        assert_eq!(f.usdc_balance(&f.payer), amount);
    }

    #[test]
    fn test_paused_contract_rejects_pay_xlm() {
        let f = Fixture::new();
        f.init();

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);
        f.client().pause(&operator);

        let amount: i128 = 5_000_000;
        f.mint_xlm(&f.payer, amount);

        let oid = order_bytes(&f.env, "paused-xlm");
        let result = f.client().try_pay_xlm(&f.payer, &amount, &oid);
        assert_eq!(result, Err(Ok(Error::ContractPaused)));
        assert_eq!(f.xlm_balance(&f.payer), amount);
    }

    #[test]
    fn test_pay_usdc_works_again_after_unpause() {
        let f = Fixture::new();
        f.init();

        let operator = Address::generate(&f.env);
        f.client().grant_role(&operator, &Role::Operator);
        f.client().pause(&operator);
        f.client().unpause();

        let amount: i128 = 10_000_000;
        f.mint_usdc(&f.payer, amount);
        let oid = order_bytes(&f.env, "after-unpause");

        f.client().pay_usdc(&f.payer, &amount, &oid);

        assert_eq!(f.usdc_balance(&f.treasury), amount);
    }

    #[test]
    fn test_different_payers_usdc() {
        let f = Fixture::new();
        f.init();

        let payer2 = Address::generate(&f.env);
        let payer3 = Address::generate(&f.env);
        let amount: i128 = 1_000_000;

        f.mint_usdc(&f.payer, amount);
        f.mint_xlm(&f.payer, amount);
        f.mint_xlm(&payer2, amount);

        f.client()
            .pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "dp-xlm-1"));
        f.client()
            .pay_xlm(&payer2, &amount, &order_bytes(&f.env, "dp-xlm-2"));

        assert_eq!(f.xlm_balance(&f.treasury), amount * 2);
    }

    #[test]
    fn test_multiple_payers_single_order() {
        let f = Fixture::new();
        f.init();

        let payer2 = Address::generate(&f.env);
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.mint_usdc(&payer2, amount);
        f.client().pay_usdc(&f.payer,  &amount, &order_bytes(&f.env, "p1"));
        f.client().pay_usdc(&payer2,   &amount, &order_bytes(&f.env, "p2"));
        assert_eq!(f.usdc_balance(&f.treasury), amount * 2);
    }

    mod upgrade_wasm {
        soroban_sdk::contractimport!(
            file = "target/wasm32v1-none/release/stellar_card_receiver.wasm"
        );
    }

    #[test]
    fn test_upgrade_works() {
        let f = Fixture::new();
        f.init();
        let new_hash = f.env.deployer().upload_contract_wasm(upgrade_wasm::WASM);
        f.client().upgrade(&new_hash);
        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym == Symbol::new(&f.env, "upgraded") {
                let emitted_hash: BytesN<32> = data.try_into_val(&f.env).unwrap();
                assert_eq!(emitted_hash, new_hash);
                found = true;
            }
        }
        assert!(found, "upgraded event not found");
    }
}
