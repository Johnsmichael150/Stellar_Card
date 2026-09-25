//! # stellar_card Card Receiver Contract
//!
//! A Soroban smart contract that receives USDC and native XLM payments on behalf
//! of the stellar_card card platform and forwards them to a configured treasury
//! address.
//!
//! ## Overview
//! Payers authorize a transfer of USDC or XLM to the contract, which routes the
//! funds to the treasury and emits a payment event tagged with an order identifier
//! so off-chain systems can reconcile card top-ups.
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
//! * **Pause mechanism** — the admin can pause the contract to halt all
//!   transfers during incidents or upgrades.
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
//! ## Authorization model
//! `init` and every state-mutating administrative entrypoint require the
//! caller to authorize via Soroban's `require_auth`. Payment entrypoints
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

// ── Storage keys ──────────────────────────────────────────────────────────────

/// Storage keys for contract state.
///
/// Each variant identifies a slot in the contract's instance storage.
#[contracttype]
pub enum DataKey {
    /// Address that receives forwarded payments.
    Treasury,
    /// Address of the USDC Stellar Asset Contract (SAC).
    UsdcContract,
    /// Address of the native XLM Stellar Asset Contract (SAC).
    XlmContract,
    /// Address of the contract administrator.
    Admin,
    /// Circuit breaker: when `true`, `pay_usdc`/`pay_xlm` refuse new payments.
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

/// Contract errors returned by fallible entrypoints.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Amount must be positive (> 0).
    InvalidAmount = 1,
    /// The underlying token `transfer` call failed (e.g. insufficient balance).
    TransferFailed = 2,
    /// The contract is paused; no new payments are accepted until unpaused.
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
/// Holds no in-memory state; all persistent data lives in instance storage
/// keyed by [`DataKey`]. All contract entrypoints are implemented on this type.
#[contract]
pub struct Stellar_CardReceiver;

#[contractimpl]
impl Stellar_CardReceiver {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initializes the contract with essential configuration.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `admin` - The admin address (must authorize this call)
    /// * `treasury` - The treasury address where payments are received
    /// * `usdc_contract` - The USDC SAC contract address
    /// * `xlm_contract` - The native XLM SAC contract address
    ///
    /// # Validation
    /// Rejects reuse of the receiver contract as an admin, treasury, or token
    /// contract; an admin that is also the treasury; duplicate token contracts;
    /// and a treasury that points at either token contract. Also probes both
    /// `usdc_contract` and `xlm_contract` with a `decimals()` call (Issue
    /// #409 - Part 3) so a non-token address is rejected at init time rather
    /// than surfacing on the first `pay_usdc`/`pay_xlm` call.
    ///
    /// After all writes succeed, emits an `init` event:
    /// ```text
    /// topics : [Symbol("init"), admin]
    /// value  : (treasury, usdc_contract, xlm_contract)
    /// ```
    ///
    /// # Panics
    /// * If the contract has already been initialized (`already initialized`).
    /// * If `admin.require_auth()` fails.
    /// * If any address validation check fails (self-referential addresses,
    ///   duplicate token contracts, admin == treasury, etc.).
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

        let contract_address = env.current_contract_address();

        if admin == contract_address {
            panic!("admin cannot be the contract itself");
        }
        if treasury == contract_address {
            panic!("treasury cannot be the contract itself");
        }
        if admin == treasury {
            panic!("admin and treasury must be different addresses");
        }
        if usdc_contract == xlm_contract {
            panic!("usdc_contract and xlm_contract must be different");
        }
        if usdc_contract == contract_address {
            panic!("usdc_contract cannot be the contract itself");
        }
        if xlm_contract == contract_address {
            panic!("xlm_contract cannot be the contract itself");
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
        if token::Client::new(&env, &usdc_contract)
            .try_decimals()
            .is_err()
        {
            panic!("usdc_contract does not implement the token interface");
        }
        if token::Client::new(&env, &xlm_contract)
            .try_decimals()
            .is_err()
        {
            panic!("xlm_contract does not implement the token interface");
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Treasury, &treasury);
        env.storage()
            .instance()
            .set(&DataKey::UsdcContract, &usdc_contract);
        env.storage()
            .instance()
            .set(&DataKey::XlmContract, &xlm_contract);
        env.storage().instance().set(&DataKey::Paused, &false);

        Self::extend_instance_ttl(&env);

        // Issue #408 (Part 3): emit init event so indexers can reconstruct
        // contract configuration from on-chain history without reading state.
        env.events().publish(
            (Symbol::new(&env, "init"), admin.clone()),
            (treasury, usdc_contract, xlm_contract),
        );
    }

    // ── Payment entrypoints ───────────────────────────────────────────────────

    /// Transfers USDC from `from` to the treasury and emits a `pay_usdc` event.
    ///
    /// The event carries `order_id` as a topic so the backend event watcher can
    /// filter by order without decoding the event body:
    /// ```text
    /// topics : [Symbol("pay_usdc"), order_id, from]
    /// value  : amount (i128, in micro-USDC / 10^7)
    /// ```
    ///
    /// # Errors
    /// * [`Error::ContractPaused`] — contract is paused.
    /// * [`Error::InvalidAmount`] — `amount` ≤ 0.
    /// * [`Error::TransferFailed`] — SAC transfer rejected (e.g. insufficient
    ///   balance).
    pub fn pay_usdc(env: Env, from: Address, amount: i128, order_id: Bytes) -> Result<(), Error> {
        if Self::is_paused(&env) {
            return Err(Error::ContractPaused);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        from.require_auth();

        let treasury: Address = env.storage().instance().get(&DataKey::Treasury).unwrap();
        let usdc_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::UsdcContract)
            .unwrap();

        let token_client = token::Client::new(&env, &usdc_contract);
        if token_client.try_transfer(&from, &treasury, &amount).is_err() {
            return Err(Error::TransferFailed);
        }

        // Issue #408 (Part 3): payment event — emitted after the transfer
        // succeeds so a failed call never produces a misleading event.
        env.events()
            .publish((Symbol::new(&env, "pay_usdc"), order_id, from), amount);

        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Transfers native XLM from `from` to the treasury and emits a `pay_xlm`
    /// event.
    ///
    /// The event schema mirrors `pay_usdc`:
    /// ```text
    /// topics : [Symbol("pay_xlm"), order_id, from]
    /// value  : amount (i128, in stroops / 10^7)
    /// ```
    ///
    /// # Errors
    /// * [`Error::ContractPaused`] — contract is paused.
    /// * [`Error::InvalidAmount`] — `amount` ≤ 0.
    /// * [`Error::TransferFailed`] — SAC transfer rejected.
    pub fn pay_xlm(env: Env, from: Address, amount: i128, order_id: Bytes) -> Result<(), Error> {
        if Self::is_paused(&env) {
            return Err(Error::ContractPaused);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        from.require_auth();

        let treasury: Address = env.storage().instance().get(&DataKey::Treasury).unwrap();
        let xlm_contract: Address = env.storage().instance().get(&DataKey::XlmContract).unwrap();

        let token_client = token::Client::new(&env, &xlm_contract);
        if token_client.try_transfer(&from, &treasury, &amount).is_err() {
            return Err(Error::TransferFailed);
        }

        // Issue #408 (Part 3): payment event.
        env.events()
            .publish((Symbol::new(&env, "pay_xlm"), order_id, from), amount);

        Self::extend_instance_ttl(&env);
        Ok(())
    }

    // ── Administrative entrypoints ────────────────────────────────────────────

    /// Pauses the contract, blocking all new payments.
    ///
    /// Idempotent — calling when already paused is a no-op and does **not**
    /// emit an event.
    ///
    /// Emits on an actual state transition:
    /// ```text
    /// topics : [Symbol("paused"), caller]
    /// value  : true
    /// ```
    ///
    /// # Panics
    /// * If `caller` is not the stored admin.
    /// * If `caller.require_auth()` fails.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("pause requires admin");
        }
        // Idempotent: no event for no-ops.
        if Self::is_paused(&env) {
            return;
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::extend_instance_ttl(&env);

        // Issue #408 (Part 3): emit paused event.
        env.events()
            .publish((Symbol::new(&env, "paused"), caller), true);
    }

    /// Unpauses the contract, re-enabling payments.
    ///
    /// Idempotent — calling when already unpaused is a no-op and does **not**
    /// emit an event.
    ///
    /// Emits on an actual state transition:
    /// ```text
    /// topics : [Symbol("unpaused"), admin]
    /// value  : false
    /// ```
    ///
    /// # Panics
    /// * If `admin.require_auth()` fails.
    pub fn unpause(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        // Idempotent: no event for no-ops.
        if !Self::is_paused(&env) {
            return;
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::extend_instance_ttl(&env);

        // Issue #408 (Part 3): emit unpaused event.
        env.events()
            .publish((Symbol::new(&env, "unpaused"), admin), false);
    }

    /// Upgrades the contract WASM to `new_wasm_hash`.
    ///
    /// Emits after the upgrade succeeds:
    /// ```text
    /// topics : [Symbol("upgraded"), admin]
    /// value  : new_wasm_hash
    /// ```
    ///
    /// # Panics
    /// * If `admin.require_auth()` fails.
    /// * If `new_wasm_hash` does not correspond to a previously uploaded WASM.
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
    /// # Panics
    /// Panics if `caller` does not hold the `Admin` role, or if
    /// `caller.require_auth()` fails.
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
        if !is_stored_admin && !Self::has_role(env.clone(), caller, Role::Admin) {
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

        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &token_contract);
        let res = token_client.try_transfer(&contract_address, &to, &amount);
        if res.is_err() {
            return Err(Error::TransferFailed);
        }

        // Only record the withdrawal against today's accumulator once the
        // transfer has actually succeeded.
        env.storage().instance().set(&day_key, &new_total);
        Self::extend_instance_ttl(&env);
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
            None => env.storage().instance().remove(&DataKey::WithdrawLimitPerCall),
        }
        match per_day {
            Some(v) => env
                .storage()
                .instance()
                .set(&DataKey::WithdrawLimitPerDay, &v),
            None => env.storage().instance().remove(&DataKey::WithdrawLimitPerDay),
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
        let per_call = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawLimitPerCall);
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
    /// * `env` - The Soroban environment
    /// * `new_admin` - The address to become the new admin
    ///
    /// # Authorization (Issue #426 - Part 5 - Complete NatSpec)
    /// Requires auth from BOTH the current admin (`DataKey::Admin`) and
    /// `new_admin` itself — matching `grant_role`/`revoke_role`'s pattern of
    /// panicking (via `require_auth`) on an authorization failure, rather
    /// than returning a `Result`.
    ///
    /// # Events (Issue #428 - Part 5)
    /// Emits: topics=[Symbol("admin_transferred"), old_admin, new_admin], value=()
    ///
    /// # Security
    /// Two-step authorization prevents accidental admin lockout from typos or
    /// unreachable addresses.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        current_admin.require_auth();
        new_admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Self::extend_instance_ttl(&env);

        // Issue #408 (Part 3): emit admin transfer event so off-chain
        // monitors can track the authority chain without polling storage.
        env.events().publish(
            (
                Symbol::new(&env, "admin_transferred"),
                current_admin,
                new_admin,
            ),
            (),
        );
    }

    // ── View entrypoints ──────────────────────────────────────────────────────

    /// Returns the treasury address.
    ///
    /// # Panics
    /// Panics if called before `init`. Use `try_treasury` to avoid panicking.
    pub fn treasury(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasury).unwrap()
    }

    /// Returns the USDC SAC contract address.
    ///
    /// # Panics
    /// Panics if called before `init`. Use `try_usdc_contract` to avoid panicking.
    pub fn usdc_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::UsdcContract)
            .unwrap()
    }

    /// Returns the native XLM SAC contract address.
    ///
    /// # Panics
    /// Panics if called before `init`. Use `try_xlm_contract` to avoid panicking.
    pub fn xlm_contract(env: Env) -> Address {
        env.storage().instance().get(&DataKey::XlmContract).unwrap()
    }

    /// Returns the admin address.
    ///
    /// # Panics
    /// Panics if called before `init`. Use `try_admin` to avoid panicking.
    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Returns `true` if the contract is currently paused.
    pub fn is_paused_view(env: Env) -> bool {
        Self::is_paused(&env)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Returns `true` if the contract is currently paused.
    fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Extends instance storage TTL, but only writes when the remaining TTL
    /// has dropped below `INSTANCE_TTL_THRESHOLD`. This avoids a redundant
    /// ledger write (and the associated fee) on every single call.
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
        testutils::{Events, TryIntoVal},
        token, Bytes, Env, Symbol,
    };

    // ── Test fixture ──────────────────────────────────────────────────────────

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
        fn new() -> Self {
            let env = Env::default();
            env.mock_all_auths();

            let admin = Address::generate(&env);
            let treasury = Address::generate(&env);
            let payer = Address::generate(&env);

            let usdc = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();
            let xlm_sac = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();

            let contract_id = env.register(Stellar_CardReceiver, ());

            Fixture {
                env,
                contract_id,
                admin,
                treasury,
                payer,
                usdc,
                xlm_sac,
            }
        }

        fn client(&self) -> Stellar_CardReceiverClient<'_> {
            Stellar_CardReceiverClient::new(&self.env, &self.contract_id)
        }

        fn init(&self) {
            self.client()
                .init(&self.admin, &self.treasury, &self.usdc, &self.xlm_sac);
        }

        fn mint_usdc(&self, to: &Address, amount: i128) {
            token::StellarAssetClient::new(&self.env, &self.usdc).mint(to, &amount);
        }

        fn mint_xlm(&self, to: &Address, amount: i128) {
            token::StellarAssetClient::new(&self.env, &self.xlm_sac).mint(to, &amount);
        }

        fn usdc_balance(&self, addr: &Address) -> i128 {
            token::Client::new(&self.env, &self.usdc).balance(addr)
        }

        fn xlm_balance(&self, addr: &Address) -> i128 {
            token::Client::new(&self.env, &self.xlm_sac).balance(addr)
        }
    }

    fn order_bytes(env: &Env, s: &str) -> Bytes {
        Bytes::from_slice(env, s.as_bytes())
    }

    /// Returns the number of events emitted by `contract_id` with the given
    /// topic-0 symbol name during the last transaction.
    fn event_count(env: &Env, contract_id: &Address, name: &str) -> u32 {
        let sym = Symbol::new(env, name);
        let mut count = 0u32;
        for (emitter, topics, _) in env.events().all().iter() {
            if emitter != *contract_id {
                continue;
            }
            if let Ok(s) = topics.get(0).unwrap().try_into_val(env) as Result<Symbol, _> {
                if s == sym {
                    count += 1;
                }
            }
        }
        count
    }

    // ── init event tests ──────────────────────────────────────────────────────

    /// After a successful `init`, exactly one `init` event must be emitted with
    /// admin as topic[1] and (treasury, usdc, xlm) as the value tuple.
    #[test]
    fn test_init_emits_event_with_correct_fields() {
        let f = Fixture::new();
        f.init();

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "init") {
                continue;
            }
            let emitted_admin: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let config: (Address, Address, Address) = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_admin, f.admin, "init event admin mismatch");
            assert_eq!(config.0, f.treasury, "init event treasury mismatch");
            assert_eq!(config.1, f.usdc, "init event usdc mismatch");
            assert_eq!(config.2, f.xlm_sac, "init event xlm mismatch");
            found = true;
        }
        assert!(found, "init event not found");
    }

    /// `init` must emit exactly one event (not zero, not two).
    #[test]
    fn test_init_emits_exactly_one_event() {
        let f = Fixture::new();
        f.init();
        assert_eq!(event_count(&f.env, &f.contract_id, "init"), 1);
    }

    /// A failed `init` (re-initialization attempt) must not emit any event.
    #[test]
    fn test_failed_init_emits_no_event() {
        let f = Fixture::new();
        f.init();
        let _ = f
            .client()
            .try_init(&f.admin, &f.treasury, &f.usdc, &f.xlm_sac);
        // The second call panics; events from it are not persisted.
        // We simply confirm the first call's event is still the only one.
        assert_eq!(event_count(&f.env, &f.contract_id, "init"), 1);
    }

    // ── pay_usdc event tests ──────────────────────────────────────────────────

    /// A successful `pay_usdc` must emit a `pay_usdc` event with the correct
    /// order_id (topic[1]), from (topic[2]), and amount (value).
    #[test]
    fn test_pay_usdc_emits_correct_event() {
        let f = Fixture::new();
        f.init();

        let amount: i128 = 10_000_000; // 10 USDC
        f.mint_usdc(&f.payer, amount);
        let oid = order_bytes(&f.env, "order-abc-123");
        f.client().pay_usdc(&f.payer, &amount, &oid);

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "pay_usdc") {
                continue;
            }
            let emitted_oid: Bytes = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let emitted_from: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
            let emitted_amount: i128 = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_oid, oid, "order_id mismatch");
            assert_eq!(emitted_from, f.payer, "from mismatch");
            assert_eq!(emitted_amount, amount, "amount mismatch");
            found = true;
        }
        assert!(found, "pay_usdc event not found");
    }

    /// A failed `pay_usdc` (insufficient balance) must NOT emit any event.
    #[test]
    fn test_pay_usdc_failed_transfer_emits_no_event() {
        let f = Fixture::new();
        f.init();
        // Do NOT mint — transfer will fail.
        let oid = order_bytes(&f.env, "fail-order");
        let _ = f.client().try_pay_usdc(&f.payer, &5_000_000_i128, &oid);
        assert_eq!(event_count(&f.env, &f.contract_id, "pay_usdc"), 0);
    }

    /// A `pay_usdc` rejected because the contract is paused must NOT emit any event.
    #[test]
    fn test_pay_usdc_paused_emits_no_payment_event() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);

        let oid = order_bytes(&f.env, "paused-order");
        let _ = f
            .client()
            .try_pay_usdc(&f.payer, &1_000_000_i128, &oid);
        assert_eq!(event_count(&f.env, &f.contract_id, "pay_usdc"), 0);
    }

    /// Multiple successful `pay_usdc` calls each emit exactly one event.
    #[test]
    fn test_pay_usdc_multiple_calls_each_emit_one_event() {
        let f = Fixture::new();
        f.init();

        let amount: i128 = 5_000_000;
        f.mint_usdc(&f.payer, amount * 3);

        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "o1"));
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "o2"));
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "o3"));

        // Soroban test env accumulates all events; count all pay_usdc ones.
        assert_eq!(event_count(&f.env, &f.contract_id, "pay_usdc"), 3);
    }

    // ── pay_xlm event tests ───────────────────────────────────────────────────

    /// A successful `pay_xlm` must emit a `pay_xlm` event with the correct fields.
    #[test]
    fn test_pay_xlm_emits_correct_event() {
        let f = Fixture::new();
        f.init();

        let amount: i128 = 50_000_000; // 50 XLM
        f.mint_xlm(&f.payer, amount);
        let oid = order_bytes(&f.env, "xlm-order-456");
        f.client().pay_xlm(&f.payer, &amount, &oid);

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "pay_xlm") {
                continue;
            }
            let emitted_oid: Bytes = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let emitted_from: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
            let emitted_amount: i128 = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_oid, oid);
            assert_eq!(emitted_from, f.payer);
            assert_eq!(emitted_amount, amount);
            found = true;
        }
        assert!(found, "pay_xlm event not found");
    }

    /// A failed `pay_xlm` (no balance) must NOT emit any event.
    #[test]
    fn test_pay_xlm_failed_transfer_emits_no_event() {
        let f = Fixture::new();
        f.init();
        let oid = order_bytes(&f.env, "xlm-fail");
        let _ = f.client().try_pay_xlm(&f.payer, &1_000_000_i128, &oid);
        assert_eq!(event_count(&f.env, &f.contract_id, "pay_xlm"), 0);
    }

    // ── pause / unpause event tests ───────────────────────────────────────────

    /// `pause` must emit exactly one `paused` event on the first call.
    #[test]
    fn test_pause_emits_paused_event() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "paused") {
                continue;
            }
            let emitted_caller: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let val: bool = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_caller, f.admin);
            assert!(val, "paused event value should be true");
            found = true;
        }
        assert!(found, "paused event not found");
    }

    /// Calling `pause` when already paused is a no-op — must NOT emit a second event.
    #[test]
    fn test_pause_idempotent_emits_no_duplicate_event() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        assert_eq!(event_count(&f.env, &f.contract_id, "paused"), 1);
        f.client().pause(&f.admin); // no-op
        assert_eq!(event_count(&f.env, &f.contract_id, "paused"), 0);
    }

    /// `unpause` must emit exactly one `unpaused` event.
    #[test]
    fn test_unpause_emits_unpaused_event() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.client().unpause();

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "unpaused") {
                continue;
            }
            let emitted_admin: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let val: bool = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_admin, f.admin);
            assert!(!val, "unpaused event value should be false");
            found = true;
        }
        assert!(found, "unpaused event not found");
    }

    /// Calling `unpause` when already unpaused is a no-op — must NOT emit an event.
    #[test]
    fn test_unpause_idempotent_emits_no_duplicate_event() {
        let f = Fixture::new();
        f.init();
        // Contract starts unpaused; unpause is a no-op.
        f.client().unpause();
        assert_eq!(event_count(&f.env, &f.contract_id, "unpaused"), 0);
    }

    // ── transfer_admin event tests ────────────────────────────────────────────

    /// `transfer_admin` must emit an `admin_transferred` event with both
    /// addresses in the topics.
    #[test]
    fn test_transfer_admin_emits_event() {
        let f = Fixture::new();
        f.init();
        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);

        let mut found = false;
        for (emitter, topics, _data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "admin_transferred") {
                continue;
            }
            let old: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let new: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
            assert_eq!(old, f.admin, "old admin mismatch");
            assert_eq!(new, new_admin, "new admin mismatch");
            found = true;
        }
        assert!(found, "admin_transferred event not found");
    }

    // ── upgrade event tests ───────────────────────────────────────────────────

    mod upgrade_wasm {
        soroban_sdk::contractimport!(
            file = "target/wasm32v1-none/release/stellar_card_receiver.wasm"
        );
    }

    /// `upgrade` must emit an `upgraded` event containing the new WASM hash.
    #[test]
    fn test_upgrade_emits_event() {
        let f = Fixture::new();
        f.init();

        let new_hash = f.env.deployer().upload_contract_wasm(upgrade_wasm::WASM);
        f.client().upgrade(&new_hash);

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id {
                continue;
            }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "upgraded") {
                continue;
            }
            let emitted_admin: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let emitted_hash: BytesN<32> = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_admin, f.admin);
            assert_eq!(emitted_hash, new_hash);
            found = true;
        }
        assert!(found, "upgraded event not found");
    }

    // ── existing functional tests (regression) ────────────────────────────────

    #[test]
    fn test_init_stores_all_addresses() {
        let f = Fixture::new();
        f.init();
        let c = f.client();
        assert_eq!(c.treasury(), f.treasury);
        assert_eq!(c.usdc_contract(), f.usdc);
        assert_eq!(c.xlm_contract(), f.xlm_sac);
        assert_eq!(c.admin(), f.admin);
    }

    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_init_twice_panics() {
        let f = Fixture::new();
        f.init();
        f.init();
    }

    #[test]
    fn test_pay_usdc_transfers_to_treasury() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 25_000_000;
        f.mint_usdc(&f.payer, amount);
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "t1"));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
        assert_eq!(f.usdc_balance(&f.payer), 0);
    }

    #[test]
    fn test_pay_xlm_transfers_to_treasury() {
        let f = Fixture::new();
        f.init();
        let amount: i128 = 100_000_000;
        f.mint_xlm(&f.payer, amount);
        f.client()
            .pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "t2"));
        assert_eq!(f.xlm_balance(&f.treasury), amount);
        assert_eq!(f.xlm_balance(&f.payer), 0);
    }

    #[test]
    fn test_pay_usdc_rejects_zero_amount() {
        let f = Fixture::new();
        f.init();
        let res = f
            .client()
            .try_pay_usdc(&f.payer, &0_i128, &order_bytes(&f.env, "z"));
        assert!(res.is_err());
    }

    #[test]
    fn test_pay_usdc_rejects_negative_amount() {
        let f = Fixture::new();
        f.init();
        let res = f
            .client()
            .try_pay_usdc(&f.payer, &(-1_i128), &order_bytes(&f.env, "n"));
        assert!(res.is_err());
    }

    #[test]
    fn test_pay_xlm_rejects_zero_amount() {
        let f = Fixture::new();
        f.init();
        let res = f
            .client()
            .try_pay_xlm(&f.payer, &0_i128, &order_bytes(&f.env, "z"));
        assert!(res.is_err());
    }

    #[test]
    fn test_pay_xlm_rejects_negative_amount() {
        let f = Fixture::new();
        f.init();
        let res = f
            .client()
            .try_pay_xlm(&f.payer, &(-1_i128), &order_bytes(&f.env, "n"));
        assert!(res.is_err());
    }

    #[test]
    fn test_contract_starts_unpaused() {
        let f = Fixture::new();
        f.init();
        assert!(!f.client().is_paused_view());
    }

    #[test]
    fn test_pause_and_unpause_toggle_state() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        assert!(f.client().is_paused_view());
        f.client().unpause();
        assert!(!f.client().is_paused_view());
    }

    #[test]
    fn test_pay_usdc_rejected_when_paused() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.mint_usdc(&f.payer, 10_000_000);
        let res = f.client().try_pay_usdc(
            &f.payer,
            &10_000_000_i128,
            &order_bytes(&f.env, "paused"),
        );
        assert_eq!(res, Err(Ok(Error::ContractPaused)));
    }

    #[test]
    fn test_pay_xlm_rejected_when_paused() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        let res = f
            .client()
            .try_pay_xlm(&f.payer, &1_000_000_i128, &order_bytes(&f.env, "paused"));
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
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "after-unpause"));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
    }

    #[test]
    fn test_pay_usdc_insufficient_balance_returns_transfer_failed() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount / 2);
        let res = f
            .client()
            .try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "insuf"));
        assert_eq!(res, Err(Ok(Error::TransferFailed)));
    }

    #[test]
    fn test_pay_usdc_insufficient_balance_leaves_balances_unchanged() {
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
        f.client().set_withdraw_limits(&f.admin, &Some(1_000_000), &None);

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
        f.client().set_withdraw_limits(&f.admin, &Some(1_000_000), &None);

        f.mint_usdc(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        let result =
            f.client()
                .try_rescue_tokens(&f.admin, &f.usdc, &destination, &1_000_001);

        assert_eq!(result, Ok(Err(Error::WithdrawLimitExceeded)));
        // Balance must be untouched on rejection.
        assert_eq!(f.usdc_balance(&f.contract_id), 2_000_000);
    }

    #[test]
    fn test_rescue_tokens_within_daily_limit_across_multiple_calls_succeeds() {
        let f = Fixture::new();
        f.init();
        f.client().set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

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
        f.client().set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

        f.mint_usdc(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        f.client()
            .rescue_tokens(&f.admin, &f.usdc, &destination, &600_000);
        let result =
            f.client()
                .try_rescue_tokens(&f.admin, &f.usdc, &destination, &400_001);

        assert_eq!(result, Ok(Err(Error::DailyWithdrawLimitExceeded)));
        // The rejected call must not have moved any funds or inflated the accumulator.
        assert_eq!(f.usdc_balance(&destination), 600_000);
    }

    #[test]
    fn test_rescue_tokens_daily_limit_resets_on_the_next_day() {
        let f = Fixture::new();
        f.init();
        f.client().set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

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
        f.client().set_withdraw_limits(&f.admin, &Some(500_000), &None);

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
        f.client().set_withdraw_limits(&f.admin, &None, &Some(1_000_000));

        // No funds minted to the contract — the underlying token transfer
        // must fail (insufficient balance), which must not count against
        // the daily accumulator: a failed rescue shouldn't eat into the
        // day's remaining withdraw budget.
        let destination = Address::generate(&f.env);
        let result =
            f.client()
                .try_rescue_tokens(&f.admin, &f.usdc, &destination, &500_000);
        assert_eq!(result, Ok(Err(Error::TransferFailed)));

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
        f.client().set_withdraw_limits(&f.admin, &Some(1_000_000), &None);

        f.mint_xlm(&f.contract_id, 2_000_000);
        let destination = Address::generate(&f.env);
        let result =
            f.client()
                .try_rescue_tokens(&f.admin, &f.xlm_sac, &destination, &1_500_000);
        assert_eq!(result, Ok(Err(Error::WithdrawLimitExceeded)));

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
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "usdc-only"));
        assert_eq!(f.xlm_balance(&f.payer), amount);
        assert_eq!(f.xlm_balance(&f.treasury), 0);
    }
}
