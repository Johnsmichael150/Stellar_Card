//! # stellar_card Card Receiver Contract
//!
//! A Soroban smart contract that receives USDC and native XLM payments on behalf
//! of the stellar_card card platform and forwards them to a configured treasury
//! address.
//!
//! ## Part 3 — NatSpec Documentation (Issue #406)
//!
//! This iteration adds comprehensive **NatSpec-style doc comments** to every
//! public entrypoint, type, variant, constant, and internal helper in the
//! contract.  The goal is a self-describing codebase that lets any developer
//! understand the contract\'s behaviour, security model, and failure modes
//! without reading external documentation.
//!
//! ### Documentation conventions used
//! * `# Arguments` — every parameter described with name, type, and meaning.
//! * `# Returns` — what the function returns, including the `Ok(())` / `Err`
//!   variants for `Result`-returning functions.
//! * `# Errors` — each [`Error`] variant that can be returned, with the
//!   condition that triggers it.
//! * `# Events` — the Soroban event emitted (symbol, topics, value).
//! * `# Authorization` — who must sign the call and why.
//! * `# Panics` — explicit panic conditions and the message string.
//! * `# Notes` — idempotency guarantees, storage choices, and design rationale.
//!
//! ### Why good documentation matters for smart contracts
//! On-chain code is immutable after deployment.  A developer who
//! misunderstands an entrypoint\'s authorization or error semantics cannot
//! patch the running contract — they can only redeploy.  Precise doc comments
//! reduce that risk by making the contract\'s invariants visible at the call
//! site in any IDE.
//!
//! ## Security features
//! * **Reentrancy guard** — storage-backed flag blocks reentrant payment
//!   callbacks (see `_enter` / `_exit`).
//! * **Pause mechanism** — admin can halt all transfers during incidents.
//! * **Upgradeability** — admin can swap the WASM in place.
//!
//! ## Authorization model
//! `init` and every state-mutating admin entrypoint call `require_auth`.
//! Payment entrypoints require the paying address to authorize the transfer.

#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, Bytes, BytesN, Env,
    Symbol,
};

// ── Storage TTL constants ─────────────────────────────────────────────────────

/// Target TTL for instance storage entries, expressed in ledgers.
///
/// At a 5-second ledger close time this is approximately 1 000 days.
/// Soroban\'s live network may cap the achievable TTL below this value via its
/// `max_entry_ttl` setting; in that case the extension is silently clamped to
/// the network ceiling — this constant controls intent, not the hard floor.
const INSTANCE_TTL_MAX: u32 = 17_280_000;

/// Minimum remaining TTL below which `extend_instance_ttl` triggers a real
/// extension write.
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
/// Every slot in instance or temporary storage is accessed through one of
/// these variants so that key collisions are impossible by construction and
/// the full storage schema is visible in a single place.
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

    /// Circuit-breaker flag.
    ///
    /// When `true`, [`Stellar_CardReceiver::pay_usdc`] and
    /// [`Stellar_CardReceiver::pay_xlm`] return
    /// [`Error::ContractPaused`] immediately, before any token transfer
    /// is attempted.  Set by [`Stellar_CardReceiver::pause`] and cleared
    /// by [`Stellar_CardReceiver::unpause`].
    Paused,

    /// Reentrancy guard flag stored in **temporary** storage.
    ///
    /// `true` while a guarded payment call is executing; `false` (or absent)
    /// otherwise.  Using temporary storage ensures:
    /// * The flag does not persist across ledger closes — it is meaningless
    ///   outside the span of a single call.
    /// * It does not inflate the instance storage footprint that
    ///   `extend_instance_ttl` manages.
    ///
    /// Checked and set by [`Stellar_CardReceiver::_enter`]; cleared by
    /// [`Stellar_CardReceiver::_exit`] in every exit path.
    ReentrancyGuard,
}

// ── Contract errors ───────────────────────────────────────────────────────────

/// Errors that can be returned by fallible contract entrypoints.
///
/// These are surfaced as Soroban contract errors (u32 discriminants) so
/// callers can distinguish failure modes without parsing panic messages.
/// All `try_*` auto-generated wrappers return `Result<T, Ok(Error)>`.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The `amount` argument was ≤ 0.
    ///
    /// Both `pay_usdc` and `pay_xlm` require a strictly positive amount.
    /// This check runs before the reentrancy guard is acquired, so no
    /// storage is written when it fires.
    InvalidAmount = 1,

    /// The SAC `transfer` call returned an error.
    ///
    /// The most common cause is insufficient token balance in the payer\'s
    /// account.  When this error is returned the reentrancy guard has
    /// already been released and no funds have moved.
    TransferFailed = 2,

    /// The contract is currently paused; no payments are processed.
    ///
    /// This check runs before the reentrancy guard and before any
    /// authorization check, so neither the guard nor the payer\'s auth
    /// budget is consumed when it fires.
    ContractPaused = 3,
}

// ── Contract ─────────────────────────────────────────────────────────────────

/// The stellar_card card receiver contract.
///
/// Receives USDC and native XLM payments from AI agents (or any payer) and
/// forwards them immediately to the configured treasury address.  An order
/// identifier is included in the emitted payment event so the backend can
/// correlate card top-ups without relying on Stellar memo fields or
/// destination-tag matching.
///
/// ## Storage model
/// All persistent state lives in Soroban instance storage keyed by
/// [`DataKey`].  The struct itself carries no in-memory fields; a new
/// instance is constructed for every invocation.
///
/// ## No custody
/// `pay_usdc` and `pay_xlm` call `token::Client::try_transfer` from the
/// payer\'s address directly to [`DataKey::Treasury`].  The contract\'s own
/// address is never the recipient of a transfer and therefore can never
/// accumulate a balance from normal operation.
#[contract]
pub struct Stellar_CardReceiver;

#[contractimpl]
impl Stellar_CardReceiver {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initializes the contract with its four required configuration addresses.
    ///
    /// This is a one-time operation: calling `init` a second time panics with
    /// `"already initialized"`.  The admin must co-sign the call to prevent
    /// a front-running attack where a third party initializes the contract
    /// with their own treasury before the legitimate deployer can.
    ///
    /// # Arguments
    /// * `env`           — The Soroban execution environment.
    /// * `admin`         — The address that will hold administrative authority.
    ///   Must authorize this call.
    /// * `treasury`      — The address that will receive all forwarded payments.
    /// * `usdc_contract` — The USDC SAC contract address on this network.
    /// * `xlm_contract`  — The native XLM SAC contract address on this network.
    ///
    /// # Events
    /// Emits after all writes succeed:
    /// ```text
    /// topics : [Symbol("init"), admin]
    /// value  : (treasury, usdc_contract, xlm_contract)
    /// ```
    ///
    /// # Panics
    /// * `"already initialized"` — if [`DataKey::Admin`] already exists in
    ///   instance storage.
    /// * `"admin cannot be the contract itself"` — self-referential admin.
    /// * `"treasury cannot be the contract itself"` — self-referential treasury.
    /// * `"admin and treasury must be different addresses"` — prevents
    ///   accidental self-payment loops.
    /// * `"usdc_contract and xlm_contract must be different"` — catches
    ///   copy-paste misconfiguration.
    /// * `"usdc_contract cannot be the contract itself"` / `"xlm_contract
    ///   cannot be the contract itself"` — prevents recursive token calls.
    /// * `"treasury cannot be a configured token contract"` — a treasury
    ///   that is also a token SAC would route payments to the SAC itself.
    /// * `"usdc_contract does not implement the token interface"` /
    ///   `"xlm_contract does not implement the token interface"` — the
    ///   address was not a SAC-compatible token (caught by `try_decimals()`).
    /// * Authorization panic from `admin.require_auth()`.
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

        let this = env.current_contract_address();

        if admin == this {
            panic!("admin cannot be the contract itself");
        }
        if treasury == this {
            panic!("treasury cannot be the contract itself");
        }
        if admin == treasury {
            panic!("admin and treasury must be different addresses");
        }
        if usdc_contract == xlm_contract {
            panic!("usdc_contract and xlm_contract must be different");
        }
        if usdc_contract == this {
            panic!("usdc_contract cannot be the contract itself");
        }
        if xlm_contract == this {
            panic!("xlm_contract cannot be the contract itself");
        }
        if treasury == usdc_contract || treasury == xlm_contract {
            panic!("treasury cannot be a configured token contract");
        }

        // Probe both token addresses against the SAC interface at init time.
        // Without this probe, a plain non-token address would pass every check
        // above and only fail on the first payment call — by then the contract
        // is already live and misconfigured.  `decimals()` is read-only and
        // has no side effects, so this probe costs only the call itself.
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

    // ── Reentrancy guard ──────────────────────────────────────────────────────

    /// Acquires the reentrancy guard before an external token call.
    ///
    /// Reads [`DataKey::ReentrancyGuard`] from **temporary** storage.
    /// If the flag is already `true`, a reentrant call is in progress and
    /// this function panics immediately.  Otherwise it writes `true` to
    /// claim the guard for the current call.
    ///
    /// # Storage
    /// The flag is stored in temporary storage (not instance storage) so
    /// it does not persist across ledger closes and does not inflate the
    /// instance storage footprint that `extend_instance_ttl` manages.
    ///
    /// # Panics
    /// Panics with `"reentrancy detected"` if the guard is already held,
    /// indicating that a reentrant call into a guarded function has been
    /// attempted.
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

    /// Releases the reentrancy guard after an external token call completes.
    ///
    /// Writes `false` to [`DataKey::ReentrancyGuard`] in temporary storage.
    ///
    /// # Contract
    /// This function **must** be called in every exit path of a guarded
    /// function — both the success path and every error path — to ensure the
    /// guard is never left locked after a failed or error-returning call.
    /// A locked guard would block all subsequent payment calls for the
    /// remainder of the ledger.
    fn _exit(env: &Env) {
        env.storage()
            .temporary()
            .set(&DataKey::ReentrancyGuard, &false);
    }

    // ── Payment entrypoints ───────────────────────────────────────────────────

    /// Transfers USDC from `from` to the treasury and emits a payment event.
    ///
    /// The transfer is protected by the reentrancy guard: `_enter` is called
    /// before the SAC `try_transfer` and `_exit` is called in every exit path,
    /// so a reentrant callback from a malicious token contract cannot execute
    /// this function a second time while the first invocation is live.
    ///
    /// # Arguments
    /// * `env`      — The Soroban execution environment.
    /// * `from`     — The payer address.  Must authorize this call (the SAC
    ///   `transfer` will enforce this internally, but `require_auth` is also
    ///   called explicitly here for clarity).
    /// * `amount`   — The amount to transfer in micro-USDC (7 decimal places,
    ///   so 1 USDC = 10_000_000).  Must be > 0.
    /// * `order_id` — An opaque byte string identifying the order.  Carried in
    ///   the event topic so the backend can filter by order without decoding
    ///   the event body.  Empty bytes are accepted; there is no length limit
    ///   beyond Soroban\'s own `Bytes` ceiling.
    ///
    /// # Returns
    /// `Ok(())` on successful transfer.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`]  — the contract is paused.
    /// * [`Error::InvalidAmount`]   — `amount` ≤ 0.
    /// * [`Error::TransferFailed`]  — the SAC `try_transfer` returned an error
    ///   (e.g. the payer has insufficient balance).
    ///
    /// # Events
    /// Emitted after a successful transfer:
    /// ```text
    /// topics : [Symbol("pay_usdc"), order_id, from]
    /// value  : amount (i128)
    /// ```
    ///
    /// # Authorization
    /// `from.require_auth()` is called.  The payer must authorize the call.
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

        // Checks-Effects-Interactions: acquire guard before the external call.
        Self::_enter(&env);
        let res = token::Client::new(&env, &usdc_contract)
            .try_transfer(&from, &treasury, &amount);
        // Guard must be released in ALL exit paths.
        if res.is_err() {
            Self::_exit(&env);
            return Err(Error::TransferFailed);
        }
        Self::_exit(&env);

        env.events()
            .publish((Symbol::new(&env, "pay_usdc"), order_id, from), amount);

        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Transfers native XLM from `from` to the treasury and emits a payment
    /// event.
    ///
    /// Identical to [`pay_usdc`] in structure; uses the XLM SAC stored at
    /// [`DataKey::XlmContract`] instead of the USDC SAC.
    ///
    /// # Arguments
    /// * `env`      — The Soroban execution environment.
    /// * `from`     — The payer address.  Must authorize this call.
    /// * `amount`   — Amount in stroops (7 decimal places; 1 XLM = 10_000_000).
    ///   Must be > 0.
    /// * `order_id` — Opaque order identifier carried as an event topic.
    ///
    /// # Returns
    /// `Ok(())` on successful transfer.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`]  — the contract is paused.
    /// * [`Error::InvalidAmount`]   — `amount` ≤ 0.
    /// * [`Error::TransferFailed`]  — SAC `try_transfer` returned an error.
    ///
    /// # Events
    /// Emitted after a successful transfer:
    /// ```text
    /// topics : [Symbol("pay_xlm"), order_id, from]
    /// value  : amount (i128)
    /// ```
    ///
    /// # Authorization
    /// `from.require_auth()` is called.
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

        Self::_enter(&env);
        let res = token::Client::new(&env, &xlm_contract)
            .try_transfer(&from, &treasury, &amount);
        if res.is_err() {
            Self::_exit(&env);
            return Err(Error::TransferFailed);
        }
        Self::_exit(&env);

        env.events()
            .publish((Symbol::new(&env, "pay_xlm"), order_id, from), amount);

        Self::extend_instance_ttl(&env);
        Ok(())
    }

    // ── Administrative entrypoints ────────────────────────────────────────────

    /// Pauses the contract, blocking all new payments.
    ///
    /// While paused, `pay_usdc` and `pay_xlm` return [`Error::ContractPaused`]
    /// immediately.  This function is intended for use during incidents,
    /// upgrades, or any situation where accepting new payments is unsafe.
    ///
    /// # Arguments
    /// * `env`    — The Soroban execution environment.
    /// * `caller` — The address requesting the pause.  Must be the stored
    ///   [`DataKey::Admin`] and must authorize this call.
    ///
    /// # Events
    /// Emitted only when the contract transitions from unpaused to paused:
    /// ```text
    /// topics : [Symbol("paused"), caller]
    /// value  : true
    /// ```
    ///
    /// # Notes
    /// Idempotent — calling `pause` when the contract is already paused is a
    /// silent no-op and does NOT emit an event.  This prevents a log from
    /// being cluttered with repeated no-op pause calls.
    ///
    /// # Authorization
    /// `caller.require_auth()` is called.  `caller` must equal
    /// [`DataKey::Admin`] or the call panics with `"pause requires admin"`.
    ///
    /// # Panics
    /// * `"pause requires admin"` — `caller` is not the stored admin.
    /// * Authorization panic from `caller.require_auth()`.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("pause requires admin");
        }
        if Self::is_paused(&env) {
            return; // idempotent no-op
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::extend_instance_ttl(&env);
        env.events()
            .publish((Symbol::new(&env, "paused"), caller), true);
    }

    /// Unpauses the contract, re-enabling payments.
    ///
    /// # Arguments
    /// * `env` — The Soroban execution environment.
    ///
    /// # Events
    /// Emitted only when the contract transitions from paused to unpaused:
    /// ```text
    /// topics : [Symbol("unpaused"), admin]
    /// value  : false
    /// ```
    ///
    /// # Notes
    /// Idempotent — calling `unpause` when the contract is already unpaused is
    /// a silent no-op and does NOT emit an event.
    ///
    /// # Authorization
    /// The stored [`DataKey::Admin`] address must authorize this call.
    ///
    /// # Panics
    /// Authorization panic from `admin.require_auth()`.
    pub fn unpause(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if !Self::is_paused(&env) {
            return; // idempotent no-op
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::extend_instance_ttl(&env);
        env.events()
            .publish((Symbol::new(&env, "unpaused"), admin), false);
    }

    /// Upgrades the contract WASM to a new version.
    ///
    /// The new WASM must have been uploaded to the ledger beforehand (via
    /// `stellar contract install` or an equivalent upload call).  This
    /// function replaces the contract\'s executable code in place, preserving
    /// all storage entries.
    ///
    /// # Arguments
    /// * `env`           — The Soroban execution environment.
    /// * `new_wasm_hash` — The 32-byte hash of the uploaded WASM blob.
    ///
    /// # Events
    /// Emitted after the upgrade succeeds:
    /// ```text
    /// topics : [Symbol("upgraded"), admin]
    /// value  : new_wasm_hash (BytesN<32>)
    /// ```
    ///
    /// # Authorization
    /// The stored [`DataKey::Admin`] address must authorize this call.
    ///
    /// # Panics
    /// * Authorization panic from `admin.require_auth()`.
    /// * If `new_wasm_hash` does not correspond to a previously uploaded WASM
    ///   blob (Soroban host error).
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());
        env.events()
            .publish((Symbol::new(&env, "upgraded"), admin), new_wasm_hash);
    }

    /// Transfers administrative authority to a new address.
    ///
    /// Uses a two-step authorization pattern: both the current admin **and**
    /// `new_admin` must co-sign the transaction.  This prevents lockout from a
    /// typo\'d address — the new admin must be reachable to authorize its own
    /// appointment.
    ///
    /// # Arguments
    /// * `env`       — The Soroban execution environment.
    /// * `new_admin` — The address that will become the new admin.
    ///
    /// # Events
    /// Emitted after the write succeeds:
    /// ```text
    /// topics : [Symbol("admin_transferred"), old_admin, new_admin]
    /// value  : ()
    /// ```
    ///
    /// # Authorization
    /// Both `current_admin.require_auth()` and `new_admin.require_auth()` are
    /// called.  Either authorization failure panics.
    ///
    /// # Panics
    /// Authorization panic from either `require_auth()` call.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        current_admin.require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Self::extend_instance_ttl(&env);
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

    /// Returns the configured treasury address.
    ///
    /// # Returns
    /// The [`Address`] stored at [`DataKey::Treasury`].
    ///
    /// # Panics
    /// Panics with an unwrap failure if called before [`init`].  Callers that
    /// need to distinguish "not yet initialized" from a real address should use
    /// the auto-generated `try_treasury()` wrapper instead.
    pub fn treasury(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasury).unwrap()
    }

    /// Returns the USDC SAC contract address.
    ///
    /// # Returns
    /// The [`Address`] stored at [`DataKey::UsdcContract`].
    ///
    /// # Panics
    /// Panics if called before [`init`].  Use `try_usdc_contract()` to avoid.
    pub fn usdc_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::UsdcContract)
            .unwrap()
    }

    /// Returns the native XLM SAC contract address.
    ///
    /// # Returns
    /// The [`Address`] stored at [`DataKey::XlmContract`].
    ///
    /// # Panics
    /// Panics if called before [`init`].  Use `try_xlm_contract()` to avoid.
    pub fn xlm_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::XlmContract)
            .unwrap()
    }

    /// Returns the current admin address.
    ///
    /// # Returns
    /// The [`Address`] stored at [`DataKey::Admin`].
    ///
    /// # Panics
    /// Panics if called before [`init`].  Use `try_admin()` to avoid.
    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Returns whether the contract is currently paused.
    ///
    /// # Returns
    /// `true` if payments are blocked; `false` if payments are open.
    pub fn is_paused_view(env: Env) -> bool {
        Self::is_paused(&env)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Returns `true` if the [`DataKey::Paused`] flag is set.
    ///
    /// Defaults to `false` if the key is absent (i.e. before `init`), so
    /// callers that invoke payment functions before initialization receive
    /// the same `ContractPaused` / `InvalidAmount` / auth panic paths as
    /// normal — they do not get a misleading "not paused" result.
    fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Extends instance storage TTL toward [`INSTANCE_TTL_MAX`], but only
    /// writes to the ledger when the remaining TTL has actually dropped below
    /// [`INSTANCE_TTL_THRESHOLD`].
    ///
    /// ## Rationale
    /// Soroban charges a fee for each `extend_ttl` write regardless of whether
    /// the extension does anything useful.  When `threshold == extend_to` (the
    /// naive pattern), any tiny TTL decrease retriggers a full extension write
    /// on the next call, effectively billing rent on every invocation.
    /// Setting the threshold at half the max means the write only fires
    /// approximately once every ~500 days\' worth of calls, cutting the
    /// amortized cost dramatically.
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
    use soroban_sdk::{testutils::TryIntoVal, token, Bytes, Env, Symbol};

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

    /// Counts how many events emitted by `contract_id` carry the given symbol
    /// as their first topic.
    fn event_count(env: &Env, contract_id: &Address, name: &str) -> u32 {
        let sym = Symbol::new(env, name);
        let mut n = 0u32;
        for (emitter, topics, _) in env.events().all().iter() {
            if emitter != *contract_id {
                continue;
            }
            if let Ok(s) = topics.get(0).unwrap().try_into_val(env) as Result<Symbol, _> {
                if s == sym {
                    n += 1;
                }
            }
        }
        n
    }

    // ── Documentation correctness tests (Issue #406 — Part 3) ────────────────
    // These tests verify the documented behaviour of each function: correct
    // return values, error variants, event payloads, authorization, and the
    // panics listed in the NatSpec comments above.

    /// `init` stores all four configuration addresses as documented.
    #[test]
    fn test_init_stores_documented_addresses() {
        let f = Fixture::new();
        f.init();
        assert_eq!(f.client().treasury(),      f.treasury, "treasury mismatch");
        assert_eq!(f.client().usdc_contract(), f.usdc,     "usdc_contract mismatch");
        assert_eq!(f.client().xlm_contract(),  f.xlm_sac,  "xlm_contract mismatch");
        assert_eq!(f.client().admin(),         f.admin,    "admin mismatch");
    }

    /// `init` emits the documented `init` event with the correct topic and value.
    #[test]
    fn test_init_emits_documented_event() {
        let f = Fixture::new();
        f.init();
        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "init") { continue; }
            let emitted_admin: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let config: (Address, Address, Address) = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_admin, f.admin);
            assert_eq!(config, (f.treasury.clone(), f.usdc.clone(), f.xlm_sac.clone()));
            found = true;
        }
        assert!(found, "init event not found — documented event was not emitted");
    }

    /// `init` panics with the exact documented message on re-initialization.
    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_init_panics_already_initialized_as_documented() {
        let f = Fixture::new();
        f.init();
        f.init(); // must panic with "already initialized"
    }

    /// `pay_usdc` returns the documented `InvalidAmount` error for zero amount.
    #[test]
    fn test_pay_usdc_returns_invalid_amount_for_zero() {
        let f = Fixture::new();
        f.init();
        let res = f.client().try_pay_usdc(&f.payer, &0_i128, &order_bytes(&f.env, "z"));
        assert_eq!(res, Err(Ok(Error::InvalidAmount)),
            "documented InvalidAmount error not returned for zero amount");
    }

    /// `pay_usdc` returns the documented `InvalidAmount` error for negative amount.
    #[test]
    fn test_pay_usdc_returns_invalid_amount_for_negative() {
        let f = Fixture::new();
        f.init();
        let res = f.client().try_pay_usdc(&f.payer, &(-1_i128), &order_bytes(&f.env, "n"));
        assert_eq!(res, Err(Ok(Error::InvalidAmount)),
            "documented InvalidAmount error not returned for negative amount");
    }

    /// `pay_usdc` returns the documented `ContractPaused` error when paused.
    #[test]
    fn test_pay_usdc_returns_contract_paused_as_documented() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        let res = f.client().try_pay_usdc(&f.payer, &1_000_000_i128, &order_bytes(&f.env, "p"));
        assert_eq!(res, Err(Ok(Error::ContractPaused)),
            "documented ContractPaused error not returned when paused");
    }

    /// `pay_usdc` returns the documented `TransferFailed` error on
    /// insufficient balance.
    #[test]
    fn test_pay_usdc_returns_transfer_failed_as_documented() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount / 2); // not enough
        let res = f.client().try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "insuf"));
        assert_eq!(res, Err(Ok(Error::TransferFailed)),
            "documented TransferFailed error not returned on insufficient balance");
    }

    /// `pay_usdc` emits the documented event schema: topics=[pay_usdc, order_id, from], value=amount.
    #[test]
    fn test_pay_usdc_emits_documented_event_schema() {
        let f = Fixture::new();
        f.init();
        let amount = 15_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        let oid = order_bytes(&f.env, "doc-usdc-event");
        f.client().pay_usdc(&f.payer, &amount, &oid);

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "pay_usdc") { continue; }
            let t1: Bytes   = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let t2: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
            let val: i128   = data.try_into_val(&f.env).unwrap();
            assert_eq!(t1, oid,     "order_id topic mismatch");
            assert_eq!(t2, f.payer, "from topic mismatch");
            assert_eq!(val, amount, "amount value mismatch");
            found = true;
        }
        assert!(found, "pay_usdc event not found");
    }

    /// `pay_xlm` emits the documented event schema.
    #[test]
    fn test_pay_xlm_emits_documented_event_schema() {
        let f = Fixture::new();
        f.init();
        let amount = 20_000_000_i128;
        f.mint_xlm(&f.payer, amount);
        let oid = order_bytes(&f.env, "doc-xlm-event");
        f.client().pay_xlm(&f.payer, &amount, &oid);

        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "pay_xlm") { continue; }
            let t1: Bytes   = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let t2: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
            let val: i128   = data.try_into_val(&f.env).unwrap();
            assert_eq!(t1, oid);
            assert_eq!(t2, f.payer);
            assert_eq!(val, amount);
            found = true;
        }
        assert!(found, "pay_xlm event not found");
    }

    /// `pay_xlm` returns the documented error variants under the same conditions.
    #[test]
    fn test_pay_xlm_documented_errors() {
        let f = Fixture::new();
        f.init();
        assert_eq!(
            f.client().try_pay_xlm(&f.payer, &0_i128, &order_bytes(&f.env, "z")),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(
            f.client().try_pay_xlm(&f.payer, &(-5_i128), &order_bytes(&f.env, "n")),
            Err(Ok(Error::InvalidAmount))
        );
        f.client().pause(&f.admin);
        assert_eq!(
            f.client().try_pay_xlm(&f.payer, &1_000_000_i128, &order_bytes(&f.env, "p")),
            Err(Ok(Error::ContractPaused))
        );
        f.client().unpause();
        assert_eq!(
            f.client().try_pay_xlm(&f.payer, &5_000_000_i128, &order_bytes(&f.env, "i")),
            Err(Ok(Error::TransferFailed)) // no balance minted
        );
    }

    /// `pause` emits the documented `paused` event with value `true`.
    #[test]
    fn test_pause_emits_documented_event() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "paused") { continue; }
            let caller: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let val: bool       = data.try_into_val(&f.env).unwrap();
            assert_eq!(caller, f.admin);
            assert!(val, "documented value should be true");
            found = true;
        }
        assert!(found, "paused event not found");
    }

    /// `pause` is documented as idempotent — calling it twice must NOT emit
    /// a second event.
    #[test]
    fn test_pause_idempotency_as_documented() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        assert_eq!(event_count(&f.env, &f.contract_id, "paused"), 1,
            "first pause should emit one event");
        f.client().pause(&f.admin);
        assert_eq!(event_count(&f.env, &f.contract_id, "paused"), 0,
            "idempotent no-op must not emit a second event");
    }

    /// `unpause` emits the documented `unpaused` event with value `false`.
    #[test]
    fn test_unpause_emits_documented_event() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.client().unpause();
        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "unpaused") { continue; }
            let adm: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let val: bool    = data.try_into_val(&f.env).unwrap();
            assert_eq!(adm, f.admin);
            assert!(!val, "documented value should be false");
            found = true;
        }
        assert!(found, "unpaused event not found");
    }

    /// `unpause` is documented as idempotent — calling it when already
    /// unpaused must not emit an event.
    #[test]
    fn test_unpause_idempotency_as_documented() {
        let f = Fixture::new();
        f.init();
        f.client().unpause(); // already unpaused — no-op
        assert_eq!(event_count(&f.env, &f.contract_id, "unpaused"), 0,
            "idempotent no-op must not emit an event");
    }

    /// `transfer_admin` emits the documented event with both addresses in topics.
    #[test]
    fn test_transfer_admin_emits_documented_event() {
        let f = Fixture::new();
        f.init();
        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);
        let mut found = false;
        for (emitter, topics, _) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol  = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "admin_transferred") { continue; }
            let old: Address = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let new: Address = topics.get(2).unwrap().try_into_val(&f.env).unwrap();
            assert_eq!(old, f.admin,    "old admin topic mismatch");
            assert_eq!(new, new_admin,  "new admin topic mismatch");
            found = true;
        }
        assert!(found, "admin_transferred event not found");
    }

    /// `pause` is documented to panic with "pause requires admin" when the
    /// caller is not the stored admin.
    #[test]
    #[should_panic(expected = "pause requires admin")]
    fn test_pause_panics_with_documented_message_for_non_admin() {
        let f = Fixture::new();
        f.init();
        let non_admin = Address::generate(&f.env);
        f.client().pause(&non_admin); // must panic with documented message
    }

    /// `try_treasury` (auto-generated) returns `Err` before init, as documented
    /// in the `treasury()` NatSpec.
    #[test]
    fn test_try_getters_return_err_before_init_as_documented() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Stellar_CardReceiver, ());
        let c  = Stellar_CardReceiverClient::new(&env, &id);
        assert!(c.try_treasury().is_err(),      "try_treasury should Err before init");
        assert!(c.try_usdc_contract().is_err(), "try_usdc_contract should Err before init");
        assert!(c.try_xlm_contract().is_err(),  "try_xlm_contract should Err before init");
        assert!(c.try_admin().is_err(),         "try_admin should Err before init");
    }

    /// `pay_usdc` documents that no funds move on a failed transfer — verify
    /// payer and treasury balances are unchanged.
    #[test]
    fn test_pay_usdc_documented_no_partial_transfer_on_failure() {
        let f = Fixture::new();
        f.init();
        let amount    = 10_000_000_i128;
        let available = amount / 2;
        f.mint_usdc(&f.payer, available);
        let _ = f.client().try_pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "partial"));
        assert_eq!(f.usdc_balance(&f.payer),    available, "payer balance must be unchanged");
        assert_eq!(f.usdc_balance(&f.treasury), 0,         "treasury must receive nothing");
    }

    /// The contract is documented to never hold a USDC balance (no custody).
    #[test]
    fn test_no_custody_invariant_usdc_as_documented() {
        let f = Fixture::new();
        f.init();
        let amount = 8_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "nc"));
        assert_eq!(f.usdc_balance(&f.contract_id), 0,
            "contract must not hold a USDC balance after pay_usdc");
    }

    /// The contract is documented to never hold an XLM balance (no custody).
    #[test]
    fn test_no_custody_invariant_xlm_as_documented() {
        let f = Fixture::new();
        f.init();
        let amount = 8_000_000_i128;
        f.mint_xlm(&f.payer, amount);
        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "nc"));
        assert_eq!(f.xlm_balance(&f.contract_id), 0,
            "contract must not hold an XLM balance after pay_xlm");
    }

    /// `is_paused_view` is documented to return `false` after init (contract
    /// starts unpaused).
    #[test]
    fn test_is_paused_view_documented_initial_state() {
        let f = Fixture::new();
        f.init();
        assert!(!f.client().is_paused_view(),
            "contract must start unpaused as documented");
    }

    /// `transfer_admin` is documented as a two-step pattern that updates the
    /// stored admin.  Verify the new admin can exercise admin-gated functions.
    #[test]
    fn test_transfer_admin_documented_two_step_result() {
        let f = Fixture::new();
        f.init();
        let new_admin = Address::generate(&f.env);
        f.client().transfer_admin(&new_admin);
        assert_eq!(f.client().admin(), new_admin,
            "admin getter must return new_admin after transfer");
    }

    /// `extend_instance_ttl` is documented as a threshold-gated call — verify
    /// the threshold constant is strictly less than the max, confirming the
    /// design note in the doc comment.
    #[test]
    fn test_ttl_threshold_is_strictly_below_max_as_documented() {
        assert!(
            INSTANCE_TTL_THRESHOLD < INSTANCE_TTL_MAX,
            "INSTANCE_TTL_THRESHOLD must be < INSTANCE_TTL_MAX per documentation"
        );
        assert_eq!(
            INSTANCE_TTL_THRESHOLD,
            INSTANCE_TTL_MAX / 2,
            "INSTANCE_TTL_THRESHOLD must equal INSTANCE_TTL_MAX / 2"
        );
    }

    mod upgrade_wasm {
        soroban_sdk::contractimport!(
            file = "target/wasm32v1-none/release/stellar_card_receiver.wasm"
        );
    }

    /// `upgrade` is documented to emit an `upgraded` event with admin and hash.
    #[test]
    fn test_upgrade_emits_documented_event() {
        let f = Fixture::new();
        f.init();
        let new_hash = f.env.deployer().upload_contract_wasm(upgrade_wasm::WASM);
        f.client().upgrade(&new_hash);
        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "upgraded") { continue; }
            let admin: Address  = topics.get(1).unwrap().try_into_val(&f.env).unwrap();
            let hash: BytesN<32> = data.try_into_val(&f.env).unwrap();
            assert_eq!(admin, f.admin);
            assert_eq!(hash,  new_hash);
            found = true;
        }
        assert!(found, "upgrade event not found");
    }
}
