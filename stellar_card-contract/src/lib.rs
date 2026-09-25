//! # stellar_card Card Receiver Contract
//!
//! A Soroban smart contract that receives USDC and native XLM payments on behalf
//! of the stellar_card card platform and forwards them to a configured treasury
//! address.
//!
//! ## Part 3 — Reentrancy Guard for Payment Callbacks (Issue #407)
//!
//! This iteration adds a **storage-backed reentrancy guard** that protects
//! `pay_usdc` and `pay_xlm` from reentrant calls during the external token
//! transfer step.
//!
//! ### Why this matters on Soroban
//! Soroban's execution model is more constrained than the EVM, but a
//! SAC-compatible token contract that implements a custom `transfer` hook
//! *could* still call back into this contract mid-execution.  Without a guard,
//! such a callback could emit a spurious payment event for the same funds,
//! confusing off-chain reconciliation.  If future iterations introduce fund
//! custody (e.g. an escrow hold), unguarded reentrancy could be exploited to
//! drain those funds.  Adding the guard now costs almost nothing and prevents
//! the entire class of attacks going forward.
//!
//! ### Implementation: Checks-Effects-Interactions + temporary-storage flag
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  pay_usdc / pay_xlm                                          │
//! │                                                              │
//! │  1. CHECKS:      validate amount, paused flag                │
//! │  2. EFFECTS:     _enter(env)  ← sets ReentrancyGuard = true  │
//! │  3. INTERACTION: token.try_transfer(from, treasury, amount)  │
//! │  4. EFFECTS:     _exit(env)   ← sets ReentrancyGuard = false │
//! │     (called in both success and failure paths)               │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! The flag is stored in **temporary** storage, not instance storage:
//! * It only needs to live for the span of a single invocation — there is no
//!   reason to persist it across ledger closes.
//! * Keeping it out of instance storage prevents it from inflating the entry
//!   that `extend_instance_ttl` manages.
//!
//! ### Guard contract
//! * `_enter` panics with `"reentrancy detected"` if the flag is already `true`.
//! * `_exit` **must** be called in every exit path — both success and
//!   `TransferFailed` — so the guard is never left locked after an error.
//!
//! ## Security features
//! * **Reentrancy guard** (this part) — blocks reentrant payment callbacks.
//! * **Pause mechanism** — admin can halt all transfers during incidents.
//! * **Upgradeability** — admin can swap the WASM in place.
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

// ── Storage keys ──────────────────────────────────────────────────────────────

/// Storage keys for contract state.
///
/// Each variant identifies a slot in the contract's storage.
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
    /// Circuit breaker: `true` means payments are rejected.
    Paused,
    /// Reentrancy guard flag (Issue #407, Part 3).
    ///
    /// Stored in **temporary** storage so it exists only for the span of
    /// a single call and does not affect instance storage TTL or rent.
    ///
    /// * `true`  — a guarded payment call is currently executing.
    /// * `false` — no call in progress; entrypoint is free.
    ReentrancyGuard,
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
    /// Stores `admin`, `treasury`, `usdc_contract`, and `xlm_contract` in
    /// instance storage and sets `Paused = false`.  The admin must co-sign to
    /// prevent front-running on deployment.
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

        let this = env.current_contract_address();
        if admin == this      { panic!("admin cannot be the contract itself"); }
        if treasury == this   { panic!("treasury cannot be the contract itself"); }
        if admin == treasury  { panic!("admin and treasury must be different addresses"); }
        if usdc_contract == xlm_contract {
            panic!("usdc_contract and xlm_contract must be different");
        }
        if usdc_contract == this { panic!("usdc_contract cannot be the contract itself"); }
        if xlm_contract == this  { panic!("xlm_contract cannot be the contract itself"); }
        if treasury == usdc_contract || treasury == xlm_contract {
            panic!("treasury cannot be a configured token contract");
        }

        // Probe token interfaces at init time: a non-token address would only
        // surface as a failure on the first payment call otherwise.
        if token::Client::new(&env, &usdc_contract).try_decimals().is_err() {
            panic!("usdc_contract does not implement the token interface");
        }
        if token::Client::new(&env, &xlm_contract).try_decimals().is_err() {
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

    // ── Reentrancy guard (Issue #407 — Part 3) ────────────────────────────────

    /// Acquires the reentrancy guard before an external token call.
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

    // ── Payment entrypoints ───────────────────────────────────────────────────

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

        // CEI — acquire guard before the external call.
        Self::_enter(&env);
        let res = token::Client::new(&env, &usdc_contract)
            .try_transfer(&from, &treasury, &amount);
        // Release guard in ALL exit paths.
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
        let xlm_contract: Address = env.storage().instance().get(&DataKey::XlmContract).unwrap();

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
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        env.events().publish((Symbol::new(&env, "upgraded"), admin), new_wasm_hash);
    }

    /// Transfers admin authority to `new_admin`.
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

    /// Returns the treasury address.
    pub fn treasury(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasury).unwrap()
    }

    /// Returns the USDC SAC contract address.
    pub fn usdc_contract(env: Env) -> Address {
        env.storage().instance().get(&DataKey::UsdcContract).unwrap()
    }

    /// Returns the native XLM SAC contract address.
    pub fn xlm_contract(env: Env) -> Address {
        env.storage().instance().get(&DataKey::XlmContract).unwrap()
    }

    /// Returns the admin address.
    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Returns `true` if the contract is currently paused.
    pub fn is_paused_view(env: Env) -> bool {
        Self::is_paused(&env)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
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
    use soroban_sdk::{testutils::TryIntoVal, token, Bytes, Env, Symbol};

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
            let admin    = Address::generate(&env);
            let treasury = Address::generate(&env);
            let payer    = Address::generate(&env);
            let usdc     = env.register_stellar_asset_contract_v2(admin.clone()).address();
            let xlm_sac  = env.register_stellar_asset_contract_v2(admin.clone()).address();
            let contract_id = env.register(Stellar_CardReceiver, ());
            Fixture { env, contract_id, admin, treasury, payer, usdc, xlm_sac }
        }

        fn client(&self) -> Stellar_CardReceiverClient<'_> {
            Stellar_CardReceiverClient::new(&self.env, &self.contract_id)
        }

        fn init(&self) {
            self.client().init(&self.admin, &self.treasury, &self.usdc, &self.xlm_sac);
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

    /// After a successful `pay_usdc`, the guard must be cleared so the next
    /// sequential call also succeeds.
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
        let amount = 25_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "t1"));
        assert_eq!(f.usdc_balance(&f.treasury), amount);
        assert_eq!(f.usdc_balance(&f.payer), 0);
    }

    #[test]
    fn test_pay_xlm_transfers_to_treasury() {
        let f = Fixture::new();
        f.init();
        let amount = 100_000_000_i128;
        f.mint_xlm(&f.payer, amount);
        f.client().pay_xlm(&f.payer, &amount, &order_bytes(&f.env, "t2"));
        assert_eq!(f.xlm_balance(&f.treasury), amount);
    }

    #[test]
    fn test_pay_usdc_rejects_zero() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_usdc(&f.payer, &0_i128, &order_bytes(&f.env, "z")).is_err());
    }

    #[test]
    fn test_pay_usdc_rejects_negative() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_usdc(&f.payer, &(-1_i128), &order_bytes(&f.env, "n")).is_err());
    }

    #[test]
    fn test_pay_xlm_rejects_zero() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_xlm(&f.payer, &0_i128, &order_bytes(&f.env, "z")).is_err());
    }

    #[test]
    fn test_pay_xlm_rejects_negative() {
        let f = Fixture::new();
        f.init();
        assert!(f.client().try_pay_xlm(&f.payer, &(-1_i128), &order_bytes(&f.env, "n")).is_err());
    }

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
    fn test_pay_usdc_insufficient_balance_leaves_balances_unchanged() {
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
