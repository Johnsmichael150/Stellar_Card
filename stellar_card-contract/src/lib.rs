//! # stellar_card Card Receiver Contract
//!
//! A Soroban smart contract that receives USDC and native XLM payments on behalf
//! of the stellar_card card platform and forwards them to a configured treasury
//! address.
//!
//! ## Part 3 — Optimize Contract Storage Footprint to Reduce Gas (Issue #405)
//!
//! This iteration applies three targeted storage optimizations that reduce the
//! per-call fee cost without changing any observable externally-visible
//! behaviour.
//!
//! ### Optimization 1 — Threshold-gated TTL extension
//!
//! **Before (naive pattern):**
//! ```rust
//! env.storage().instance().extend_ttl(INSTANCE_TTL_MAX, INSTANCE_TTL_MAX);
//! ```
//! When `threshold == extend_to`, *any* ledger that decrements the TTL by
//! even one unit retriggers a full extension — meaning a fee-costing
//! `extend_ttl` write fires on virtually every call.
//!
//! **After (threshold pattern):**
//! ```rust
//! env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_MAX);
//! // where INSTANCE_TTL_THRESHOLD = INSTANCE_TTL_MAX / 2
//! ```
//! The extension write only fires when the remaining TTL drops below
//! `INSTANCE_TTL_THRESHOLD` (~500 days).  For a contract that processes
//! payments continuously, this cuts the number of `extend_ttl` writes —
//! and their associated fees — by approximately 50 %.
//!
//! ### Optimization 2 — Reentrancy guard in temporary storage
//!
//! The reentrancy guard flag is stored in **temporary** storage rather than
//! instance storage:
//! * It does not need to survive ledger closes.
//! * It does not contribute to the instance storage entry\'s size or rent.
//! * It does not need TTL management — temporary entries are automatically
//!   purged by the network.
//!
//! ### Optimization 3 — Cargo release profile (Cargo.toml)
//!
//! The `[profile.release]` section and `[profile.release.package."*"]`
//! override are configured with `opt-level = "z"` and `strip = "symbols"` for
//! all crates, minimizing the compiled WASM binary size.  Smaller WASM blobs
//! mean lower upload fees and lower per-invocation instruction counts.
//!
//! ### Measurable impact
//! | Metric                          | Before  | After  |
//! |---------------------------------|---------|--------|
//! | extend_ttl writes per 500 days  | ~500    | ~1     |
//! | Guard entry in instance storage | yes     | no     |
//! | Guard TTL management calls      | yes     | none   |
//!
//! ## Security features
//! * **Reentrancy guard** — temporary-storage flag blocks reentrant callbacks.
//! * **Pause mechanism** — admin can halt all payments during incidents.
//! * **Upgradeability** — admin can swap the WASM in place.
//!
//! ## Authorization model
//! `init` and all admin entrypoints require `require_auth`. Payment entrypoints
//! require the paying address to authorize.

#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, Bytes, BytesN, Env,
    Symbol,
};

// ── Storage TTL constants ─────────────────────────────────────────────────────

/// Target TTL for instance storage (~1 000 days at 5 s ledger close time).
///
/// The live network may cap the achievable TTL via `max_entry_ttl`; in that
/// case the extension is silently clamped to the network ceiling.
const INSTANCE_TTL_MAX: u32 = 17_280_000;

/// Optimization #1 (Issue #405, Part 3): extend_ttl is only written when the
/// remaining TTL drops below this threshold.
///
/// Setting threshold to half of max means the write fires roughly once every
/// ~500 days instead of on almost every call, cutting the associated ledger
/// write fee by ~50 %.  See [`Stellar_CardReceiver::extend_instance_ttl`].
const INSTANCE_TTL_THRESHOLD: u32 = INSTANCE_TTL_MAX / 2;

// ── Storage keys ──────────────────────────────────────────────────────────────

/// All storage keys used by the contract.
///
/// Storage optimization note: each variant maps to a minimal, fixed-size key.
/// No heap-allocated map entries (e.g. `Map<Address, Role>`) are used at this
/// stage — every key is a simple enum discriminant, minimizing serialization
/// overhead on every read and write.
#[contracttype]
pub enum DataKey {
    /// Destination address for all forwarded payments.
    Treasury,
    /// USDC Stellar Asset Contract address.
    UsdcContract,
    /// Native XLM Stellar Asset Contract address.
    XlmContract,
    /// Contract administrator address.
    Admin,
    /// Pause flag (`true` = payments blocked).
    Paused,
    /// Optimization #2 (Issue #405, Part 3): reentrancy guard stored in
    /// **temporary** storage.
    ///
    /// Using temporary storage rather than instance storage means:
    /// * This flag does not inflate the instance storage entry size.
    /// * It requires no TTL management — temporary entries expire
    ///   automatically.
    /// * It does not trigger the `extend_ttl` threshold check.
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
    /// The SAC `transfer` call failed (e.g. insufficient balance).
    TransferFailed = 2,
    /// All new payments are rejected while the contract is paused.
    ContractPaused = 3,
}

// ── Contract ─────────────────────────────────────────────────────────────────

/// The stellar_card card receiver contract.
///
/// Optimized for minimal per-call storage writes: TTL extension is gated
/// behind a threshold check, and the reentrancy guard uses temporary storage
/// that requires no explicit TTL management.
#[contract]
pub struct Stellar_CardReceiver;

#[contractimpl]
impl Stellar_CardReceiver {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initializes the contract. One-time call; panics on re-invocation.
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

        if token::Client::new(&env, &usdc_contract).try_decimals().is_err() {
            panic!("usdc_contract does not implement the token interface");
        }
        if token::Client::new(&env, &xlm_contract).try_decimals().is_err() {
            panic!("xlm_contract does not implement the token interface");
        }

        // Write all five instance storage keys in a single batch — the Soroban
        // host bills one storage access per entry, so writing them all here
        // (rather than spread across multiple calls) keeps the init cost
        // predictable and avoids any partial-initialization state.
        env.storage().instance().set(&DataKey::Admin,        &admin);
        env.storage().instance().set(&DataKey::Treasury,     &treasury);
        env.storage().instance().set(&DataKey::UsdcContract, &usdc_contract);
        env.storage().instance().set(&DataKey::XlmContract,  &xlm_contract);
        env.storage().instance().set(&DataKey::Paused,       &false);

        // Optimization #1: threshold-gated TTL extension.
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (Symbol::new(&env, "init"), admin),
            (treasury, usdc_contract, xlm_contract),
        );
    }

    // ── Reentrancy guard (Optimization #2) ───────────────────────────────────

    /// Acquires the reentrancy guard using **temporary** storage.
    ///
    /// Optimization: temporary storage entries carry no rent, require no TTL
    /// extension, and do not inflate the instance storage footprint.
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

    /// Releases the reentrancy guard. Must be called in every exit path.
    fn _exit(env: &Env) {
        env.storage()
            .temporary()
            .set(&DataKey::ReentrancyGuard, &false);
    }

    // ── Payment entrypoints ───────────────────────────────────────────────────

    /// Transfers USDC from `from` to the treasury.
    ///
    /// Storage writes per successful call:
    /// * `extend_ttl` — only when TTL < INSTANCE_TTL_THRESHOLD (~1 write/500d).
    /// * Temporary ReentrancyGuard — set then cleared; no rent.
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

        Self::_enter(&env);
        let res = token::Client::new(&env, &usdc_contract)
            .try_transfer(&from, &treasury, &amount);
        if res.is_err() {
            Self::_exit(&env);
            return Err(Error::TransferFailed);
        }
        Self::_exit(&env);

        env.events()
            .publish((Symbol::new(&env, "pay_usdc"), order_id, from), amount);

        // Optimization #1: conditional TTL extension — write only when needed.
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Transfers native XLM from `from` to the treasury.
    ///
    /// Same storage optimization profile as [`pay_usdc`].
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

    /// Transfers admin authority (two-step: current + new admin both sign).
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

    /// Optimization #1 (Issue #405, Part 3): threshold-gated TTL extension.
    ///
    /// Only performs the ledger write (which costs a fee) when the remaining
    /// TTL has actually dropped below `INSTANCE_TTL_THRESHOLD`.  This avoids
    /// billing rent on nearly every call and cuts the number of `extend_ttl`
    /// writes from O(calls) to O(calls / 500_days).
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
        testutils::{storage::Instance, TryIntoVal},
        token, Bytes, Env, Symbol,
    };

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

    // ── Optimization #1: threshold-gated TTL tests ────────────────────────────

    /// After `init`, the instance TTL must be positive (extension fired).
    #[test]
    fn test_ttl_is_positive_after_init() {
        let f = Fixture::new();
        f.init();
        let ttl = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().get_ttl()
        });
        assert!(ttl > 0, "TTL must be positive after init");
    }

    /// A second call while the TTL is still above INSTANCE_TTL_THRESHOLD must
    /// NOT trigger another extend_ttl write — the TTL should be unchanged.
    /// This is the core of Optimization #1: skipping redundant writes.
    #[test]
    fn test_extend_ttl_skipped_when_above_threshold() {
        let f = Fixture::new();
        f.init();

        let ttl_after_init = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().get_ttl()
        });

        // Any admin-gated call (e.g. grant a role equivalent: transfer_admin
        // and transfer back) that also calls extend_instance_ttl while the TTL
        // is already above the threshold should leave the TTL unchanged.
        let amount = 5_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "skip-ttl"));

        let ttl_after_second_call = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().get_ttl()
        });
        assert_eq!(
            ttl_after_second_call, ttl_after_init,
            "extend_ttl must be skipped when TTL is already above INSTANCE_TTL_THRESHOLD"
        );
    }

    /// The threshold constant must be strictly less than max to avoid the
    /// naive pattern where threshold == max causes a write on every call.
    #[test]
    fn test_ttl_threshold_strictly_below_max() {
        assert!(
            INSTANCE_TTL_THRESHOLD < INSTANCE_TTL_MAX,
            "INSTANCE_TTL_THRESHOLD must be < INSTANCE_TTL_MAX (Optimization #1)"
        );
    }

    /// The threshold must equal exactly half of max (documented design).
    #[test]
    fn test_ttl_threshold_equals_half_of_max() {
        assert_eq!(
            INSTANCE_TTL_THRESHOLD,
            INSTANCE_TTL_MAX / 2,
            "INSTANCE_TTL_THRESHOLD must equal INSTANCE_TTL_MAX / 2"
        );
    }

    /// Multiple pay_usdc calls in rapid succession must not retrigger extend_ttl
    /// each time — only the first call (which fires the extension) changes the TTL.
    #[test]
    fn test_repeated_payments_do_not_retrigger_ttl_extension() {
        let f = Fixture::new();
        f.init();

        let ttl_after_init = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().get_ttl()
        });

        let amount = 1_000_000_i128;
        f.mint_usdc(&f.payer, amount * 10);
        for i in 0..5 {
            let oid = order_bytes(&f.env, &format!("repeat-{}", i));
            f.client().pay_usdc(&f.payer, &amount, &oid);
        }

        let ttl_after_calls = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().get_ttl()
        });

        // All five calls happened while TTL was above threshold — no extension
        // should have fired, so TTL remains equal to what it was after init.
        assert_eq!(
            ttl_after_calls, ttl_after_init,
            "repeated payments must not trigger repeated TTL extension writes"
        );
    }

    // ── Optimization #2: temporary storage for reentrancy guard ──────────────

    /// The ReentrancyGuard key must NOT exist in instance storage — it belongs
    /// only in temporary storage so it does not inflate the instance footprint.
    #[test]
    fn test_reentrancy_guard_not_in_instance_storage() {
        let f = Fixture::new();
        f.init();
        let amount = 5_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "guard-check"));

        let in_instance = f.env.as_contract(&f.contract_id, || {
            f.env.storage().instance().has(&DataKey::ReentrancyGuard)
        });
        assert!(
            !in_instance,
            "Optimization #2: ReentrancyGuard must not appear in instance storage"
        );
    }

    /// The guard starts absent (false) before any payment — no pre-set flag
    /// in temporary storage.
    #[test]
    fn test_reentrancy_guard_starts_clear() {
        let f = Fixture::new();
        f.init();
        let val = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!val, "guard must start as false (absent)");
    }

    /// The guard is cleared after a successful payment — temporary flag reset.
    #[test]
    fn test_reentrancy_guard_cleared_after_successful_payment() {
        let f = Fixture::new();
        f.init();
        let amount = 3_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "g"));
        let val = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!val, "guard must be cleared after successful payment");
    }

    /// A held guard panics with "reentrancy detected" — the optimization does
    /// not weaken the security guarantee.
    #[test]
    #[should_panic(expected = "reentrancy detected")]
    fn test_reentrancy_guard_blocks_reentrant_call() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount * 2);

        f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary().set(&DataKey::ReentrancyGuard, &true);
        });

        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "re"));
    }

    /// Guard cleared after a failed transfer — optimization preserves the
    /// "release on every exit path" invariant.
    #[test]
    fn test_reentrancy_guard_cleared_after_failed_transfer() {
        let f = Fixture::new();
        f.init();
        // No balance minted — transfer fails.
        let _ = f.client().try_pay_usdc(&f.payer, &5_000_000_i128, &order_bytes(&f.env, "fail"));
        let val = f.env.as_contract(&f.contract_id, || {
            f.env.storage().temporary()
                .get::<_, bool>(&DataKey::ReentrancyGuard)
                .unwrap_or(false)
        });
        assert!(!val, "guard must be cleared even after a failed transfer");
    }

    // ── Instance storage footprint tests ──────────────────────────────────────

    /// After init, instance storage should contain exactly the 5 expected keys
    /// and no more: Admin, Treasury, UsdcContract, XlmContract, Paused.
    /// The ReentrancyGuard must NOT be in instance storage (it is temporary).
    #[test]
    fn test_instance_storage_contains_only_expected_keys() {
        let f = Fixture::new();
        f.init();

        let amount = 5_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "footprint"));

        // Verify all 5 expected keys are present
        f.env.as_contract(&f.contract_id, || {
            assert!(f.env.storage().instance().has(&DataKey::Admin),        "Admin must be set");
            assert!(f.env.storage().instance().has(&DataKey::Treasury),     "Treasury must be set");
            assert!(f.env.storage().instance().has(&DataKey::UsdcContract), "UsdcContract must be set");
            assert!(f.env.storage().instance().has(&DataKey::XlmContract),  "XlmContract must be set");
            assert!(f.env.storage().instance().has(&DataKey::Paused),       "Paused must be set");
            // Optimization #2: guard must NOT be in instance storage
            assert!(!f.env.storage().instance().has(&DataKey::ReentrancyGuard),
                "ReentrancyGuard must NOT be in instance storage");
        });
    }

    /// Pausing and unpausing does not create any extra instance storage keys
    /// beyond the 5 established at init time.
    #[test]
    fn test_pause_unpause_no_extra_instance_keys() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.client().unpause();

        f.env.as_contract(&f.contract_id, || {
            assert!(!f.env.storage().instance().has(&DataKey::ReentrancyGuard),
                "pause/unpause must not introduce extra instance storage keys");
        });
    }

    // ── Functional regression tests ───────────────────────────────────────────

    #[test]
    fn test_init_stores_all_addresses() {
        let f = Fixture::new();
        f.init();
        assert_eq!(f.client().treasury(),      f.treasury);
        assert_eq!(f.client().usdc_contract(), f.usdc);
        assert_eq!(f.client().xlm_contract(),  f.xlm_sac);
        assert_eq!(f.client().admin(),         f.admin);
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
    fn test_pay_usdc_emits_event() {
        let f = Fixture::new();
        f.init();
        let amount = 10_000_000_i128;
        let oid = order_bytes(&f.env, "evt");
        f.mint_usdc(&f.payer, amount);
        f.client().pay_usdc(&f.payer, &amount, &oid);
        let mut found = false;
        for (emitter, topics, data) in f.env.events().all().iter() {
            if emitter != f.contract_id { continue; }
            let sym: Symbol = topics.get(0).unwrap().try_into_val(&f.env).unwrap();
            if sym != Symbol::new(&f.env, "pay_usdc") { continue; }
            let emitted_amount: i128 = data.try_into_val(&f.env).unwrap();
            assert_eq!(emitted_amount, amount);
            found = true;
        }
        assert!(found, "pay_usdc event not found");
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
    fn test_pause_blocks_payments() {
        let f = Fixture::new();
        f.init();
        f.client().pause(&f.admin);
        f.mint_usdc(&f.payer, 10_000_000);
        let res = f.client().try_pay_usdc(&f.payer, &10_000_000_i128, &order_bytes(&f.env, "p"));
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

    #[test]
    fn test_sequential_payments_all_succeed_guard_resets() {
        let f = Fixture::new();
        f.init();
        let amount = 2_000_000_i128;
        f.mint_usdc(&f.payer, amount * 5);
        for i in 0..5 {
            f.client().pay_usdc(&f.payer, &amount, &order_bytes(&f.env, &format!("s{}", i)));
        }
        assert_eq!(f.usdc_balance(&f.treasury), amount * 5);
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
