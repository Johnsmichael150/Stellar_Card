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
    /// Stores the `admin`, `treasury`, `usdc_contract`, and `xlm_contract`
    /// addresses in instance storage and sets the initial pause state to
    /// `false`. The admin must co-sign the transaction to prevent front-running
    /// on deployment.
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

        // Probe both token addresses against the SAC interface so a
        // misconfigured non-token address is caught at init time rather
        // than silently failing on the first payment call.
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

        // Write state
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
    /// Emits after the write succeeds:
    /// ```text
    /// topics : [Symbol("admin_transferred"), old_admin, new_admin]
    /// value  : ()
    /// ```
    ///
    /// # Panics
    /// * If `current_admin.require_auth()` or `new_admin.require_auth()` fails.
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
        let amount = 10_000_000_i128;
        f.mint_usdc(&f.payer, amount);
        f.mint_xlm(&f.payer, amount);
        f.client()
            .pay_usdc(&f.payer, &amount, &order_bytes(&f.env, "usdc-only"));
        assert_eq!(f.xlm_balance(&f.payer), amount);
        assert_eq!(f.xlm_balance(&f.treasury), 0);
    }
}
