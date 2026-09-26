//! Integration tests for the receiver contract (Issue #400 - Part 2).
//!
//! Unit tests in `src/lib.rs` check one entrypoint at a time and can reach
//! into contract storage. These tests only use the public client, the same
//! surface a wallet, the backend or `scripts/test_local_network.sh` uses,
//! and they drive the contract through full multi-step flows against real
//! Stellar Asset Contracts. Authorization is checked for real where it
//! matters (`mock_auths` with specific signers) rather than blanket-mocked.
//!
//! Run with `cargo test --test integration`, or as part of `make test`.

use soroban_sdk::{
    testutils::{Address as _, Events, Ledger as _, MockAuth, MockAuthInvoke},
    token, Address, Bytes, Env, IntoVal, Symbol, TryIntoVal, Val, Vec,
};
use stellar_card_receiver::{Error, Role, Stellar_CardReceiver, Stellar_CardReceiverClient};

/// A deployed receiver plus the accounts and tokens around it.
struct Network {
    env: Env,
    receiver: Address,
    admin: Address,
    treasury: Address,
    usdc: Address,
    xlm: Address,
}

impl Network {
    /// Deploys two SACs and the receiver, then initializes it. `init` runs
    /// with only the admin's signature mocked, so it proves `init` needs
    /// no other authorization.
    fn deploy() -> Self {
        let env = Env::default();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let issuer = Address::generate(&env);
        let usdc = env
            .register_stellar_asset_contract_v2(issuer.clone())
            .address();
        let xlm = env
            .register_stellar_asset_contract_v2(issuer.clone())
            .address();
        let receiver = env.register(Stellar_CardReceiver, ());

        let client = Stellar_CardReceiverClient::new(&env, &receiver);
        client
            .mock_auths(&[MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &receiver,
                    fn_name: "init",
                    args: (&admin, &treasury, &usdc, &xlm).into_val(&env),
                    sub_invokes: &[],
                },
            }])
            .init(&admin, &treasury, &usdc, &xlm);

        // Every later step signs as whoever it needs to.
        env.mock_all_auths();

        Network {
            env,
            receiver,
            admin,
            treasury,
            usdc,
            xlm,
        }
    }

    fn client(&self) -> Stellar_CardReceiverClient<'_> {
        Stellar_CardReceiverClient::new(&self.env, &self.receiver)
    }

    fn mint(&self, token: &Address, to: &Address, amount: i128) {
        token::StellarAssetClient::new(&self.env, token).mint(to, &amount);
    }

    fn balance(&self, token: &Address, of: &Address) -> i128 {
        token::Client::new(&self.env, token).balance(of)
    }

    fn order(&self, id: &str) -> Bytes {
        Bytes::from_slice(&self.env, id.as_bytes())
    }

    /// `(topics, data)` of every event the receiver emitted in the last
    /// invocation, in order. Read events before calling any other function,
    /// getters included, since each invocation replaces this list.
    fn receiver_events(&self) -> std::vec::Vec<(Vec<Val>, Val)> {
        self.env
            .events()
            .all()
            .iter()
            .filter(|(contract, _, _)| *contract == self.receiver)
            .map(|(_, topics, data)| (topics, data))
            .collect()
    }

    fn event_names(&self) -> std::vec::Vec<Symbol> {
        self.receiver_events()
            .into_iter()
            .map(|(topics, _)| topics.get(0).unwrap().try_into_val(&self.env).unwrap())
            .collect()
    }

    fn sym(&self, name: &str) -> Symbol {
        Symbol::new(&self.env, name)
    }
}

#[test]
fn full_payment_lifecycle() {
    let net = Network::deploy();
    let client = net.client();
    let payer = Address::generate(&net.env);
    net.mint(&net.usdc, &payer, 50_000_000);
    net.mint(&net.xlm, &payer, 20_000_000);

    // Configuration is readable straight after init.
    assert_eq!(client.admin(), net.admin);
    assert_eq!(client.treasury(), net.treasury);
    assert_eq!(client.usdc_contract(), net.usdc);
    assert_eq!(client.xlm_contract(), net.xlm);
    assert!(!client.is_paused_view());
    assert!(client.has_role(&net.admin, &Role::Admin));

    // USDC then XLM payments land in the treasury, never in the receiver.
    client.pay_usdc(&payer, &30_000_000, &net.order("order-1"));
    let (topics, data) = net.receiver_events().pop().unwrap();
    let order: Bytes = topics.get(1).unwrap().try_into_val(&net.env).unwrap();
    let from: Address = topics.get(2).unwrap().try_into_val(&net.env).unwrap();
    let amount: i128 = data.try_into_val(&net.env).unwrap();
    assert_eq!(
        (order, from, amount),
        (net.order("order-1"), payer.clone(), 30_000_000)
    );

    client.pay_xlm(&payer, &20_000_000, &net.order("order-2"));
    assert_eq!(net.event_names(), [net.sym("pay_xlm")]);

    assert_eq!(net.balance(&net.usdc, &net.treasury), 30_000_000);
    assert_eq!(net.balance(&net.xlm, &net.treasury), 20_000_000);
    assert_eq!(net.balance(&net.usdc, &payer), 20_000_000);
    assert_eq!(net.balance(&net.xlm, &payer), 0);
    assert_eq!(net.balance(&net.usdc, &net.receiver), 0);
    assert_eq!(net.balance(&net.xlm, &net.receiver), 0);

    // A payment the payer can't cover fails cleanly and moves nothing.
    assert_eq!(
        client.try_pay_xlm(&payer, &1, &net.order("order-3")),
        Err(Ok(Error::TransferFailed))
    );
    assert_eq!(net.balance(&net.xlm, &net.treasury), 20_000_000);
}

#[test]
fn incident_response_pause_and_resume() {
    let net = Network::deploy();
    let client = net.client();
    let payer = Address::generate(&net.env);
    let operator = Address::generate(&net.env);
    net.mint(&net.usdc, &payer, 10_000_000);

    // The admin delegates incident response to an operator.
    client.grant_role(&operator, &Role::Operator);
    client.pause(&operator);
    assert_eq!(net.event_names(), [net.sym("paused")]);
    assert!(client.is_paused_view());

    // While paused, no payment goes through and nothing moves.
    assert_eq!(
        client.try_pay_usdc(&payer, &1_000_000, &net.order("paused")),
        Err(Ok(Error::ContractPaused))
    );
    assert_eq!(net.balance(&net.usdc, &payer), 10_000_000);

    // Only the admin can resume, and payments work again afterwards.
    client.unpause();
    assert!(!client.is_paused_view());
    client.pay_usdc(&payer, &1_000_000, &net.order("resumed"));
    assert_eq!(net.balance(&net.usdc, &net.treasury), 1_000_000);
}

#[test]
fn only_the_payer_can_authorize_a_payment() {
    let net = Network::deploy();
    let payer = Address::generate(&net.env);
    let attacker = Address::generate(&net.env);
    net.mint(&net.usdc, &payer, 5_000_000);

    // Replace the blanket mock with a signature from the attacker only.
    let order = net.order("stolen");
    let result = net
        .client()
        .mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &net.receiver,
                fn_name: "pay_usdc",
                args: (&payer, 5_000_000_i128, &order).into_val(&net.env),
                sub_invokes: &[],
            },
        }])
        .try_pay_usdc(&payer, &5_000_000, &order);

    assert!(result.is_err());
    assert_eq!(net.balance(&net.usdc, &payer), 5_000_000);
    assert_eq!(net.balance(&net.usdc, &net.treasury), 0);
}

#[test]
fn admin_handover_moves_control_to_the_new_admin() {
    let net = Network::deploy();
    let client = net.client();
    let new_admin = Address::generate(&net.env);

    client.transfer_admin(&new_admin);
    assert_eq!(net.event_names(), [net.sym("admin_transferred")]);
    assert_eq!(client.admin(), new_admin);

    // Admin-only actions now require the new admin's signature.
    client.pause(&net.admin); // the old admin still holds the Admin role
    let unpause_as_old_admin = client
        .mock_auths(&[MockAuth {
            address: &net.admin,
            invoke: &MockAuthInvoke {
                contract: &net.receiver,
                fn_name: "unpause",
                args: ().into_val(&net.env),
                sub_invokes: &[],
            },
        }])
        .try_unpause();
    assert!(unpause_as_old_admin.is_err());
    assert!(client.is_paused_view());

    client
        .mock_auths(&[MockAuth {
            address: &new_admin,
            invoke: &MockAuthInvoke {
                contract: &net.receiver,
                fn_name: "unpause",
                args: ().into_val(&net.env),
                sub_invokes: &[],
            },
        }])
        .unpause();
    assert!(!client.is_paused_view());
}

#[test]
fn role_lifecycle_grant_revoke_renounce() {
    let net = Network::deploy();
    let client = net.client();
    let alice = Address::generate(&net.env);
    let bob = Address::generate(&net.env);
    let carol = Address::generate(&net.env);

    client.grant_roles(
        &soroban_sdk::vec![&net.env, alice.clone(), bob.clone()],
        &Role::Viewer,
    );
    client.grant_role(&carol, &Role::Operator);
    assert!(client.has_role(&alice, &Role::Viewer));
    assert!(!client.has_role(&alice, &Role::Operator));
    assert!(client.has_role(&carol, &Role::Viewer));

    client.revoke_role(&alice);
    assert_eq!(client.get_role(&alice), None);

    client.renounce_role(&carol);
    assert_eq!(client.get_role(&carol), None);
    assert_eq!(client.get_role(&bob), Some(Role::Viewer));

    // A role holder that gave up its role can no longer pause.
    let result = client.try_pause(&carol);
    assert!(result.is_err());
    assert!(!client.is_paused_view());
}

#[test]
fn rescue_tokens_with_daily_limits_across_days() {
    let net = Network::deploy();
    let client = net.client();
    let destination = Address::generate(&net.env);

    // Someone sends USDC straight to the receiver by mistake.
    net.mint(&net.usdc, &net.receiver, 5_000_000);
    client.set_withdraw_limits(&net.admin, &Some(2_000_000), &Some(3_000_000));
    assert_eq!(client.withdraw_limits(), (Some(2_000_000), Some(3_000_000)));

    assert_eq!(
        client.try_rescue_tokens(&net.admin, &net.usdc, &destination, &2_000_001),
        Err(Ok(Error::WithdrawLimitExceeded))
    );
    client.rescue_tokens(&net.admin, &net.usdc, &destination, &2_000_000);
    client.rescue_tokens(&net.admin, &net.usdc, &destination, &1_000_000);
    assert_eq!(
        client.try_rescue_tokens(&net.admin, &net.usdc, &destination, &1),
        Err(Ok(Error::DailyWithdrawLimitExceeded))
    );

    // The daily budget resets on the next day.
    net.env.ledger().with_mut(|li| li.timestamp += 86_400);
    client.rescue_tokens(&net.admin, &net.usdc, &destination, &2_000_000);

    assert_eq!(net.balance(&net.usdc, &destination), 5_000_000);
    assert_eq!(net.balance(&net.usdc, &net.receiver), 0);
}

#[test]
fn init_cannot_be_replayed_after_deployment() {
    let net = Network::deploy();
    let attacker = Address::generate(&net.env);

    // Even with a valid signature from its own key, nobody can re-run init
    // to take over a live deployment.
    let result = net
        .client()
        .try_init(&attacker, &attacker, &net.usdc, &net.xlm);
    assert!(result.is_err());
    assert_eq!(net.client().admin(), net.admin);
    assert_eq!(net.client().treasury(), net.treasury);
}
