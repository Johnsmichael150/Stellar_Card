#!/usr/bin/env bash
set -euo pipefail

# End-to-end integration test against a real local Stellar network.
# Requires: cargo, curl, docker, and Stellar CLI.
#
# Configuration (all optional):
#   STELLAR_RPC_PORT   Host port the Quickstart container is published on (default: 8000)
#   QUICKSTART_IMAGE   Quickstart image to run (default: stellar/quickstart:latest)
#   RPC_WAIT_SECONDS   How long to wait for RPC + friendbot to come up (default: 180)
#   KEEP_NETWORK=1     Leave the container running after the test, for debugging
#   SKIP_BUILD=1       Reuse an existing release WASM instead of rebuilding it
#
# Issue #400 (Part 2): scenarios are grouped into functions that each assert
# on real on-chain state (balances, getters, events), and every assertion
# goes through the same helpers so a failure always says what was expected.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RPC_PORT="${STELLAR_RPC_PORT:-8000}"
QUICKSTART_IMAGE="${QUICKSTART_IMAGE:-stellar/quickstart:latest}"
RPC_WAIT_SECONDS="${RPC_WAIT_SECONDS:-180}"
CONTAINER_NAME="stellar-card-contract-test-$$"
RPC_URL="http://localhost:$RPC_PORT/rpc"
FRIENDBOT_URL="http://localhost:$RPC_PORT/friendbot"
NETWORK_PASSPHRASE="Standalone Network ; February 2017"
STELLAR_CONFIG_DIR="$(mktemp -d)"
WASM_PATH="$PROJECT_ROOT/target/wasm32v1-none/release/stellar_card_receiver.wasm"
CURRENT_STEP="setup"

# ── helpers ─────────────────────────────────────────────────────────────────

log() {
  echo "==> $*"
}

fail() {
  echo "FAIL [$CURRENT_STEP]: $*" >&2
  exit 1
}

step() {
  CURRENT_STEP="$1"
  log "$1"
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && docker ps -q --filter "name=^${CONTAINER_NAME}$" | grep -q .; then
    echo "---- last 50 lines of $CONTAINER_NAME logs ----" >&2
    docker logs --tail 50 "$CONTAINER_NAME" >&2 || true
  fi
  if [ "${KEEP_NETWORK:-0}" = "1" ]; then
    echo "KEEP_NETWORK=1: leaving $CONTAINER_NAME running (config: $STELLAR_CONFIG_DIR)"
  else
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf "$STELLAR_CONFIG_DIR"
  fi
  if [ "$status" -ne 0 ]; then
    echo "Local network integration test FAILED during: $CURRENT_STEP" >&2
  fi
}
trap cleanup EXIT

stellar_local() {
  stellar --config-dir "$STELLAR_CONFIG_DIR" "$@"
}

# invoke <contract-id> <source-identity> -- <fn> [args...]
invoke() {
  local contract_id="$1" source="$2"
  shift 2
  stellar_local contract invoke \
    --id "$contract_id" \
    --source "$source" \
    --network local \
    "$@"
}

# expect_failure <description> <invoke args...>
# Runs an invocation that the contract must reject.
expect_failure() {
  local description="$1"
  shift
  if invoke "$@" >/dev/null 2>&1; then
    fail "expected failure but call succeeded: $description"
  fi
  log "  rejected as expected: $description"
}

# Strips the quotes/whitespace the CLI wraps scalar results in.
scalar() {
  tr -d '[:space:]"'
}

balance_of() {
  local token_id="$1" address="$2"
  invoke "$token_id" deployer -- balance --id "$address" | scalar
}

assert_eq() {
  local description="$1" expected="$2" actual="$3"
  if [ "$expected" != "$actual" ]; then
    fail "$description: expected '$expected', got '$actual'"
  fi
  log "  ok: $description = $actual"
}

latest_ledger() {
  curl -sf \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' \
    "$RPC_URL" | grep -o '"sequence"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$'
}

# Base64 XDR of an ScVal::Symbol, the form event topic filters take.
symbol_topic() {
  local name="$1"
  local len=${#name}
  local pad=$(((4 - len % 4) % 4))
  {
    printf '\x00\x00\x00\x0f'
    printf "\\x$(printf '%02x' $((len >> 24 & 255)))\\x$(printf '%02x' $((len >> 16 & 255)))"
    printf "\\x$(printf '%02x' $((len >> 8 & 255)))\\x$(printf '%02x' $((len & 255)))"
    printf '%s' "$name"
    head -c "$pad" /dev/zero
  } | base64 | tr -d '\n'
}

# count_events <contract-id> <start-ledger> <event-name>
# Counts events whose first topic is <event-name>, emitted by the contract
# from <start-ledger> onwards. Filtering happens server-side, so this doesn't
# depend on how a given CLI version prints decoded events.
count_events() {
  local contract_id="$1" start_ledger="$2" name="$3"
  stellar_local events \
    --network local \
    --start-ledger "$start_ledger" \
    --id "$contract_id" \
    --type contract \
    --topic "$(symbol_topic "$name"),**" \
    --count 100 \
    --output json | grep -c '"ledger"' || true
}

assert_event_count() {
  local contract_id="$1" start_ledger="$2" name="$3" expected="$4"
  assert_eq "'$name' events since ledger $start_ledger" "$expected" \
    "$(count_events "$contract_id" "$start_ledger" "$name")"
}

# ── network setup ───────────────────────────────────────────────────────────

for command in cargo curl docker stellar base64; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Error: required command '$command' is not installed" >&2
    exit 1
  fi
done

step "Starting local Stellar network ($QUICKSTART_IMAGE on port $RPC_PORT)"
docker run -d --rm \
  --name "$CONTAINER_NAME" \
  -p "$RPC_PORT:8000" \
  "$QUICKSTART_IMAGE" \
  --local --enable rpc,horizon >/dev/null

step "Waiting for RPC health"
rpc_healthy=false
for _ in $(seq 1 $((RPC_WAIT_SECONDS / 2))); do
  if curl -sf \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
    "$RPC_URL" | grep -q '"status"[[:space:]]*:[[:space:]]*"healthy"' \
    && curl -s "$FRIENDBOT_URL" | grep -q '"invalid_field"[[:space:]]*:[[:space:]]*"addr"'; then
    rpc_healthy=true
    break
  fi
  sleep 2
done
if [ "$rpc_healthy" != true ]; then
  fail "local Stellar RPC did not become healthy within ${RPC_WAIT_SECONDS}s"
fi

cd "$PROJECT_ROOT"
if [ "${SKIP_BUILD:-0}" = "1" ] && [ -f "$WASM_PATH" ]; then
  step "Reusing existing contract build (SKIP_BUILD=1)"
else
  step "Building contract"
  cargo build --target wasm32v1-none --release
fi

stellar_local network add local \
  --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE"

step "Creating and funding identities"
for identity in deployer treasury payer issuer operator viewer rescue; do
  stellar_local keys generate "$identity" --overwrite
  stellar_local keys fund "$identity" --network local
done

DEPLOYER_ADDRESS="$(stellar_local keys public-key deployer)"
TREASURY_ADDRESS="$(stellar_local keys public-key treasury)"
PAYER_ADDRESS="$(stellar_local keys public-key payer)"
ISSUER_ADDRESS="$(stellar_local keys public-key issuer)"
OPERATOR_ADDRESS="$(stellar_local keys public-key operator)"
VIEWER_ADDRESS="$(stellar_local keys public-key viewer)"
RESCUE_ADDRESS="$(stellar_local keys public-key rescue)"

step "Deploying asset and receiver contracts"
USDC_CONTRACT_ID="$(stellar_local contract asset deploy \
  --asset "USDC:$ISSUER_ADDRESS" \
  --source issuer \
  --network local)"
XLM_CONTRACT_ID="$(stellar_local contract asset deploy \
  --asset native \
  --source deployer \
  --network local)"
RECEIVER_CONTRACT_ID="$(stellar_local contract deploy \
  --wasm "$WASM_PATH" \
  --source deployer \
  --network local)"

# ── scenarios ───────────────────────────────────────────────────────────────

scenario_init() {
  step "Initializing receiver"
  local start_ledger
  start_ledger="$(latest_ledger)"

  invoke "$RECEIVER_CONTRACT_ID" deployer -- init \
    --admin "$DEPLOYER_ADDRESS" \
    --treasury "$TREASURY_ADDRESS" \
    --usdc_contract "$USDC_CONTRACT_ID" \
    --xlm_contract "$XLM_CONTRACT_ID"

  assert_eq "admin()" "$DEPLOYER_ADDRESS" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- admin | scalar)"
  assert_eq "treasury()" "$TREASURY_ADDRESS" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- treasury | scalar)"
  assert_eq "usdc_contract()" "$USDC_CONTRACT_ID" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- usdc_contract | scalar)"
  assert_eq "xlm_contract()" "$XLM_CONTRACT_ID" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- xlm_contract | scalar)"
  assert_eq "is_paused_view()" "false" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- is_paused_view | scalar)"
  assert_event_count "$RECEIVER_CONTRACT_ID" "$start_ledger" init 1

  expect_failure "second init" "$RECEIVER_CONTRACT_ID" deployer -- init \
    --admin "$DEPLOYER_ADDRESS" \
    --treasury "$TREASURY_ADDRESS" \
    --usdc_contract "$USDC_CONTRACT_ID" \
    --xlm_contract "$XLM_CONTRACT_ID"
}

scenario_usdc_payment() {
  step "Executing a USDC payment"
  for identity in payer treasury rescue; do
    stellar_local tx new change-trust \
      --source "$identity" \
      --line "USDC:$ISSUER_ADDRESS" \
      --network local
  done

  invoke "$USDC_CONTRACT_ID" issuer -- mint \
    --to "$PAYER_ADDRESS" \
    --amount 10000000

  local start_ledger
  start_ledger="$(latest_ledger)"

  invoke "$RECEIVER_CONTRACT_ID" payer -- pay_usdc \
    --from "$PAYER_ADDRESS" \
    --amount 10000000 \
    --order_id 6c6f63616c2d736d6f6b65

  assert_eq "treasury USDC balance" 10000000 "$(balance_of "$USDC_CONTRACT_ID" "$TREASURY_ADDRESS")"
  assert_eq "payer USDC balance" 0 "$(balance_of "$USDC_CONTRACT_ID" "$PAYER_ADDRESS")"
  assert_eq "receiver USDC balance (no custody)" 0 "$(balance_of "$USDC_CONTRACT_ID" "$RECEIVER_CONTRACT_ID")"
  assert_event_count "$RECEIVER_CONTRACT_ID" "$start_ledger" pay_usdc 1

  expect_failure "pay_usdc with zero amount" "$RECEIVER_CONTRACT_ID" payer -- pay_usdc \
    --from "$PAYER_ADDRESS" \
    --amount 0 \
    --order_id 7a65726f
  expect_failure "pay_usdc beyond payer balance" "$RECEIVER_CONTRACT_ID" payer -- pay_usdc \
    --from "$PAYER_ADDRESS" \
    --amount 1 \
    --order_id 656d707479
}

# Issue #410 (Part 3): the USDC path above only exercises pay_usdc — pay_xlm
# has its own token client lookup and its own reentrancy-guard entry/exit, so
# a regression there could ship even with the USDC assertion green.
scenario_xlm_payment() {
  step "Executing a native XLM payment"
  local amount=5000000
  local payer_before treasury_before
  payer_before="$(balance_of "$XLM_CONTRACT_ID" "$PAYER_ADDRESS")"
  treasury_before="$(balance_of "$XLM_CONTRACT_ID" "$TREASURY_ADDRESS")"

  invoke "$RECEIVER_CONTRACT_ID" payer -- pay_xlm \
    --from "$PAYER_ADDRESS" \
    --amount "$amount" \
    --order_id 6c6f63616c2d736d6f6b652d786c6d

  # Friendbot funds the treasury account with native XLM, so compare deltas.
  assert_eq "treasury XLM increase" "$amount" \
    "$(($(balance_of "$XLM_CONTRACT_ID" "$TREASURY_ADDRESS") - treasury_before))"
  # The payer also pays transaction fees in XLM, so it must have lost at
  # least the payment amount.
  local payer_spent=$((payer_before - $(balance_of "$XLM_CONTRACT_ID" "$PAYER_ADDRESS")))
  if [ "$payer_spent" -lt "$amount" ]; then
    fail "payer XLM decreased by $payer_spent, expected at least $amount"
  fi
  log "  ok: payer XLM decreased by $payer_spent (>= $amount)"
}

# Issue #410 (Part 3): exercise the pause circuit breaker end to end — an
# admin/role-gated path with real-network auth semantics that the in-memory
# unit tests (mock_all_auths) can't fully stand in for.
scenario_pause_and_rbac() {
  step "Verifying RBAC-gated pause, and that unpause resumes payments"
  expect_failure "pause by an address with no role" "$RECEIVER_CONTRACT_ID" operator -- pause \
    --caller "$OPERATOR_ADDRESS"

  invoke "$RECEIVER_CONTRACT_ID" deployer -- grant_role \
    --address "$OPERATOR_ADDRESS" \
    --role '"Operator"'
  invoke "$RECEIVER_CONTRACT_ID" deployer -- grant_role \
    --address "$VIEWER_ADDRESS" \
    --role '"Viewer"'
  assert_eq "has_role(operator, Operator)" "true" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- has_role \
    --address "$OPERATOR_ADDRESS" --required_role '"Operator"' | scalar)"
  assert_eq "has_role(viewer, Operator)" "false" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- has_role \
    --address "$VIEWER_ADDRESS" --required_role '"Operator"' | scalar)"

  expect_failure "pause by a Viewer" "$RECEIVER_CONTRACT_ID" viewer -- pause \
    --caller "$VIEWER_ADDRESS"

  invoke "$RECEIVER_CONTRACT_ID" operator -- pause --caller "$OPERATOR_ADDRESS"
  assert_eq "is_paused_view() after pause" "true" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- is_paused_view | scalar)"

  expect_failure "pay_xlm while paused" "$RECEIVER_CONTRACT_ID" payer -- pay_xlm \
    --from "$PAYER_ADDRESS" \
    --amount 1 \
    --order_id 6c6f63616c2d7061757365642d747279
  expect_failure "unpause by the Operator (admin only)" "$RECEIVER_CONTRACT_ID" operator -- unpause

  invoke "$RECEIVER_CONTRACT_ID" deployer -- unpause
  assert_eq "is_paused_view() after unpause" "false" "$(invoke "$RECEIVER_CONTRACT_ID" deployer -- is_paused_view | scalar)"

  local treasury_before
  treasury_before="$(balance_of "$XLM_CONTRACT_ID" "$TREASURY_ADDRESS")"
  invoke "$RECEIVER_CONTRACT_ID" payer -- pay_xlm \
    --from "$PAYER_ADDRESS" \
    --amount 1000 \
    --order_id 726573756d6564
  assert_eq "treasury XLM increase after unpause" 1000 \
    "$(($(balance_of "$XLM_CONTRACT_ID" "$TREASURY_ADDRESS") - treasury_before))"
}

scenario_rescue_tokens() {
  step "Recovering tokens sent directly to the receiver"
  invoke "$USDC_CONTRACT_ID" issuer -- mint \
    --to "$RECEIVER_CONTRACT_ID" \
    --amount 3000000
  assert_eq "receiver USDC balance after mistaken send" 3000000 \
    "$(balance_of "$USDC_CONTRACT_ID" "$RECEIVER_CONTRACT_ID")"

  invoke "$RECEIVER_CONTRACT_ID" deployer -- set_withdraw_limits \
    --caller "$DEPLOYER_ADDRESS" \
    --per_call 2000000 \
    --per_day 2500000

  expect_failure "rescue_tokens by the Operator" "$RECEIVER_CONTRACT_ID" operator -- rescue_tokens \
    --caller "$OPERATOR_ADDRESS" \
    --token_contract "$USDC_CONTRACT_ID" \
    --to "$RESCUE_ADDRESS" \
    --amount 1
  expect_failure "rescue_tokens over the per-call limit" "$RECEIVER_CONTRACT_ID" deployer -- rescue_tokens \
    --caller "$DEPLOYER_ADDRESS" \
    --token_contract "$USDC_CONTRACT_ID" \
    --to "$RESCUE_ADDRESS" \
    --amount 2000001

  invoke "$RECEIVER_CONTRACT_ID" deployer -- rescue_tokens \
    --caller "$DEPLOYER_ADDRESS" \
    --token_contract "$USDC_CONTRACT_ID" \
    --to "$RESCUE_ADDRESS" \
    --amount 2000000
  assert_eq "rescued USDC delivered" 2000000 "$(balance_of "$USDC_CONTRACT_ID" "$RESCUE_ADDRESS")"

  expect_failure "rescue_tokens over the daily limit" "$RECEIVER_CONTRACT_ID" deployer -- rescue_tokens \
    --caller "$DEPLOYER_ADDRESS" \
    --token_contract "$USDC_CONTRACT_ID" \
    --to "$RESCUE_ADDRESS" \
    --amount 1000000
  assert_eq "receiver USDC balance after rescue" 1000000 \
    "$(balance_of "$USDC_CONTRACT_ID" "$RECEIVER_CONTRACT_ID")"
}

scenario_init
scenario_usdc_payment
scenario_xlm_payment
scenario_pause_and_rbac
scenario_rescue_tokens

CURRENT_STEP="done"
echo "Local network integration test passed."
