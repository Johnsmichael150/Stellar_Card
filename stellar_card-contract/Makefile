.PHONY: build test integration-test wasm-size

WASM_PATH := target/wasm32-unknown-unknown/release/stellar_card_receiver.wasm
# Soroban's own network-enforced ceiling is 64KiB (65536 bytes). This budget
# is set conservatively below that (not tightly against current actual size,
# which this change doesn't have a build available to measure) so it only
# trips on a real, substantial regression rather than normal size drift —
# tighten it once a maintainer has a measured baseline to set it against.
WASM_SIZE_BUDGET_BYTES := 61440

# The [profile.release] section in Cargo.toml already sets opt-level=z,
# strip=symbols, lto=true, codegen-units=1 (issue #432). wasm-opt -Oz is an
# additional binaryen-level pass beyond what rustc's own codegen can do
# (further dead-code elimination, instruction-level size optimizations) —
# skipped gracefully if wasm-opt isn't installed rather than failing the build.
build:
	cargo build --target wasm32-unknown-unknown --release
	@if command -v wasm-opt >/dev/null 2>&1; then \
		wasm-opt -Oz \
			$(WASM_PATH) \
			-o $(WASM_PATH); \
	else \
		echo "wasm-opt not found — skipping extra size optimization pass. Install binaryen for a smaller binary."; \
	fi
	@$(MAKE) wasm-size

# Issue #412 (Part 3): report the built WASM's size and fail if it regresses
# past WASM_SIZE_BUDGET_BYTES, so a size regression is caught in CI at build
# time instead of only being noticed after deployment starts costing more
# per invocation or, worse, approaching the network's 64KiB hard limit.
wasm-size:
	@if [ ! -f "$(WASM_PATH)" ]; then \
		echo "wasm-size: $(WASM_PATH) not found — run 'make build' first" >&2; \
		exit 1; \
	fi
	@size=$$(wc -c < "$(WASM_PATH)"); \
	echo "wasm-size: $(WASM_PATH) is $$size bytes (budget: $(WASM_SIZE_BUDGET_BYTES) bytes)"; \
	if [ "$$size" -gt "$(WASM_SIZE_BUDGET_BYTES)" ]; then \
		echo "wasm-size: FAIL — binary exceeds the $(WASM_SIZE_BUDGET_BYTES)-byte budget by $$((size - $(WASM_SIZE_BUDGET_BYTES))) bytes" >&2; \
		exit 1; \
	fi

# The upgrade test imports the compiled contract WASM.
test:
	cargo build --target wasm32v1-none --release
	cargo test

integration-test:
	./scripts/test_local_network.sh
