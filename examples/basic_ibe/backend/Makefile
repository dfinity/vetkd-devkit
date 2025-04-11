.PHONY: compile-wasm
.SILENT: compile-wasm
compile-wasm:
	cargo build --release --target wasm32-unknown-unknown

.PHONY: extract-candid
.SILENT: extract-candid
extract-candid: compile-wasm
	candid-extractor ../../../target/wasm32-unknown-unknown/release/ic_vetkd_example_basic_ibe_backend.wasm > backend.did

.PHONY: compile-wasm-test
.SILENT: compile-wasm-test
compile-wasm-test:
	cargo build --release --target wasm32-unknown-unknown --features expose-testing-api

.PHONY: deploy-test
.SILENT: deploy-test
deploy-test: compile-wasm-test
	dfx canister create chainkey_testing_canister && \
	dfx canister create basic_ibe && \
	dfx build chainkey_testing_canister && \
	dfx canister install --upgrade-unchanged --mode auto chainkey_testing_canister && \
	dfx canister install --upgrade-unchanged --mode auto --wasm ../../../target/wasm32-unknown-unknown/release/ic_vetkd_example_basic_ibe_backend.wasm basic_ibe

.PHONY: mock
.SILENT: mock
mock: deploy-test
	CANISTER_ID_VETKD_MOCK=$(shell dfx canister id chainkey_testing_canister); \
	echo "Changing to using mock canister instead of management canister for vetkd to "$${CANISTER_ID_VETKD_MOCK}""; \
    CMD="dfx canister call basic_ibe set_vetkd_testing_canister_id '(principal "\"$${CANISTER_ID_VETKD_MOCK}\"")'"; \
	eval "$${CMD}"

.PHONY: export-cmd
.SILENT: export-cmd
export-cmd:
	CANISTER_ID_BASIC_IBE=$(shell dfx canister id basic_ibe); \
	CMD="export CANISTER_ID_BASIC_IBE=$${CANISTER_ID_BASIC_IBE}"; \
	echo "$${CMD}"

.PHONY: clean
.SILENT: clean
clean:
	cargo clean
	rm -rf .dfx