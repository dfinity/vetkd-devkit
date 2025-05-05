PWD:=$(shell pwd)

.PHONY: compile-wasm
.SILENT: compile-wasm
compile-wasm:
	dfx build --check

.PHONY: test
.SILENT: test
test: compile-wasm
	CUSTOM_WASM_PATH=$(PWD)/.dfx/local/canisters/ic_vetkeys_manager_canister/ic_vetkeys_manager_canister.wasm cargo test -p ic-vetkeys-manager-canister
