#!/bin/bash

set -e

# Check that `dfx` is installed.
dfx --version >> /dev/null

# Run `dfx` if it is not already running.
dfx ping &> /dev/null || dfx start --background --clean >> /dev/null

# Deploy the Internet Identity canister and export the environment variable of
# the canister ID.
dfx deps pull && dfx deps init && dfx deps deploy &&
    export CANISTER_ID_INTERNET_IDENTITY=rdmx6-jaaaa-aaaaa-aaadq-cai

# Deploy the backend canister.
pushd ../../backend/rs/canisters/ic_vetkeys_encrypted_maps_canister
    dfx deploy
    export CANISTER_ID_IC_VETKEYS_ENCRYPTED_MAPS_CANISTER=$(dfx canister id ic_vetkeys_encrypted_maps_canister)
popd

# Store environment variables for the frontend.
echo "DFX_NETWORK=$DFX_NETWORK" > frontend/.env
echo "CANISTER_ID_IC_VETKEYS_ENCRYPTED_MAPS_CANISTER=$CANISTER_ID_IC_VETKEYS_ENCRYPTED_MAPS_CANISTER" >> frontend/.env
echo "CANISTER_ID_INTERNET_IDENTITY=$CANISTER_ID_INTERNET_IDENTITY" >> frontend/.env

# Build frontend.
pushd frontend
    npm i
    npm run build
popd

# Deploy the frontend canister.
dfx deploy www
