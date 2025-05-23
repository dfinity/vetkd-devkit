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

dfx canister create basic_bls_signing

# Store environment variables for the frontend.
echo "DFX_NETWORK=$DFX_NETWORK" > frontend/.env
echo "CANISTER_ID_BASIC_BLS_SIGNING=$(dfx canister id basic_bls_signing)" >> frontend/.env
echo "CANISTER_ID_INTERNET_IDENTITY=$CANISTER_ID_INTERNET_IDENTITY" >> frontend/.env

npm i

# Build frontend.
pushd frontend
    npm run build
popd

# Deploy canisters.
pushd backend
    dfx deploy
popd
