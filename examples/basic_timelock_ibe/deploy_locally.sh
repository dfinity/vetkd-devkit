#!/bin/bash

set -e

# Check that `dfx` is installed.
dfx --version >> /dev/null

# Run `dfx` if it is not already running.
dfx ping &> /dev/null || dfx start --background --clean --replica >> /dev/null

# Deploy the backend canister.
pushd backend
    dfx deploy
popd

# Deploy the Internet Identity canister and export the environment variable of
# the canister ID.
dfx deps pull && dfx deps init && dfx deps deploy &&
    export CANISTER_ID_INTERNET_IDENTITY=rdmx6-jaaaa-aaaaa-aaadq-cai

# Store environment variables for the frontend.
echo "DFX_NETWORK=$DFX_NETWORK" > frontend/.env
echo "CANISTER_ID_BASIC_TIMELOCK_IBE=$CANISTER_ID_BASIC_TIMELOCK_IBE" >> frontend/.env
echo "CANISTER_ID_INTERNET_IDENTITY=$CANISTER_ID_INTERNET_IDENTITY" >> frontend/.env

npm i

# Build frontend.
pushd frontend
    npm run build
popd

# Deploy the frontend canister.
dfx deploy www
