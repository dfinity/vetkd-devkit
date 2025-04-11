#!/bin/bash

set -e

# Check that `dfx` is installed.
dfx --version >> /dev/null

# Run `dfx` if it is not already running.
dfx ping &> /dev/null || dfx start --background --clean >> /dev/null

# Deploy the chainkey testing canister and the backend canister, and replace the
# management canister ID for the VetKD interface with the chainkey testing
# canister. Then, export the environment variable of the canister ID.
pushd backend
    make mock &&
    eval $(make export-cmd)
popd

# Deploy the Internet Identity canister and export the environment variable of
# the canister ID.
dfx deps pull && dfx deps init && dfx deps deploy &&
    export CANISTER_ID_INTERNET_IDENTITY=rdmx6-jaaaa-aaaaa-aaadq-cai

# Store environment variables for the frontend.
echo "DFX_NETWORK=$DFX_NETWORK" > frontend/.env
echo "CANISTER_ID_BASIC_IBE=$CANISTER_ID_BASIC_IBE" >> frontend/.env
echo "CANISTER_ID_INTERNET_IDENTITY=$CANISTER_ID_INTERNET_IDENTITY" >> frontend/.env

# Build frontend.
pushd frontend
    npm i
    npm run build
popd

# Deploy the frontend canister.
dfx deploy www
