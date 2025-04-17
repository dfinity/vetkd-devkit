#! /bin/bash

set -e

cd ..

mkdir -p docs/generated/backend
mkdir -p docs/generated/frontend

npm run make:docs -w frontend/ic_vetkeys
cargo doc -p ic-vetkeys

cp -r target/doc/ic_vetkeys docs/generated/backend/
cp -r target/doc/static.files docs/generated/backend/
