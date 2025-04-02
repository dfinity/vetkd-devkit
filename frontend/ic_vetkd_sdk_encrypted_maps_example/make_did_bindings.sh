set -ex

function make_and_copy_declarations () {
    DIR=$1

    pushd $DIR
    make extract-candid
    dfx generate
    popd

    mkdir -p declarations
    cp -R "$DIR/src/declarations/ic_vetkeys_encrypted_maps_canister" "src/declarations/"
}

make_and_copy_declarations "../../backend/canisters/ic_vetkeys_encrypted_maps_canister"
