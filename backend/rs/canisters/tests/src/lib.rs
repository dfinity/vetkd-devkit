use ic_cdk::update;
use ic_vetkeys::vetkd_api_types::{
    VetKDDeriveKeyReply, VetKDDeriveKeyRequest, VetKDKeyId, VetKDPublicKeyReply,
    VetKDPublicKeyRequest,
};

#[update]
async fn sign_with_bls(input: Vec<u8>, context: Vec<u8>, key_id: VetKDKeyId) -> Vec<u8> {
    ic_vetkeys::management_canister::sign_with_bls(input, context, key_id)
        .await
        .expect("derive_public_vetkey call failed")
}

#[update]
async fn vetkd_derive_key(
    input: Vec<u8>,
    context: Vec<u8>,
    key_id: VetKDKeyId,
    transport_public_key: Vec<u8>,
) -> Vec<u8> {
    let request = VetKDDeriveKeyRequest {
        input,
        context,
        key_id,
        // Encryption with the G1 generator produces unencrypted vetKeys
        transport_public_key,
    };

    let reply: (VetKDDeriveKeyReply,) = ic_cdk::api::call::call_with_payment128(
        candid::Principal::management_canister(),
        "vetkd_derive_key",
        (request,),
        26_153_846_153,
    )
    .await
    .expect("vetkd_derive_key call failed");

    reply.0.encrypted_key
}

#[update]
async fn bls_public_key(context: Vec<u8>, key_id: VetKDKeyId) -> Vec<u8> {
    ic_vetkeys::management_canister::bls_public_key(None, context, key_id)
        .await
        .expect("bls_public_key call failed")
}

#[update]
async fn get_verification_key(context: Vec<u8>, key_id: VetKDKeyId) -> Vec<u8> {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        context,
        key_id,
    };

    let reply: (VetKDPublicKeyReply,) = ic_cdk::api::call::call(
        candid::Principal::management_canister(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("vetkd_public_key call failed");

    reply.0.public_key
}
