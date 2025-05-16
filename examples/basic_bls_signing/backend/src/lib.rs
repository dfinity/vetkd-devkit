pub mod types;
use candid::Principal;
use ic_cdk::{query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableLog,
};
use ic_vetkd_utils::*;
use serde_bytes::ByteBuf;
use std::{cell::RefCell, str::FromStr};
use types::*;

type Memory = VirtualMemory<DefaultMemoryImpl>;

type VetKeyPublicKey = ByteBuf;
type RawSignature = ByteBuf;
type RawMessage = String;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static PUBLISHED_SIGNATURES: RefCell<StableLog<Signature, Memory, Memory>> = RefCell::new(StableLog::new(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), // index memory
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), // data memory
    ));

    static VETKD_ROOT_IBE_PUBLIC_KEY: RefCell<Option<VetKeyPublicKey>> =  const { RefCell::new(None) };
}

#[update]
async fn sign_message(message: RawMessage) -> RawSignature {
    let signer = ic_cdk::caller();
    // create a transport secret key with a constant seed containing just zeros
    let transport_secret_key =
        TransportSecretKey::from_seed(vec![0; 32]).expect("Failed to create transport secret key");
    let transport_public_key = transport_secret_key.public_key();

    let context = get_context(signer);

    let request = VetKDDeriveKeyRequest {
        input: message.as_bytes().to_vec(),
        context: context.clone(),
        key_id: bls12_381_dfx_test_key(),
        transport_public_key,
    };

    let (VetKDDeriveKeyReply { encrypted_key },) =
        ic_cdk::api::call::call_with_payment128::<_, (VetKDDeriveKeyReply,)>(
            CanisterId::from_str("aaaaa-aa").unwrap(),
            "vetkd_derive_key",
            (request,),
            26_153_846_153,
        )
        .await
        .expect("call to vetkd_derive_key failed");

    let root_public_key_raw = match VETKD_ROOT_IBE_PUBLIC_KEY.with(|v| v.borrow().to_owned()) {
        Some(root_ibe_public_key) => root_ibe_public_key.into_vec(),
        None => get_root_public_key().await.into_vec(),
    };
    let root_public_key = DerivedPublicKey::deserialize(&root_public_key_raw)
        .expect("Failed to deserialize root ibe public key");
    let derived_public_key = root_public_key.derive_sub_key(&get_context(signer));

    let encrypted_key_typed = EncryptedVetKey::deserialize(&encrypted_key)
        .expect("Failed to deserialize encrypted vetkey");

    // decrypt the encrypted vetkey
    let vetkey = encrypted_key_typed
        .decrypt_and_verify(&transport_secret_key, &derived_public_key, message.as_ref())
        .expect("Failed to decrypt and verify vetkey");

    // return the vetkey, which serves as the signature
    vetkey.signature_bytes().to_vec().into()
}

#[update]
fn publish_my_signature_no_verification(message: RawMessage, signature: RawSignature) {
    let signature = Signature {
        message,
        signature: signature.into_vec(),
        timestamp: ic_cdk::api::time(),
        signer: ic_cdk::caller(),
    };
    PUBLISHED_SIGNATURES
        .with_borrow_mut(|log| log.append(&signature))
        .expect("Failed to append signature to log");
}

#[query]
fn get_published_signatures() -> Vec<Signature> {
    PUBLISHED_SIGNATURES.with_borrow(|log| log.iter().collect())
}

#[update]
async fn get_root_public_key() -> VetKeyPublicKey {
    match VETKD_ROOT_IBE_PUBLIC_KEY.with(|v| v.borrow().to_owned()) {
        Some(root_ibe_public_key) => root_ibe_public_key,
        None => {
            let request = VetKDPublicKeyRequest {
                canister_id: None,
                context: vec![],
                key_id: bls12_381_dfx_test_key(),
            };

            let (result,) = ic_cdk::api::call::call::<_, (VetKDPublicKeyReply,)>(
                CanisterId::from_str("aaaaa-aa").unwrap(),
                "vetkd_public_key",
                (request,),
            )
            .await
            .expect("call to vetkd_public_key failed");

            result.public_key.into()
        }
    }
}

fn get_context(signer: Principal) -> Vec<u8> {
    // A domain separator is not strictly necessary in this dapp, but having one is considered a good practice.
    const DOMAIN_SEPARATOR: [u8; 22] = *b"basic_bls_signing_dapp";
    const DOMAIN_SEPARATOR_LENGTH: u8 = DOMAIN_SEPARATOR.len() as u8;
    [DOMAIN_SEPARATOR_LENGTH]
        .into_iter()
        .chain(DOMAIN_SEPARATOR)
        .chain(signer.as_ref().iter().cloned())
        .collect()
}

fn bls12_381_dfx_test_key() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some other dependencies) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// the used RNGs are _manually_ seeded rather than by the system.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();
