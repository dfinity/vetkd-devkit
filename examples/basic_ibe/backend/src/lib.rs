use candid::Principal;
use ic_cdk::api::management_canister::provisional::CanisterId;
use ic_cdk::{query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap as StableBTreeMap, DefaultMemoryImpl};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::str::FromStr;

mod types;
use types::*;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type VetKey = ByteBuf;
type VetKeyPublicKey = ByteBuf;
type TransportPublicKey = ByteBuf;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static INBOXES: RefCell<StableBTreeMap<Principal, Inbox, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
    ));

    #[cfg(feature = "expose-testing-api")]
    static CANISTER_ID_VETKD_MOCK: RefCell<Option<Principal>> = const { RefCell::new(None) };
}

static DOMAIN_SEPARATOR: &str = "basic_ibe";
const CANISTER_ID_VETKD_SYSTEM_API: &str = "aaaaa-aa";

#[update]
fn send_message(request: SendMessageRequest) -> Result<(), String> {
    let sender = ic_cdk::caller();
    let SendMessageRequest {
        receiver,
        encrypted_message,
    } = request;
    let timestamp = ic_cdk::api::time();

    let message = Message {
        sender,
        receiver,
        encrypted_message,
        timestamp,
    };

    INBOXES.with_borrow_mut(|inboxes| {
        let mut inbox = inboxes.get(&receiver).unwrap_or_default();
        if inbox.messages.len() >= MAX_MESSAGES_PER_INBOX {
            Err(format!("Inbox for {} is full", receiver))
        } else {
            inbox.messages.push(message);
            inboxes.insert(receiver, inbox);
            Ok(())
        }
    })
}

#[update]
async fn get_root_ibe_public_key() -> VetKeyPublicKey {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![DOMAIN_SEPARATOR.as_bytes().to_vec()],
        key_id: bls12_381_test_key_1(),
    };

    let (result,) = ic_cdk::api::call::call::<_, (VetKDPublicKeyReply,)>(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("call to vetkd_public_key failed");

    VetKeyPublicKey::from(result.public_key)
}

#[update]
async fn get_my_encrypted_ibe_key(transport_key: TransportPublicKey) -> VetKey {
    let caller = ic_cdk::caller();
    let request = VetKDEncryptedKeyRequest {
        derivation_id: caller.as_ref().to_vec(),
        public_key_derivation_path: vec![DOMAIN_SEPARATOR.as_bytes().to_vec()],
        key_id: bls12_381_test_key_1(),
        encryption_public_key: transport_key.into_vec(),
    };

    let (result,) = ic_cdk::api::call::call::<_, (VetKDEncryptedKeyReply,)>(
        vetkd_system_api_canister_id(),
        "vetkd_encrypted_key",
        (request,),
    )
    .await
    .expect("call to vetkd_encrypted_key failed");

    VetKey::from(result.encrypted_key)
}

#[query]
fn get_my_messages() -> Inbox {
    let caller = ic_cdk::caller();
    INBOXES.with_borrow_mut(|inboxes| inboxes.get(&caller).unwrap_or_default())
}

#[update]
fn remove_my_messages() -> Inbox {
    let caller = ic_cdk::caller();
    INBOXES.with_borrow_mut(|inboxes| inboxes.remove(&caller).unwrap_or_default())
}

fn bls12_381_test_key_1() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381,
        name: "insecure_test_key_1".to_string(),
    }
}

fn vetkd_system_api_canister_id() -> CanisterId {
    #[cfg(feature = "expose-testing-api")]
    {
        if let Some(canister_id) = CANISTER_ID_VETKD_MOCK.with(|cell| cell.borrow().clone()) {
            return canister_id;
        }
    }
    CanisterId::from_str(CANISTER_ID_VETKD_SYSTEM_API).expect("failed to create canister ID")
}

#[cfg(feature = "expose-testing-api")]
#[update]
fn set_vetkd_testing_canister_id(vetkd_testing_canister: Principal) {
    CANISTER_ID_VETKD_MOCK.with(|cell| {
        *cell.borrow_mut() = Some(vetkd_testing_canister);
    });
}

ic_cdk::export_candid!();
