use candid::{CandidType, Principal};
use ic_cdk::api::management_canister::main::CanisterId;
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::borrow::Cow;

pub const MAX_MESSAGES_PER_INBOX: usize = 10;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub sender: Principal,
    pub receiver: Principal,
    #[serde(with = "serde_bytes")]
    pub encrypted_message: Vec<u8>,
    pub timestamp: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct Inbox {
    pub messages: Vec<Message>,
}

impl Storable for Inbox {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(&bytes).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for Message {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(&bytes).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SendMessageRequest {
    pub receiver: Principal,
    #[serde(with = "serde_bytes")]
    pub encrypted_message: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GetEncryptedIbeKeyRequest {
    #[serde(with = "serde_bytes")]
    pub public_transport_key: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SendMessageReply {
    pub message_id: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum VetKDCurve {
    #[serde(rename = "bls12_381")]
    Bls12_381,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct VetKDKeyId {
    pub curve: VetKDCurve,
    pub name: String,
}

#[serde_as]
#[derive(CandidType, Deserialize)]
pub struct VetKDPublicKeyRequest {
    pub canister_id: Option<CanisterId>,
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize)]
pub struct VetKDPublicKeyReply {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[serde_as]
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct VetKDEncryptedKeyRequest {
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    pub public_key_derivation_path: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub derivation_id: Vec<u8>,
    pub key_id: VetKDKeyId,
    #[serde(with = "serde_bytes")]
    pub encryption_public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct VetKDEncryptedKeyReply {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}
