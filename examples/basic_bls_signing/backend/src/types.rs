use std::borrow::Cow;

use candid::{CandidType, Principal};
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};

pub type CanisterId = Principal;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]

pub struct Signature {
    pub message: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub signer: Principal,
}

impl Storable for Signature {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(&bytes).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum VetKDCurve {
    #[serde(rename = "bls12_381_g2")]
    #[allow(non_camel_case_types)]
    Bls12_381_G2,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub(crate) struct VetKDKeyId {
    pub curve: VetKDCurve,
    pub name: String,
}

#[derive(CandidType, Deserialize)]
pub(crate) struct VetKDPublicKeyRequest {
    pub canister_id: Option<CanisterId>,
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize)]
pub(crate) struct VetKDPublicKeyReply {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub(crate) struct VetKDDeriveKeyRequest {
    #[serde(with = "serde_bytes")]
    pub input: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub transport_public_key: Vec<u8>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize)]
pub(crate) struct VetKDDeriveKeyReply {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}
