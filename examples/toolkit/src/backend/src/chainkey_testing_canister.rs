// This is an experimental feature to generate Rust binding from Candid.
// You may want to manually adjust some of the types.
#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::call::CallResult as Result;

#[derive(Debug, CandidType, Deserialize)]
pub struct CallCountsResultCallCountsItem {
    pub call_count: u64,
    pub method_name: String,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct CallCountsResult {
    pub call_counts: Vec<CallCountsResultCallCountsItem>,
}

#[derive(Debug, CandidType, Deserialize)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256K1,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct EcdsaPublicKeyArgsKeyId {
    pub name: String,
    pub curve: EcdsaCurve,
}

pub type CanisterId = Principal;
#[derive(Debug, CandidType, Deserialize)]
pub struct EcdsaPublicKeyArgs {
    pub key_id: EcdsaPublicKeyArgsKeyId,
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<serde_bytes::ByteBuf>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct EcdsaPublicKeyResult {
    pub public_key: serde_bytes::ByteBuf,
    pub chain_code: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256K1,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SchnorrPublicKeyArgsKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SchnorrPublicKeyArgs {
    pub key_id: SchnorrPublicKeyArgsKeyId,
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<serde_bytes::ByteBuf>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SchnorrPublicKeyResult {
    pub public_key: serde_bytes::ByteBuf,
    pub chain_code: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithEcdsaArgsKeyId {
    pub name: String,
    pub curve: EcdsaCurve,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithEcdsaArgs {
    pub key_id: SignWithEcdsaArgsKeyId,
    pub derivation_path: Vec<serde_bytes::ByteBuf>,
    pub message_hash: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithEcdsaResult {
    pub signature: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub enum SchnorrAux {
    #[serde(rename = "bip341")]
    Bip341 {
        merkle_root_hash: serde_bytes::ByteBuf,
    },
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithSchnorrArgsKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithSchnorrArgs {
    pub aux: Option<SchnorrAux>,
    pub key_id: SignWithSchnorrArgsKeyId,
    pub derivation_path: Vec<serde_bytes::ByteBuf>,
    pub message: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithSchnorrResult {
    pub signature: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub enum VetkdCurve {
    #[serde(rename = "bls12_381_g2")]
    Bls12381G2,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct VetkdDeriveEncryptedKeyArgsKeyId {
    pub name: String,
    pub curve: VetkdCurve,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct VetkdDeriveEncryptedKeyArgs {
    pub key_id: VetkdDeriveEncryptedKeyArgsKeyId,
    pub derivation_path: Vec<serde_bytes::ByteBuf>,
    pub derivation_id: serde_bytes::ByteBuf,
    pub encryption_public_key: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct VetkdDeriveEncryptedKeyResult {
    pub encrypted_key: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct VetkdPublicKeyArgsKeyId {
    pub name: String,
    pub curve: VetkdCurve,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct VetkdPublicKeyArgs {
    pub key_id: VetkdPublicKeyArgsKeyId,
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<serde_bytes::ByteBuf>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct VetkdPublicKeyResult {
    pub public_key: serde_bytes::ByteBuf,
}

pub struct ChainkeyTestingCanister(pub Principal);
impl ChainkeyTestingCanister {
    pub async fn call_counts(&self) -> Result<(CallCountsResult,)> {
        ic_cdk::call(self.0, "call_counts", ()).await
    }
    pub async fn ecdsa_public_key(
        &self,
        arg0: EcdsaPublicKeyArgs,
    ) -> Result<(EcdsaPublicKeyResult,)> {
        ic_cdk::call(self.0, "ecdsa_public_key", (arg0,)).await
    }
    pub async fn schnorr_public_key(
        &self,
        arg0: SchnorrPublicKeyArgs,
    ) -> Result<(SchnorrPublicKeyResult,)> {
        ic_cdk::call(self.0, "schnorr_public_key", (arg0,)).await
    }
    pub async fn sign_with_ecdsa(&self, arg0: SignWithEcdsaArgs) -> Result<(SignWithEcdsaResult,)> {
        ic_cdk::call(self.0, "sign_with_ecdsa", (arg0,)).await
    }
    pub async fn sign_with_schnorr(
        &self,
        arg0: SignWithSchnorrArgs,
    ) -> Result<(SignWithSchnorrResult,)> {
        ic_cdk::call(self.0, "sign_with_schnorr", (arg0,)).await
    }
    pub async fn vetkd_derive_encrypted_key(
        &self,
        arg0: VetkdDeriveEncryptedKeyArgs,
    ) -> Result<(VetkdDeriveEncryptedKeyResult,)> {
        ic_cdk::call(self.0, "vetkd_derive_encrypted_key", (arg0,)).await
    }
    pub async fn vetkd_public_key(
        &self,
        arg0: VetkdPublicKeyArgs,
    ) -> Result<(VetkdPublicKeyResult,)> {
        ic_cdk::call(self.0, "vetkd_public_key", (arg0,)).await
    }
}
pub const CANISTER_ID : Principal = Principal::from_slice(&[0, 0, 0, 0, 1, 176, 203, 121, 1, 1]); // vrqyr-saaaa-aaaan-qzn4q-cai
pub const CHAINKEY_TESTING_CANISTER: ChainkeyTestingCanister = ChainkeyTestingCanister(CANISTER_ID);
