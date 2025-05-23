//! Verifiably Encrypted Threshold Key Derivation Utilities
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![forbid(missing_docs)]

use ic_bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar,
};
use ic_cdk::api::call::RejectionCode;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::array::TryFromSliceError;
use std::ops::Neg;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::vetkd_api_types::{VetKDCurve, VetKDDeriveKeyReply, VetKDDeriveKeyRequest, VetKDKeyId};

lazy_static::lazy_static! {
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

const G1AFFINE_BYTES: usize = 48; // Size of compressed form
const G2AFFINE_BYTES: usize = 96; // Size of compressed form

/// Derive a symmetric key using HKDF-SHA256
pub fn derive_symmetric_key(input: &[u8], domain_sep: &str, len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, input);
    let mut okm = vec![0u8; len];
    hk.expand(domain_sep.as_bytes(), &mut okm)
        .expect("Unsupported output length for HKDF");
    okm
}

fn hash_to_scalar(input: &[u8], domain_sep: &str) -> ic_bls12_381::Scalar {
    use ic_bls12_381::hash_to_curve::HashToField;

    let mut s = [ic_bls12_381::Scalar::zero()];
    <ic_bls12_381::Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(
        input,
        domain_sep.as_bytes(),
        &mut s,
    );
    s[0]
}

fn hash_to_scalar_two_inputs(
    input1: &[u8],
    input2: &[u8],
    domain_sep: &str,
) -> ic_bls12_381::Scalar {
    let combined_input = {
        let mut c = Vec::with_capacity(2 * 8 + input1.len() + input2.len());
        c.extend_from_slice(&(input1.len() as u64).to_be_bytes());
        c.extend_from_slice(input1);
        c.extend_from_slice(&(input2.len() as u64).to_be_bytes());
        c.extend_from_slice(input2);
        c
    };

    hash_to_scalar(&combined_input, domain_sep)
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
/// Secret key of the transport key pair
pub struct TransportSecretKey {
    secret_key: Scalar,
}

impl TransportSecretKey {
    /// Creates a transport secret key from a 32-byte seed.
    pub fn from_seed(seed: Vec<u8>) -> Result<TransportSecretKey, String> {
        let seed_32_bytes: [u8; 32] = seed.try_into().map_err(|_e| "seed not 32 bytes")?;
        let rng = &mut ChaCha20Rng::from_seed(seed_32_bytes);
        use pairing::group::ff::Field;
        let secret_key = Scalar::random(rng);
        Ok(Self { secret_key })
    }

    /// Returns the serialized public key associated with this secret key
    pub fn public_key(&self) -> Vec<u8> {
        let public_key = G1Affine::generator() * self.secret_key;
        use pairing::group::Curve;
        public_key.to_affine().to_compressed().to_vec()
    }

    /// Serialize this transport secret key to a bytestring
    pub fn serialize(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    /// Serialize this transport secret key to a bytestring
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "TransportSecretKey must be exactly 32 bytes not {}",
                bytes.len()
            ));
        }

        let bytes: [u8; 32] = bytes.try_into().expect("Length already checked");

        if let Some(s) = Scalar::from_bytes(&bytes).into_option() {
            Ok(Self { secret_key: s })
        } else {
            Err("Invalid TransportSecretKey bytes".to_string())
        }
    }
}

/// Return true iff the argument is a valid encoding of a transport public key
pub fn is_valid_transport_public_key_encoding(bytes: &[u8]) -> bool {
    match bytes.try_into() {
        Ok(bytes) => option_from_ctoption(G1Affine::from_compressed(&bytes)).is_some(),
        Err(_) => false,
    }
}

#[derive(Copy, Clone, Debug)]
/// Error indicating deserializing a derived public key failed
pub enum PublicKeyDeserializationError {
    /// The public key is invalid
    InvalidPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A master VetKD public key
pub struct MasterPublicKey {
    point: G2Affine,
}

impl MasterPublicKey {
    const BYTES: usize = G2AFFINE_BYTES;

    // TODO(CRP-2797) add
    // pub fn production_key(key_id: SomeEnum) -> Self

    /// Deserializes a (derived) public key.
    ///
    /// Only compressed points are supported.
    ///
    /// Normally the bytes provided here will have been returned by the
    /// Internet Computer's `vetkd_public_key`` management canister interface.
    ///
    /// Returns an error if the key is invalid (e.g., it has invalid length,
    /// i.e., not 96 bytes, it is not in compressed format, is is not a point
    /// on the curve, it is not torsion-free).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PublicKeyDeserializationError> {
        let dpk_bytes: &[u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_e: TryFromSliceError| PublicKeyDeserializationError::InvalidPublicKey)?;
        let dpk = option_from_ctoption(G2Affine::from_compressed(dpk_bytes))
            .ok_or(PublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { point: dpk })
    }

    /// Perform first-stage derivation of a canister public key from the master public key
    ///
    /// To create the derived public key in VetKD, a two step derivation is performed;
    ///
    /// - The first step creates a canister public key, sometimes called canister master key.
    ///   This step is implemented by the `derive_canister_key` method.
    ///
    /// - The second step derives a canister sub-key which incorporates the "context" value provided to the
    ///   `vetkd_public_key` management canister interface. This step is implemented by the
    ///   `DerivedPublicKey::derive_sub_key` method.
    pub fn derive_canister_key(&self, canister_id: &[u8]) -> DerivedPublicKey {
        let dst = "ic-vetkd-bls12-381-g2-canister-id";

        let offset = hash_to_scalar_two_inputs(&self.serialize(), canister_id, dst);

        let derived_key = G2Affine::from(self.point + G2Affine::generator() * offset);
        DerivedPublicKey { point: derived_key }
    }

    /// Return the byte encoding of this master public key
    pub fn serialize(&self) -> Vec<u8> {
        self.point.to_compressed().to_vec()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A derived public key
pub struct DerivedPublicKey {
    point: G2Affine,
}

impl From<DerivedPublicKey> for G2Affine {
    fn from(public_key: DerivedPublicKey) -> Self {
        public_key.point
    }
}

impl DerivedPublicKey {
    const BYTES: usize = G2AFFINE_BYTES;

    /// Deserializes a (derived) public key.
    ///
    /// Only compressed points are supported.
    ///
    /// Normally the bytes provided here will have been returned by the
    /// Internet Computer's `vetkd_public_key`` management canister interface.
    ///
    /// Returns an error if the key is invalid (e.g., it has invalid length,
    /// i.e., not 96 bytes, it is not in compressed format, is is not a point
    /// on the curve, it is not torsion-free).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PublicKeyDeserializationError> {
        let dpk_bytes: &[u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_e: TryFromSliceError| PublicKeyDeserializationError::InvalidPublicKey)?;
        let dpk = option_from_ctoption(G2Affine::from_compressed(dpk_bytes))
            .ok_or(PublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { point: dpk })
    }

    /// Perform second-stage derivation of a public key from a canister public key
    ///
    /// To create the derived public key in VetKD, a two step derivation is performed;
    ///
    /// - The first step creates a canister public key, sometimes called canister master key. This step is implemented
    ///   by the `MasterKey::derive_canister_key` method.
    /// - The second step derives a canister sub-key which incorporates the "context" value provided to the
    ///   `vetkd_public_key` management canister interface. This step is implemented by the `derive_sub_key` method.
    ///
    /// If `vetkd_public_key` is invoked with an empty derivation context, it simply returns the
    /// canister master key. Then the second derivation step can be done offline, using this
    /// function. This is useful if you wish to derive multiple keys without having to interact with
    /// the IC each time.
    pub fn derive_sub_key(&self, context: &[u8]) -> Self {
        if context.is_empty() {
            return self.clone();
        }

        let dst = "ic-vetkd-bls12-381-g2-context";

        let offset = hash_to_scalar_two_inputs(&self.serialize(), context, dst);

        let derived_key = G2Affine::from(self.point + G2Affine::generator() * offset);
        Self { point: derived_key }
    }

    /// Return the byte encoding of this derived public key
    pub fn serialize(&self) -> Vec<u8> {
        self.point.to_compressed().to_vec()
    }
}

/// A verifiably encrypted threshold key derived by the VetKD protocol
///
/// A VetKey is a valid BLS signature created for an input specified
/// by the user
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VetKey {
    pt: G1Affine,
    pt_bytes: [u8; 48],
}

impl VetKey {
    fn new(pt: G1Affine) -> Self {
        Self {
            pt,
            pt_bytes: pt.to_compressed(),
        }
    }

    /**
     * Return the VetKey bytes, aka the BLS signature
     *
     * Use the raw bytes only if your design makes use of the fact that VetKeys
     * are BLS signatures (eg for random beacon or threshold BLS signature
     * generation). If you are using VetKD for key distribution, instead use
     * derive_symmetric_key
     */
    pub fn signature_bytes(&self) -> &[u8; 48] {
        &self.pt_bytes
    }

    /**
     * Derive a symmetric key of the requested length from the VetKey
     *
     * The `domain_sep` parameter should be a string unique to your application and
     * also your usage of the resulting key. For example say your application
     * "my-app" is deriving two keys, one for usage "foo" and the other for
     * "bar". You might use as domain separators "my-app-foo" and "my-app-bar".
     */
    pub fn derive_symmetric_key(&self, domain_sep: &str, output_len: usize) -> Vec<u8> {
        derive_symmetric_key(&self.pt_bytes, domain_sep, output_len)
    }

    /**
     * Deserialize a VetKey from the byte encoding
     *
     * Typically this would have been created using [`VetKey::signature_bytes`]
     */
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        let bytes48: [u8; 48] = bytes.try_into().map_err(|_e: TryFromSliceError| {
            format!("Vetkey is unexpected length {}", bytes.len())
        })?;

        if let Some(pt) = option_from_ctoption(G1Affine::from_compressed(&bytes48)) {
            Ok(Self {
                pt,
                pt_bytes: bytes48,
            })
        } else {
            Err("Invalid VetKey".to_string())
        }
    }
}

#[derive(Copy, Clone, Debug)]
/// Error indicating that deserializing an encrypted key failed
pub enum EncryptedVetKeyDeserializationError {
    /// Error indicating one or more of the points was invalid
    InvalidEncryptedVetKey,
}

/// An encrypted VetKey
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedVetKey {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

impl EncryptedVetKey {
    /// The length of the serialized encoding of this type
    const BYTES: usize = 2 * G1AFFINE_BYTES + G2AFFINE_BYTES;

    const C2_OFFSET: usize = G1AFFINE_BYTES;
    const C3_OFFSET: usize = G1AFFINE_BYTES + G2AFFINE_BYTES;

    /// Decrypts and verifies the VetKey
    pub fn decrypt_and_verify(
        &self,
        tsk: &TransportSecretKey,
        derived_public_key: &DerivedPublicKey,
        input: &[u8],
    ) -> Result<VetKey, String> {
        use pairing::group::Group;

        // Check that c1 and c2 have the same discrete logarithm

        let c2_prep = G2Prepared::from(self.c2);

        let c1_c2 = gt_multipairing(&[
            (&self.c1, &G2PREPARED_NEG_G),
            (&G1Affine::generator(), &c2_prep),
        ]);

        if !bool::from(c1_c2.is_identity()) {
            return Err("invalid encrypted key: c1 inconsistent with c2".to_string());
        }

        // Recover the purported VetKey
        let k = G1Affine::from(G1Projective::from(&self.c3) - self.c1 * tsk.secret_key);

        // Check that the VetKey is a valid BLS signature
        if verify_bls_signature_pt(derived_public_key, input, &k) {
            Ok(VetKey::new(k))
        } else {
            Err("invalid encrypted key: verification failed".to_string())
        }
    }

    /// Deserializes an encrypted key from a byte vector
    pub fn deserialize(bytes: &[u8]) -> Result<EncryptedVetKey, String> {
        let ek_bytes: &[u8; Self::BYTES] = bytes.try_into().map_err(|_e: TryFromSliceError| {
            format!("key not {} bytes but {}", Self::BYTES, bytes.len())
        })?;
        Self::deserialize_array(ek_bytes).map_err(|e| format!("{:?}", e))
    }

    /// Deserializes an encrypted key from a byte array
    pub fn deserialize_array(
        val: &[u8; Self::BYTES],
    ) -> Result<Self, EncryptedVetKeyDeserializationError> {
        let c1_bytes: &[u8; G1AFFINE_BYTES] = &val[..Self::C2_OFFSET]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;
        let c2_bytes: &[u8; G2AFFINE_BYTES] = &val[Self::C2_OFFSET..Self::C3_OFFSET]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;
        let c3_bytes: &[u8; G1AFFINE_BYTES] = &val[Self::C3_OFFSET..]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;

        let c1 = option_from_ctoption(G1Affine::from_compressed(c1_bytes));
        let c2 = option_from_ctoption(G2Affine::from_compressed(c2_bytes));
        let c3 = option_from_ctoption(G1Affine::from_compressed(c3_bytes));

        match (c1, c2, c3) {
            (Some(c1), Some(c2), Some(c3)) => Ok(Self { c1, c2, c3 }),
            (_, _, _) => Err(EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey),
        }
    }
}

const IBE_SEED_BYTES: usize = 32;

const IBE_HEADER_BYTES: usize = 8;
const IBE_HEADER: [u8; IBE_HEADER_BYTES] = [b'I', b'C', b' ', b'I', b'B', b'E', 0x00, 0x01];

#[derive(Clone, Debug, Eq, PartialEq)]
/// An IBE (identity based encryption) ciphertext
pub struct IBECiphertext {
    header: Vec<u8>,
    c1: G2Affine,
    c2: [u8; IBE_SEED_BYTES],
    c3: Vec<u8>,
}

enum IBEDomainSep {
    HashToMask,
    MaskSeed,
    MaskMsg(usize),
}

impl IBEDomainSep {
    #[allow(clippy::inherent_to_string)]
    fn to_string(&self) -> String {
        match self {
            Self::HashToMask => "ic-vetkd-bls12-381-ibe-hash-to-mask".to_owned(),
            Self::MaskSeed => "ic-vetkd-bls12-381-ibe-mask-seed".to_owned(),
            // Zero prefix the length up to 20 digits, which is sufficient to be fixed
            // length for any 64-bit length. This ensures all of the MaskMsg domain
            // separators are of equal length. With how we use the domain separators, this
            // padding isn't required - we only need uniquness - but having variable
            // length domain separators is generally not considered a good practice and is
            // easily avoidable here.
            Self::MaskMsg(len) => format!("ic-vetkd-bls12-381-ibe-mask-msg-{:020}", len),
        }
    }
}

impl IBECiphertext {
    /// Serialize this IBE ciphertext
    pub fn serialize(&self) -> Vec<u8> {
        let mut output =
            Vec::with_capacity(self.header.len() + G2AFFINE_BYTES + IBE_SEED_BYTES + self.c3.len());

        output.extend_from_slice(&self.header);
        output.extend_from_slice(&self.c1.to_compressed());
        output.extend_from_slice(&self.c2);
        output.extend_from_slice(&self.c3);

        output
    }

    /// Deserialize an IBE ciphertext
    ///
    /// Returns Err if the encoding is not valid
    pub fn deserialize(bytes: &[u8]) -> Result<IBECiphertext, String> {
        if bytes.len() < IBE_HEADER_BYTES + G2AFFINE_BYTES + IBE_SEED_BYTES {
            return Err("IBECiphertext too short to be valid".to_string());
        }

        let header = bytes[0..IBE_HEADER_BYTES].to_vec();
        let c1 = deserialize_g2(&bytes[IBE_HEADER_BYTES..(IBE_HEADER_BYTES + G2AFFINE_BYTES)])?;

        let mut c2 = [0u8; IBE_SEED_BYTES];
        c2.copy_from_slice(
            &bytes[IBE_HEADER_BYTES + G2AFFINE_BYTES
                ..(IBE_HEADER_BYTES + G2AFFINE_BYTES + IBE_SEED_BYTES)],
        );

        let c3 = bytes[IBE_HEADER_BYTES + G2AFFINE_BYTES + IBE_SEED_BYTES..].to_vec();

        if header != IBE_HEADER {
            return Err("IBECiphertext has unknown header".to_string());
        }

        Ok(Self { header, c1, c2, c3 })
    }

    fn hash_to_mask(header: &[u8], seed: &[u8; IBE_SEED_BYTES], msg: &[u8]) -> Scalar {
        let domain_sep = IBEDomainSep::HashToMask;
        let mut ro_input = Vec::with_capacity(seed.len() + msg.len());
        ro_input.extend_from_slice(header);
        ro_input.extend_from_slice(seed);
        ro_input.extend_from_slice(msg);

        hash_to_scalar(&ro_input, &domain_sep.to_string())
    }

    fn mask_seed(seed: &[u8; IBE_SEED_BYTES], t: &Gt) -> [u8; IBE_SEED_BYTES] {
        let domain_sep = IBEDomainSep::MaskSeed;
        let mask = derive_symmetric_key(&t.to_bytes(), &domain_sep.to_string(), IBE_SEED_BYTES);

        let mut masked_seed = [0u8; IBE_SEED_BYTES];
        for i in 0..IBE_SEED_BYTES {
            masked_seed[i] = mask[i] ^ seed[i];
        }
        masked_seed
    }

    fn mask_msg(msg: &[u8], seed: &[u8; IBE_SEED_BYTES]) -> Vec<u8> {
        fn derive_ibe_ctext_mask(seed: &[u8], msg_len: usize) -> Vec<u8> {
            use sha3::{
                digest::{ExtendableOutputReset, Update, XofReader},
                Shake256,
            };

            let mut shake = Shake256::default();
            shake.update(seed);

            let mut xof = shake.finalize_xof_reset();
            let mut mask = vec![0u8; msg_len];
            xof.read(&mut mask);
            mask
        }

        let domain_sep = IBEDomainSep::MaskMsg(msg.len());

        let shake_seed = derive_symmetric_key(seed, &domain_sep.to_string(), 32);

        let mut mask = derive_ibe_ctext_mask(&shake_seed, msg.len());

        for i in 0..msg.len() {
            mask[i] ^= msg[i];
        }

        mask
    }

    /// Encrypt a message using IBE
    ///
    /// The message can be of arbitrary length
    ///
    /// The seed must be exactly 256 bits (32 bytes) long and should be
    /// generated with a cryptographically secure random number generator. Do
    /// not reuse the seed for encrypting another message or any other purpose.
    ///
    /// To decrypt this message requires using the VetKey associated with the
    /// provided derived public key (ie the same master key and context string),
    /// and with an `input` equal to the provided `identity` parameter.
    pub fn encrypt(
        dpk: &DerivedPublicKey,
        identity: &[u8],
        msg: &[u8],
        seed: &[u8],
    ) -> Result<IBECiphertext, String> {
        let seed: &[u8; IBE_SEED_BYTES] = seed
            .try_into()
            .map_err(|_e| format!("Provided seed must be {} bytes long ", IBE_SEED_BYTES))?;

        let header = IBE_HEADER.to_vec();

        let t = Self::hash_to_mask(&header, seed, msg);

        let pt = augmented_hash_to_g1(&dpk.point, identity);

        let tsig = ic_bls12_381::pairing(&pt, &dpk.point) * t;

        let c1 = G2Affine::from(G2Affine::generator() * t);
        let c2 = Self::mask_seed(seed, &tsig);
        let c3 = Self::mask_msg(msg, seed);

        Ok(Self { header, c1, c2, c3 })
    }

    /// Decrypt an IBE ciphertext
    ///
    /// The VetKey provided must be the VetKey produced by a request to the IC
    /// for a given `identity` (aka `input`) and `context` both matching the
    /// values used during encryption.
    ///
    /// Returns the plaintext, or Err if decryption failed
    pub fn decrypt(&self, vetkey: &VetKey) -> Result<Vec<u8>, String> {
        let t = ic_bls12_381::pairing(&vetkey.pt, &self.c1);

        let seed = Self::mask_seed(&self.c2, &t);

        let msg = Self::mask_msg(&self.c3, &seed);

        let t = Self::hash_to_mask(&self.header, &seed, &msg);

        let g_t = G2Affine::from(G2Affine::generator() * t);

        if self.c1 == g_t {
            Ok(msg)
        } else {
            Err("decryption failed".to_string())
        }
    }
}

/// Verify an augmented BLS signature
///
/// Augmented BLS signatures include the public key as part of the input, and
/// "under the hood" a vetKey is an augmented BLS signature. This function allows
/// verifying, for example, that a vetKey used as a VRF output is in fact a valid
/// signature.
///
/// See <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#name-message-augmentation>
/// for more details on BLS message augmentation.
///
/// Returns true if and only if the provided signature is valid with respect to
/// the provided public key and input
pub fn verify_bls_signature(dpk: &DerivedPublicKey, input: &[u8], signature: &[u8]) -> bool {
    let signature: G1Affine = match <[u8; 48]>::try_from(signature) {
        Ok(bytes) => match option_from_ctoption(G1Affine::from_compressed(&bytes)) {
            Some(pt) => pt,
            None => return false,
        },
        Err(_) => return false,
    };

    verify_bls_signature_pt(dpk, input, &signature)
}

/// Verify an augmented BLS signature
///
/// Returns true if and only if the provided signature is valid with respect to
/// the provided public key and input
fn verify_bls_signature_pt(dpk: &DerivedPublicKey, input: &[u8], signature: &G1Affine) -> bool {
    let msg = augmented_hash_to_g1(&dpk.point, input);
    let dpk_prep = G2Prepared::from(dpk.point);

    use pairing::group::Group;
    let is_valid =
        gt_multipairing(&[(signature, &G2PREPARED_NEG_G), (&msg, &dpk_prep)]).is_identity();
    bool::from(is_valid)
}

fn augmented_hash_to_g1(pk: &G2Affine, data: &[u8]) -> G1Affine {
    let domain_sep = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

    let mut signature_input = Vec::with_capacity(G2AFFINE_BYTES + data.len());
    signature_input.extend_from_slice(&pk.to_compressed());
    signature_input.extend_from_slice(data);

    let pt = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        signature_input,
        domain_sep,
    );
    G1Affine::from(pt)
}

fn gt_multipairing(terms: &[(&G1Affine, &G2Prepared)]) -> Gt {
    ic_bls12_381::multi_miller_loop(terms).final_exponentiation()
}

fn option_from_ctoption<T>(ctoption: subtle::CtOption<T>) -> Option<T> {
    if bool::from(ctoption.is_some()) {
        Some(ctoption.unwrap())
    } else {
        None
    }
}

fn deserialize_g2(bytes: &[u8]) -> Result<G2Affine, String> {
    let bytes: &[u8; G2AFFINE_BYTES] = bytes
        .try_into()
        .map_err(|_| "Invalid length for G2".to_string())?;

    let pt = G2Affine::from_compressed(bytes);
    if bool::from(pt.is_some()) {
        Ok(pt.unwrap())
    } else {
        Err("Invalid G2 elliptic curve point".to_string())
    }
}

/// This module contains functions for calling the ICP management canister's `vetkd_derive_key` endpoint from within a canister.
pub mod management_canister {
    use crate::{
        types::CanisterId,
        vetkd_api_types::{VetKDPublicKeyReply, VetKDPublicKeyRequest},
    };

    use super::*;

    /// Derives a vetKey that is public to the canister and ICP nodes.
    /// This function is useful if vetKeys are supposed to be decrypted by the canister itself, e.g., when vetKeys are used as BLS signatures, for timelock encryption, or for producing verifiable randomness.
    ///
    /// **Warning**: A vetKey produced by this function is *insecure* to use as a private key by a user.
    ///
    /// A public vetKey is derived by calling the ICP management canister's `vetkd_derive_key` endpoint with a **fixed public transport key** that produces an **unencrypted vetKey**.
    /// Therefore, this function is more efficient than actually retrieving the encrypted vetKey and calling [`EncryptedVetKey::decrypt_and_verify`].
    ///
    /// # Arguments
    /// * `input` - corresponds to `input` in `vetkd_derive_key`
    /// * `context` - corresponds to `context` in `vetkd_derive_key`
    /// * `key_id` - corresponds to `key_id` in `vetkd_derive_key`
    ///
    /// # Returns
    /// * `Ok(VetKey)` - The derived vetKey on success
    /// * `Err(DeriveUnencryptedVetkeyError)` - If derivation fails due to unsupported curve or canister call error
    async fn derive_public_vetkey(
        input: Vec<u8>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> Result<Vec<u8>, VetKDDeriveKeyCallError> {
        if key_id.curve != VetKDCurve::Bls12_381_G2 {
            return Err(VetKDDeriveKeyCallError::UnsupportedCurve);
        }

        let request = VetKDDeriveKeyRequest {
            input,
            context,
            key_id,
            // Encryption with the G1 identity element produces unencrypted vetKeys
            transport_public_key: G1Affine::identity().to_compressed().to_vec(),
        };

        let reply: (VetKDDeriveKeyReply,) =
            ic_cdk::api::call::call_with_payment128::<_, (VetKDDeriveKeyReply,)>(
                candid::Principal::management_canister(),
                "vetkd_derive_key",
                (request,),
                26_153_846_153,
            )
            .await
            .map_err(VetKDDeriveKeyCallError::CallFailed)?;

        if reply.0.encrypted_key.len() < EncryptedVetKey::BYTES {
            return Err(VetKDDeriveKeyCallError::InvalidReply);
        }

        Ok(reply.0.encrypted_key
            [EncryptedVetKey::C3_OFFSET..EncryptedVetKey::C3_OFFSET + G1AFFINE_BYTES]
            .to_vec())
    }

    #[derive(Debug, Eq, PartialEq)]
    /// Errors that can occur when deriving an unencrypted vetKey
    pub enum VetKDDeriveKeyCallError {
        /// The curve is not supported in `derive_unencrypted_vetkey`
        UnsupportedCurve,
        /// The canister call failed
        CallFailed((RejectionCode, String)),
        /// Invalid reply from the management canister
        InvalidReply,
    }

    /// Creates a threshold BLS12-381 signature for the given `message`.
    ///
    /// # Arguments
    /// * `message` - the message to be signed
    /// * `context` - the identity of the signer
    /// * `key_id` - the key ID of the threshold key deployed on the Internet Computer
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The signature on success
    /// * `Err(VetKDDeriveKeyCallError)` - If derivation fails due to unsupported curve or canister call error
    pub async fn sign_with_bls(
        message: Vec<u8>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> Result<Vec<u8>, VetKDDeriveKeyCallError> {
        derive_public_vetkey(message, context, key_id).await
    }

    /// Returns the public key of a threshold BLS12-381 key. If `context` is empty, the public key of the canister is returned.
    ///
    /// # Arguments
    /// * `canister_id` - the canister ID of the threshold key deployed on the Internet Computer
    /// * `context` - the identity of the signer
    /// * `key_id` - the key ID of the threshold key deployed on the Internet Computer
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The public key on success
    /// * `Err((RejectionCode, String))` - If the canister call fails
    pub async fn bls_public_key(
        canister_id: Option<CanisterId>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> Result<Vec<u8>, (RejectionCode, String)> {
        let request = VetKDPublicKeyRequest {
            canister_id,
            context,
            key_id,
        };

        let reply: (VetKDPublicKeyReply,) = ic_cdk::api::call::call(
            candid::Principal::management_canister(),
            "vetkd_public_key",
            (request,),
        )
        .await?;

        Ok(reply.0.public_key)
    }
}
