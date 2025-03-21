use std::{convert::TryInto, ops::Range};

use candid::Principal;
use ic_stable_structures::storable::Blob;
use ic_vetkd_cdk_types::{AccessRights, ByteBuf, KeyName};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::convert::TryFrom;

pub fn reproducible_rng() -> ChaCha20Rng {
    let seed = rand::rng().random();
    println!("RNG seed: {seed:?}");
    ChaCha20Rng::from_seed(seed)
}

pub fn random_unique_memory_ids<R: Rng + CryptoRng>(rng: &mut R) -> (u8, [u8; 3]) {
    const MAX_MEMORY_ID: u8 = 254;
    let mut set = std::collections::HashSet::<u8>::new();
    let mut unique_memory_ids = [0; 4];
    while set.len() != unique_memory_ids.len() {
        set.insert(rng.random_range(0..=MAX_MEMORY_ID));
    }
    unique_memory_ids = set.into_iter().collect::<Vec<u8>>().try_into().unwrap();

    let memory_id_encrypted_maps = unique_memory_ids[0];
    let memory_ids_key_manager = [
        unique_memory_ids[1],
        unique_memory_ids[2],
        unique_memory_ids[3],
    ];
    (memory_id_encrypted_maps, memory_ids_key_manager)
}

pub fn random_name<R: Rng + CryptoRng>(rng: &mut R) -> KeyName {
    random_blob(rng)
}

pub fn random_blob<R: Rng + CryptoRng, const N: usize>(rng: &mut R) -> Blob<N> {
    let mut result = [0u8; N];
    rng.fill_bytes(&mut result);
    Blob::try_from(result.as_slice()).unwrap()
}

pub fn random_bytebuf<R: Rng + CryptoRng>(rng: &mut R, range: Range<usize>) -> ByteBuf {
    let length: usize = rng.random_range(range);
    let mut result: Vec<u8> = vec![0; length];
    rng.fill_bytes(&mut result);
    ByteBuf::from(result)
}

pub fn random_key<R: Rng + CryptoRng>(rng: &mut R) -> Blob<32> {
    random_blob(rng)
}

pub fn random_self_authenticating_principal<R: Rng + CryptoRng>(rng: &mut R) -> Principal {
    let mut fake_public_key = vec![0u8; 32];
    rng.fill_bytes(&mut fake_public_key);
    Principal::self_authenticating::<&[u8]>(fake_public_key.as_ref())
}

pub fn random_access_rights<R: Rng + CryptoRng>(rng: &mut R) -> AccessRights {
    loop {
        if let Some(ar) = AccessRights::from_repr(rng.random()) {
            return ar;
        }
    }
}

pub fn random_utf8_string<R: Rng + CryptoRng>(rng: &mut R, len: usize) -> String {
    rng.sample_iter::<char, _>(&rand::distr::StandardUniform)
        .take(len)
        .collect()
}
