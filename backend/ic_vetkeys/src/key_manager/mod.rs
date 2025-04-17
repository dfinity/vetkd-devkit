//! # VetKD Backend - KeyManager
//!
//! ## Overview
//!
//! The **KeyManager** is a support library for **vetKeys**, an Internet Computer (ICP) feature
//! that enables the derivation of **encrypted cryptographic keys**. This library simplifies
//! the process of key retrieval, encryption, and controlled sharing, ensuring secure and
//! efficient key management for canisters and users.
//!
//! ## Core Features
//!
//! - **Request an Encrypted Key:** Users can derive any number of **encrypted cryptographic keys**,
//!   secured using a **transport key**. Each key is associated with a unique **key id**.
//! - **Manage Key Sharing:** A user can **share their keys** with other users while controlling access rights.
//! - **Access Control Management:** Users can define and enforce **fine-grained permissions**
//!   (read, write, manage) for each key.
//! - **Uses Stable Storage:** The library persists key access information using **StableBTreeMap**,
//!   ensuring reliability across canister upgrades.
//!
//! ## KeyManager Architecture
//!
//! The **KeyManager** consists of two primary components:
//!
//! 1. **Access Control Map** (`access_control`): Maps `(Caller, KeyId)` to `T`, defining permissions for each user.
//! 2. **Shared Keys Map** (`shared_keys`): Tracks which users have access to shared keys.

use crate::types::{AccessControl, ByteBuf, KeyName, TransportKey};
use candid::Principal;
use ic_cdk::api::management_canister::main::CanisterId;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use std::future::Future;
use std::str::FromStr;

#[cfg(feature = "expose-testing-api")]
use std::cell::RefCell;

use crate::vetkd_api_types::{
    VetKDCurve, VetKDEncryptedKeyReply, VetKDEncryptedKeyRequest, VetKDKeyId, VetKDPublicKeyReply,
    VetKDPublicKeyRequest,
};

const VETKD_SYSTEM_API_CANISTER_ID: &str = "aaaaa-aa";

// On a high level,
// `ENCRYPTED_MAPS[MapName][MapKey] = EncryptedMapValue`, e.g.
// `ENCRYPTED_MAPS[b"alex's map".into()][b"github API token".into()] = b"secret-api-token-to-be-encrypted".into()`.

pub type VetKeyVerificationKey = ByteBuf;
pub type VetKey = ByteBuf;
pub type Creator = Principal;
pub type Caller = Principal;
pub type KeyId = (Caller, KeyName);

#[cfg(feature = "expose-testing-api")]
thread_local! {
    static VETKD_TESTING_CANISTER_ID: RefCell<Option<Principal>> = const { RefCell::new(None) };
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

pub struct KeyManager<T: AccessControl> {
    pub domain_separator: StableCell<String, Memory>,
    pub access_control: StableBTreeMap<(Caller, KeyId), T, Memory>,
    pub shared_keys: StableBTreeMap<(KeyId, Caller), (), Memory>,
}

impl<T: AccessControl> KeyManager<T> {
    /// Initializes the KeyManager with stable storage.
    /// This function must be called exactly once before any other KeyManager operation can be invoked.
    pub fn init(
        domain_separator: &str,
        memory_domain_separator: Memory,
        memory_access_control: Memory,
        memory_shared_keys: Memory,
    ) -> Self {
        let domain_separator =
            StableCell::init(memory_domain_separator, domain_separator.to_string())
                .expect("failed to initialize domain separator");
        KeyManager {
            domain_separator,
            access_control: StableBTreeMap::init(memory_access_control),
            shared_keys: StableBTreeMap::init(memory_shared_keys),
        }
    }

    /// Retrieves all key IDs shared with the given caller.
    pub fn get_accessible_shared_key_ids(&self, caller: Principal) -> Vec<KeyId> {
        self.access_control
            .range((caller, (Principal::management_canister(), Blob::default()))..)
            .take_while(|((p, _), _)| p == &caller)
            .map(|((_, key_id), _)| key_id)
            .collect()
    }

    /// Retrieves a list of users with whom a given key has been shared, along with their access rights.
    pub fn get_shared_user_access_for_key(
        &self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<(Principal, T)>, String> {
        self.ensure_user_can_get_user_rights(caller, key_id)?;

        let users: Vec<_> = self
            .shared_keys
            .range((key_id, Principal::management_canister())..)
            .take_while(|((k, _), _)| k == &key_id)
            .map(|((_, user), _)| user)
            .collect();

        users
            .into_iter()
            .map(|user| {
                self.get_user_rights(caller, key_id, user)
                    .map(|opt_user_rights| {
                        (user, opt_user_rights.expect("always some access rights"))
                    })
            })
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn get_vetkey_verification_key(
        &self,
    ) -> impl Future<Output = VetKeyVerificationKey> + Send + Sync {
        use futures::future::FutureExt;

        let request = VetKDPublicKeyRequest {
            canister_id: None,
            derivation_path: vec![self.domain_separator.get().to_bytes().to_vec()],
            key_id: bls12_381_test_key_1(),
        };

        let future = ic_cdk::api::call::call::<_, (VetKDPublicKeyReply,)>(
            vetkd_system_api_canister_id(),
            "vetkd_public_key",
            (request,),
        );

        future.map(|call_result| {
            let (reply,) = call_result.expect("call to vetkd_public_key failed");
            VetKeyVerificationKey::from(reply.public_key)
        })
    }

    /// Retrieves an encrypted vetkey for caller and key id.
    pub fn get_encrypted_vetkey(
        &self,
        caller: Principal,
        key_id: KeyId,
        transport_key: TransportKey,
    ) -> Result<impl Future<Output = VetKey> + Send + Sync, String> {
        use futures::future::FutureExt;

        self.ensure_user_can_read(caller, key_id)?;

        let request = VetKDEncryptedKeyRequest {
            derivation_id: key_id_to_derivation_id(key_id.0, key_id.1.as_ref()),
            public_key_derivation_path: vec![self.domain_separator.get().to_bytes().to_vec()],
            key_id: bls12_381_test_key_1(),
            encryption_public_key: transport_key.into(),
        };

        let future = ic_cdk::api::call::call::<_, (VetKDEncryptedKeyReply,)>(
            vetkd_system_api_canister_id(),
            "vetkd_encrypted_key",
            (request,),
        );

        Ok(future.map(|call_result| {
            let (reply,) = call_result.expect("call to vetkd_encrypted_key failed");
            VetKey::from(reply.encrypted_key)
        }))
    }

    /// Retrieves the access rights a given user has to a specific key.
    pub fn get_user_rights(
        &self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<T>, String> {
        self.ensure_user_can_read(caller, key_id)?;
        Ok(self.ensure_user_can_read(user, key_id).ok())
    }

    /// Grants or modifies access rights for a user to a given key.
    /// Only the key owner or a user with management rights can perform this action.
    pub fn set_user_rights(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
        access_rights: T,
    ) -> Result<Option<T>, String> {
        self.ensure_user_can_set_user_rights(caller, key_id)?;

        if caller == key_id.0 && caller == user {
            return Err("cannot change key owner's user rights".to_string());
        }
        self.shared_keys.insert((key_id, user), ());
        Ok(self.access_control.insert((user, key_id), access_rights))
    }

    /// Revokes a user's access to a shared key.
    /// The key owner cannot remove their own access.
    pub fn remove_user(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<T>, String> {
        self.ensure_user_can_set_user_rights(caller, key_id)?;

        if caller == user && caller == key_id.0 {
            return Err("cannot remove key owner".to_string());
        }

        self.shared_keys.remove(&(key_id, user));
        Ok(self.access_control.remove(&(user, key_id)))
    }

    /// Ensures that a user has read access to a key before proceeding.
    /// Returns an error if the user is not authorized.
    fn ensure_user_can_read(&self, user: Principal, key_id: KeyId) -> Result<T, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(T::owner_rights());
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        if let Some(access_rights) = has_shared_access {
            return Ok(access_rights);
        }

        Err("unauthorized".to_string())
    }

    fn ensure_user_can_get_user_rights(&self, user: Principal, key_id: KeyId) -> Result<T, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(T::owner_rights());
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        match has_shared_access {
            Some(access_rights) if access_rights.can_get_user_rights() => Ok(access_rights),
            _ => Err("unauthorized".to_string()),
        }
    }

    /// Ensures that a user has management access to a key before proceeding.
    /// Returns an error if the user is not authorized.
    fn ensure_user_can_set_user_rights(&self, user: Principal, key_id: KeyId) -> Result<T, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(T::owner_rights());
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        match has_shared_access {
            Some(access_rights) if access_rights.can_set_user_rights() => Ok(access_rights),
            _ => Err("unauthorized".to_string()),
        }
    }
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
        if let Some(canister_id) = VETKD_TESTING_CANISTER_ID.with(|cell| cell.borrow().clone()) {
            return canister_id;
        }
    }
    CanisterId::from_str(VETKD_SYSTEM_API_CANISTER_ID).expect("failed to create canister ID")
}

pub fn key_id_to_derivation_id(principal: Principal, key_name: &[u8]) -> Vec<u8> {
    let mut derivation_id = Vec::with_capacity(principal.as_slice().len() + 1 + key_name.len());
    derivation_id.push(principal.as_slice().len() as u8);
    derivation_id.extend(principal.as_slice());
    derivation_id.extend(key_name);
    derivation_id
}

#[cfg(feature = "expose-testing-api")]
pub fn set_vetkd_testing_canister_id(canister_id: Principal) {
    VETKD_TESTING_CANISTER_ID.with(|cell| {
        *cell.borrow_mut() = Some(canister_id);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_vetkd_canister_id_should_be_management_canister_id() {
        assert_eq!(
            vetkd_system_api_canister_id(),
            CanisterId::from_str("aaaaa-aa").unwrap()
        );
    }
}
