//! # VetKD CDK - EncryptedMaps
//!
//! ## Overview
//!
//! **EncryptedMaps** is a support library built on top of **KeyManager**, designed to facilitate
//! secure, encrypted data sharing between users on the Internet Computer (ICP) using the **vetKeys** feature.
//! It allows developers to store encrypted key-value pairs (**maps**) securely and to manage fine-grained user access.
//!
//! ## Core Features
//!
//! - **Encrypted Key-Value Storage:** Securely store and manage encrypted key-value pairs within named maps.
//! - **User-Specific Map Access:** Control precisely which users can read or modify entries in an encrypted map.
//! - **Integrated Access Control:** Leverages the **KeyManager** library to manage and enforce user permissions.
//! - **Stable Storage:** Utilizes **StableBTreeMap** for reliable, persistent storage across canister upgrades.
//!
//! ## EncryptedMaps Architecture
//!
//! The **EncryptedMaps** library contains:
//!
//! - **Encrypted Values Storage:** Maps `(KeyId, MapKey)` to `EncryptedMapValue`, securely storing encrypted data.
//! - **KeyManager Integration:** Uses **KeyManager** to handle user permissions, ensuring authorized access to maps.

use candid::Principal;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;
use std::future::Future;

use ic_vetkd_cdk_key_manager::KeyId;
use ic_vetkd_cdk_types::{AccessRights, ByteBuf, EncryptedMapValue, MapKey, TransportKey};

// On a high level,
// `ENCRYPTED_MAPS[MapName][MapKey] = EncryptedMapValue`, e.g.
// `ENCRYPTED_MAPS[b"alex's map".into()][b"github API token".into()] = b"secret-api-token-to-be-encrypted".into()`.

pub type VetKeyVerificationKey = ByteBuf;
pub type VetKey = ByteBuf;

thread_local! {
    static ENCRYPTED_MAPS: RefCell<Option<EncryptedMaps>> = const { RefCell::new(None) };
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

pub struct EncryptedMaps {
    pub key_manager: ic_vetkd_cdk_key_manager::KeyManager,
    pub mapkey_vals: StableBTreeMap<(KeyId, MapKey), EncryptedMapValue, Memory>,
}

impl EncryptedMaps {
    /// Initializes the EncryptedMaps and the underlying KeyManager.
    /// Must be called before any other EncryptedMaps operations.
    pub fn init(
        domain_separator: &str,
        memory_domain_separator: Memory,
        memory_access_control: Memory,
        memory_shared_keys: Memory,
        memory_encrypted_maps: Memory,
    ) -> Self {
        let key_manager = ic_vetkd_cdk_key_manager::KeyManager::init(
            domain_separator,
            memory_domain_separator,
            memory_access_control,
            memory_shared_keys,
        );

        let mapkey_vals = StableBTreeMap::init(memory_encrypted_maps);

        Self {
            key_manager,
            mapkey_vals,
        }
    }

    /// Lists all map names shared with the caller.
    pub fn get_accessible_shared_map_names(&self, caller: Principal) -> Vec<KeyId> {
        self.key_manager.get_accessible_shared_key_ids(caller)
    }

    /// Retrieves all users and their access rights for a specific map.
    pub fn get_shared_user_access_for_map(
        &self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<(Principal, AccessRights)>, String> {
        self.key_manager
            .get_shared_user_access_for_key(caller, key_id)
    }

    /// Removes all values from a map if the caller has sufficient rights.
    /// Returns the removed keys.
    pub fn remove_map_values(
        &mut self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<MapKey>, String> {
        match self.key_manager.get_user_rights(caller, key_id, caller)? {
            Some(AccessRights::ReadWrite) | Some(AccessRights::ReadWriteManage) => Ok(()),
            Some(AccessRights::Read) | None => Err("unauthorized user".to_string()),
        }?;

        let keys: Vec<_> = self
            .mapkey_vals
            .range((key_id, Blob::default())..)
            .take_while(|((k, _), _)| k == &key_id)
            .map(|((_name, key), _value)| key)
            .collect();

        for key in keys.iter() {
            self.mapkey_vals.remove(&(key_id, *key));
        }

        Ok(keys)
    }

    /// Retrieves all encrypted key-value pairs from a map.
    pub fn get_encrypted_values_for_map(
        &self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<(MapKey, EncryptedMapValue)>, String> {
        match self.key_manager.get_user_rights(caller, key_id, caller)? {
            Some(_) => Ok(()),
            None => Err("unauthorized user".to_string()),
        }?;

        Ok(self
            .mapkey_vals
            .range((key_id, Blob::default())..)
            .take_while(|((k, _), _)| k == &key_id)
            .map(|((_, k), v)| (k, v))
            .collect())
    }

    /// Retrieves a specific encrypted value from a map.
    pub fn get_encrypted_value(
        &self,
        caller: Principal,
        key_id: KeyId,
        key: MapKey,
    ) -> Result<Option<EncryptedMapValue>, String> {
        match self.key_manager.get_user_rights(caller, key_id, caller)? {
            Some(_) => Ok(()),
            None => Err("unauthorized user".to_string()),
        }?;

        Ok(self.mapkey_vals.get(&(key_id, key)))
    }

    /// Retrieves the non-empty map names owned by the caller.
    pub fn get_owned_non_empty_map_names(
        &self,
        caller: Principal,
    ) -> Result<Vec<ic_vetkd_cdk_types::MapName>, String> {
        let map_names: std::collections::HashSet<Vec<u8>> = self
            .mapkey_vals
            .keys_range(((caller, Blob::default()), Blob::default())..)
            .take_while(|((principal, _map_name), _key_name)| principal == &caller)
            .map(|((_principal, map_name), _key_name)| map_name.as_slice().to_vec())
            .collect();
        Ok(map_names
            .into_iter()
            .map(|map_name| Blob::<32>::try_from(map_name.as_slice()).unwrap())
            .collect())
    }

    /// Inserts or updates an encrypted value in a map.
    pub fn insert_encrypted_value(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        key: MapKey,
        encrypted_value: EncryptedMapValue,
    ) -> Result<Option<EncryptedMapValue>, String> {
        match self.key_manager.get_user_rights(caller, key_id, caller)? {
            Some(AccessRights::ReadWrite) | Some(AccessRights::ReadWriteManage) => Ok(()),
            Some(AccessRights::Read) | None => Err("unauthorized user".to_string()),
        }?;

        Ok(self.mapkey_vals.insert((key_id, key), encrypted_value))
    }

    /// Removes an encrypted value from a map.
    pub fn remove_encrypted_value(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        key: MapKey,
    ) -> Result<Option<EncryptedMapValue>, String> {
        match self.key_manager.get_user_rights(caller, key_id, caller)? {
            Some(AccessRights::ReadWrite) | Some(AccessRights::ReadWriteManage) => Ok(()),
            Some(AccessRights::Read) | None => Err("unauthorized user".to_string()),
        }?;

        Ok(self.mapkey_vals.remove(&(key_id, key)))
    }

    /// Retrieves the public verification key from KeyManager.
    pub fn get_vetkey_verification_key(
        &self,
    ) -> impl Future<Output = VetKeyVerificationKey> + Send + Sync {
        self.key_manager.get_vetkey_verification_key()
    }

    /// Retrieves an encrypted vetkey for the caller.
    pub fn get_encrypted_vetkey(
        &self,
        caller: Principal,
        key_id: KeyId,
        transport_key: TransportKey,
    ) -> Result<impl Future<Output = VetKey> + Send + Sync, String> {
        self.key_manager
            .get_encrypted_vetkey(caller, key_id, transport_key)
    }

    /// Retrieves access rights for a user from KeyManager.
    pub fn get_user_rights(
        &self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<AccessRights>, String> {
        self.key_manager.get_user_rights(caller, key_id, user)
    }

    /// Sets or updates access rights for a user to a map.
    pub fn set_user_rights(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
        access_rights: AccessRights,
    ) -> Result<Option<AccessRights>, String> {
        self.key_manager
            .set_user_rights(caller, key_id, user, access_rights)
    }

    /// Removes access rights for a user from a map.
    pub fn remove_user(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<AccessRights>, String> {
        self.key_manager.remove_user(caller, key_id, user)
    }
}

#[cfg(feature = "expose-testing-api")]
pub fn set_vetkd_testing_canister_id(canister_id: Principal) {
    ic_vetkd_cdk_key_manager::set_vetkd_testing_canister_id(canister_id);
}
