//! See [`KeyManager`] for the main documentation.

use crate::types::{AccessControl, ByteBuf, KeyManagerConfig, KeyName, TransportKey};
use candid::Principal;
use ic_cdk::api::management_canister::main::CanisterId;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use std::future::Future;
use std::str::FromStr;

use crate::vetkd_api_types::{
    VetKDDeriveKeyReply, VetKDDeriveKeyRequest, VetKDKeyId, VetKDPublicKeyReply,
    VetKDPublicKeyRequest,
};

const VETKD_SYSTEM_API_CANISTER_ID: &str = "aaaaa-aa";

pub type VetKeyVerificationKey = ByteBuf;
pub type VetKey = ByteBuf;
pub type Owner = Principal;
pub type Caller = Principal;
pub type KeyId = (Owner, KeyName);

type Memory = VirtualMemory<DefaultMemoryImpl>;

/// The **KeyManager** backend is a support library for **vetKeys**.
///
/// **vetKeys** is a feature of the Internet Computer (ICP) that enables the derivation of **encrypted cryptographic keys**. This library simplifies the process of key retrieval, encryption, and controlled sharing, ensuring secure and efficient key management for canisters and users.
///
/// For an introduction to **vetKeys**, refer to the [vetKeys Overview](https://internetcomputer.org/docs/building-apps/network-features/encryption/vetkeys).
///
/// IMPORTANT:
/// These support libraries are under active development and are subject to change. Access to the repositories has been opened to allow for early feedback. Check back regularly for updates.
/// Please share your feedback on the [developer forum](https://forum.dfinity.org/t/threshold-key-derivation-privacy-on-the-ic/16560/179).
///
/// ## Core Features
///
/// The **KeyManager** support library provides the following core functionalities:
///
/// - **Request an Encrypted Key:** Users can derive any number of **encrypted cryptographic keys**, secured using a user-provided **public transport key**. Each vetKey is associated with a unique **key id**.
/// - **Manage vetKey Sharing:** A user can **share their vetKeys** with other users while controlling access rights.
/// - **Access Control Management:** Users can define and enforce **fine-grained permissions** (read, write, manage) for each vetKey.
/// - **Uses Stable Storage:** The library persists key access information using **StableBTreeMap**, ensuring reliability across canister upgrades.
///
/// ## KeyManager Architecture
///
/// The **KeyManager** consists of two primary components:
///
/// 1. **Access Control Map** (`access_control`): Maps `(Caller, KeyId)` to `T`, defining permissions for each user.
/// 2. **Shared Keys Map** (`shared_keys`): Tracks which users have access to shared vetKeys.
///
/// ## Example Use Case
///
/// 1. **User A** requests a vetKey from KeyManager.
/// 2. KeyManager verifies permissions and derives an **encrypted cryptographic key**.
/// 3. **User A** securely shares access with **User B** using `set_user_rights`.
/// 4. **User B** retrieves the key securely via `get_encrypted_vetkey`.
///
/// ## Security Considerations
///
/// - vetKeys are derived **on demand** and constructed from encrypted vetKey shares.
/// - Only authorized users can access shared vetKeys.
/// - Stable storage ensures vetKeys persist across canister upgrades.
/// - Access control logic ensures only authorized users retrieve vetKeys or modify access rights.
///
/// ## Summary
/// [`KeyManager`] simplifies the usage of **vetKeys** on the ICP, providing a secure and efficient mechanism for **cryptographic key derivation, sharing, and management**.
pub struct KeyManager<T: AccessControl> {
    pub config: StableCell<KeyManagerConfig, Memory>,
    pub access_control: StableBTreeMap<(Principal, KeyId), T, Memory>,
    pub shared_keys: StableBTreeMap<(KeyId, Principal), (), Memory>,
}

impl<T: AccessControl> KeyManager<T> {
    /// Initializes the KeyManager with stable storage.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ic_cdk::init;
    /// use ic_stable_structures::{
    ///     memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    ///     DefaultMemoryImpl,
    /// };
    /// use ic_vetkeys::types::AccessRights;
    /// use ic_vetkeys::key_manager::KeyManager;
    /// use ic_vetkeys::vetkd_api_types::{VetKDCurve, VetKDKeyId};
    /// use std::cell::RefCell;
    ///
    /// type Memory = VirtualMemory<DefaultMemoryImpl>;
    ///
    /// thread_local! {
    ///     static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
    ///         RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    ///     static KEY_MANAGER: RefCell<Option<KeyManager<AccessRights>>> = const { RefCell::new(None) };
    /// }
    ///
    /// #[init]
    /// fn init(key_name: String) {
    ///     let key_id = VetKDKeyId {
    ///         curve: VetKDCurve::Bls12_381_G2,
    ///         name: key_name,
    ///     };
    ///     KEY_MANAGER.with_borrow_mut(|km| {
    ///         km.replace(KeyManager::init(
    ///             "key_manager_dapp",
    ///             key_id,
    ///             id_to_memory(0),
    ///             id_to_memory(1),
    ///             id_to_memory(2),
    ///         ))
    ///     });
    /// }
    ///
    /// fn id_to_memory(id: u8) -> Memory {
    ///     MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(id)))
    /// }
    /// ```
    pub fn init(
        domain_separator: &str,
        key_id: VetKDKeyId,
        memory_key_manager_config: Memory,
        memory_access_control: Memory,
        memory_shared_keys: Memory,
    ) -> Self {
        let config = StableCell::init(
            memory_key_manager_config,
            KeyManagerConfig {
                domain_separator: domain_separator.to_string(),
                key_id: key_id.clone(),
            },
        )
        .expect("failed to initialize key manager config");
        KeyManager {
            config,
            access_control: StableBTreeMap::init(memory_access_control),
            shared_keys: StableBTreeMap::init(memory_shared_keys),
        }
    }

    /// Retrieves all vetKey IDs shared with the given caller.
    /// This method returns a list of all vetKeys that the caller has access to.
    pub fn get_accessible_shared_key_ids(&self, caller: Principal) -> Vec<KeyId> {
        self.access_control
            .range((caller, (Principal::management_canister(), Blob::default()))..)
            .take_while(|((p, _), _)| p == &caller)
            .map(|((_, key_id), _)| key_id)
            .collect()
    }

    /// Retrieves a list of users with whom a given vetKey has been shared, along with their access rights.
    /// The caller must have appropriate permissions to view this information.
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

    /// Retrieves the vetKD verification key for this canister.
    /// This key is used to verify the authenticity of derived vetKeys.
    pub fn get_vetkey_verification_key(
        &self,
    ) -> impl Future<Output = VetKeyVerificationKey> + Send + Sync {
        use futures::future::FutureExt;

        let request = VetKDPublicKeyRequest {
            canister_id: None,
            context: self.config.get().domain_separator.to_bytes().to_vec(),
            key_id: self.config.get().key_id.clone(),
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

    /// Retrieves an encrypted vetKey for caller and key id.
    /// The vetKey is secured using the provided transport key and can only be accessed by authorized users.
    /// Returns an error if the caller is not authorized to access the vetKey.
    pub fn get_encrypted_vetkey(
        &self,
        caller: Principal,
        key_id: KeyId,
        transport_key: TransportKey,
    ) -> Result<impl Future<Output = VetKey> + Send + Sync, String> {
        use futures::future::FutureExt;

        self.ensure_user_can_read(caller, key_id)?;

        let request = VetKDDeriveKeyRequest {
            input: key_id_to_vetkd_input(key_id.0, key_id.1.as_ref()),
            context: self.config.get().domain_separator.to_bytes().to_vec(),
            key_id: self.config.get().key_id.clone(),
            transport_public_key: transport_key.into(),
        };

        let future = ic_cdk::api::call::call_with_payment128::<_, (VetKDDeriveKeyReply,)>(
            vetkd_system_api_canister_id(),
            "vetkd_derive_key",
            (request,),
            26_153_846_153,
        );

        Ok(future.map(|call_result| {
            let (reply,) = call_result.expect("call to vetkd_derive_key failed");
            VetKey::from(reply.encrypted_key)
        }))
    }

    /// Retrieves the access rights a given user has to a specific vetKey.
    /// The caller must have appropriate permissions to view this information.
    pub fn get_user_rights(
        &self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<T>, String> {
        self.ensure_user_can_get_user_rights(caller, key_id)?;
        Ok(self.ensure_user_can_read(user, key_id).ok())
    }

    /// Grants or modifies access rights for a user to a given vetKey.
    /// Only the vetKey owner or a user with management rights can perform this action.
    /// The vetKey owner cannot change their own rights.
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

    /// Revokes a user's access to a shared vetKey.
    /// The vetKey owner cannot remove their own access.
    /// Only the vetKey owner or a user with management rights can perform this action.
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

    /// Ensures that a user has read access to a vetKey before proceeding.
    /// Returns an error if the user is not authorized.
    pub fn ensure_user_can_read(&self, user: Principal, key_id: KeyId) -> Result<T, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(T::owner_rights());
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        match has_shared_access {
            Some(access_rights) if access_rights.can_read() => Ok(access_rights),
            _ => Err("unauthorized".to_string()),
        }
    }

    /// Ensures that a user has write access to a vetKey before proceeding.
    /// Returns an error if the user is not authorized.
    pub fn ensure_user_can_write(&self, user: Principal, key_id: KeyId) -> Result<T, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(T::owner_rights());
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        match has_shared_access {
            Some(access_rights) if access_rights.can_write() => Ok(access_rights),
            _ => Err("unauthorized".to_string()),
        }
    }

    /// Ensures that a user has permission to view user rights for a vetKey.
    /// Returns an error if the user is not authorized.
    pub fn ensure_user_can_get_user_rights(
        &self,
        user: Principal,
        key_id: KeyId,
    ) -> Result<T, String> {
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

    /// Ensures that a user has management access to a vetKey before proceeding.
    /// Returns an error if the user is not authorized.
    pub fn ensure_user_can_set_user_rights(
        &self,
        user: Principal,
        key_id: KeyId,
    ) -> Result<T, String> {
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

fn vetkd_system_api_canister_id() -> CanisterId {
    CanisterId::from_str(VETKD_SYSTEM_API_CANISTER_ID).expect("failed to create canister ID")
}

pub fn key_id_to_vetkd_input(principal: Principal, key_name: &[u8]) -> Vec<u8> {
    let mut vetkd_input = Vec::with_capacity(principal.as_slice().len() + 1 + key_name.len());
    vetkd_input.push(principal.as_slice().len() as u8);
    vetkd_input.extend(principal.as_slice());
    vetkd_input.extend(key_name);
    vetkd_input
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
