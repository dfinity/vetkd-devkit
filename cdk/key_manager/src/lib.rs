//! Types for V1 encrypted maps. V1 uses one vetkey per map that each authorized
//! user can access. The encryption keys for the map-keys are derived from the
//! vetkey hash.
//!
//! APIs for V1 encrypted maps. V1 uses one vetkey per map that each authorized
//! user can access. The encryption keys for the map-keys are derived from the
//! vetkey hash.

use candid::Principal;
use ic_cdk::api::management_canister::main::CanisterId;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::{Blob, Bound};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use ic_vetkd_cdk_types::{AccessRights, ByteBuf, KeyName, TransportKey};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::borrow::Cow;
use std::future::Future;
use std::str::FromStr;

#[cfg(feature = "expose-testing-api")]
use std::cell::RefCell;

pub mod vetkd_api_types;
use vetkd_api_types::{
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

pub struct KeyManager {
    pub domain_separator: StableCell<String, Memory>,
    pub access_control: StableBTreeMap<(Caller, KeyId), AccessRights, Memory>,
    pub shared_keys: StableBTreeMap<(KeyId, Caller), (), Memory>,
}

impl KeyManager {
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

    pub fn get_accessible_shared_key_ids(&self, caller: Principal) -> Vec<KeyId> {
        self.access_control
            .range((caller, (Principal::management_canister(), Blob::default()))..)
            .take_while(|((p, _), _)| p == &caller)
            .map(|((_, key_id), _)| key_id)
            .collect()
    }

    pub fn get_shared_user_access_for_key(
        &self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<(Principal, AccessRights)>, String> {
        self.ensure_user_can_read(caller, key_id)?;

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

    pub fn get_encrypted_vetkey(
        &self,
        caller: Principal,
        key_id: KeyId,
        transport_key: TransportKey,
    ) -> Result<impl Future<Output = VetKey> + Send + Sync, String> {
        use futures::future::FutureExt;

        self.ensure_user_can_read(caller, key_id)?;

        let derivation_id = key_id
            .0
            .as_slice()
            .iter()
            .chain(key_id.1.as_ref().iter())
            .cloned()
            .collect();

        let request = VetKDEncryptedKeyRequest {
            derivation_id,
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

    pub fn get_user_rights(
        &self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<AccessRights>, String> {
        self.ensure_user_can_read(caller, key_id)?;
        Ok(self.ensure_user_can_read(user, key_id).ok())
    }

    pub fn set_user_rights(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
        access_rights: AccessRights,
    ) -> Result<Option<AccessRights>, String> {
        self.ensure_user_can_manage(caller, key_id)?;

        if caller == key_id.0 && caller == user {
            return Err("cannot change key owner's user rights".to_string());
        }
        self.shared_keys.insert((key_id, user), ());
        Ok(self.access_control.insert((user, key_id), access_rights))
    }

    pub fn remove_user(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<AccessRights>, String> {
        self.ensure_user_can_manage(caller, key_id)?;

        if caller == user && caller == key_id.0 {
            return Err("cannot remove key owner".to_string());
        }

        self.shared_keys.remove(&(key_id, user));
        Ok(self.access_control.remove(&(user, key_id)))
    }

    pub fn is_key_shared(&self, key_id: KeyId) -> bool {
        self.shared_keys
            .range(&(key_id, Principal::management_canister())..)
            .take_while(|((k, _), _)| k == &key_id)
            .next()
            .is_some()
    }

    fn ensure_user_can_read(&self, user: Principal, key_id: KeyId) -> Result<AccessRights, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(AccessRights::ReadWriteManage);
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        if let Some(access_rights) = has_shared_access {
            return Ok(access_rights);
        }

        Err("unauthorized".to_string())
    }

    fn ensure_user_can_manage(
        &self,
        user: Principal,
        key_id: KeyId,
    ) -> Result<AccessRights, String> {
        let is_owner = user == key_id.0;
        if is_owner {
            return Ok(AccessRights::ReadWriteManage);
        }

        let has_shared_access = self.access_control.get(&(user, key_id));
        match has_shared_access {
            Some(access_rights) if access_rights == AccessRights::ReadWriteManage => {
                Ok(access_rights)
            }
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

#[serde_as]
#[derive(Serialize, Deserialize)]
struct StorableDerivationPath {
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    derivation_path: Vec<Vec<u8>>,
}

impl Storable for StorableDerivationPath {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(&self.derivation_path).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let derivation_path =
            serde_cbor::from_slice(bytes.as_ref()).expect("failed to deserialize");
        Self { derivation_path }
    }

    const BOUND: Bound = Bound::Unbounded;
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
