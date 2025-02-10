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
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, Storable};
use ic_vetkd_cdk_types::{AccessRights, ByteBuf, KeyName, MemoryInitializationError, TransportKey};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Debug;
use std::str::FromStr;

pub mod vetkd_api_types;
use vetkd_api_types::{
    VetKDCurve, VetKDEncryptedKeyReply, VetKDEncryptedKeyRequest, VetKDKeyId, VetKDPublicKeyReply,
    VetKDPublicKeyRequest,
};

const VETKD_SYSTEM_API_CANISTER_ID: &str = "aaaaa-aa";
const KEY_MANAGER_DERIVATION_PATH: &[u8] = b"key_manager";

// On a high level,
// `ENCRYPTED_MAPS[MapName][MapKey] = EncryptedMapValue`, e.g.
// `ENCRYPTED_MAPS[b"alex's map".into()][b"github API token".into()] = b"secret-api-token-to-be-encrypted".into()`.

pub type VetKeyVerificationKey = ByteBuf;
pub type VetKey = ByteBuf;
pub type Creator = Principal;
pub type Caller = Principal;
pub type KeyId = (Caller, KeyName);

thread_local! {
    static ENCRYPTED_MAPS: RefCell<Option<KeyManager>> = const { RefCell::new(None) };
    #[cfg(feature = "expose-testing-api")]
    static VETKD_TESTING_CANISTER_ID: RefCell<Option<Principal>> = const { RefCell::new(None) };
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

pub struct KeyManager {
    pub access_control: StableBTreeMap<(Caller, KeyId), AccessRights, Memory>,
    pub shared_keys: StableBTreeMap<(KeyId, Caller), (), Memory>,
}

impl KeyManager {
    pub fn try_init(memory_0: Memory, memory_1: Memory) -> Result<(), MemoryInitializationError> {
        if ENCRYPTED_MAPS.with(|cell| cell.borrow().is_some()) {
            return Err(MemoryInitializationError::AlreadyInitialized);
        }

        let access_control = StableBTreeMap::init(memory_0);
        let map_existance = StableBTreeMap::init(memory_1);

        ENCRYPTED_MAPS.with(|cell| {
            *cell.borrow_mut() = Some(KeyManager {
                access_control,
                shared_keys: map_existance,
            });
        });

        Ok(())
    }

    pub fn with_borrow<R, E: Debug>(
        f: impl FnOnce(&KeyManager) -> Result<R, E>,
    ) -> Result<R, String> {
        ENCRYPTED_MAPS.with_borrow(|cell| match cell.as_ref() {
            Some(db) => f(db).map_err(|e| format!("{e:?}")),
            None => Err("memory not initialized".to_string()),
        })
    }

    pub fn with_borrow_mut<R, E: Debug>(
        f: impl FnOnce(&mut KeyManager) -> Result<R, E>,
    ) -> Result<R, String> {
        ENCRYPTED_MAPS.with_borrow_mut(|cell| match cell.as_mut() {
            Some(db) => f(db).map_err(|e| format!("{e:?}")),
            None => Err("memory not initialized".to_string()),
        })
    }
}

pub fn get_accessible_shared_key_ids(caller: Principal) -> Vec<KeyId> {
    KeyManager::with_borrow(|km| {
        Ok::<_, ()>(
            km.access_control
                .range((caller, (Principal::management_canister(), Blob::default()))..)
                .take_while(|((p, _), _)| p == &caller)
                .map(|((_, key_id), _)| key_id)
                .collect(),
        )
    })
    .expect("cannot fail")
}

pub fn get_shared_user_access_for_key(
    caller: Principal,
    key_id: KeyId,
) -> Result<Vec<(Principal, AccessRights)>, String> {
    ensure_user_can_read(caller, key_id)?;

    let users: Vec<Principal> = KeyManager::with_borrow(|km| {
        Ok::<_, ()>(
            km.shared_keys
                .range((key_id, Principal::management_canister())..)
                .take_while(|((k, _), _)| k == &key_id)
                .map(|((_, user), _)| user)
                .collect(),
        )
    })
    .expect("cannot fail");

    users
        .into_iter()
        .map(|user| {
            get_user_rights(caller, key_id, user)
                .map(|opt_user_rights| (user, opt_user_rights.expect("always some access rights")))
        })
        .collect::<Result<Vec<_>, _>>()
}

pub async fn get_vetkey_verification_key() -> VetKeyVerificationKey {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![KEY_MANAGER_DERIVATION_PATH.to_vec()],
        key_id: bls12_381_test_key_1(),
    };

    let (response,): (VetKDPublicKeyReply,) = ic_cdk::api::call::call(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("call to vetkd_public_key failed");

    VetKeyVerificationKey::from(response.public_key)
}

pub async fn get_encrypted_vetkey(
    caller: Principal,
    key_id: KeyId,
    transport_key: TransportKey,
) -> Result<VetKey, String> {
    ensure_user_can_read(caller, key_id)?;

    let derivation_id = key_id
        .0
        .as_slice()
        .iter()
        .chain(key_id.1.as_ref().iter())
        .cloned()
        .collect();

    let request = VetKDEncryptedKeyRequest {
        derivation_id,
        public_key_derivation_path: vec![KEY_MANAGER_DERIVATION_PATH.to_vec()],
        key_id: bls12_381_test_key_1(),
        encryption_public_key: transport_key.into(),
    };

    let (reply,): (VetKDEncryptedKeyReply,) = ic_cdk::api::call::call(
        vetkd_system_api_canister_id(),
        "vetkd_encrypted_key",
        (request,),
    )
    .await
    .expect("call to vetkd_encrypted_key failed");

    Ok(VetKey::from(reply.encrypted_key))
}

pub fn get_user_rights(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
) -> Result<Option<AccessRights>, String> {
    ensure_user_can_read(caller, key_id)?;
    Ok(ensure_user_can_read(user, key_id).ok())
}

pub fn set_user_rights(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
    access_rights: AccessRights,
) -> Result<Option<AccessRights>, String> {
    ensure_user_can_manage(caller, key_id)?;

    if caller == key_id.0 && caller == user {
        return Err("cannot change key owner's user rights".to_string());
    }
    KeyManager::with_borrow_mut(|km| {
        km.shared_keys.insert((key_id, user), ());
        Ok::<_, ()>(km.access_control.insert((user, key_id), access_rights))
    })
}

pub fn remove_user(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
) -> Result<Option<AccessRights>, String> {
    ensure_user_can_manage(caller, key_id)?;

    if caller == user && caller == key_id.0 {
        return Err("cannot remove key owner".to_string());
    }

    KeyManager::with_borrow_mut(|km| Ok::<_, ()>(km.access_control.remove(&(user, key_id))))
}

pub fn is_key_shared(key_id: KeyId) -> Result<bool, String> {
    KeyManager::with_borrow(|km| {
        Ok::<bool, ()>(
            km.shared_keys
                .range(&(key_id, Principal::management_canister())..)
                .take_while(|((k, _), _)| k == &key_id)
                .next()
                .is_some(),
        )
    })
}

fn ensure_user_can_read(user: Principal, key_id: KeyId) -> Result<AccessRights, String> {
    let is_owner = user == key_id.0;
    if is_owner {
        return Ok(AccessRights::ReadWriteManage);
    }

    let has_shared_access =
        KeyManager::with_borrow(|km| Ok::<_, ()>(km.access_control.get(&(user, key_id)))).unwrap();
    if let Some(access_rights) = has_shared_access {
        return Ok(access_rights);
    }

    Err(format!("{user} unauthorized"))
}

fn ensure_user_can_manage(user: Principal, key_id: KeyId) -> Result<AccessRights, String> {
    let is_owner = user == key_id.0;
    if is_owner {
        return Ok(AccessRights::ReadWriteManage);
    }

    let has_shared_access =
        KeyManager::with_borrow(|km| Ok::<_, ()>(km.access_control.get(&(user, key_id)))).unwrap();
    match has_shared_access {
        Some(access_rights) if access_rights == AccessRights::ReadWriteManage => Ok(access_rights),
        _ => Err(format!("{user} unauthorized")),
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
