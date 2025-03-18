use std::{collections::BTreeMap, iter::FromIterator};

use assert_matches::assert_matches;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    DefaultMemoryImpl,
};
use ic_vetkd_cdk_test_utils::{
    random_access_rights, random_bytebuf, random_key, random_name,
    random_self_authenticating_principal, random_unique_memory_ids, random_utf8_string,
    reproducible_rng,
};
use rand::{CryptoRng, Rng};
use strum::IntoEnumIterator;

use ic_vetkd_cdk_encrypted_maps::EncryptedMaps;
use ic_vetkd_cdk_types::AccessRights;

#[test]
fn can_init_memory() {
    // prevent the compiler from optimizing away the function call
    std::hint::black_box(random_encrypted_maps(&mut reproducible_rng()));
}

#[test]
fn can_remove_map_values() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);
    let result = encrypted_maps.remove_map_values(caller, (caller, name));
    assert_eq!(result, Ok(vec![]));
}

#[test]
fn unauthorized_delete_map_values_fails() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let unauthorized = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let key = random_key(rng);
    let encrypted_value = random_bytebuf(rng, 0..2_000_000);
    let mut encrypted_maps = random_encrypted_maps(rng);

    encrypted_maps
        .insert_encrypted_value(caller, (caller, name.clone()), key, encrypted_value)
        .unwrap();
    let result = encrypted_maps.remove_map_values(unauthorized, (caller, name));
    assert_eq!(result, Err("unauthorized".to_string()));
}

#[test]
fn can_add_user_to_map() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let user_to_be_added = random_self_authenticating_principal(rng);
    let access_rights = random_access_rights(rng);
    assert_eq!(
        encrypted_maps.set_user_rights(
            caller,
            (caller, name.clone()),
            user_to_be_added,
            access_rights
        ),
        Ok(None)
    );
    assert_eq!(
        encrypted_maps.set_user_rights(caller, (caller, name), user_to_be_added, access_rights),
        Ok(Some(access_rights))
    );
}

#[test]
fn can_remove_user_from_map() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let user_to_be_added = random_self_authenticating_principal(rng);
    let access_rights = random_access_rights(rng);
    assert_eq!(
        encrypted_maps.set_user_rights(
            caller,
            (caller, name.clone()),
            user_to_be_added,
            access_rights,
        ),
        Ok(None)
    );
    assert_eq!(
        encrypted_maps.remove_user(caller, (caller, name), user_to_be_added,),
        Ok(Some(access_rights))
    );
}

#[test]
fn add_or_remove_user_by_unauthorized_fails() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let mut unauthorized_callers = vec![random_self_authenticating_principal(rng)];

    for access_rights in [AccessRights::Read, AccessRights::ReadWrite] {
        let user_to_be_added = random_self_authenticating_principal(rng);

        assert_matches!(
            encrypted_maps.set_user_rights(
                caller,
                (caller, name.clone()),
                user_to_be_added,
                access_rights,
            ),
            Ok(_)
        );

        unauthorized_callers.push(user_to_be_added);
    }

    for unauthorized_caller in unauthorized_callers {
        for target in [random_self_authenticating_principal(rng), caller] {
            assert_eq!(
                encrypted_maps.remove_user(unauthorized_caller, (caller, name.clone()), target),
                Err("unauthorized".to_string())
            );
            assert_eq!(
                encrypted_maps.set_user_rights(
                    unauthorized_caller,
                    (caller, name.clone()),
                    target,
                    AccessRights::Read,
                ),
                Err("unauthorized".to_string())
            );
        }
    }
}

#[test]
fn can_add_a_key_to_map() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let key = random_key(rng);
    let value = random_bytebuf(rng, 0..2_000_000);
    assert_eq!(
        encrypted_maps.insert_encrypted_value(caller, (caller, name), key, value),
        Ok(None)
    );
}

#[test]
fn add_a_key_to_map_by_unauthorized_fails() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let unauthorized_caller = random_self_authenticating_principal(rng);
    let key = random_key(rng);
    let value = random_bytebuf(rng, 0..2_000_000);
    assert_eq!(
        encrypted_maps.insert_encrypted_value(
            unauthorized_caller,
            (caller, name.clone()),
            key.clone(),
            value.clone()
        ),
        Err("unauthorized".to_string())
    );

    let readonly_caller = random_self_authenticating_principal(rng);

    assert_eq!(
        encrypted_maps.set_user_rights(
            caller,
            (caller, name.clone()),
            readonly_caller,
            AccessRights::Read,
        ),
        Ok(None)
    );

    assert_eq!(
        encrypted_maps.insert_encrypted_value(readonly_caller, (caller, name), key, value),
        Err("unauthorized user".to_string())
    );
}

#[test]
fn can_remove_a_key_from_map() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let key = random_key(rng);
    let value = random_bytebuf(rng, 0..2_000_000);
    encrypted_maps
        .insert_encrypted_value(caller, (caller, name.clone()), key.clone(), value.clone())
        .unwrap();
    assert_eq!(
        encrypted_maps.remove_encrypted_value(caller, (caller, name), key),
        Ok(Some(value))
    );
}

#[test]
fn remove_of_key_from_map_by_unauthorized_fails() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let key = random_key(rng);
    let value = random_bytebuf(rng, 0..2_000_000);
    encrypted_maps
        .insert_encrypted_value(caller, (caller, name.clone()), key.clone(), value.clone())
        .unwrap();

    let unauthorized_caller = random_self_authenticating_principal(rng);
    assert_eq!(
        encrypted_maps.remove_encrypted_value(
            unauthorized_caller,
            (caller, name.clone()),
            key.clone()
        ),
        Err("unauthorized".to_string())
    );

    let readonly_caller = random_self_authenticating_principal(rng);

    assert_eq!(
        encrypted_maps.set_user_rights(
            caller,
            (caller, name.clone()),
            readonly_caller,
            AccessRights::Read,
        ),
        Ok(None)
    );

    assert_eq!(
        encrypted_maps.remove_encrypted_value(readonly_caller, (caller, name), key),
        Err("unauthorized user".to_string())
    );
}

#[test]
fn can_access_map_values() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let mut authorized_users = vec![caller];
    let mut keyvals = vec![];

    for _ in 0..3 {
        let key = random_key(rng);
        let value = random_bytebuf(rng, 0..100);
        encrypted_maps
            .insert_encrypted_value(caller, (caller, name.clone()), key.clone(), value.clone())
            .unwrap();

        for access_rights in AccessRights::iter() {
            let user_to_be_added = random_self_authenticating_principal(rng);
            assert_eq!(
                encrypted_maps.set_user_rights(
                    caller,
                    (caller, name.clone()),
                    user_to_be_added,
                    access_rights,
                ),
                Ok(None)
            );
            authorized_users.push(user_to_be_added);
        }

        keyvals.push((key.clone(), value));
    }

    for (key, value) in keyvals.clone() {
        for user in authorized_users.iter() {
            assert_eq!(
                encrypted_maps.get_encrypted_value(*user, (caller, name.clone()), key.clone()),
                Ok(Some(value.clone()))
            );
        }
    }

    for added_user in authorized_users {
        assert_eq!(
            BTreeMap::from_iter(keyvals.clone().into_iter()),
            BTreeMap::from_iter(
                encrypted_maps
                    .get_encrypted_values_for_map(added_user, (caller, name.clone()))
                    .expect("failed to obtain values")
                    .into_iter()
            )
        );
    }
}

#[test]
fn can_modify_a_key_value_in_map() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let key = random_key(rng);
    let value = random_bytebuf(rng, 0..2_000_000);
    encrypted_maps
        .insert_encrypted_value(caller, (caller, name.clone()), key.clone(), value.clone())
        .unwrap();

    let new_value = random_bytebuf(rng, 0..2_000_000);
    assert_eq!(
        encrypted_maps.insert_encrypted_value(caller, (caller, name), key, new_value),
        Ok(Some(value))
    );
}

#[test]
fn modify_a_key_value_in_map_by_unauthorized_fails() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let key = random_key(rng);
    let value = random_bytebuf(rng, 0..2_000_000);
    encrypted_maps
        .insert_encrypted_value(caller, (caller, name.clone()), key.clone(), value.clone())
        .unwrap();

    let unauthorized_caller = random_self_authenticating_principal(rng);
    let new_value = random_bytebuf(rng, 0..2_000_000);
    assert_eq!(
        encrypted_maps.insert_encrypted_value(
            unauthorized_caller,
            (caller, name.clone()),
            key.clone(),
            new_value.clone()
        ),
        Err("unauthorized".to_string())
    );

    let readonly_caller = random_self_authenticating_principal(rng);

    assert_eq!(
        encrypted_maps.set_user_rights(
            caller,
            (caller, name.clone()),
            readonly_caller,
            AccessRights::Read,
        ),
        Ok(None)
    );

    assert_eq!(
        encrypted_maps.insert_encrypted_value(readonly_caller, (caller, name), key, new_value),
        Err("unauthorized user".to_string())
    );
}

#[test]
fn can_get_owned_map_names() {
    use rand::Rng;

    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let mut encrypted_maps = random_encrypted_maps(rng);

    let mut expected_map_names = vec![];

    for _ in 0..7 {
        let map_names = encrypted_maps
            .get_owned_non_empty_map_names(caller)
            .unwrap();
        assert_eq!(map_names.len(), expected_map_names.len());
        for map_name in expected_map_names.iter() {
            assert!(map_names.contains(map_name));
        }

        let name = random_name(rng);
        expected_map_names.push(name);

        for _ in 1..3 {
            let key = random_key(rng);
            let value = random_bytebuf(rng, 0..2_000_000);
            encrypted_maps
                .insert_encrypted_value(caller, (caller, name.clone()), key.clone(), value.clone())
                .unwrap();
        }

        let map_names = encrypted_maps
            .get_owned_non_empty_map_names(caller)
            .unwrap();
        assert_eq!(map_names.len(), expected_map_names.len());
        for map_name in expected_map_names.iter() {
            assert!(map_names.contains(map_name));
        }

        let should_remove_map = rng.gen_bool(0.2);

        if should_remove_map {
            encrypted_maps
                .remove_map_values(caller, (caller, name.clone()))
                .unwrap();
            expected_map_names.pop();
        }
    }
}

fn random_encrypted_maps<R: Rng + CryptoRng>(rng: &mut R) -> EncryptedMaps {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let (memory_id_encrypted_maps, memory_ids_key_manager) = random_unique_memory_ids(rng);
    let domain_separator_len = rng.gen_range(0..32);
    EncryptedMaps::init(
        &random_utf8_string(rng, domain_separator_len),
        memory_manager.get(MemoryId::new(memory_id_encrypted_maps)),
        memory_manager.get(MemoryId::new(memory_ids_key_manager[0])),
        memory_manager.get(MemoryId::new(memory_ids_key_manager[1])),
        memory_manager.get(MemoryId::new(memory_ids_key_manager[2])),
    )
}
