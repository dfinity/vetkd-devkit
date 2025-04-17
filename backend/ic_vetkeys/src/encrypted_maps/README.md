# VetKeys Backend - EncryptedMaps

> [!IMPORTANT]  
> These support libraries are under active development and are subject to change. Access to the repositories has been opened to allow for early feedback. Check back regularly for updates.
>
> Please share your feedback on the [developer forum](https://forum.dfinity.org/t/threshold-key-derivation-privacy-on-the-ic/16560/179).

**EncryptedMaps** is a support library built on top of **VetKey - KeyManager**, designed to facilitate secure, encrypted data sharing between users on the Internet Computer (ICP) using the **vetKeys** feature. It allows developers to store encrypted key-value pairs (**maps**) securely and to manage fine-grained user access.

For an introduction to **VetKeys**, refer to the [VetKeys Overview](https://internetcomputer.org/docs/building-apps/network-features/encryption/VetKeys).

## Core Features

The **EncryptedMaps** library provides the following key functionalities:

- **Encrypted Key-Value Storage:** Securely store and manage encrypted key-value pairs within named maps.
- **User-Specific Map Access:** Control precisely which users can read or modify entries in an encrypted map.
- **Integrated Access Control:** Leverages the **KeyManager** library to manage and enforce user permissions.
- **Stable Storage:** Utilizes **[StableBTreeMap](https://crates.io/crates/ic-stable-structures)** for reliable, persistent storage across canister upgrades.

## EncryptedMaps Architecture

The **EncryptedMaps** library contains:

- **Encrypted Values Storage:** Maps `(KeyId, MapKey)` to `EncryptedMapValue`, securely storing encrypted data.
- **KeyManager Integration:** Uses **KeyManager** to handle user permissions, ensuring authorized access to maps.

## API Usage

### 1. Initialize the EncryptedMaps

Initialization requires virtual memory for storing encrypted maps and KeyManager permissions:

```rust
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl,
};
use std::cell::RefCell;

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

#[ic_cdk::init]
fn init() {
    let encrypted_maps_memory: Memory = MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)));
    let access_control_memory: Memory = MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)));
    let shared_keys_memory: Memory = MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)));

    EncryptedMaps::try_init(encrypted_maps_memory, access_control_memory, shared_keys_memory)
        .expect("failed to initialize EncryptedMaps");
}
```

### 2. Store Encrypted Values

```rust
pub fn insert_encrypted_value(
    caller: Principal,
    key_id: KeyId,
    key: MapKey,
    encrypted_value: EncryptedMapValue,
) -> Result<Option<EncryptedMapValue>, String>;
```

Stores an encrypted value in a specified map, ensuring caller has write permissions.

### 3. Retrieve Encrypted Values

```rust
pub fn get_encrypted_value(
    caller: Principal,
    key_id: KeyId,
    key: MapKey,
) -> Result<Option<EncryptedMapValue>, String>;
```

Retrieves a specific encrypted value from the map, enforcing read access control.

### 4. Remove Encrypted Values

```rust
pub fn remove_encrypted_value(
    caller: Principal,
    key_id: KeyId,
    key: MapKey,
) -> Result<Option<EncryptedMapValue>, String>;
```

Removes a specific entry from the map if the caller has write permissions.

### 5. Manage User Access Rights

#### a) Set User Access Rights

```rust
pub fn set_user_rights(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
    access_rights: AccessRights,
) -> Result<Option<AccessRights>, String>;
```

Grants or modifies user access permissions for a map.

#### b) Remove User Access

```rust
pub fn remove_user(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
) -> Result<Option<AccessRights>, String>;
```

Revokes a user's access rights to a map.

### 6. Retrieve Accessible Map Names

```rust
pub fn get_accessible_shared_map_names(caller: Principal) -> Vec<KeyId>;
```

Lists maps shared with the caller.

### 7. Retrieve Owned Map Names

```rust
pub fn get_owned_non_empty_map_names(caller: Principal) -> Result<Vec<MapName>, String>;
```

Lists non-empty maps owned by the caller.

## Access Rights

User permissions managed by **KeyManager** define access:

- **Read**: View encrypted map values.
- **Write**: Add, update, or delete encrypted map values.
- **Manage**: Manage other users' access rights.

## Example Use Case

1. **User A** initializes an encrypted map and adds values.
2. **User A** shares access to this map with **User B**.
3. **User B** retrieves encrypted values securely.
4. **User A** revokes **User B**'s access as necessary.

## Security Considerations

- Encrypted values are stored securely with fine-grained access control.
- Access rights and permissions are strictly enforced.
- Data persists securely across canister upgrades through stable storage.

## Conclusion

**EncryptedMaps** simplifies secure storage, retrieval, and controlled sharing of encrypted data on the Internet Computer, complementing the robust security and permissions management provided by **KeyManager**.
