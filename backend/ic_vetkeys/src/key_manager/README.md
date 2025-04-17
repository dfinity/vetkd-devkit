# VetKeys Backend - KeyManager

> [!IMPORTANT]  
> These support libraries are under active development and are subject to change. Access to the repositories has been opened to allow for early feedback. Check back regularly for updates.
>
> Please share your feedback on the [developer forum](https://forum.dfinity.org/t/threshold-key-derivation-privacy-on-the-ic/16560/179).

The **KeyManager** is a support library for **VetKeys**, an Internet Computer (ICP) feature that enables the derivation of **encrypted cryptographic keys**. This library simplifies the process of key retrieval, encryption, and controlled sharing, ensuring secure and efficient key management for canisters and users.

For an introduction to **VetKeys**, refer to the [VetKeys Overview](https://internetcomputer.org/docs/building-apps/network-features/encryption/VetKeys).

## Core Features

The **KeyManager** support library provides the following core functionalities:

- **Request an Encrypted Key:** Users can derive any number of **encrypted cryptographic keys**, secured using a **transport key**. Each key is associated with a unique **key id**.
- **Manage Key Sharing:** A user can **share their keys** with other users while controlling access rights.
- **Access Control Management:** Users can define and enforce **fine-grained permissions** (read, write, manage) for each key.
- **Uses Stable Storage:** The library persists key access information using **StableBTreeMap**, ensuring reliability across canister upgrades.

## KeyManager Architecture

The **KeyManager** consists of two primary components:

1. **Access Control Map** (`access_control`): Maps `(Caller, KeyId)` to `AccessRights`, defining permissions for each user.
2. **Shared Keys Map** (`shared_keys`): Tracks which users have access to shared keys.

## API Usage

### 1. Initialize the KeyManager

The **KeyManager** must be initialized with two virtual memories, for the access control and shared keys maps. The following code snippet demonstrates how to initialize the **KeyManager** when the canister is created:

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
    let access_control_memory: Memory = MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)));
    let shared_keys_memory: Memory = MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)));
    KeyManager::try_init(access_control_memory, shared_keys_memory).expect("failed to initialize memory");
}
```

### 2. Retrieve an Encrypted Key

```rust
pub async fn get_encrypted_vetkey(
    caller: Principal,
    key_id: KeyId,
    transport_key: TransportKey
) -> Result<VetKey, String>;
```

Returns an **encrypted cryptographic key** for the caller, secured with a transport key, using the `vetkd_derive_key` management canister API call.

### 3. Manage Key Sharing and Access Rights

#### a) Grant or Modify Access Rights

```rust
pub fn set_user_rights(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
    access_rights: AccessRights,
) -> Result<Option<AccessRights>, String>;
```

- **Allows the key owner or a manager to grant/restrict access**.
- The caller must have **management access** to modify rights.
- The key owner **cannot** change their own rights.

#### b) Remove a User's Access

```rust
pub fn remove_user(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
) -> Result<Option<AccessRights>, String>;
```

- Revokes a user's access to a shared key.
- The key owner **cannot** remove themselves.

#### c) List All Shared Keys a User Has Access To

```rust
pub fn get_accessible_shared_key_ids(caller: Principal) -> Vec<KeyId>;
```

- Retrieves all keys accessible by the caller.

#### d) Get All Users Who Have Access to a Key

```rust
pub fn get_shared_user_access_for_key(
    caller: Principal,
    key_id: KeyId,
) -> Result<Vec<(Principal, AccessRights)>, String>;
```

- Lists all users who have access to a specific key along with their permissions.

#### e) Retrieve a User’s Access Rights

```rust
pub fn get_user_rights(
    caller: Principal,
    key_id: KeyId,
    user: Principal,
) -> Result<Option<AccessRights>, String>;
```

- Returns the specific access rights a user has to a key.

## Access Rights

The system enforces access control based on `AccessRights`, allowing fine-grained control over key usage:

- **Read**: User can retrieve the encrypted key.
- **Write**: User can update the key.
- **Manage**: User can share/revoke access.

## Example Use Case

1. **User A** requests a key from KeyManager.
2. KeyManager verifies permissions and derives an **encrypted cryptographic key**.
3. **User A** securely shares access with **User B** using `set_user_rights`.
4. **User B** retrieves the key securely via `get_encrypted_vetkey`.

## Security Considerations

- Keys are derived **on demand** and encrypted before transmission.
- Only authorized users can access shared keys.
- Stable storage ensures keys persist across canister upgrades.
- Access control logic ensures only authorized users modify or retrieve keys.

## Conclusion

The **KeyManager** simplifies the usage of **VetKeys** on the ICP, providing a secure and efficient mechanism for **cryptographic key derivation, sharing, and management**.
