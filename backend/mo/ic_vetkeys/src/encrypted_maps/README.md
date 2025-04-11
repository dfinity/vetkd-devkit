# VetKD CDK - EncryptedMaps

## Overview

**EncryptedMaps** is a support library built on top of **KeyManager**, designed to facilitate
secure, encrypted data sharing between users on the Internet Computer (ICP) using the **vetKeys** feature.
It allows developers to store encrypted key-value pairs (**maps**) securely and to manage fine-grained user access.

## Core Features

- **Encrypted Key-Value Storage:** Securely store and manage encrypted key-value pairs within named maps.
- **User-Specific Map Access:** Control precisely which users can read or modify entries in an encrypted map.
- **Integrated Access Control:** Leverages the **KeyManager** library to manage and enforce user permissions.
- **Stable Storage:** Utilizes **OrderedMap** for reliable, persistent storage across canister upgrades.

## EncryptedMaps Architecture

The **EncryptedMaps** library contains:

- **Encrypted Values Storage:** Maps `(KeyId, MapKey)` to `EncryptedMapValue`, securely storing encrypted data.
- **KeyManager Integration:** Uses **KeyManager** to handle user permissions, ensuring authorized access to maps. 