# VetKD CDK - KeyManager

## Overview

The **KeyManager** is a support library for **vetKeys**, an Internet Computer (ICP) feature
that enables the derivation of **encrypted cryptographic keys**. This library simplifies
the process of key retrieval, encryption, and controlled sharing, ensuring secure and
efficient key management for canisters and users.

## Core Features

- **Request an Encrypted Key:** Users can derive any number of **encrypted cryptographic keys**,
  secured using a **transport key**. Each key is associated with a unique **key id**.
- **Manage Key Sharing:** A user can **share their keys** with other users while controlling access rights.
- **Access Control Management:** Users can define and enforce **fine-grained permissions**
  (read, write, manage) for each key.
- **Uses Stable Storage:** The library persists key access information using **OrderedMap**,
  ensuring reliability across canister upgrades.

## KeyManager Architecture

The **KeyManager** consists of two primary components:

1. **Access Control Map** (`accessControl`): Maps `(Caller, KeyId)` to `T`, defining permissions for each user.
2. **Shared Keys Map** (`sharedKeys`): Tracks which users have access to shared keys. 