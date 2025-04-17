# Internet Computer (IC) VetKeys

> [!IMPORTANT]
> These support libraries are under active development and are subject to change. Access to the repositories has been opened to allow for early feedback. Check back regularly for updates.
>
> Please share your feedback on the [developer forum](https://forum.dfinity.org/t/threshold-key-derivation-privacy-on-the-ic/16560/179).

This crate contains a set of tools designed to help canister developers integrate **VetKeys** into their Internet Computer (ICP) applications.

## [Encrypted Maps](./src/encrypted_maps/README.md)
An efficient canister library facilitating access control and encrypted storage for a collection of maps contatining key-value pairs. It can be used in combination with the [frontend encrypted maps library](https://github.com/dfinity/vetkd-devkit/blob/main/frontend/ic_vetkeys/src/encrypted_maps/README.md).

## [Key Manager](./src/key_manager/README.md)
A canister library for derivation of encrypted vetkeys from arbitrary strings. It can be used in combination with the [frontend key manager library](https://github.com/dfinity/vetkd-devkit/blob/main/frontend/ic_vetkeys/src/encrypted_maps/README.md).
