import { Principal } from "@dfinity/principal";
import { TransportSecretKey,EncryptedVetKey, DerivedPublicKey } from "ic_vetkd_sdk_utils/src/index";

export class KeyManager {
    canister_client: KeyManagerClient;
    constructor(canister_client: KeyManagerClient) { this.canister_client = canister_client; }

    async get_accessible_shared_key_ids(): Promise<[Principal, ByteBuf][]> {
        return await this.canister_client.get_accessible_shared_key_ids();
    }

    async get_encrypted_vetkey(key_owner: Principal, vetkey_name: string): Promise<{ 'Ok': ByteBuf } |
    { 'Err': string }> {
        // create a random transport key
        const seed = window.crypto.getRandomValues(new Uint8Array(32));
        const tsk = new TransportSecretKey(seed);
        const encrypted_vetkey = await this.canister_client.get_encrypted_vetkey(key_owner, vetkey_name, tsk.publicKeyBytes());
        if ('Err' in encrypted_vetkey) {
            return encrypted_vetkey;
        } else {
            const encrypted_key_bytes = Uint8Array.from(encrypted_vetkey.Ok.inner);
            const verification_key = await this.get_vetkey_verification_key();
            const derivedPublicKey = DerivedPublicKey.deserialize(Uint8Array.from(verification_key.inner));
            const vetkey_name_bytes = new TextEncoder().encode(vetkey_name);
            const derivaition_id = new Uint8Array([...key_owner.toUint8Array(), ...vetkey_name_bytes]);
            const encryptedDetkey = new EncryptedVetKey(encrypted_key_bytes);
            const vetkey = encryptedDetkey.decryptAndVerify(tsk, derivedPublicKey, derivaition_id);
            return { 'Ok': { inner: vetkey.signatureBytes() } };
        }
    }

    async get_vetkey_verification_key(): Promise<ByteBuf> {
        return await this.canister_client.get_vetkey_verification_key();
    }

    async set_user_rights(owner: Principal, vetkey_name: string, user: Principal, user_rights: AccessRights): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }> {
        return await this.canister_client.set_user_rights(owner, vetkey_name, user, user_rights);
    }

    async get_user_rights(owner: Principal, vetkey_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }> {
        return await this.canister_client.get_user_rights(owner, vetkey_name, user);
    }

    async remove_user(owner: Principal, vetkey_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }> {
        return await this.canister_client.remove_user(owner, vetkey_name, user);
    }
}

export interface KeyManagerClient {
    get_accessible_shared_key_ids(): Promise<[Principal, ByteBuf][]>;
    set_user_rights(owner: Principal, vetkey_name: string, user: Principal, user_rights: AccessRights): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }>;
    get_user_rights(owner: Principal, vetkey_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }>;
    remove_user(owner: Principal, vetkey_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }>;
    get_encrypted_vetkey(key_owner: Principal, vetkey_name: string, transport_key: Uint8Array): Promise<{ 'Ok': ByteBuf } |
    { 'Err': string }>;
    get_vetkey_verification_key(): Promise<ByteBuf>;
}

export type AccessRights = { 'Read': null } |
{ 'ReadWrite': null } |
{ 'ReadWriteManage': null };
export interface ByteBuf { 'inner': Uint8Array | number[] }
