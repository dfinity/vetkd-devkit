import { Principal } from "@dfinity/principal";
import { TransportSecretKey,EncryptedVetKey, DerivedPublicKey } from "ic_vetkd_sdk_utils/src/index";

export class KeyManager {
    canister_client: KeyManagerClient;
    constructor(canister_client: KeyManagerClient) { this.canister_client = canister_client; }

    async get_accessible_shared_key_ids(): Promise<[Principal, Uint8Array][]> {
        return (await this.canister_client.get_accessible_shared_key_ids()).map(([principal, byteBuf]) => {
            return [principal, Uint8Array.from(byteBuf.inner)];
        });
    }

    async get_encrypted_vetkey(key_owner: Principal, vetkey_name: string): Promise<Uint8Array> {
        // create a random transport key
        const seed = window.crypto.getRandomValues(new Uint8Array(32));
        const tsk = new TransportSecretKey(seed);
        const encrypted_vetkey = await this.canister_client.get_encrypted_vetkey(key_owner, vetkey_name, tsk.publicKeyBytes());
        if ('Err' in encrypted_vetkey) {
            throw Error(encrypted_vetkey.Err);
        } else {
            const encrypted_key_bytes = Uint8Array.from(encrypted_vetkey.Ok.inner);
            const verification_key = await this.get_vetkey_verification_key();
            const derivedPublicKey = DerivedPublicKey.deserialize(Uint8Array.from(verification_key));
            const vetkey_name_bytes = new TextEncoder().encode(vetkey_name);
            const derivaition_id = new Uint8Array([...key_owner.toUint8Array(), ...vetkey_name_bytes]);
            const encryptedDetkey = new EncryptedVetKey(encrypted_key_bytes);
            const vetkey = encryptedDetkey.decryptAndVerify(tsk, derivedPublicKey, derivaition_id);
            return vetkey.signatureBytes();
        }
    }

    async get_vetkey_verification_key(): Promise<Uint8Array> {
        return Uint8Array.from((await this.canister_client.get_vetkey_verification_key()).inner);
    }

    async set_user_rights(owner: Principal, vetkey_name: string, user: Principal, user_rights: AccessRights): Promise<AccessRights | undefined> {
        const result = await this.canister_client.set_user_rights(owner, vetkey_name, user, user_rights);
        if ('Err' in result) throw Error(result.Err);
        else if (result.Ok.length > 1) throw Error("Unexpected result from set_user_rights");

        const prevUserRights = result.Ok.length === 0 ? undefined : result.Ok[0];
        return prevUserRights;
    }

    async get_user_rights(owner: Principal, vetkey_name: string, user: Principal): Promise<AccessRights | undefined> {
        const result = await this.canister_client.get_user_rights(owner, vetkey_name, user);
        if ('Err' in result) throw Error(result.Err);
        else if (result.Ok.length > 1) throw Error("Unexpected result from set_user_rights");

        const userRights = result.Ok.length === 0 ? undefined : result.Ok[0];
        return userRights;
    }

    async remove_user(owner: Principal, vetkey_name: string, user: Principal): Promise<AccessRights | undefined> {
        const result = await this.canister_client.remove_user(owner, vetkey_name, user);

        if ('Err' in result) throw Error(result.Err);
        else if (result.Ok.length > 1) throw Error("Unexpected result from set_user_rights");

        const userRights = result.Ok.length === 0 ? undefined : result.Ok[0];
        return userRights;
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
