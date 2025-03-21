import { Principal } from "@dfinity/principal";
import { get, set } from 'idb-keyval';
import { TransportSecretKey } from "ic-vetkd-cdk-utils";

export class EncryptedMaps {
    canister_client: EncryptedMapsClient;
    verification_key: Uint8Array | undefined = undefined;

    constructor(canister_client: EncryptedMapsClient) { this.canister_client = canister_client; }

    async get_accessible_shared_map_names(): Promise<[Principal, ByteBuf][]> {
        return await this.canister_client.get_accessible_shared_map_names();
    }

    async get_owned_non_empty_map_names(): Promise<Array<ByteBuf>> {
        return await this.canister_client.get_owned_non_empty_map_names();
    }

    async get_all_accessible_encrypted_values(): Promise<Array<[[Principal, ByteBuf], Array<[ByteBuf, ByteBuf]>]>> {
        const result = await this.canister_client.get_all_accessible_encrypted_values();
        result.map(([mapId, encryptedValues]) => {
            const mapName = new TextDecoder().decode(Uint8Array.from(mapId[1].inner));
            const values = encryptedValues.map(([mapKeyBytes, encryptedValue]) => {
                const mapKey = new TextDecoder().decode(Uint8Array.from(mapKeyBytes.inner));
                return this.decrypt_for(mapId[0], mapName, mapKey, Uint8Array.from(encryptedValue.inner));
            });
            /* eslint-disable @typescript-eslint/no-unused-expressions */
            [mapId, values]
        })
        return result;
    }

    async get_all_accessible_maps(): Promise<Array<MapData>> {
        const accessibleEncryptedMaps = await this.canister_client.get_all_accessible_encrypted_maps();
        const result: Array<MapData> = [];
        for (const encryptedMapData of accessibleEncryptedMaps) {
            const mapName = new TextDecoder().decode(Uint8Array.from(encryptedMapData.map_name.inner));
            const keyvals: Array<[Uint8Array, Uint8Array]> = [];
            for (const [mapKeyBytes, encryptedValue] of encryptedMapData.keyvals) {
                const mapKey = new TextDecoder().decode(Uint8Array.from(mapKeyBytes.inner));
                const decrypted = await this.decrypt_for(encryptedMapData.map_owner, mapName, mapKey, Uint8Array.from(encryptedValue.inner));
                if ("Err" in decrypted) {
                    throw Error(decrypted.Err);
                }
                keyvals.push([Uint8Array.from(mapKeyBytes.inner), decrypted.Ok]);
            }
            result.push({
                'access_control': encryptedMapData.access_control,
                'keyvals': keyvals,
                'map_name': Uint8Array.from(encryptedMapData.map_name.inner),
                'map_owner': encryptedMapData.map_owner,
            })
        }
        return result;
    }

    async get_value(map_owner: Principal, map_name: string, map_key: string): Promise<{ 'Ok': [] | Uint8Array } |
    { 'Err': string }> {
        const encrypted_value = await this.canister_client.get_encrypted_value(map_owner, map_name, map_key);
        if ("Err" in encrypted_value) { return encrypted_value; }
        else if (encrypted_value.Ok.length === 0) { return { 'Ok': [] }; }

        return await this.decrypt_for(map_owner, map_name, map_key, Uint8Array.from(encrypted_value.Ok[0].inner));
    }

    async get_values_for_map(map_owner: Principal, map_name: string): Promise<{ 'Ok': Array<[ByteBuf, ByteBuf]> } |
    { 'Err': string }> {
        const encryptedValues = await this.canister_client.get_encrypted_values_for_map(map_owner, map_name);
        if ("Err" in encryptedValues) { return encryptedValues; }

        const resultGet = new Array<[string, Uint8Array]>();
        for (const [x, y] of encryptedValues.Ok) {
            resultGet.push([new TextDecoder().decode(Uint8Array.from(x.inner)), Uint8Array.from(y.inner)]);
        }
        // console.info("encryptedMaps.get_values_for_map(" + map_owner.toText() + ", " + map_name + " result: " + resultGet);

        const result = new Array<[ByteBuf, ByteBuf]>();
        for (const [mapKey, mapValue] of encryptedValues.Ok) {
            const passwordName = new TextDecoder().decode(Uint8Array.from(mapKey.inner));
            const decrypted = await this.decrypt_for(map_owner, map_name, passwordName, Uint8Array.from(mapValue.inner));
            if ("Ok" in decrypted) {
                result.push([mapKey, { inner: decrypted.Ok }]);
            } else {
                return decrypted;
            }
        }
        const resultDecrypted = new Array<[string, string]>();
        for (const [x, y] of result) {
            resultDecrypted.push([new TextDecoder().decode(Uint8Array.from(x.inner)), new TextDecoder().decode(Uint8Array.from(y.inner))]);
        }
        // console.info("decrypted encryptedMaps.get_values_for_map(" + map_owner.toText() + ", " + map_name + " result: " + resultDecrypted);
        return { "Ok": result };
    }

    async get_symmetric_vetkey(map_owner: Principal, map_name: string): Promise<{ 'Ok': ByteBuf } |
    { 'Err': string }> {
        // create a random transport key
        const seed = window.crypto.getRandomValues(new Uint8Array(32));
        const tsk = new TransportSecretKey(seed);
        const encrypted_vetkey = await this.canister_client.get_encrypted_vetkey(map_owner, map_name, tsk.public_key());
        if ('Err' in encrypted_vetkey) {
            return encrypted_vetkey;
        } else {
            const encrypted_key_bytes = Uint8Array.from(encrypted_vetkey.Ok.inner);
            const verification_key = await this.get_vetkey_verification_key();
            const vetkey_name_bytes = new TextEncoder().encode(map_name);
            const derivaition_id = new Uint8Array([...map_owner.toUint8Array(), ...vetkey_name_bytes]);
            const symmetric_key_bytes = 16;
            const symmetric_key_associated_data = new TextEncoder().encode("ic-vetkd-sdk-encrypted-maps");
            const vetkey = tsk.decrypt_and_hash(encrypted_key_bytes, verification_key, derivaition_id, symmetric_key_bytes, symmetric_key_associated_data);
            return { 'Ok': { inner: vetkey } };
        }
    }

    async set_value(map_owner: Principal, map_name: string, map_key: string, data: Uint8Array): Promise<{ 'Ok': [] | Uint8Array } |
    { 'Err': string }> {
        const encrypted_value_result = await this.encrypt_for(map_owner, map_name, map_key, data);
        if ("Err" in encrypted_value_result) { return encrypted_value_result; }

        const insertion_result = await this.canister_client.insert_encrypted_value(map_owner, map_name, map_key, { inner: encrypted_value_result.Ok });
        if ("Err" in insertion_result) { return insertion_result; }
        else if (insertion_result.Ok.length === 0) { return { 'Ok': [] }; }

        return await this.decrypt_for(map_owner, map_name, map_key, Uint8Array.from(insertion_result.Ok[0].inner));
    }

    async encrypt_for(map_owner: Principal, map_name: string, map_key: string, cleartext: Uint8Array): Promise<{ 'Ok': Uint8Array } |
    { 'Err': string }> {
        const derived_key_result = await this.get_subkey_and_fetch_and_derive_if_needed(map_owner, map_name, map_key);
        if ("Err" in derived_key_result) { return derived_key_result; }
        const encrypted = await encrypt(Uint8Array.from(cleartext), derived_key_result.Ok);
        return { "Ok": encrypted };
    }

    async decrypt_for(map_owner: Principal, map_name: string, map_key: string, encrypted_value: Uint8Array): Promise<{ 'Ok': Uint8Array } |
    { 'Err': string }> {
        const derived_key = await this.get_subkey_and_fetch_and_derive_if_needed(map_owner, map_name, map_key);
        if ("Err" in derived_key) { return derived_key; }
        return { "Ok": await decrypt(encrypted_value, derived_key.Ok) };
    }

    async remove_encrypted_value(map_owner: Principal, map_name: string, map_key: string): Promise<{ 'Ok': [] | [ByteBuf] } |
    { 'Err': string }> {
        return await this.canister_client.remove_encrypted_value(map_owner, map_name, map_key);
    }

    async remove_map_values(map_owner: Principal, map_name: string): Promise<{ 'Ok': Array<ByteBuf> } |
    { 'Err': string }> {
        return await this.canister_client.remove_map_values(map_owner, map_name);
    }

    async get_vetkey_verification_key(): Promise<Uint8Array> {
        if (!this.verification_key) {
            const verification_key = await this.canister_client.get_vetkey_verification_key();
            this.verification_key = Uint8Array.from(verification_key.inner);
        }
        return this.verification_key;
    }

    async set_user_rights(owner: Principal, map_name: string, user: Principal, user_rights: AccessRights): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }> {
        return await this.canister_client.set_user_rights(owner, map_name, user, user_rights);
    }

    async get_user_rights(owner: Principal, map_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }> {
        return await this.canister_client.get_user_rights(owner, map_name, user);
    }

    async get_shared_user_access_for_map(owner: Principal, map_name: string) {
        return await this.canister_client.get_shared_user_access_for_map(owner, map_name);
    }

    async remove_user(owner: Principal, map_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }> {
        return await this.canister_client.remove_user(owner, map_name, user);
    }

    async get_vetkey_or_fetch_if_needed(map_owner: Principal, map_name: string): Promise<{ 'Ok': CryptoKey } | { 'Err': string }
    > {
        const maybe_cached_vetkey = await get([map_owner.toString(), map_name]);
        if (maybe_cached_vetkey) { return { 'Ok': maybe_cached_vetkey }; }

        const aes_256_gcm_key_raw = await this.get_symmetric_vetkey(map_owner, map_name);
        if ("Err" in aes_256_gcm_key_raw) { return aes_256_gcm_key_raw };

        const vetkey: CryptoKey = await window.crypto.subtle.importKey("raw", Uint8Array.from(aes_256_gcm_key_raw.Ok.inner), "HKDF", false, ["deriveKey"]);
        await set([[map_owner.toString(), map_name]], vetkey)
        return { 'Ok': vetkey };
    }

    async get_subkey_and_fetch_and_derive_if_needed(map_owner: Principal, map_name: string, map_key: string): Promise<{ 'Ok': CryptoKey } | { 'Err': string }> {
        const maybe_derived_key = await get([[map_owner.toString(), map_name, map_key]]);
        if (maybe_derived_key) {
            return { 'Ok': maybe_derived_key };
        }
        const get_vetkey_result = await this.get_vetkey_or_fetch_if_needed(map_owner, map_name);
        if ("Err" in get_vetkey_result) { return get_vetkey_result; }

        const algorithm = {
            name: "HKDF", salt: new TextEncoder().encode(map_key),
            info: new TextEncoder().encode("ic_vetkd_sdk_encrypted_maps_subkey"),
            hash: "SHA-256",
        };
        const derived_key = await window.crypto.subtle.deriveKey(algorithm, get_vetkey_result.Ok, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

        await set([[map_owner.toString(), map_name, map_key]], derived_key);

        return { 'Ok': derived_key };
    }
}

export interface MapData {
    'access_control': Array<[Principal, AccessRights]>,
    'keyvals': Array<[Uint8Array, Uint8Array]>,
    'map_name': Uint8Array,
    'map_owner': Principal,
}

export async function encrypt(bytes_to_encrypt: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
    // The iv must never be reused with a given key.
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        bytes_to_encrypt
    );

    return Uint8Array.from([...iv, ...new Uint8Array(ciphertext)]);
}

export async function decrypt(encrypted_value: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
    const iv = Uint8Array.from(encrypted_value.slice(0, 12));
    const ciphertext = Uint8Array.from(encrypted_value.slice(12));

    const decrypted_bytes = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );

    return new Uint8Array(decrypted_bytes);
}


export interface EncryptedMapsClient {
    get_accessible_shared_map_names(): Promise<[Principal, ByteBuf][]>;
    get_shared_user_access_for_map(owner: Principal, map_name: string): Promise<{ 'Ok': Array<[Principal, AccessRights]> } | { 'Err': string }>;
    get_owned_non_empty_map_names(): Promise<Array<ByteBuf>>;
    get_all_accessible_encrypted_values(): Promise<[[Principal, ByteBuf], [ByteBuf, ByteBuf][]][]>;
    get_all_accessible_encrypted_maps(): Promise<Array<EncryptedMapData>>;
    get_encrypted_value(map_owner: Principal, map_name: string, map_key: string): Promise<{ 'Ok': [] | [ByteBuf] } |
    { 'Err': string }>;
    get_encrypted_values_for_map(map_owner: Principal, map_name: string): Promise<{ 'Ok': Array<[ByteBuf, ByteBuf]> } |
    { 'Err': string }>;
    insert_encrypted_value(map_owner: Principal, map_name: string, map_key: string, data: ByteBuf): Promise<{ 'Ok': [] | [ByteBuf] } |
    { 'Err': string }>;
    remove_encrypted_value(map_owner: Principal, map_name: string, map_key: string): Promise<{ 'Ok': [] | [ByteBuf] } |
    { 'Err': string }>;
    remove_map_values(map_owner: Principal, map_name: string): Promise<{ 'Ok': Array<ByteBuf> } |
    { 'Err': string }>;
    set_user_rights(owner: Principal, map_name: string, user: Principal, user_rights: AccessRights): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }>;
    get_user_rights(owner: Principal, map_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }>;
    remove_user(owner: Principal, map_name: string, user: Principal): Promise<{ 'Ok': [] | [AccessRights] } |
    { 'Err': string }>;
    get_encrypted_vetkey(map_owner: Principal, map_name: string, transport_key: Uint8Array): Promise<{ 'Ok': ByteBuf } |
    { 'Err': string }>;
    get_vetkey_verification_key(): Promise<ByteBuf>;
}

export interface EncryptedMapData {
    'access_control': Array<[Principal, AccessRights]>,
    'keyvals': Array<[ByteBuf, ByteBuf]>,
    'map_name': ByteBuf,
    'map_owner': Principal,
}

export type AccessRights = { 'Read': null } |
{ 'ReadWrite': null } |
{ 'ReadWriteManage': null };
export interface ByteBuf { 'inner': Uint8Array | number[] }
