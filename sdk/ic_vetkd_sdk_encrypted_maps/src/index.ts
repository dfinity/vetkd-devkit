import { Principal } from "@dfinity/principal";
import { get, set } from 'idb-keyval';
import { TransportSecretKey, DerivedKeyMaterial, EncryptedVetKey, DerivedPublicKey } from "ic_vetkd_sdk_utils/src/index";

export class EncryptedMaps {
    canister_client: EncryptedMapsClient;
    verification_key: Uint8Array | undefined = undefined;

    constructor(canister_client: EncryptedMapsClient) { this.canister_client = canister_client; }

    async get_accessible_shared_map_names(): Promise<[Principal, string][]> {
        return (await this.canister_client.get_accessible_shared_map_names()).map(([principal, byteBuf]) => {
            return [principal, new TextDecoder().decode(Uint8Array.from(byteBuf.inner))];
        });
    }

    async get_owned_non_empty_map_names(): Promise<Array<string>> {
        return (await this.canister_client.get_owned_non_empty_map_names()).map((byteBuf) => {
            return new TextDecoder().decode(Uint8Array.from(byteBuf.inner));
        });
    }

    async get_all_accessible_values(): Promise<Array<[[Principal, string], Array<[string, Uint8Array]>]>> {
        const result = await this.canister_client.get_all_accessible_encrypted_values();
        const decryptedResult: Array<[[Principal, string], Array<[string, Uint8Array]>]> = [];
        for (const [mapId, encryptedValues] of result) {
            const mapName = new TextDecoder().decode(Uint8Array.from(mapId[1].inner));
            const keyValues: Array<[string, Uint8Array]> = [];
            for (const [mapKeyBytes, encryptedValue] of encryptedValues) {
                const mapKey = new TextDecoder().decode(Uint8Array.from(mapKeyBytes.inner));
                const value = await this.decrypt_for(mapId[0], mapName, mapKey, Uint8Array.from(encryptedValue.inner));
                keyValues.push([mapKey, value]);
            };
            decryptedResult.push([[mapId[0], new TextDecoder().decode(Uint8Array.from(mapId[1].inner))], keyValues]);
        }

        return decryptedResult;
    }

    async get_all_accessible_maps(): Promise<Array<MapData>> {
        const accessibleEncryptedMaps = await this.canister_client.get_all_accessible_encrypted_maps();
        const result: Array<MapData> = [];
        for (const encryptedMapData of accessibleEncryptedMaps) {
            const mapName = new TextDecoder().decode(Uint8Array.from(encryptedMapData.map_name.inner));
            const keyvals: Array<[string, Uint8Array]> = [];
            for (const [mapKeyBytes, encryptedValue] of encryptedMapData.keyvals) {
                const mapKey = new TextDecoder().decode(Uint8Array.from(mapKeyBytes.inner));
                const decrypted = await this.decrypt_for(encryptedMapData.map_owner, mapName, mapKey, Uint8Array.from(encryptedValue.inner));
                keyvals.push([mapKey, decrypted]);
            }
            result.push({
                'access_control': encryptedMapData.access_control,
                'keyvals': keyvals,
                'map_name': mapName,
                'map_owner': encryptedMapData.map_owner,
            })
        }
        console.info("get_all_accessible_maps", JSON.stringify(result));
        return result;
    }

    async get_value(map_owner: Principal, map_name: string, map_key: string): Promise<Uint8Array> {
        const encrypted_value = await this.canister_client.get_encrypted_value(map_owner, map_name, map_key);
        if ("Err" in encrypted_value) { throw Error(encrypted_value.Err); }
        else if (encrypted_value.Ok.length === 0) { return new Uint8Array(0); }

        return await this.decrypt_for(map_owner, map_name, map_key, Uint8Array.from(encrypted_value.Ok[0].inner));
    }

    async get_values_for_map(map_owner: Principal, map_name: string): Promise<Array<[string, Uint8Array]>> {
        const encryptedValues = await this.canister_client.get_encrypted_values_for_map(map_owner, map_name);
        if ("Err" in encryptedValues) { throw Error(encryptedValues.Err); }

        const resultGet = new Array<[string, Uint8Array]>();
        for (const [k, v] of encryptedValues.Ok) {
            resultGet.push([new TextDecoder().decode(Uint8Array.from(k.inner)), Uint8Array.from(v.inner)]);
        }

        const result = new Array<[string, Uint8Array]>();
        for (const [mapKey, mapValue] of encryptedValues.Ok) {
            const passwordName = new TextDecoder().decode(Uint8Array.from(mapKey.inner));
            const decrypted = await this.decrypt_for(map_owner, map_name, passwordName, Uint8Array.from(mapValue.inner));
            result.push([passwordName, decrypted]);
        }
        return result;
    }

    async getDerivedKeyMaterial(map_owner: Principal, map_name: string): Promise<DerivedKeyMaterial> {
        const tsk = TransportSecretKey.random();
        const encrypted_vetkey = await this.canister_client.get_encrypted_vetkey(map_owner, map_name, tsk.publicKeyBytes());
        if ('Err' in encrypted_vetkey) {
            throw Error(encrypted_vetkey.Err);
        } else {
            const encrypted_key_bytes = Uint8Array.from(encrypted_vetkey.Ok.inner);
            const verification_key = await this.get_vetkey_verification_key();
            const vetkey_name_bytes = new TextEncoder().encode(map_name);
            const derivaition_id = new Uint8Array([...map_owner.toUint8Array(), ...vetkey_name_bytes]);

            const encryptedVetKey = new EncryptedVetKey(encrypted_key_bytes);
            const derivedPublicKey = DerivedPublicKey.deserialize(verification_key);
            const vetKey = encryptedVetKey.decryptAndVerify(tsk, derivedPublicKey, derivaition_id);
            return await vetKey.asDerivedKeyMaterial();
        }
    }

    async set_value(map_owner: Principal, map_name: string, map_key: string, data: Uint8Array): Promise<Uint8Array | undefined> {
        const encrypted_value = await this.encrypt_for(map_owner, map_name, map_key, data);
        const insertion_result = await this.canister_client.insert_encrypted_value(map_owner, map_name, map_key, { inner: encrypted_value });
        if ("Err" in insertion_result) { throw Error(insertion_result.Err); }
        else if (insertion_result.Ok.length === 0) { return undefined; }
        return await this.decrypt_for(map_owner, map_name, map_key, Uint8Array.from(insertion_result.Ok[0].inner));
    }

    async encrypt_for(map_owner: Principal, map_name: string, map_key: string, cleartext: Uint8Array): Promise<Uint8Array> {
        const derivedKeyMaterial = await this.getDerivedKeyMaterialOrFetchIfNeeded(map_owner, map_name);
        return await derivedKeyMaterial.encryptMessage(cleartext, map_key);
    }

    async decrypt_for(map_owner: Principal, map_name: string, map_key: string, encrypted_value: Uint8Array): Promise<Uint8Array> {
        const derivedKeyMaterial = await this.getDerivedKeyMaterialOrFetchIfNeeded(map_owner, map_name);
        return await derivedKeyMaterial.decryptMessage(encrypted_value, map_key);
    }

    async remove_encrypted_value(map_owner: Principal, map_name: string, map_key: string): Promise<Uint8Array | undefined> {
        const encryptedResult = await this.canister_client.remove_encrypted_value(map_owner, map_name, map_key);
        if ("Err" in encryptedResult) { throw Error(encryptedResult.Err); }
        else if (encryptedResult.Ok.length === 0) { return undefined; }
        return await this.decrypt_for(map_owner, map_name, map_key, Uint8Array.from(encryptedResult.Ok[0].inner));
    }

    async remove_map_values(map_owner: Principal, map_name: string): Promise<Array<string>> {
        const encryptedResult = await this.canister_client.remove_map_values(map_owner, map_name);
        if ("Err" in encryptedResult) { throw Error(encryptedResult.Err); }
        else {
            return encryptedResult.Ok.map((mapKey) => new TextDecoder().decode(Uint8Array.from(mapKey.inner)));
        }
    }

    async get_vetkey_verification_key(): Promise<Uint8Array> {
        if (!this.verification_key) {
            const verification_key = await this.canister_client.get_vetkey_verification_key();
            this.verification_key = Uint8Array.from(verification_key.inner);
        }
        return this.verification_key;
    }

    async set_user_rights(owner: Principal, map_name: string, user: Principal, user_rights: AccessRights): Promise<AccessRights | undefined> {
        const result = await this.canister_client.set_user_rights(owner, map_name, user, user_rights);
        if ('Err' in result) throw Error(result.Err);
        else if (result.Ok.length > 1) throw Error("Unexpected result from set_user_rights");
        const prevUserRights = result.Ok.length === 0 ? undefined : result.Ok[0];
        return prevUserRights;
    }

    async get_user_rights(owner: Principal, map_name: string, user: Principal): Promise<AccessRights | undefined> {
        const result = await this.canister_client.get_user_rights(owner, map_name, user);
        if ('Err' in result) throw Error(result.Err);
        else if (result.Ok.length > 1) throw Error("Unexpected result from set_user_rights");

        const userRights = result.Ok.length === 0 ? undefined : result.Ok[0];
        return userRights;
    }

    async get_shared_user_access_for_map(owner: Principal, map_name: string) : Promise<Array<[Principal, AccessRights]>> {
        const result = await this.canister_client.get_shared_user_access_for_map(owner, map_name);
        if ("Err" in result) { throw Error(result.Err); }
        return result.Ok;
    }

    async remove_user(owner: Principal, map_name: string, user: Principal): Promise<AccessRights | undefined> {
        const result = await this.canister_client.remove_user(owner, map_name, user);
        if ("Err" in result) { throw Error(result.Err); }
        const userRights = result.Ok.length === 0 ? undefined : result.Ok[0];
        return userRights;
    }

    async getDerivedKeyMaterialOrFetchIfNeeded(map_owner: Principal, map_name: string): Promise<DerivedKeyMaterial> {
        const cachedRawDerivedKeyMaterial: CryptoKey | undefined = await get([map_owner.toString(), map_name]);
        if (cachedRawDerivedKeyMaterial) { return new DerivedKeyMaterial(cachedRawDerivedKeyMaterial); }

        const derivedKeyMaterial = await this.getDerivedKeyMaterial(map_owner, map_name);
        await set([map_owner.toString(), map_name], derivedKeyMaterial.getCryptoKey());
        return derivedKeyMaterial;
    }
}

export interface MapData {
    'access_control': Array<[Principal, AccessRights]>,
    'keyvals': Array<[string, Uint8Array]>,
    'map_name': string,
    'map_owner': Principal,
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
