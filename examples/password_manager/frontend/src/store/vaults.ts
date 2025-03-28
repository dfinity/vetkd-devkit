import { writable } from "svelte/store";
import { passwordFromContent, type PasswordModel } from "../lib/password";
import { vaultFromContent, type VaultModel } from "../lib/vault";
import { auth } from "./auth";
import { showError } from "./notifications";
import {
    type AccessRights,
    EncryptedMaps,
} from "ic_vetkd_sdk_encrypted_maps/src";
import type { Principal } from "@dfinity/principal";

export const vaultsStore = writable<
    | {
          state: "uninitialized";
      }
    | {
          state: "loading";
      }
    | {
          state: "loaded";
          list: VaultModel[];
      }
    | {
          state: "error";
      }
>({ state: "uninitialized" });

let vaultPollerHandle: ReturnType<typeof setInterval> | null;

function updateVaults(vaults: VaultModel[]) {
    vaultsStore.set({
        state: "loaded",
        list: vaults,
    });
}

export async function refreshVaults(encryptedMaps: EncryptedMaps) {
    const allMaps = await encryptedMaps.get_all_accessible_maps();
    const vaults = allMaps.map((mapData) => {
        const mapName = new TextDecoder().decode(
            Uint8Array.from(mapData.map_name),
        );
        const passwords = new Array<[string, PasswordModel]>();
        for (const [passwordNameBytebuf, data] of mapData.keyvals) {
            const passwordNameString = new TextDecoder().decode(
                Uint8Array.from(passwordNameBytebuf),
            );
            const passwordContent = new TextDecoder().decode(
                Uint8Array.from(data),
            );
            const password = passwordFromContent(
                mapData.map_owner,
                mapName,
                passwordNameString,
                passwordContent,
            );
            passwords.push([passwordNameString, password]);
        }
        return vaultFromContent(
            mapData.map_owner,
            mapName,
            passwords,
            mapData.access_control,
        );
    });

    updateVaults(vaults);
}

export async function addPassword(
    password: PasswordModel,
    encryptedMaps: EncryptedMaps,
) {
    await encryptedMaps.set_value(password.owner, password.parentVaultName, password.passwordName, new TextEncoder().encode(password.content));
}

export async function removePassword(
    password: PasswordModel,
    encryptedMaps: EncryptedMaps,
) {
    const result = await encryptedMaps.remove_encrypted_value(
        password.owner,
        password.parentVaultName,
        password.passwordName,
    );
    if ("Err" in result) {
        throw new Error(result.Err);
    }
}

export async function updatePassword(
    password: PasswordModel,
    encryptedMaps: EncryptedMaps,
) {
    await encryptedMaps.set_value(password.owner, password.parentVaultName, password.passwordName, new TextEncoder().encode(password.content));
}

export async function addUser(
    owner: Principal,
    vaultName: string,
    user: Principal,
    userRights: AccessRights,
    encryptedMaps: EncryptedMaps,
) {
    const result = await encryptedMaps.set_user_rights(
        owner,
        vaultName,
        user,
        userRights,
    );
    if ("Err" in result) {
        throw new Error(result.Err);
    }
}

export async function removeUser(
    owner: Principal,
    vaultName: string,
    user: Principal,
    encryptedMaps: EncryptedMaps,
) {
    const result = await encryptedMaps.remove_user(owner, vaultName, user);
    if ("Err" in result) {
        throw new Error(result.Err);
    }
}

auth.subscribe(async ($auth) => {
    if ($auth.state === "initialized") {
        if (vaultPollerHandle !== null) {
            clearInterval(vaultPollerHandle);
            vaultPollerHandle = null;
        }

        vaultsStore.set({
            state: "loading",
        });
        try {
            await refreshVaults($auth.encryptedMaps).catch((e) =>
                showError(e, "Could not poll vaults."),
            );

            vaultPollerHandle = setInterval(async () => {
                await refreshVaults($auth.encryptedMaps).catch((e) =>
                    showError(e, "Could not poll vaults."),
                );
            }, 3000);
        } catch {
            vaultsStore.set({
                state: "error",
            });
        }
    } else if ($auth.state === "anonymous" && vaultPollerHandle !== null) {
        clearInterval(vaultPollerHandle);
        vaultPollerHandle = null;
        vaultsStore.set({
            state: "uninitialized",
        });
    }
});
