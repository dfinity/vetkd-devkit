import { HttpAgent } from "@dfinity/agent";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import fetch from 'isomorphic-fetch';
import { expect, test } from 'vitest'
import { KeyManager } from "ic_vetkd_sdk_key_manager/src";
import { DefaultKeyManagerClient } from "./index";
import { randomBytes } from "node:crypto";

function randomId(): Ed25519KeyIdentity {
  return Ed25519KeyIdentity.generate(randomBytes(32));
}

function ids(): [Ed25519KeyIdentity, Ed25519KeyIdentity] {
  return [randomId(), randomId()];
}

async function new_key_manager(id: Ed25519KeyIdentity): Promise<KeyManager> {
  const host = 'http://127.0.0.1:4943';
  const agent = await HttpAgent.create({ fetch, host, identity: id, shouldFetchRootKey: true }).catch((err) => { throw err; });
  const canisterId = process.env.CANISTER_ID_KEY_MANAGER_EXAMPLE as string;
  return new KeyManager(new DefaultKeyManagerClient(agent, canisterId));
}

test('empty get_accessible_shared_map_names', async () => {
  const id = randomId();
  const key_manager = await new_key_manager(id).catch((err) => { throw err; });
  const ids = await key_manager.get_accessible_shared_key_ids().catch((err) => { throw err; });
  expect(ids.length === 0).to.equal(true);
});

test('can get vetkey', async () => {
  const id = randomId();
  const key_manager = await new_key_manager(id).catch((err) => { throw err; });
  const owner = id.getPrincipal();
  const vetkey = await key_manager.get_encrypted_vetkey(owner, "some key").catch((err) => { throw err; });
  // no trivial key output
  expect(isEqualArray(vetkey, new Uint8Array(16))).to.equal(false);

  const second_vetkey = await key_manager.get_encrypted_vetkey(owner, "some key").catch((err) => { throw err; });
  expect(isEqualArray(vetkey, second_vetkey)).to.equal(true);
});

test('cannot get unauthorized vetkey', async () => {
  const [id0, id1] = ids();
  const key_manager = await new_key_manager(id0).catch((err) => { throw err; });
  await expect(key_manager.get_encrypted_vetkey(id1.getPrincipal(), "some key")).rejects.toThrow("unauthorized");
});

test('can share a key', async () => {
  const [id0, id1] = ids();
  const owner = id0.getPrincipal();
  const user = id1.getPrincipal();
  const key_manager_owner = await new_key_manager(id0).catch((err) => { throw err; });
  const key_manager_user = await new_key_manager(id1).catch((err) => { throw err; });
  const vetkey_owner = await key_manager_owner.get_encrypted_vetkey(owner, "some key");

  const rights = { 'ReadWrite': null };
  expect((await key_manager_owner.set_user_rights(owner, "some key", user, rights))).toBeUndefined();

  const vetkey_user = await key_manager_user.get_encrypted_vetkey(owner, "some key");

  expect(isEqualArray(vetkey_owner, vetkey_user)).to.equal(true);
});

test('sharing rights are consistent', async () => {
  const [id0, id1] = ids();
  const owner = id0.getPrincipal();
  const user = id1.getPrincipal();
  const key_manager_owner = await new_key_manager(id0).catch((err) => { throw err; });
  const key_manager_user = await new_key_manager(id1).catch((err) => { throw err; });
  const rights = { 'ReadWrite': null };

  expect((await key_manager_owner.set_user_rights(owner, "some key", user, rights))).toBeUndefined();
  expect((await key_manager_user.get_user_rights(owner, "some key", user))).to.deep.equal(rights);
});

function isEqualArray(a, b) {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] != b[i]) return false; return true;
}
