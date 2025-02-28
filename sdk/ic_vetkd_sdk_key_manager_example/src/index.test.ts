import { HttpAgent } from "@dfinity/agent";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import fetch from 'isomorphic-fetch';
import { expect, test } from 'vitest'
import { KeyManager } from "ic_vetkd_sdk_key_manager/src";
import { DefaultKeyManagerClient } from "./index";
import { randomBytes } from "crypto";

function randomId(): Ed25519KeyIdentity {
  return Ed25519KeyIdentity.generate(randomBytes(32));
}

function ids(): [Ed25519KeyIdentity, Ed25519KeyIdentity] {
  return [randomId(), randomId()];
}

async function new_key_manager(id: Ed25519KeyIdentity): Promise<KeyManager> {
  const host = 'http://127.0.0.1:4943';
  const agent = await HttpAgent.create({ fetch, host, identity: id, shouldFetchRootKey: true }).catch((err) => { throw err; });
  let canisterId = process.env.CANISTER_ID_KEY_MANAGER_EXAMPLE as string;
  return new KeyManager(new DefaultKeyManagerClient(agent, canisterId));
}

test('empty get_accessible_shared_map_names', async () => {
  const id = randomId();
  let key_manager = await new_key_manager(id).catch((err) => { throw err; });
  let ids = await key_manager.get_accessible_shared_key_ids().catch((err) => { throw err; });
  expect(ids.length === 0).to.equal(true);
});

test('can get vetkey', async () => {
  const id = randomId();
  let key_manager = await new_key_manager(id).catch((err) => { throw err; });
  let owner = id.getPrincipal();
  let vetkey = await key_manager.get_encrypted_vetkey(owner, "some key").catch((err) => { throw err; });
  expect('Ok' in vetkey).to.equal(true);
  // no trivial key output
  expect(isEqualArray(vetkey["Ok"].inner, new Uint8Array(16))).to.equal(false);

  let second_vetkey = await key_manager.get_encrypted_vetkey(owner, "some key").catch((err) => { throw err; });
  expect(isEqualArray(vetkey["Ok"].inner, second_vetkey["Ok"].inner)).to.equal(true);
});

test('cannot get unauthorized vetkey', async () => {
  const [id0, id1] = ids();
  let key_manager = await new_key_manager(id0).catch((err) => { throw err; });
  let owner = id0.getPrincipal();
  expect((await key_manager.get_encrypted_vetkey(id1.getPrincipal(), "some key"))["Err"]).to.equal("unauthorized");
});

test('can share a key', async () => {
  const [id0, id1] = ids();
  let owner = id0.getPrincipal();
  let user = id1.getPrincipal();
  let key_manager_owner = await new_key_manager(id0).catch((err) => { throw err; });
  let key_manager_user = await new_key_manager(id1).catch((err) => { throw err; });
  let vetkey_owner = await key_manager_owner.get_encrypted_vetkey(owner, "some key");
  expect("Ok" in vetkey_owner).to.equal(true);

  expect("Ok" in await key_manager_owner.remove_user(owner, "some_key", user));

  let rights = { 'ReadWrite': null };

  expect((await key_manager_owner.set_user_rights(owner, "some key", user, rights))["Ok"]).to.deep.equal([]);

  let vetkey_user = await key_manager_user.get_encrypted_vetkey(owner, "some key");

  expect(isEqualArray(vetkey_owner["Ok"].inner, vetkey_user["Ok"].inner)).to.equal(true);
});

test('sharing rights are consistent', async () => {
  const [id0, id1] = ids();
  let owner = id0.getPrincipal();
  let user = id1.getPrincipal();
  let key_manager_owner = await new_key_manager(id0).catch((err) => { throw err; });
  let key_manager_user = await new_key_manager(id1).catch((err) => { throw err; });
  let rights = { 'ReadWrite': null };

  expect((await key_manager_owner.set_user_rights(owner, "some key", user, rights))["Ok"]).to.deep.equal([]);
  expect((await key_manager_user.get_user_rights(owner, "some key", user))["Ok"]).to.deep.equal([rights]);
});

function isEqualArray(a, b) {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] != b[i]) return false; return true;
}