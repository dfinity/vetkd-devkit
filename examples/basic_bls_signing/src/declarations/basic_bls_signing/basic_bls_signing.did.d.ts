import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface Signature {
  'signature' : Uint8Array | number[],
  'message' : string,
  'timestamp' : bigint,
  'signer' : Principal,
}
export interface _SERVICE {
  'get_published_signatures' : ActorMethod<[], Array<Signature>>,
  'get_root_public_key' : ActorMethod<[], Uint8Array | number[]>,
  'publish_my_signature_no_verification' : ActorMethod<
    [string, Uint8Array | number[]],
    undefined
  >,
  'sign_message' : ActorMethod<[string], Uint8Array | number[]>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
