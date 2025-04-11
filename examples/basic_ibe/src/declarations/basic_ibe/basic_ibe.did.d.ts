import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface Inbox { 'messages' : Array<Message> }
export interface Message {
  'sender' : Principal,
  'timestamp' : bigint,
  'encrypted_message' : Uint8Array | number[],
  'receiver' : Principal,
}
export type Result = { 'Ok' : null } |
  { 'Err' : string };
export interface SendMessageRequest {
  'encrypted_message' : Uint8Array | number[],
  'receiver' : Principal,
}
export interface _SERVICE {
  'get_my_encrypted_ibe_key' : ActorMethod<
    [Uint8Array | number[]],
    Uint8Array | number[]
  >,
  'get_my_messages' : ActorMethod<[], Inbox>,
  'get_root_ibe_public_key' : ActorMethod<[], Uint8Array | number[]>,
  'remove_my_messages' : ActorMethod<[], Inbox>,
  'send_message' : ActorMethod<[SendMessageRequest], Result>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
