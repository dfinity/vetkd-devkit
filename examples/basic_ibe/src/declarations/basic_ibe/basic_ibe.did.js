export const idlFactory = ({ IDL }) => {
  const Message = IDL.Record({
    'sender' : IDL.Principal,
    'timestamp' : IDL.Nat64,
    'encrypted_message' : IDL.Vec(IDL.Nat8),
    'receiver' : IDL.Principal,
  });
  const Inbox = IDL.Record({ 'messages' : IDL.Vec(Message) });
  const SendMessageRequest = IDL.Record({
    'encrypted_message' : IDL.Vec(IDL.Nat8),
    'receiver' : IDL.Principal,
  });
  const Result = IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text });
  return IDL.Service({
    'get_my_encrypted_ibe_key' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Vec(IDL.Nat8)],
        [],
      ),
    'get_my_messages' : IDL.Func([], [Inbox], ['query']),
    'get_root_ibe_public_key' : IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    'remove_my_messages' : IDL.Func([], [Inbox], []),
    'send_message' : IDL.Func([SendMessageRequest], [Result], []),
  });
};
export const init = ({ IDL }) => { return []; };
