export const idlFactory = ({ IDL }) => {
  const Signature = IDL.Record({
    'signature' : IDL.Vec(IDL.Nat8),
    'message' : IDL.Text,
    'timestamp' : IDL.Nat64,
    'signer' : IDL.Principal,
  });
  return IDL.Service({
    'get_published_signatures' : IDL.Func([], [IDL.Vec(Signature)], ['query']),
    'get_root_public_key' : IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    'publish_my_signature_no_verification' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8)],
        [],
        [],
      ),
    'sign_message' : IDL.Func([IDL.Text], [IDL.Vec(IDL.Nat8)], []),
  });
};
export const init = ({ IDL }) => { return []; };
