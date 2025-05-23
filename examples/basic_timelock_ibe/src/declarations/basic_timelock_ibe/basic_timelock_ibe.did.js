export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : IDL.Text });
  const LotStatus = IDL.Variant({
    'Open' : IDL.Null,
    'ClosedWithWinner' : IDL.Principal,
    'ClosedNoBids' : IDL.Null,
  });
  const LotInformation = IDL.Record({
    'id' : IDL.Nat,
    'status' : LotStatus,
    'creator' : IDL.Principal,
    'name' : IDL.Text,
    'description' : IDL.Text,
    'end_time' : IDL.Nat64,
    'start_time' : IDL.Nat64,
  });
  const OpenLotsResponse = IDL.Record({
    'lots' : IDL.Vec(LotInformation),
    'bidders' : IDL.Vec(IDL.Vec(IDL.Principal)),
  });
  const ClosedLotsResponse = IDL.Record({
    'bids' : IDL.Vec(IDL.Vec(IDL.Tuple(IDL.Principal, IDL.Nat))),
    'lots' : IDL.Vec(LotInformation),
  });
  const Result_1 = IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text });
  return IDL.Service({
    'create_lot' : IDL.Func([IDL.Text, IDL.Text, IDL.Nat16], [Result], []),
    'get_lots' : IDL.Func(
        [],
        [OpenLotsResponse, ClosedLotsResponse],
        ['query'],
      ),
    'get_root_ibe_public_key' : IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    'place_bid' : IDL.Func([IDL.Nat, IDL.Vec(IDL.Nat8)], [Result_1], []),
    'start_with_interval_secs' : IDL.Func([IDL.Nat64], [], []),
  });
};
export const init = ({ IDL }) => { return [IDL.Text]; };
