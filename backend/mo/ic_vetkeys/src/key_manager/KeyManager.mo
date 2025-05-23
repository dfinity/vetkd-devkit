import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Debug "mo:base/Debug";
import OrderedMap "mo:base/OrderedMap";
import Result "mo:base/Result";
import Types "../Types";
import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";

module {
    public type VetKeyVerificationKey = Blob;
    public type VetKey = Blob;
    public type Owner = Principal;
    public type Caller = Principal;
    public type KeyName = Blob;
    public type KeyId = (Owner, KeyName);
    public type TransportKey = Blob;
    type VetkdSystemApi = actor {
        vetkd_public_key : ({
            canister_id : ?Principal;
            context : Blob;
            key_id : { curve : { #bls12_381_g2 }; name : Text };
        }) -> async ({ public_key : Blob });
        vetkd_derive_key : ({
            context : Blob;
            input : Blob;
            key_id : { curve : { #bls12_381_g2 }; name : Text };
            transport_public_key : Blob;
        }) -> async ({ encrypted_key : Blob });
    };

    func compareKeyIds(a : KeyId, b : KeyId) : { #less; #greater; #equal } {
        let ownersCompare = Principal.compare(a.0, b.0);
        if (ownersCompare == #equal) {
            Blob.compare(a.1, b.1);
        } else {
            ownersCompare;
        };
    };

    func accessControlMapOps() : OrderedMap.Operations<Caller> {
        OrderedMap.Make<Caller>(Principal.compare);
    };

    func sharedKeysMapOps() : OrderedMap.Operations<KeyId> {
        OrderedMap.Make<KeyId>(compareKeyIds);
    };

    // KeyManager class
    public class KeyManager<T>(key_id : { curve : { #bls12_381_g2 }; name : Text }, domainSeparator : Text, accessRightsOperations : Types.AccessControlOperations<T>) {
        public var accessControl : OrderedMap.Map<Principal, [(KeyId, T)]> = accessControlMapOps().empty();
        public var sharedKeys : OrderedMap.Map<KeyId, [Principal]> = sharedKeysMapOps().empty();
        let domainSeparatorBytes = Text.encodeUtf8(domainSeparator);

        // Get accessible shared key IDs for a caller
        public func getAccessibleSharedKeyIds(caller : Caller) : [KeyId] {
            switch (accessControlMapOps().get(accessControl, caller)) {
                case (null) { [] };
                case (?entries) {
                    Array.map<(KeyId, T), KeyId>(entries, func((keyId, _)) = keyId);
                };
            };
        };

        // Get shared user access for a key
        public func getSharedUserAccessForKey(caller : Caller, keyId : KeyId) : Result.Result<[(Caller, T)], Text> {
            let canRead = ensureUserCanRead(caller, keyId);
            switch (canRead) {
                case (#err(msg)) { return #err(msg) };
                case (_) {};
            };

            let users = switch (sharedKeysMapOps().get(sharedKeys, keyId)) {
                case (null) { return #ok([]) };
                case (?users) users;
            };

            let results = Buffer.Buffer<(Caller, T)>(0);
            for (user in users.vals()) {
                switch (getUserRights(caller, keyId, user)) {
                    case (#err(msg)) { return #err(msg) };
                    case (#ok(optRights)) {
                        switch (optRights) {
                            case (null) {
                                Debug.trap("bug: missing access rights");
                            };
                            case (?rights) {
                                results.add((user, rights));
                            };
                        };
                    };
                };
            };
            #ok(Buffer.toArray(results));
        };

        // Get vetkey verification key
        public func getVetkeyVerificationKey() : async VetKeyVerificationKey {
            let context = domainSeparatorBytes;

            let request = {
                canister_id = null;
                context;
                key_id;
            };

            let (reply) = await (actor ("aaaaa-aa") : VetkdSystemApi).vetkd_public_key(request);
            reply.public_key;
        };

        // Get encrypted vetkey
        public func getEncryptedVetkey(caller : Caller, keyId : KeyId, transportKey : TransportKey) : async Result.Result<VetKey, Text> {
            switch (ensureUserCanRead(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let principalBytes = Blob.toArray(Principal.toBlob(keyId.0));
                    let input = Array.flatten<Nat8>([
                        [Nat8.fromNat(Array.size<Nat8>(principalBytes))],
                        principalBytes,
                        Blob.toArray(keyId.1),
                    ]);

                    let context = domainSeparatorBytes;

                    let request = {
                        input = Blob.fromArray(input);
                        context;
                        key_id;
                        transport_public_key = transportKey;
                    };

                    let (reply) = await (with cycles = 26_153_846_153) (actor ("aaaaa-aa") : VetkdSystemApi).vetkd_derive_key(request);
                    #ok(reply.encrypted_key);
                };
            };
        };

        // Get user rights
        public func getUserRights(caller : Caller, keyId : KeyId, user : Principal) : Result.Result<?T, Text> {
            switch (ensureUserCanGetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    #ok(
                        do ? {
                            if (Principal.equal(user, keyId.0)) {
                                accessRightsOperations.ownerRights();
                            } else {
                                let entries = accessControlMapOps().get(accessControl, user)!;
                                let (k, rights) = Array.find<(KeyId, T)>(
                                    entries,
                                    func((k, rights)) = compareKeyIds(k, keyId) == #equal,
                                )!;
                                rights;
                            };
                        }
                    );
                };
            };
        };

        // Set user rights
        public func setUserRights(caller : Caller, keyId : KeyId, user : Principal, accessRights : T) : Result.Result<?T, Text> {
            switch (ensureUserCanSetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    if (Principal.equal(caller, keyId.0) and Principal.equal(caller, user)) {
                        return #err("Cannot change key owner's user rights");
                    };

                    // Update sharedKeys
                    let currentUsers = switch (sharedKeysMapOps().get(sharedKeys, keyId)) {
                        case (null) { [] };
                        case (?users) { users };
                    };

                    let newUsers = switch (Array.indexOf<Principal>(user, currentUsers, Principal.equal)) {
                        case (?_) currentUsers;
                        case (null) Array.append<Principal>(currentUsers, [user]);
                    };

                    sharedKeys := sharedKeysMapOps().put(sharedKeys, keyId, newUsers);

                    // Update accessControl
                    let currentEntries = switch (accessControlMapOps().get(accessControl, user)) {
                        case (null) { [] };
                        case (?entries) { entries };
                    };

                    var oldRights : ?T = null;
                    let newEntries = switch (
                        Array.indexOf<(KeyId, T)>(
                            (keyId, accessRightsOperations.ownerRights()),
                            currentEntries,
                            func(a, b) = compareKeyIds(a.0, b.0) == #equal,
                        )
                    ) {
                        case (?index) {
                            let mutCurrentEntries = Array.thaw<(KeyId, T)>(currentEntries);
                            oldRights := ?mutCurrentEntries[index].1;
                            mutCurrentEntries[index] := (keyId, accessRights);
                            Array.freeze(mutCurrentEntries);
                        };
                        case (null) {
                            Array.append<(KeyId, T)>(currentEntries, [(keyId, accessRights)]);
                        };
                    };
                    accessControl := accessControlMapOps().put(accessControl, user, newEntries);
                    #ok(oldRights);
                };
            };
        };

        // Remove user
        public func removeUserRights(caller : Caller, keyId : KeyId, user : Principal) : Result.Result<?T, Text> {
            switch (ensureUserCanSetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    if (Principal.equal(caller, user) and Principal.equal(caller, keyId.0)) {
                        return #err("Cannot remove key owner");
                    };

                    // Update sharedKeys
                    let currentUsers = switch (sharedKeysMapOps().get(sharedKeys, keyId)) {
                        case (null) { [] };
                        case (?users) { users };
                    };
                    let newUsers = Array.filter<Caller>(currentUsers, func(u) = not Principal.equal(u, user));
                    sharedKeys := sharedKeysMapOps().put(sharedKeys, keyId, newUsers);

                    // Update accessControl
                    let currentEntries = switch (accessControlMapOps().get(accessControl, user)) {
                        case (null) { [] };
                        case (?entries) { entries };
                    };
                    let (newEntries, oldRights) = Array.foldRight<(KeyId, T), ([(KeyId, T)], ?T)>(
                        currentEntries,
                        ([], null),
                        func((k, r), (entries, rights)) {
                            if (compareKeyIds(k, keyId) == #equal) {
                                (entries, ?r);
                            } else {
                                (Array.append<(KeyId, T)>(entries, [(k, r)]), rights);
                            };
                        },
                    );
                    accessControl := accessControlMapOps().put(accessControl, user, newEntries);
                    #ok(oldRights);
                };
            };
        };

        public func ensureUserCanRead(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canRead(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        public func ensureUserCanWrite(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canWrite(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        private func ensureUserCanGetUserRights(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canGetUserRights(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        private func ensureUserCanSetUserRights(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canSetUserRights(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };
    };
};
