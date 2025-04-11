import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Debug "mo:base/Debug";
import OrderedMap "mo:base/OrderedMap";
import Result "mo:base/Result";
import Types "../Types";
import Text "mo:base/Text";

module {
    type VetKeyVerificationKey = Blob;
    type VetKey = Blob;
    type Creator = Principal;
    type Caller = Principal;
    type KeyName = Blob;
    type KeyId = (Caller, KeyName);
    type TransportKey = Blob;
    type VetkdSystemApi = actor {
        vetkd_public_key : ({
            canister_id : ?Principal;
            derivation_path : [Blob];
            key_id : { curve : { #bls12_381_g2 }; name : Text };
        }) -> async ({ public_key : Blob });
        vetkd_derive_encrypted_key : ({
            derivation_path : [Blob];
            derivation_id : Blob;
            key_id : { curve : { #bls12_381_g2 }; name : Text };
            encryption_public_key : Blob;
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
    public class KeyManager<T>(domainSeparatorArg : Text, accessRightsOperationsArg : Types.AccessControlOperations<T>) {
        let accessRightsOperations = accessRightsOperationsArg;
        public let domainSeparator = domainSeparatorArg;
        public var accessControl : OrderedMap.Map<Caller, [(KeyId, T)]> = accessControlMapOps().empty();
        public var sharedKeys : OrderedMap.Map<KeyId, [Caller]> = sharedKeysMapOps().empty();
        public var managementCanisterPrincipalText = "aaaaa-aa";

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
            switch (ensureUserCanGetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    switch (sharedKeysMapOps().get(sharedKeys, keyId)) {
                        case (null) { #ok([]) };
                        case (?users) {
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
                    };
                };
            };
        };

        // Get vetkey verification key
        public func getVetkeyVerificationKey() : async VetKeyVerificationKey {
            let derivationPath = [Text.encodeUtf8(domainSeparator)];

            let request = {
                canister_id = null;
                derivation_path = derivationPath;
                key_id = bls12_381TestKey1();
            };

            let (reply) = await (actor (managementCanisterPrincipalText) : VetkdSystemApi).vetkd_public_key(request);
            reply.public_key;
        };

        // Get encrypted vetkey
        public func getEncryptedVetkey(caller : Caller, keyId : KeyId, transportKey : TransportKey) : async Result.Result<VetKey, Text> {
            switch (ensureUserCanRead(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let derivationId = Array.flatten<Nat8>([
                        Blob.toArray(Principal.toBlob(keyId.0)),
                        Blob.toArray(keyId.1),
                    ]);

                    let derivationPath = [Text.encodeUtf8(domainSeparator)];

                    let request = {
                        derivation_id = Blob.fromArray(derivationId);
                        derivation_path = derivationPath;
                        key_id = bls12_381TestKey1();
                        encryption_public_key = transportKey;
                    };

                    let (reply) = await (actor (managementCanisterPrincipalText) : VetkdSystemApi).vetkd_derive_encrypted_key(request);
                    #ok(reply.encrypted_key);
                };
            };
        };

        // Get user rights
        public func getUserRights(caller : Caller, keyId : KeyId, user : Caller) : Result.Result<?T, Text> {
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
                                    func((k, rights)) = Principal.equal(k.0, keyId.0) and Blob.equal(k.1, keyId.1),
                                )!;
                                rights;
                            };
                        }
                    );
                };
            };
        };

        // Set user rights
        public func setUserRights(caller : Caller, keyId : KeyId, user : Caller, accessRights : T) : Result.Result<?T, Text> {
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

                    let newUsers = switch (Array.indexOf<Caller>(user, currentUsers, Principal.equal)) {
                        case (?index) {
                            let mutCurrentUsers = Array.thaw<Caller>(currentUsers);
                            mutCurrentUsers[index] := user;
                            Array.freeze(mutCurrentUsers);
                        };
                        case (null) {
                            Array.append<Caller>(currentUsers, [user]);
                        };
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
                    if (Array.size<(KeyId, T)>(newEntries) > 0) {
                        accessControl := accessControlMapOps().put(accessControl, user, newEntries);
                    } else {
                        accessControl := accessControlMapOps().delete(accessControl, user);
                    };
                    #ok(oldRights);
                };
            };
        };

        // Remove user
        public func removeUserRights(caller : Caller, keyId : KeyId, user : Caller) : Result.Result<?T, Text> {
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
                            if (Principal.equal(k.0, keyId.0) and Blob.equal(k.1, keyId.1)) {
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

        private func ensureUserCanRead(user : Caller, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (Principal.equal(k.0, keyId.0) and Blob.equal(k.1, keyId.1)) {
                            return #ok(rights);
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        private func ensureUserCanGetUserRights(user : Caller, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (Principal.equal(k.0, keyId.0) and Blob.equal(k.1, keyId.1)) {
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

        private func ensureUserCanSetUserRights(user : Caller, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (Principal.equal(k.0, keyId.0) and Blob.equal(k.1, keyId.1)) {
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

    // Helper function for BLS12-381 test key
    func bls12_381TestKey1() : { curve : { #bls12_381_g2 }; name : Text } {
        { curve = #bls12_381_g2; name = "insecure_text_key_1" };
    };
};
