import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Option "mo:base/Option";
import Debug "mo:base/Debug";
import OrderedMap "mo:base/OrderedMap";
import Result "mo:base/Result";
import Types "../Types";
import Text "mo:base/Text";
import KeyManager "../key_manager/KeyManager";

module {
    type VetKeyVerificationKey = Blob;
    type VetKey = Blob;
    type Caller = Principal;
    type KeyName = Blob;
    type KeyId = (Caller, KeyName);
    type MapName = KeyName;
    type MapId = KeyId;
    type MapKey = Blob;
    type TransportKey = Blob;
    type EncryptedMapValue = Blob;

    type EncryptedMapData<T> = {
        map_owner : Principal;
        map_name : Blob;
        keyvals : [(Blob, EncryptedMapValue)];
        access_control : [(Principal, T)];
    };

    func compareKeyIds(a : KeyId, b : KeyId) : { #less; #greater; #equal } {
        let ownersCompare = Principal.compare(a.0, b.0);
        if (ownersCompare == #equal) {
            Blob.compare(a.1, b.1);
        } else {
            ownersCompare;
        };
    };

    func mapKeyValsMapOps() : OrderedMap.Operations<(KeyId, MapKey)> {
        let compare = func(a : (KeyId, MapKey), b : (KeyId, MapKey)) : {
            #less;
            #greater;
            #equal;
        } {
            let keyIdCompare = compareKeyIds(a.0, b.0);
            if (keyIdCompare == #equal) {
                Blob.compare(a.1, b.1);
            } else {
                keyIdCompare;
            };
        };
        return OrderedMap.Make<(KeyId, MapKey)>(compare);
    };

    func mapKeysMapOps() : OrderedMap.Operations<KeyId> {
        return OrderedMap.Make<KeyId>(compareKeyIds);
    };

    public class EncryptedMaps<T>(domainSeparatorArg : Text, accessRightsOperationsArg : Types.AccessControlOperations<T>) {
        let accessRightsOperations = accessRightsOperationsArg;
        public let domainSeparator = domainSeparatorArg;
        public var keyManager = KeyManager.KeyManager<T>(domainSeparatorArg, accessRightsOperationsArg);
        public var mapKeyVals : OrderedMap.Map<(KeyId, MapKey), EncryptedMapValue> = mapKeyValsMapOps().empty();
        public var mapKeys : OrderedMap.Map<KeyId, [MapKey]> = mapKeysMapOps().empty();

        // Get accessible shared map names for a caller
        public func getAccessibleSharedMapNames(caller : Caller) : [KeyId] {
            keyManager.getAccessibleSharedKeyIds(caller);
        };

        // Get shared user access for a map
        public func getSharedUserAccessForMap(caller : Caller, keyId : KeyId) : Result.Result<[(Caller, T)], Text> {
            keyManager.getSharedUserAccessForKey(caller, keyId);
        };

        // Remove all values from a map
        public func removeMapValues(caller : Caller, keyId : KeyId) : Result.Result<[MapKey], Text> {
            switch (keyManager.getUserRights(caller, keyId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(optRights)) {
                    switch (optRights) {
                        case (null) { #err("unauthorized") };
                        case (?rights) {
                            if (accessRightsOperations.canWrite(rights)) {
                                let keys = switch (mapKeysMapOps().get(mapKeys, keyId)) {
                                    case (null) { [] };
                                    case (?ks) { ks };
                                };
                                for (key in keys.vals()) {
                                    mapKeyVals := mapKeyValsMapOps().delete(mapKeyVals, (keyId, key));
                                };
                                mapKeys := mapKeysMapOps().delete(mapKeys, keyId);
                                #ok(keys);
                            } else {
                                #err("unauthorized");
                            };
                        };
                    };
                };
            };
        };

        // Get encrypted values for a map
        public func getEncryptedValuesForMap(caller : Caller, keyId : KeyId) : Result.Result<[(MapKey, EncryptedMapValue)], Text> {
            switch (keyManager.getUserRights(caller, keyId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let values = Buffer.Buffer<(MapKey, EncryptedMapValue)>(0);
                    let keys = switch (mapKeysMapOps().get(mapKeys, keyId)) {
                        case (null) { [] };
                        case (?ks) { ks };
                    };
                    for (key in keys.vals()) {
                        switch (mapKeyValsMapOps().get(mapKeyVals, (keyId, key))) {
                            case (null) {};
                            case (?value) {
                                values.add((key, value));
                            };
                        };
                    };
                    #ok(Buffer.toArray(values));
                };
            };
        };

        // Get encrypted value
        public func getEncryptedValue(caller : Caller, keyId : KeyId, key : MapKey) : Result.Result<?EncryptedMapValue, Text> {
            switch (keyManager.getUserRights(caller, keyId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    #ok(mapKeyValsMapOps().get(mapKeyVals, (keyId, key)));
                };
            };
        };

        // Get all accessible encrypted values
        public func getAllAccessibleEncryptedValues(caller : Caller) : [(MapId, [(MapKey, EncryptedMapValue)])] {
            let result = Buffer.Buffer<(MapId, [(MapKey, EncryptedMapValue)])>(0);
            for (mapId in getAccessibleMapIdsIter(caller)) {
                switch (getEncryptedValuesForMap(caller, mapId)) {
                    case (#err(_)) {
                        Debug.trap("bug: failed to get encrypted values");
                    };
                    case (#ok(mapValues)) {
                        result.add((mapId, mapValues));
                    };
                };
            };
            Buffer.toArray(result);
        };

        // Get all accessible encrypted maps
        public func getAllAccessibleEncryptedMaps(caller : Caller) : [EncryptedMapData<T>] {
            let result = Buffer.Buffer<EncryptedMapData<T>>(0);
            for (mapId in getAccessibleMapIdsIter(caller)) {
                let keyvals = switch (getEncryptedValuesForMap(caller, mapId)) {
                    case (#err(_)) {
                        Debug.trap("bug: failed to get encrypted values");
                    };
                    case (#ok(mapValues)) {
                        Array.map<(MapKey, EncryptedMapValue), (Blob, EncryptedMapValue)>(
                            mapValues,
                            func((key, value)) = (key, value),
                        );
                    };
                };
                let map = {
                    map_owner = mapId.0;
                    map_name = mapId.1;
                    keyvals = keyvals;
                    access_control = switch (getSharedUserAccessForMap(caller, mapId)) {
                        case (#err(_)) { [] };
                        case (#ok(access)) { access };
                    };
                };
                result.add(map);
            };
            Buffer.toArray(result);
        };

        // Get owned non-empty map names
        public func getOwnedNonEmptyMapNames(caller : Caller) : [MapName] {
            let mapNames = Buffer.Buffer<MapName>(0);
            for ((keyId, _) in mapKeysMapOps().entries(mapKeys)) {
                if (Principal.equal(keyId.0, caller)) {
                    mapNames.add(keyId.1);
                };
            };
            Buffer.toArray(mapNames);
        };

        // Insert encrypted value
        public func insertEncryptedValue(
            caller : Caller,
            keyId : KeyId,
            key : MapKey,
            encryptedValue : EncryptedMapValue,
        ) : Result.Result<?EncryptedMapValue, Text> {
            switch (keyManager.getUserRights(caller, keyId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(optRights)) {
                    switch (optRights) {
                        case (null) { #err("unauthorized") };
                        case (?rights) {
                            if (accessRightsOperations.canWrite(rights)) {
                                let oldValue = mapKeyValsMapOps().get(mapKeyVals, (keyId, key));
                                mapKeyVals := mapKeyValsMapOps().put(mapKeyVals, (keyId, key), encryptedValue);

                                // Update mapKeys
                                let currentKeys = switch (mapKeysMapOps().get(mapKeys, keyId)) {
                                    case (null) { [] };
                                    case (?ks) { ks };
                                };
                                if (Option.isNull(Array.find<MapKey>(currentKeys, func(k) = Blob.equal(k, key)))) {
                                    mapKeys := mapKeysMapOps().put(mapKeys, keyId, Array.append<MapKey>(currentKeys, [key]));
                                };

                                #ok(oldValue);
                            } else {
                                #err("unauthorized");
                            };
                        };
                    };
                };
            };
        };

        // Remove encrypted value
        public func removeEncryptedValue(
            caller : Caller,
            keyId : KeyId,
            key : MapKey,
        ) : Result.Result<?EncryptedMapValue, Text> {
            switch (keyManager.getUserRights(caller, keyId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(optRights)) {
                    switch (optRights) {
                        case (null) { #err("unauthorized") };
                        case (?rights) {
                            if (accessRightsOperations.canWrite(rights)) {
                                let oldValue = mapKeyValsMapOps().get(mapKeyVals, (keyId, key));
                                mapKeyVals := mapKeyValsMapOps().delete(mapKeyVals, (keyId, key));

                                // Update mapKeys
                                let currentKeys = switch (mapKeysMapOps().get(mapKeys, keyId)) {
                                    case (null) { [] };
                                    case (?ks) { ks };
                                };
                                let newKeys = Array.filter<MapKey>(currentKeys, func(k) = not Blob.equal(k, key));
                                if (newKeys.size() == 0) {
                                    mapKeys := mapKeysMapOps().delete(mapKeys, keyId);
                                } else {
                                    mapKeys := mapKeysMapOps().put(mapKeys, keyId, newKeys);
                                };

                                #ok(oldValue);
                            } else {
                                #err("unauthorized");
                            };
                        };
                    };
                };
            };
        };

        // Get vetkey verification key
        public func getVetkeyVerificationKey() : async VetKeyVerificationKey {
            await keyManager.getVetkeyVerificationKey();
        };

        // Get encrypted vetkey
        public func getEncryptedVetkey(
            caller : Caller,
            keyId : KeyId,
            transportKey : TransportKey,
        ) : async Result.Result<VetKey, Text> {
            await keyManager.getEncryptedVetkey(caller, keyId, transportKey);
        };

        // Get user rights
        public func getUserRights(caller : Caller, keyId : KeyId, user : Caller) : Result.Result<?T, Text> {
            keyManager.getUserRights(caller, keyId, user);
        };

        // Set user rights
        public func setUserRights(
            caller : Caller,
            keyId : KeyId,
            user : Caller,
            accessRights : T,
        ) : Result.Result<?T, Text> {
            keyManager.setUserRights(caller, keyId, user, accessRights);
        };

        // Remove user
        public func removeUser(caller : Caller, keyId : KeyId, user : Caller) : Result.Result<?T, Text> {
            keyManager.removeUserRights(caller, keyId, user);
        };

        // Private helper functions
        func getAccessibleMapIdsIter(caller : Caller) : Iter.Iter<MapId> {
            let accessibleMapIds = Iter.fromArray(getAccessibleSharedMapNames(caller));
            let ownedMapIds = Iter.map<MapName, MapId>(
                Iter.fromArray(getOwnedNonEmptyMapNames(caller)),
                func(mapName) = (caller, mapName),
            );
            return Iter.concat(accessibleMapIds, ownedMapIds);
        };
    };
};
