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
    public type Caller = Principal;
    public type MapName = KeyManager.KeyName;
    public type MapId = KeyManager.KeyId;
    public type MapKey = Blob;
    public type EncryptedMapValue = Blob;

    type EncryptedMapData<T> = {
        map_owner : Principal;
        map_name : MapName;
        keyvals : [(MapKey, EncryptedMapValue)];
        access_control : [(Principal, T)];
    };

    func compareMapIds(a : MapId, b : MapId) : { #less; #greater; #equal } {
        let ownersCompare = Principal.compare(a.0, b.0);
        if (ownersCompare == #equal) {
            Blob.compare(a.1, b.1);
        } else {
            ownersCompare;
        };
    };

    func mapKeyValsMapOps() : OrderedMap.Operations<(MapId, MapKey)> {
        let compare = func(a : (MapId, MapKey), b : (MapId, MapKey)) : {
            #less;
            #greater;
            #equal;
        } {
            let mapIdCompare = compareMapIds(a.0, b.0);
            if (mapIdCompare == #equal) {
                Blob.compare(a.1, b.1);
            } else {
                mapIdCompare;
            };
        };
        return OrderedMap.Make<(MapId, MapKey)>(compare);
    };

    func mapKeysMapOps() : OrderedMap.Operations<MapId> {
        return OrderedMap.Make<MapId>(compareMapIds);
    };

    public class EncryptedMaps<T>(key_id : { curve : { #bls12_381_g2 }; name : Text }, domainSeparator : Text, accessRightsOperations : Types.AccessControlOperations<T>) {
        public var keyManager = KeyManager.KeyManager<T>(key_id, domainSeparator, accessRightsOperations);
        public var mapKeyVals : OrderedMap.Map<(MapId, MapKey), EncryptedMapValue> = mapKeyValsMapOps().empty();
        public var mapKeys : OrderedMap.Map<MapId, [MapKey]> = mapKeysMapOps().empty();

        // Get accessible shared map names for a caller
        public func getAccessibleSharedMapNames(caller : Caller) : [MapId] {
            keyManager.getAccessibleSharedKeyIds(caller);
        };

        // Get shared user access for a map
        public func getSharedUserAccessForMap(caller : Caller, mapId : MapId) : Result.Result<[(Caller, T)], Text> {
            keyManager.getSharedUserAccessForKey(caller, mapId);
        };

        // Remove all values from a map
        public func removeMapValues(caller : Caller, mapId : MapId) : Result.Result<[MapKey], Text> {
            switch (keyManager.getUserRights(caller, mapId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(optRights)) {
                    switch (optRights) {
                        case (null) { #err("unauthorized") };
                        case (?rights) {
                            if (accessRightsOperations.canWrite(rights)) {
                                let keys = switch (mapKeysMapOps().get(mapKeys, mapId)) {
                                    case (null) { [] };
                                    case (?ks) { ks };
                                };
                                for (key in keys.vals()) {
                                    mapKeyVals := mapKeyValsMapOps().delete(mapKeyVals, (mapId, key));
                                };
                                mapKeys := mapKeysMapOps().delete(mapKeys, mapId);
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
        public func getEncryptedValuesForMap(caller : Caller, mapId : MapId) : Result.Result<[(MapKey, EncryptedMapValue)], Text> {
            switch (keyManager.getUserRights(caller, mapId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let values = Buffer.Buffer<(MapKey, EncryptedMapValue)>(0);
                    let keys = switch (mapKeysMapOps().get(mapKeys, mapId)) {
                        case (null) { [] };
                        case (?ks) { ks };
                    };
                    for (key in keys.vals()) {
                        switch (mapKeyValsMapOps().get(mapKeyVals, (mapId, key))) {
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
        public func getEncryptedValue(caller : Caller, mapId : MapId, key : MapKey) : Result.Result<?EncryptedMapValue, Text> {
            switch (keyManager.ensureUserCanRead(caller, mapId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    #ok(mapKeyValsMapOps().get(mapKeyVals, (mapId, key)));
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
            for ((mapId, _) in mapKeysMapOps().entries(mapKeys)) {
                if (Principal.equal(mapId.0, caller)) {
                    mapNames.add(mapId.1);
                };
            };
            Buffer.toArray(mapNames);
        };

        // Insert encrypted value
        public func insertEncryptedValue(
            caller : Caller,
            mapId : MapId,
            key : MapKey,
            encryptedValue : EncryptedMapValue,
        ) : Result.Result<?EncryptedMapValue, Text> {
            switch (keyManager.ensureUserCanWrite(caller, mapId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let oldValue = mapKeyValsMapOps().get(mapKeyVals, (mapId, key));
                    mapKeyVals := mapKeyValsMapOps().put(mapKeyVals, (mapId, key), encryptedValue);

                    // Update mapKeys
                    let currentKeys = switch (mapKeysMapOps().get(mapKeys, mapId)) {
                        case (null) { [] };
                        case (?ks) { ks };
                    };
                    if (Option.isNull(Array.find<MapKey>(currentKeys, func(k) = Blob.equal(k, key)))) {
                        mapKeys := mapKeysMapOps().put(mapKeys, mapId, Array.append<MapKey>(currentKeys, [key]));
                    };

                    #ok(oldValue);
                };
            };
        };

        // Remove encrypted value
        public func removeEncryptedValue(
            caller : Caller,
            mapId : MapId,
            key : MapKey,
        ) : Result.Result<?EncryptedMapValue, Text> {
            switch (keyManager.getUserRights(caller, mapId, caller)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let oldValue = mapKeyValsMapOps().get(mapKeyVals, (mapId, key));
                    mapKeyVals := mapKeyValsMapOps().delete(mapKeyVals, (mapId, key));

                    // Update mapKeys
                    let currentKeys = switch (mapKeysMapOps().get(mapKeys, mapId)) {
                        case (null) { [] };
                        case (?ks) { ks };
                    };
                    let newKeys = Array.filter<MapKey>(currentKeys, func(k) = not Blob.equal(k, key));
                    if (newKeys.size() == 0) {
                        mapKeys := mapKeysMapOps().delete(mapKeys, mapId);
                    } else {
                        mapKeys := mapKeysMapOps().put(mapKeys, mapId, newKeys);
                    };

                    #ok(oldValue);
                };
            };
        };

        // Get vetkey verification key
        public func getVetkeyVerificationKey() : async KeyManager.VetKeyVerificationKey {
            await keyManager.getVetkeyVerificationKey();
        };

        // Get encrypted vetkey
        public func getEncryptedVetkey(
            caller : Caller,
            mapId : MapId,
            transportKey : KeyManager.TransportKey,
        ) : async Result.Result<KeyManager.VetKey, Text> {
            await keyManager.getEncryptedVetkey(caller, mapId, transportKey);
        };

        // Get user rights
        public func getUserRights(caller : Caller, mapId : MapId, user : Principal) : Result.Result<?T, Text> {
            keyManager.getUserRights(caller, mapId, user);
        };

        // Set user rights
        public func setUserRights(
            caller : Caller,
            mapId : MapId,
            user : Principal,
            accessRights : T,
        ) : Result.Result<?T, Text> {
            keyManager.setUserRights(caller, mapId, user, accessRights);
        };

        // Remove user
        public func removeUser(caller : Caller, mapId : MapId, user : Principal) : Result.Result<?T, Text> {
            keyManager.removeUserRights(caller, mapId, user);
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
