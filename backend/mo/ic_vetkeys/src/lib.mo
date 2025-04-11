import KeyManagerModule "key_manager/KeyManager";
import EncryptedMapsModule "encrypted_maps/EncryptedMaps";
import Types "Types";

module {
	public type AccessControlOperations<T> = Types.AccessControlOperations<T>;
	public type AccessRights = Types.AccessRights;

	public type KeyManager<T> = KeyManagerModule.KeyManager<T>;
	public let KeyManager = KeyManagerModule.KeyManager;
	public type EncryptedMaps<T> = EncryptedMapsModule.EncryptedMaps<T>;
	public let EncryptedMaps = EncryptedMapsModule.EncryptedMaps;
	public let accessRightsOperations = Types.accessRightsOperations;
};
