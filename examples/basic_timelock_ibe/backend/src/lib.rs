use crate::types::{DecryptedBid, EncryptedBid, LotId, LotInformation};
use candid::Principal;
use ic_cdk::api::management_canister::provisional::CanisterId;
use ic_cdk::{init, post_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap as StableBTreeMap, DefaultMemoryImpl};
use ic_vetkd_utils::{DerivedPublicKey, EncryptedVetKey};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::str::FromStr;

mod types;
use types::*;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type VetKeyPublicKey = ByteBuf;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static LOTS: RefCell<StableBTreeMap<LotId, LotInformation, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
    ));
    static BIDS_ON_LOTS: RefCell<StableBTreeMap<(LotId, Principal), Bid, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
    ));
    static OPEN_LOTS_DEADLINES: RefCell<StableBTreeMap<u64, LotId, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
    ));

    static VETKD_ROOT_IBE_PUBLIC_KEY: RefCell<Option<VetKeyPublicKey>> = RefCell::new(None);

    #[cfg(feature = "expose-testing-api")]
    static CANISTER_ID_VETKD_MOCK: RefCell<Option<Principal>> = const { RefCell::new(None) };
}

const DOMAIN_SEPARATOR: &str = "basic_timelock_ibe_example_dapp";
const CANISTER_ID_VETKD_SYSTEM_API: &str = "aaaaa-aa";

#[init]
fn init() {
    start_with_interval_secs(5);
}

#[post_upgrade]
fn post_upgrade() {
    start_with_interval_secs(5);
}

#[update(guard = is_authenticated)]
fn create_lot(name: String, description: String, duration_seconds: u16) -> Result<LotId, String> {
    let caller = ic_cdk::caller();
    ic_cdk::println!(
        "create_lot: name={:?}, description={:?}, duration_seconds={:?}",
        name,
        description,
        duration_seconds
    );

    if duration_seconds == 0 {
        return Err("Duration must be greater than 0".to_string());
    }

    let lot_id = LOTS.with_borrow_mut(|lots| {
        let lot_id = lots.len() as u128;

        let lot = LotInformation {
            id: lot_id,
            name,
            description,
            start_time: ic_cdk::api::time(),
            end_time: ic_cdk::api::time() + duration_seconds as u64 * 1_000_000_000,
            creator: caller,
            status: LotStatus::Open(0),
        };

        OPEN_LOTS_DEADLINES.with_borrow_mut(|open_lots_deadlines| {
            open_lots_deadlines.insert(lot.end_time, lot_id);
        });

        lots.insert(lot_id, lot);

        lot_id
    });

    Ok(lot_id)
}

#[update(guard = is_authenticated)]
async fn get_root_ibe_public_key() -> VetKeyPublicKey {
    if let Some(key) = VETKD_ROOT_IBE_PUBLIC_KEY.with_borrow(|key| key.clone()) {
        return key;
    }

    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![DOMAIN_SEPARATOR.as_bytes().to_vec()],
        key_id: bls12_381_test_key_1(),
    };

    let (result,) = ic_cdk::api::call::call::<_, (VetKDPublicKeyReply,)>(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("call to vetkd_public_key failed");

    VetKeyPublicKey::from(result.public_key)
}

#[query(guard = is_authenticated)]
fn get_lots() -> (OpenLotsResponse, ClosedLotsResponse) {
    let caller = ic_cdk::caller();
    let mut open_lots = OpenLotsResponse::default();
    let mut closed_lots = ClosedLotsResponse::default();

    LOTS.with_borrow(|lots| {
        for (lot_id, lot) in lots.iter() {
            let have_i_bid = BIDS_ON_LOTS.with_borrow(|bids| bids.get(&(lot_id, caller)).is_some());
            match lot.status {
                LotStatus::Open(_) => {
                    open_lots.have_i_bid.push(have_i_bid);
                    open_lots.lots.push(lot);
                }
                _ => {
                    closed_lots.have_i_bid.push(have_i_bid);
                    closed_lots.lots.push(lot);

                    let bids: Vec<u128> = BIDS_ON_LOTS.with_borrow(|bids| {
                        bids.range((lot_id, Principal::management_canister())..)
                            .take_while(|((this_lot_id, _), _)| *this_lot_id == lot_id)
                            .map(|(_, bid)| match bid {
                                Bid::Encrypted(_) => {
                                    panic!("bug: encrypted bid in a closed lot")
                                }
                                Bid::Decrypted(decrypted_bid) => decrypted_bid.amount,
                            })
                            .collect()
                    });
                    closed_lots.bids.push(bids);
                }
            }
        }
    });
    (open_lots, closed_lots)
}

#[update(guard = is_authenticated)]
fn place_bid(lot_id: u128, encrypted_amount: Vec<u8>) -> Result<(), String> {
    let bidder = ic_cdk::caller();
    let now = ic_cdk::api::time();
    ic_cdk::println!(
        "place_bid: lot_id={:?}, bidder={:?}, encrypted_amount={:?}",
        lot_id,
        bidder,
        encrypted_amount
    );

    LOTS.with_borrow(|lots| match lots.get(&lot_id) {
        Some(LotInformation {
            status: LotStatus::Open(_),
            creator,
            end_time,
            ..
        }) if creator != bidder && now < end_time => Ok(()),
        Some(LotInformation { creator, .. }) if creator == bidder => {
            Err("lot creator cannot bid".to_string())
        }
        Some(_) => Err("lot is closed".to_string()),
        None => Err("lot not found".to_string()),
    })?;

    if encrypted_amount.len() > 1000 {
        return Err("encrypted amount is too large to be valid".to_string());
    }

    BIDS_ON_LOTS.with_borrow_mut(|bids| {
        bids.insert(
            (lot_id, bidder),
            Bid::Encrypted(EncryptedBid {
                encrypted_amount,
                bidder,
            }),
        );
    });

    Ok(())
}

#[update]
fn start_with_interval_secs(secs: u64) {
    ic_cdk::println!("start_with_interval_secs: {:?}", secs);
    let secs = std::time::Duration::from_secs(secs);
    ic_cdk_timers::set_timer_interval(secs, || ic_cdk::spawn(close_one_lot_if_any_is_open()));
}

async fn close_one_lot_if_any_is_open() {
    let root_ibe_public_key =
        if let Some(key) = VETKD_ROOT_IBE_PUBLIC_KEY.with_borrow(|key| key.clone()) {
            key
        } else {
            get_root_ibe_public_key().await
        }
        .to_vec();

    let now = ic_cdk::api::time();
    let lot_to_close: Option<LotId> = OPEN_LOTS_DEADLINES.with_borrow_mut(|open_lots_deadlines| {
        open_lots_deadlines
            .iter()
            .take_while(|(deadline, _)| *deadline <= now)
            .next()
            .map(|(deadline, lot_to_close)| {
                // remove the lot from the open lots deadlines to prevent double processing
                open_lots_deadlines.remove(&deadline);
                lot_to_close
            })
    });

    ic_cdk::println!("close_one_lot_if_any_is_open: {:?}", lot_to_close);

    if let Some(lot_id) = lot_to_close {
        let encrypted_bids: Vec<EncryptedBid> = BIDS_ON_LOTS.with_borrow(|bids| {
            bids.range((lot_id, Principal::management_canister())..)
                .take_while(|((this_lot_id, _), _)| *this_lot_id == lot_id)
                .map(|(_, bid)| match bid {
                    Bid::Encrypted(encrypted_bid) => encrypted_bid,
                    Bid::Decrypted(_) => panic!("bug: decrypted bid in a closed lot"),
                })
                .collect()
        });

        let decrypted_bids = decrypt_bids(lot_id, encrypted_bids, root_ibe_public_key).await;

        let status = match decrypted_bids.iter().max_by(|x, y| x.amount.cmp(&y.amount)) {
            Some(winner_bid) => LotStatus::ClosedWithWinner(winner_bid.bidder),
            None => LotStatus::ClosedNoBids,
        };

        BIDS_ON_LOTS.with_borrow_mut(|bids| {
            for decrypted_bid in decrypted_bids {
                // replace the encrypted bid with the decrypted bid
                bids.insert(
                    (lot_id, decrypted_bid.bidder),
                    Bid::Decrypted(decrypted_bid),
                );
            }
        });

        LOTS.with_borrow_mut(|lots| {
            lots.insert(
                lot_id,
                LotInformation {
                    id: lot_id,
                    name: lots.get(&lot_id).unwrap().name,
                    description: lots.get(&lot_id).unwrap().description,
                    start_time: lots.get(&lot_id).unwrap().start_time,
                    end_time: lots.get(&lot_id).unwrap().end_time,
                    creator: lots.get(&lot_id).unwrap().creator,
                    status,
                },
            );
        });
    }
}

async fn decrypt_bids(
    lot_id: LotId,
    encrypted_bids: Vec<EncryptedBid>,
    root_ibe_public_key_bytes: Vec<u8>,
) -> Vec<DecryptedBid> {
    let dummy_seed = vec![0; 32];
    let transport_secret_key = ic_vetkd_utils::TransportSecretKey::from_seed(dummy_seed.clone())
        .expect("failed to create transport secret key");

    let request = VetKDEncryptedKeyRequest {
        public_key_derivation_path: vec![DOMAIN_SEPARATOR.as_bytes().to_vec()],
        derivation_id: lot_id.to_le_bytes().to_vec(),
        key_id: bls12_381_test_key_1(),
        encryption_public_key: transport_secret_key.public_key().to_vec(),
    };

    let (result,) = ic_cdk::api::call::call::<_, (VetKDEncryptedKeyReply,)>(
        vetkd_system_api_canister_id(),
        "vetkd_encrypted_key",
        (request,),
    )
    .await
    .expect("call to vetkd_encrypted_key failed");

    let root_ibe_public_key = DerivedPublicKey::deserialize(&root_ibe_public_key_bytes).unwrap();
    let encrypted_vetkey = EncryptedVetKey::deserialize(&result.encrypted_key).unwrap();

    let ibe_decryption_key = encrypted_vetkey
        .decrypt_and_verify(
            &transport_secret_key,
            &root_ibe_public_key,
            &lot_id.to_le_bytes().to_vec(),
        )
        .expect("failed to decrypt ibe key");

    let mut decrypted_bids = Vec::new();

    for encrypted_bid in encrypted_bids {
        let decrypted_bid: Result<u128, String> =
            ic_vetkd_utils::IBECiphertext::deserialize(&encrypted_bid.encrypted_amount)
                .map_err(|e| format!("failed to deserialize ibe ciphertext: {e}"))
                .and_then(|c| {
                    c.decrypt(&ibe_decryption_key)
                        .map_err(|_| "failed to decrypt ibe ciphertext".to_string())
                })
                .and_then(|bytes| {
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| "failed to convert amount to u128".to_string())
                })
                .map(|array| u128::from_le_bytes(array));
        match decrypted_bid {
            Ok(amount) => {
                decrypted_bids.push(DecryptedBid {
                    amount,
                    bidder: encrypted_bid.bidder,
                });
            }
            Err(e) => {
                ic_cdk::println!(
                    "Failed to decrypt bid for lot id {lot_id} by {}: {e}",
                    encrypted_bid.bidder
                );
            }
        }
    }
    decrypted_bids
}

fn is_authenticated() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if caller != Principal::anonymous() {
        Ok(())
    } else {
        Err("the caller must be authenticated".to_string())
    }
}

fn bls12_381_test_key_1() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381,
        name: "insecure_test_key_1".to_string(),
    }
}

fn vetkd_system_api_canister_id() -> CanisterId {
    #[cfg(feature = "expose-testing-api")]
    {
        if let Some(canister_id) = CANISTER_ID_VETKD_MOCK.with(|cell| cell.borrow().clone()) {
            return canister_id;
        }
    }
    CanisterId::from_str(CANISTER_ID_VETKD_SYSTEM_API).expect("failed to create canister ID")
}

#[cfg(feature = "expose-testing-api")]
#[update]
fn set_vetkd_testing_canister_id(vetkd_testing_canister: Principal) {
    CANISTER_ID_VETKD_MOCK.with(|cell| {
        *cell.borrow_mut() = Some(vetkd_testing_canister);
    });
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some other dependencies) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// the used RNGs are _manually_ seeded rather than by the system.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();
