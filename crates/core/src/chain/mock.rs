//! `MockChainBackend` + its in-memory state -- the offline e2e on-chain stand-in(PR4 move-only).
use super::types::*;
use super::{note_id_hex, ChainBackend};
use crate::machine::{Settlement, StreamMachine};
use crate::note::{Note, NotePubkey};
use crate::params::{DobParams, ProtocolConsts, Shell};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Endpoints file record: key -- `token_contract`, value -- the endpoint ciphertext.
/// The same format carries over to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EndpointsFile {
    /// `token_contract` -> base64-independent raw ciphertext(as Vec<u8> in JSON).
    handovers: HashMap<TokenContract, Vec<u8>>,
}

/// Internal state of a single stream in the mock.
#[derive(Serialize, Deserialize)]
struct StreamCell {
    machine: StreamMachine,
    buyer_pubkey: NotePubkey,
    seller_locked: u128,
    buyer_locked: u128,
    seller_received: u128,
    buyer_refunded: u128,
    burned: u128,
    closed: bool,
    /// The agreed ceiling on delivered ticks. Guard in `advance_tick`
    /// the mock does not deliver more than the offer, just as the real TC is bounded by deposit.
    #[serde(default = "unbounded_max_ticks")]
    max_ticks: u64,
    /// A dispute is open: this deal's contested amount and seller bond are frozen(not burned)
    /// until `release_dispute`, which returns the contested amount to the buyer.
    #[serde(default)]
    disputed: bool,
}

/// Default `max_ticks` for the old/carried state field -- no ceiling(do not block existing streams).
fn unbounded_max_ticks() -> u64 {
    u64::MAX
}

/// Internal state of the mock on-chain. Serialized to a sidecar file -- this makes the mock
/// **shared across processes** the same way the real chain is in (book/matches/streams
/// live outside the processes). The endpoints file holds ONLY the handover format SEPARATELY.
#[derive(Serialize, Deserialize, Default)]
struct MockState {
    offers: HashMap<TokenContract, SellOffer>,
    /// Filled offers are no longer active book asks, but the consumed terms remain part of the deal.
    #[serde(default)]
    matched_offers: HashMap<TokenContract, SellOffer>,
    /// Seller(hex of the note's ed-pubkey) per offer -- for discovery/blacklist.
    #[serde(default)]
    offer_sellers: HashMap<TokenContract, String>,
    matches: HashMap<TokenContract, Match>,
    streams: HashMap<TokenContract, StreamCell>,
}

/// Mock on-chain backend. Book/matches/streams -- in the sidecar state file;
/// the enc-endpoint -- in the endpoints file.
#[derive(Clone)]
pub struct MockChainBackend {
    /// Serialization of critical sections(atomicity of read-modify-write over the file).
    lock: Arc<Mutex<()>>,
    endpoints_path: PathBuf,
    state_path: PathBuf,
    consts: ProtocolConsts,
    params: DobParams,
}

impl MockChainBackend {
    /// Create a mock with the given endpoints file path. The on-chain state is placed alongside
    /// in `<endpoints>.chainstate.json` -- shared between the seller/buyer processes.
    pub fn new(endpoints_path: PathBuf, consts: ProtocolConsts, params: DobParams) -> Self {
        let state_path = endpoints_path.with_extension("chainstate.json");
        Self {
            lock: Arc::new(Mutex::new(())),
            endpoints_path,
            state_path,
            consts,
            params,
        }
    }

    fn load_state(&self) -> Result<MockState, ChainError> {
        match std::fs::read(&self.state_path) {
            Ok(bytes) if !bytes.is_empty() => {
                serde_json::from_slice(&bytes).map_err(|e| ChainError::EndpointsFile(e.to_string()))
            }
            Ok(_) => Ok(MockState::default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MockState::default()),
            Err(e) => Err(ChainError::EndpointsFile(e.to_string())),
        }
    }

    fn store_state(&self, st: &MockState) -> Result<(), ChainError> {
        let bytes = serde_json::to_vec(st).map_err(|e| ChainError::EndpointsFile(e.to_string()))?;
        std::fs::write(&self.state_path, bytes)
            .map_err(|e| ChainError::EndpointsFile(e.to_string()))
    }

    fn read_endpoints(&self) -> Result<EndpointsFile, ChainError> {
        match std::fs::read(&self.endpoints_path) {
            Ok(bytes) if !bytes.is_empty() => {
                serde_json::from_slice(&bytes).map_err(|e| ChainError::EndpointsFile(e.to_string()))
            }
            Ok(_) => Ok(EndpointsFile::default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EndpointsFile::default()),
            Err(e) => Err(ChainError::EndpointsFile(e.to_string())),
        }
    }

    fn write_endpoints(&self, f: &EndpointsFile) -> Result<(), ChainError> {
        let bytes = serde_json::to_vec(f).map_err(|e| ChainError::EndpointsFile(e.to_string()))?;
        std::fs::write(&self.endpoints_path, bytes)
            .map_err(|e| ChainError::EndpointsFile(e.to_string()))
    }
}

#[async_trait]
impl ChainBackend for MockChainBackend {
    async fn discover_offers(&self) -> Result<Vec<OfferListing>, ChainError> {
        let _g = self.lock.lock().unwrap();
        let st = self.load_state()?;
        Ok(st
            .offers
            .values()
            .map(|o| OfferListing {
                seller_id: st
                    .offer_sellers
                    .get(&o.token_contract)
                    .cloned()
                    .unwrap_or_default(),
                token_contract: o.token_contract.clone(),
                price_per_tick: o.price_per_tick,
                max_ticks: o.max_ticks,
            })
            .collect())
    }

    async fn post_offer(&self, offer: SellOffer, note: &dyn Note) -> Result<(), ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        // Seller = hex of the note's ed-pubkey.
        let seller_id: String = note
            .pubkey()
            .ed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if st.offers.contains_key(&offer.token_contract) {
            return Err(ChainError::Chain(format!(
                "duplicate active sell order for TokenContract {}: cancel/fill the old order before reposting",
                offer.token_contract
            )));
        }
        st.offer_sellers
            .insert(offer.token_contract.clone(), seller_id);
        st.offers.insert(offer.token_contract.clone(), offer);
        self.store_state(&st)
    }

    async fn place_buy(
        &self,
        token_contract: &TokenContract,
        note: &dyn Note,
    ) -> Result<(), ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let offer = st
            .offers
            .get(token_contract)
            .ok_or_else(|| ChainError::NoMatch(token_contract.clone()))?
            .clone();
        st.offers.remove(token_contract);
        st.matched_offers
            .insert(token_contract.clone(), offer.clone());
        // The order book records the buyer's pubkey into token_contract. The order book's role is done.
        st.matches.insert(
            token_contract.clone(),
            Match {
                token_contract: token_contract.clone(),
                buyer_pubkey: note.pubkey(),
                price_per_tick: offer.price_per_tick,
            },
        );
        self.store_state(&st)
    }

    async fn read_match(&self, token_contract: &TokenContract) -> Result<Match, ChainError> {
        let _g = self.lock.lock().unwrap();
        let st = self.load_state()?;
        st.matches
            .get(token_contract)
            .cloned()
            .ok_or_else(|| ChainError::NoMatch(token_contract.clone()))
    }

    async fn read_openable_match_now(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Match>, ChainError> {
        let _g = self.lock.lock().unwrap();
        let st = self.load_state()?;
        Ok(st.matches.get(token_contract).cloned())
    }

    async fn open_stream(
        &self,
        token_contract: &TokenContract,
        enc_endpoint: Vec<u8>,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let m = st
            .matches
            .get(token_contract)
            .cloned()
            .ok_or_else(|| ChainError::NoMatch(token_contract.clone()))?;

        // Ceiling on delivered ticks from the consumed offer.
        let max_ticks = st
            .matched_offers
            .get(token_contract)
            .or_else(|| st.offers.get(token_contract))
            .map(|o| o.max_ticks)
            .unwrap_or(u64::MAX);
        // the first tick is frozen(the buyer locked 1 tick), the seller posted
        // the 2P mirror bond. There is no prepayment ahead.
        let machine = StreamMachine::open(m.price_per_tick, &self.params);
        let cell = StreamCell {
            machine,
            buyer_pubkey: m.buyer_pubkey.clone(),
            seller_locked: 2 * u128::from(m.price_per_tick),
            buyer_locked: u128::from(m.price_per_tick), // probe tick frozen
            seller_received: 0,
            buyer_refunded: 0,
            burned: 0,
            closed: false,
            max_ticks,
            disputed: false,
        };
        st.streams.insert(token_contract.clone(), cell);
        self.store_state(&st)?;

        // Seam: the enc-endpoint is placed into the endpoints file.
        let mut ef = self.read_endpoints()?;
        ef.handovers.insert(token_contract.clone(), enc_endpoint);
        self.write_endpoints(&ef)?;
        Ok(())
    }

    async fn read_handover(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Vec<u8>>, ChainError> {
        let _g = self.lock.lock().unwrap();
        let ef = self.read_endpoints()?;
        Ok(ef.handovers.get(token_contract).cloned())
    }

    async fn accept_probe(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let cell = st
            .streams
            .get_mut(token_contract)
            .ok_or_else(|| ChainError::NoStream(token_contract.clone()))?;
        // the probe is accepted -> the probe tick goes to the seller; the 2P mirror
        // bond STAYS locked(it collateralises the whole deal until a terminal state).
        cell.machine
            .on_probe_accepted()
            .map_err(|e| ChainError::EndpointsFile(e.0.to_string()))?;
        let p = u128::from(cell.machine.price());
        cell.buyer_locked -= p;
        cell.seller_received += p;
        // The two-tick invariant kicks in: the next tick is prepaid, one more is frozen.
        cell.buyer_locked += 2 * p;
        self.store_state(&st)
    }

    async fn advance_tick(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let cell = st
            .streams
            .get_mut(token_contract)
            .ok_or_else(|| ChainError::NoStream(token_contract.clone()))?;
        // the mock does not deliver more than the offer's `max_ticks`(the real TC is bounded by deposit). We count
        // finalized ticks by-fact(`seller_received / p`) and reject delivery beyond the ceiling.
        let p = cell.machine.price();
        let delivered = if p > 0 {
            cell.seller_received / u128::from(p)
        } else {
            0
        };
        if delivered >= u128::from(cell.max_ticks) {
            return Err(ChainError::Limit(format!(
                "advance_tick: max_ticks ({}) reached -- the mock does not deliver beyond the offer",
                cell.max_ticks
            )));
        }
        cell.machine
            .on_tick_delivered()
            .map_err(|e| ChainError::EndpointsFile(e.0.to_string()))?;
        cell.seller_received += u128::from(p);
        // `buyer_locked` does NOT change: the 2P window holds -- 1 tick is finalized to the seller, the next
        // is already frozen(deposited by the previous transition). Previously there was a `sub(p).add(p)`(no-op)
        // here, which read as a bug -- the arithmetic was removed.
        self.store_state(&st)
    }

    async fn stop(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let cell = st
            .streams
            .get_mut(token_contract)
            .ok_or_else(|| ChainError::NoStream(token_contract.clone()))?;
        if cell.closed {
            return Err(ChainError::Chain(format!(
                "stop: {token_contract} is already closed"
            )));
        }
        let settlement = cell.machine.buyer_stop();
        match &settlement {
            Settlement::BurnBoth(b) => {
                // the buyer's probe tick P + a mirror P from the seller bond are
                // burned, to no one; the remaining bond returns to the seller(bond fully resolved).
                cell.burned += b.total();
                cell.buyer_refunded += b.buyer_refund;
                cell.buyer_locked -= u128::from(b.buyer);
                cell.buyer_locked -= b.buyer_refund;
                cell.seller_locked = 0;
                // The seller receives no service revenue; only unused principal is refunded.
            }
            Settlement::AmicableSplit {
                to_seller_ticks,
                to_buyer_refund,
            } => {
                // the prepaid(delivered) tick -> to the seller, the frozen buffer -> to the buyer.
                // Both of the buyer's still-locked ticks are resolved: the lock is released entirely.
                let to_seller = u128::from(*to_seller_ticks) * u128::from(cell.machine.price());
                cell.seller_received += to_seller;
                cell.buyer_refunded += *to_buyer_refund;
                cell.buyer_locked -= to_seller;
                cell.buyer_locked -= *to_buyer_refund;
                // clean close -> the seller mirror bond returns in full.
                cell.seller_locked = 0;
            }
            Settlement::SellerNoShow { .. } => {
                // no-show is not slashed -> the seller mirror bond returns in full.
                cell.seller_locked = 0;
            }
        }
        cell.machine.close();
        cell.closed = true;
        // Finalize the net fee by-fact: burn the net from what was delivered.
        burn_net_fee(cell, &self.consts);
        self.store_state(&st)?;
        Ok(settlement)
    }

    async fn dispute(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        // a dispute FREEZES this TC's contested buyer amount and seller bond (does NOT burn,
        // unlike `stop`) until `release_dispute`. Other TCs owned by either note remain independent.
        // Scam revenue stays 0. We return the EXPECTED post-release outcome.
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let (to_buyer, seller_bond) = {
            let cell = st
                .streams
                .get_mut(token_contract)
                .ok_or_else(|| ChainError::NoStream(token_contract.clone()))?;
            cell.machine.buyer_dispute();
            cell.disputed = true;
            (cell.buyer_locked, cell.seller_locked)
        };
        self.store_state(&st)?;
        Ok(Settlement::SellerNoShow {
            to_buyer_refund: to_buyer,
            seller_bond_returned: seller_bond,
        })
    }

    async fn release_dispute(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        // the seller concedes -> the frozen amount is returned to the buyer and the seller bond
        // is returned, WITHOUT burn. Other deals were never affected. Scam revenue = 0.
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let settlement = {
            let cell = st
                .streams
                .get_mut(token_contract)
                .ok_or_else(|| ChainError::NoStream(token_contract.clone()))?;
            if !cell.disputed {
                return Err(ChainError::Chain(format!(
                    "release_dispute: {token_contract} not in dispute"
                )));
            }
            let to_buyer = cell.buyer_locked;
            let seller_bond = cell.seller_locked;
            cell.buyer_refunded += to_buyer;
            cell.buyer_locked = 0;
            cell.seller_locked -= seller_bond;
            cell.disputed = false;
            cell.machine.close();
            cell.closed = true;
            Settlement::SellerNoShow {
                to_buyer_refund: to_buyer,
                seller_bond_returned: seller_bond,
            }
        };
        self.store_state(&st)?;
        Ok(settlement)
    }

    async fn seller_timeout(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        let cell = st
            .streams
            .get_mut(token_contract)
            .ok_or_else(|| ChainError::NoStream(token_contract.clone()))?;
        let settlement = cell.machine.seller_timeout();
        if let Settlement::SellerNoShow {
            to_buyer_refund,
            seller_bond_returned,
        } = &settlement
        {
            let buyer_locked =
                cell.buyer_locked
                    .checked_sub(*to_buyer_refund)
                    .ok_or_else(|| {
                        ChainError::Chain(
                            "mock seller_timeout buyer refund exceeds persisted buyer lock"
                                .to_string(),
                        )
                    })?;
            let seller_locked = cell
                .seller_locked
                .checked_sub(*seller_bond_returned)
                .ok_or_else(|| {
                    ChainError::Chain(
                        "mock seller_timeout bond return exceeds persisted seller lock".to_string(),
                    )
                })?;
            // the buyer takes the frozen tick, pays zero; the seller's
            // exact seller bond is returned -- NOT burned.
            cell.buyer_refunded += *to_buyer_refund;
            cell.buyer_locked = buyer_locked;
            cell.seller_locked = seller_locked;
        }
        cell.machine.close();
        cell.closed = true;
        self.store_state(&st)?;
        Ok(settlement)
    }

    async fn cleanup_unopened(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let _g = self.lock.lock().unwrap();
        let mut st = self.load_state()?;
        if st.streams.contains_key(token_contract) {
            return Err(ChainError::Chain(format!(
                "cleanup_unopened: {token_contract} is already opened"
            )));
        }
        if !st.matches.contains_key(token_contract) {
            return Err(ChainError::NoMatch(token_contract.clone()));
        }
        st.matches.remove(token_contract);
        st.matched_offers.remove(token_contract);
        self.store_state(&st)?;
        Ok(Settlement::SellerNoShow {
            to_buyer_refund: 0,
            seller_bond_returned: 0,
        })
    }

    async fn deal_state(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainState>, ChainError> {
        let _g = self.lock.lock().unwrap();
        let st = self.load_state()?;
        if let Some(cell) = st.streams.get(token_contract) {
            return Ok(Some(DealChainState {
                funded: true,
                opened: !cell.closed,
                disputed: cell.disputed,
                probe_accepted: cell.seller_received > 0,
                funded_time: Some(0),
                last_advance: 0,
            }));
        }
        if st.matches.contains_key(token_contract) {
            return Ok(Some(DealChainState {
                funded: true,
                opened: false,
                disputed: false,
                probe_accepted: false,
                funded_time: Some(0),
                last_advance: 0,
            }));
        }
        Ok(None)
    }

    async fn snapshot(&self, token_contract: &TokenContract) -> Option<StreamSnapshot> {
        let _g = self.lock.lock().unwrap();
        let st = self.load_state().ok()?;
        st.streams.get(token_contract).map(|c| StreamSnapshot {
            seller_locked: c.seller_locked,
            buyer_locked: c.buyer_locked,
            // the mock holds no separate unspent deposit -- its lock IS the at-risk lead.
            buyer_lead: c.buyer_locked,
            seller_received: c.seller_received,
            buyer_refunded: c.buyer_refunded,
            burned: c.burned,
            closed: c.closed,
        })
    }

    /// Full scan of the note's state: own offers + deals(as seller/buyer)
    /// with the anonymous counterparty and by-fact settlement + exposure(locked in open deals).
    /// The lists are taken under the lock, then the lock is released -- by-fact snapshots are pulled via separate
    /// `snapshot` calls(the sync Mutex is not reentrant). Read only.
    async fn note_snapshot(&self, note: &NotePubkey) -> Result<NoteSnapshot, ChainError> {
        let note_id = note_id_hex(note);
        let (offers, deal_keys) = {
            let _g = self.lock.lock().unwrap();
            let st = self.load_state()?;
            let mut offers = Vec::new();
            for (tc, o) in &st.offers {
                if st.offer_sellers.get(tc) == Some(&note_id) {
                    offers.push(OfferListing {
                        seller_id: note_id.clone(),
                        token_contract: tc.clone(),
                        price_per_tick: o.price_per_tick,
                        max_ticks: o.max_ticks,
                    });
                }
            }
            let mut deal_keys: Vec<(TokenContract, DealRole, Option<String>, Shell)> = Vec::new();
            let mut seen = HashSet::new();
            for (tc, seller) in &st.offer_sellers {
                if seller == &note_id {
                    let counterparty = st.matches.get(tc).map(|m| note_id_hex(&m.buyer_pubkey));
                    let price = st
                        .matches
                        .get(tc)
                        .map(|m| m.price_per_tick)
                        .or_else(|| st.matched_offers.get(tc).map(|o| o.price_per_tick))
                        .or_else(|| st.offers.get(tc).map(|o| o.price_per_tick))
                        .unwrap_or(0);
                    deal_keys.push((tc.clone(), DealRole::Seller, counterparty, price));
                    seen.insert(tc.clone());
                }
            }
            for (tc, m) in &st.matches {
                if note_id_hex(&m.buyer_pubkey) == note_id && seen.insert(tc.clone()) {
                    let counterparty = st.offer_sellers.get(tc).cloned();
                    deal_keys.push((tc.clone(), DealRole::Buyer, counterparty, m.price_per_tick));
                }
            }
            (offers, deal_keys)
        };
        let mut deals = Vec::new();
        let mut exposure: Shell = 0;
        for (tc, role, counterparty, price) in deal_keys {
            let snapshot = self.snapshot(&tc).await;
            if let Some(s) = &snapshot {
                if !s.closed {
                    let locked = match role {
                        DealRole::Buyer => s.buyer_locked,
                        DealRole::Seller => s.seller_locked,
                    };
                    exposure =
                        exposure.saturating_add(Shell::try_from(locked).unwrap_or(Shell::MAX));
                }
            }
            deals.push(DealView {
                token_contract: tc,
                role,
                counterparty,
                price_per_tick: price,
                // The mock book carries no per-deal model(the offer has none); real model names are
                // resolved by the real-chain reader from the TC's RootModel.
                model: None,
                snapshot,
            });
        }
        Ok(NoteSnapshot {
            note_id,
            offers,
            deals,
            exposure,
        })
    }
}

/// Burn the net fee(after-rebate) by-fact from the delivered volume.
/// Clean close without a dispute -> the rebate is accounted for; here the stream is already closed amicably.
fn burn_net_fee(cell: &mut StreamCell, consts: &ProtocolConsts) {
    let p = cell.machine.price();
    if p == 0 {
        return;
    }
    let delivered_ticks = cell.seller_received / u128::from(p);
    if delivered_ticks == 0 {
        return;
    }
    let delivered_ticks =
        u64::try_from(delivered_ticks).expect("mock delivered ticks are bounded by max_ticks");
    cell.burned += u128::from(crate::settle::net_burn(delivered_ticks, p, consts));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::LocalNote;

    #[tokio::test]
    async fn high_price_timeout_rejects_legacy_wrapped_seller_lock() {
        let base =
            std::env::temp_dir().join(format!("dexdo-high-price-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let chain = MockChainBackend::new(
            base.join("eps.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        let seller = LocalNote::from_seed(&[15u8; 32]);
        let buyer = LocalNote::from_seed(&[16u8; 32]);
        let tc = "tc-high-price-timeout".to_string();
        let step = u64::try_from(crate::params::PRICE_STEP).unwrap();
        let price = u64::MAX - (u64::MAX % step);
        let p = u128::from(price);
        let wrapped_legacy_bond = u128::from((2 * p) as u64);

        chain
            .post_offer(
                SellOffer {
                    price_per_tick: price,
                    max_ticks: 1,
                    token_contract: tc.clone(),
                },
                &seller,
            )
            .await
            .unwrap();
        chain.place_buy(&tc, &buyer).await.unwrap();
        chain.open_stream(&tc, vec![], &seller).await.unwrap();

        let mut state = chain.load_state().unwrap();
        state.streams.get_mut(&tc).unwrap().seller_locked = wrapped_legacy_bond;
        chain.store_state(&state).unwrap();

        let error = chain
            .seller_timeout(&tc)
            .await
            .expect_err("a legacy wrapped seller lock must fail closed")
            .to_string();
        assert!(
            error.contains("bond return exceeds persisted seller lock"),
            "{error}"
        );
        let unchanged = chain.snapshot(&tc).await.unwrap();
        assert!(!unchanged.closed);
        assert_eq!(unchanged.seller_locked, wrapped_legacy_bond);
        assert_eq!(unchanged.buyer_locked, p);
        assert_eq!(unchanged.buyer_refunded, 0);

        let _ = std::fs::remove_dir_all(&base);
    }
}
