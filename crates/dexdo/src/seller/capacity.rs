//! Crash-safe seller delivery capacity for one funded TokenContract.
//! The chain is authoritative for the funded total, the current no-rollover subscription cap and the
//! cumulative `tokensPending` high-water. The gateway persists only the delivery debt that the chain cannot
//! know yet: exact authoritative tokens forwarded after that high-water and request capacity reserved before
//! contacting an upstream. Prompts, responses, keys and provider credentials never enter this file.

use anyhow::{anyhow, bail, Result};
use dexdo_core::{
    order_flags as flags, DealChainState, DealSubscription, TokenContract, PROBE_SEED_TOKENS,
    TICK_SIZE,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CAPACITY_RECORD_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableCapacityRecord {
    version: u32,
    token_contract: TokenContract,
    #[serde(with = "decimal_u128")]
    funded_tokens: u128,
    #[serde(with = "decimal_u128")]
    authoritative_cap: u128,
    #[serde(with = "decimal_u128")]
    tokens_pending_anchor: u128,
    #[serde(with = "decimal_u128")]
    local_delivered_after_anchor: u128,
    #[serde(with = "decimal_u128")]
    outstanding_reservation: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacitySnapshot {
    pub funded_tokens: u128,
    pub authoritative_cap: u128,
    pub tokens_pending_anchor: u128,
    pub local_delivered_after_anchor: u128,
    pub outstanding_reservation: u128,
}

impl From<&DurableCapacityRecord> for CapacitySnapshot {
    fn from(record: &DurableCapacityRecord) -> Self {
        Self {
            funded_tokens: record.funded_tokens,
            authoritative_cap: record.authoritative_cap,
            tokens_pending_anchor: record.tokens_pending_anchor,
            local_delivered_after_anchor: record.local_delivered_after_anchor,
            outstanding_reservation: record.outstanding_reservation,
        }
    }
}

impl CapacitySnapshot {
    pub fn committed(self) -> Result<u128> {
        self.tokens_pending_anchor
            .checked_add(self.local_delivered_after_anchor)
            .and_then(|value| value.checked_add(self.outstanding_reservation))
            .ok_or_else(|| anyhow!("seller capacity committed-token sum overflows uint128"))
    }

    pub fn available(self) -> Result<u128> {
        self.authoritative_cap
            .checked_sub(self.committed()?)
            .ok_or_else(|| anyhow!("seller capacity invariant is already exceeded"))
    }
}

struct CapacityEntryState {
    record: DurableCapacityRecord,
    terminal: bool,
}

struct CapacityEntry {
    path: Option<PathBuf>,
    state: Mutex<CapacityEntryState>,
}

/// One capacity ledger per running gateway. Entries remain independently locked, so concurrent requests for
/// different TCs do not serialize and concurrent requests for one TC cannot reserve the same token.
pub struct CapacityManager {
    store_dir: Option<PathBuf>,
    entries: Mutex<HashMap<TokenContract, Arc<CapacityEntry>>>,
}

impl CapacityManager {
    pub fn in_memory() -> Self {
        Self {
            store_dir: None,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn in_deals_dir(deals_dir: PathBuf) -> Self {
        Self {
            store_dir: Some(deals_dir.join("seller-capacity")),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Register or refresh one funded deal from a strict paired
    /// `getState()` / `getSubscription()` read.
    /// `tokensPending` is the only chain anchor: promotion lag must never make an already delivered token
    /// available again. A later anchor advance consumes exactly the corresponding prefix of durable local
    /// delivery. Outstanding/ambiguous reservations are never guessed away.
    pub fn reconcile_deal(
        &self,
        token_contract: &TokenContract,
        state: DealChainState,
        deal: DealSubscription,
    ) -> Result<Option<CapacitySnapshot>> {
        if state.is_stopped() {
            self.mark_terminal(token_contract)?;
            return Ok(None);
        }
        validate_live_deal_shape(token_contract, state, deal)?;
        let mut cap = authoritative_cap(state, deal)?;
        let subscription_term_ended = deal.is_subscription() && deal.week_index >= deal.sub_weeks;

        let entry = {
            let mut entries = self.entries.lock().unwrap();
            if let Some(entry) = entries.get(token_contract) {
                entry.clone()
            } else {
                let path = self
                    .store_dir
                    .as_ref()
                    .map(|directory| capacity_path(directory, token_contract));
                let record = match path.as_deref().map(load_record).transpose()? {
                    Some(Some(record)) => {
                        validate_record(&record)?;
                        if record.token_contract != *token_contract {
                            bail!(
                                "seller capacity file is for TokenContract {}, not {}",
                                record.token_contract,
                                token_contract
                            );
                        }
                        record
                    }
                    Some(None) | None => DurableCapacityRecord {
                        version: CAPACITY_RECORD_VERSION,
                        token_contract: token_contract.clone(),
                        funded_tokens: deal.funded_tokens,
                        authoritative_cap: cap,
                        tokens_pending_anchor: state.tokens_pending,
                        local_delivered_after_anchor: 0,
                        outstanding_reservation: 0,
                    },
                };
                let entry = Arc::new(CapacityEntry {
                    path,
                    state: Mutex::new(CapacityEntryState {
                        record,
                        terminal: false,
                    }),
                });
                entries.insert(token_contract.clone(), entry.clone());
                entry
            }
        };

        let mut locked = entry.state.lock().unwrap();
        if locked.terminal {
            bail!("TokenContract {token_contract} capacity is terminal");
        }
        let old = &locked.record;
        if old.funded_tokens != deal.funded_tokens {
            bail!(
                "TokenContract {token_contract} fundedTokens changed from {} to {}",
                old.funded_tokens,
                deal.funded_tokens
            );
        }
        if state.tokens_pending < old.tokens_pending_anchor {
            bail!(
                "TokenContract {token_contract} tokensPending regressed from {} to {}",
                old.tokens_pending_anchor,
                state.tokens_pending
            );
        }
        if cap < old.authoritative_cap && !subscription_term_ended {
            bail!(
                "TokenContract {token_contract} authoritative capacity regressed from {} to {}",
                old.authoritative_cap,
                cap
            );
        }
        let acknowledged = state.tokens_pending - old.tokens_pending_anchor;
        // An accepted probe is one tick credited AND paid, per the single statement of that rule on
        // `PROBE_SEED_TOKENS`: the buyer bought the trial tick whatever the model actually produced for it,
        // and the claim driver already starts its cumulative high-water from it. So the seed is a
        // protocol-owned credit, not an unbacked delivery advance. Exclude exactly that seed from the
        // delivery-backed comparison on the single observation that crosses into `probeAccepted`; every
        // token beyond it keeps the strict comparison below. `validate_live_deal_shape` pins a pre-probe
        // anchor to exactly zero and an accepted-probe anchor to at least one tick, and the durable anchor
        // never regresses, so the crossing is credited at most once per deal -- re-observing the same state,
        // and restarting from a record already carrying the crossed anchor, both leave the anchor at or
        // above the seed.
        let probe_seed = if state.probe_accepted && old.tokens_pending_anchor == 0 {
            PROBE_SEED_TOKENS.min(acknowledged)
        } else {
            0
        };
        let backed_by_delivery = acknowledged - probe_seed;
        if backed_by_delivery > old.local_delivered_after_anchor && !subscription_term_ended {
            bail!(
                "TokenContract {token_contract} tokensPending advanced by {acknowledged} \
                 ({backed_by_delivery} beyond the protocol probe seed), beyond durable local delivery {}",
                old.local_delivered_after_anchor
            );
        }
        let local_delivered_after_anchor = old
            .local_delivered_after_anchor
            .saturating_sub(acknowledged);
        if subscription_term_ended {
            // The final claim grace keeps the deal open but must not expose a fifth weekly quota. Keep
            // every amount already durably committed before the boundary, then make new availability zero.
            cap = state
                .tokens_pending
                .checked_add(local_delivered_after_anchor)
                .and_then(|value| value.checked_add(old.outstanding_reservation))
                .ok_or_else(|| anyhow!("post-term seller capacity commitment overflows uint128"))?;
        }
        let candidate = DurableCapacityRecord {
            version: CAPACITY_RECORD_VERSION,
            token_contract: token_contract.clone(),
            funded_tokens: deal.funded_tokens,
            authoritative_cap: cap,
            tokens_pending_anchor: state.tokens_pending,
            local_delivered_after_anchor,
            outstanding_reservation: old.outstanding_reservation,
        };
        validate_record(&candidate)?;
        if candidate != locked.record {
            persist_candidate(entry.path.as_deref(), &candidate)?;
            locked.record = candidate;
        }
        Ok(Some(CapacitySnapshot::from(&locked.record)))
    }

    pub fn reserve(
        &self,
        token_contract: &TokenContract,
        requested: u64,
    ) -> std::result::Result<CapacityReservation, ReserveError> {
        if requested == 0 {
            return Err(ReserveError::Exhausted);
        }
        let entry = self
            .entries
            .lock()
            .unwrap()
            .get(token_contract)
            .cloned()
            .ok_or(ReserveError::UnknownDeal)?;
        let mut locked = entry.state.lock().unwrap();
        if locked.terminal {
            return Err(ReserveError::Terminal);
        }
        validate_record(&locked.record).map_err(ReserveError::InvalidState)?;
        let available = CapacitySnapshot::from(&locked.record)
            .available()
            .map_err(ReserveError::InvalidState)?;
        let amount = available.min(u128::from(requested));
        if amount == 0 {
            return Err(ReserveError::Exhausted);
        }
        let mut candidate = locked.record.clone();
        candidate.outstanding_reservation = candidate
            .outstanding_reservation
            .checked_add(amount)
            .ok_or_else(|| {
            ReserveError::InvalidState(anyhow!("request reservation overflows uint128"))
        })?;
        validate_record(&candidate).map_err(ReserveError::InvalidState)?;
        persist_candidate(entry.path.as_deref(), &candidate).map_err(ReserveError::InvalidState)?;
        locked.record = candidate;
        drop(locked);

        Ok(CapacityReservation {
            entry,
            request: Mutex::new(RequestReservation {
                initial: amount,
                remaining: amount,
                finished: false,
            }),
        })
    }

    pub fn snapshot(&self, token_contract: &TokenContract) -> Result<Option<CapacitySnapshot>> {
        let Some(entry) = self.entries.lock().unwrap().get(token_contract).cloned() else {
            return Ok(None);
        };
        let locked = entry.state.lock().unwrap();
        if locked.terminal {
            return Ok(None);
        }
        validate_record(&locked.record)?;
        Ok(Some(CapacitySnapshot::from(&locked.record)))
    }

    pub fn mark_terminal(&self, token_contract: &TokenContract) -> Result<()> {
        let entry = self.entries.lock().unwrap().remove(token_contract);
        if let Some(entry) = entry {
            let mut locked = entry.state.lock().unwrap();
            locked.terminal = true;
            if let Some(path) = &entry.path {
                remove_if_present(path)?;
            }
        } else if let Some(directory) = &self.store_dir {
            remove_if_present(&capacity_path(directory, token_contract))?;
        }
        Ok(())
    }
}

impl Default for CapacityManager {
    fn default() -> Self {
        Self::in_memory()
    }
}

#[derive(Debug)]
pub enum ReserveError {
    UnknownDeal,
    Terminal,
    Exhausted,
    InvalidState(anyhow::Error),
}

impl fmt::Display for ReserveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDeal => write!(formatter, "deal capacity is not registered"),
            Self::Terminal => write!(formatter, "deal capacity is terminal"),
            Self::Exhausted => write!(formatter, "deal capacity is exhausted"),
            Self::InvalidState(error) => write!(formatter, "invalid deal capacity: {error}"),
        }
    }
}

impl std::error::Error for ReserveError {}

struct RequestReservation {
    initial: u128,
    remaining: u128,
    finished: bool,
}

/// Request-scoped reservation. Dropping it deliberately does not release anything: a task/process crash is
/// ambiguous, so restart must retain the durable upper bound until exact chain evidence acknowledges it.
pub struct CapacityReservation {
    entry: Arc<CapacityEntry>,
    request: Mutex<RequestReservation>,
}

impl CapacityReservation {
    pub fn amount(&self) -> u64 {
        let initial = self.request.lock().unwrap().initial;
        u64::try_from(initial).expect("reservation is bounded by requested u64")
    }

    pub fn remaining(&self) -> u64 {
        let remaining = self.request.lock().unwrap().remaining;
        u64::try_from(remaining).expect("reservation is bounded by requested u64")
    }

    pub fn record_delivered(&self, tokens: u64) -> Result<()> {
        if tokens == 0 {
            bail!("authoritative delivered delta must be positive");
        }
        let mut request = self.request.lock().unwrap();
        if request.finished {
            bail!("capacity reservation already finished");
        }
        let tokens = u128::from(tokens);
        if tokens > request.remaining {
            bail!(
                "authoritative delivered delta {tokens} exceeds request reservation {}",
                request.remaining
            );
        }
        let mut locked = self.entry.state.lock().unwrap();
        if locked.terminal {
            bail!("deal capacity became terminal");
        }
        let mut candidate = locked.record.clone();
        candidate.outstanding_reservation =
            candidate
                .outstanding_reservation
                .checked_sub(tokens)
                .ok_or_else(|| anyhow!("aggregate reservation underflow"))?;
        candidate.local_delivered_after_anchor = candidate
            .local_delivered_after_anchor
            .checked_add(tokens)
            .ok_or_else(|| anyhow!("local delivered counter overflows uint128"))?;
        validate_record(&candidate)?;
        persist_candidate(self.entry.path.as_deref(), &candidate)?;
        locked.record = candidate;
        request.remaining -= tokens;
        Ok(())
    }

    /// Release a request's exact unused remainder. Used for both clean completion and an interrupted stream
    /// whose every successfully forwarded output already had an authoritative token count.
    pub fn finish_exact(&self) -> Result<()> {
        let mut request = self.request.lock().unwrap();
        if request.finished {
            bail!("capacity reservation already finished");
        }
        let mut locked = self.entry.state.lock().unwrap();
        if locked.terminal {
            request.finished = true;
            request.remaining = 0;
            return Ok(());
        }
        let mut candidate = locked.record.clone();
        candidate.outstanding_reservation = candidate
            .outstanding_reservation
            .checked_sub(request.remaining)
            .ok_or_else(|| anyhow!("aggregate reservation underflow"))?;
        validate_record(&candidate)?;
        persist_candidate(self.entry.path.as_deref(), &candidate)?;
        locked.record = candidate;
        request.remaining = 0;
        request.finished = true;
        Ok(())
    }

    /// Preserve all unresolved capacity. This is the only safe terminal when some output may have reached the
    /// buyer without a valid authoritative usage count.
    pub fn finish_ambiguous(&self) -> Result<()> {
        let mut request = self.request.lock().unwrap();
        if request.finished {
            bail!("capacity reservation already finished");
        }
        request.remaining = 0;
        request.finished = true;
        Ok(())
    }
}

fn authoritative_cap(state: DealChainState, deal: DealSubscription) -> Result<u128> {
    if deal.is_subscription() && deal.week_index >= deal.sub_weeks {
        // Defense in depth for: an open final-claim grace is not a fifth subscription week.
        return Ok(state.tokens_pending);
    }
    if !state.probe_accepted {
        return Ok(TICK_SIZE.min(deal.funded_tokens));
    }
    if !deal.is_subscription() {
        return Ok(deal.funded_tokens);
    }
    deal.week_base_tokens
        .checked_add(deal.tokens_per_week)
        .map(|cap| cap.min(deal.funded_tokens))
        .ok_or_else(|| anyhow!("subscription weekBaseTokens + tokensPerWeek overflows uint128"))
}

fn validate_live_deal_shape(
    token_contract: &TokenContract,
    state: DealChainState,
    deal: DealSubscription,
) -> Result<()> {
    if deal.is_subscription() != (deal.deal_flags & flags::SUBSCRIPTION != 0) {
        bail!("TokenContract {token_contract} has contradictory subscription flag/subWeeks shape");
    }
    if !deal.is_subscription()
        && (deal.week_index != 0
            || deal.tokens_per_week != deal.funded_tokens
            || deal.week_base_tokens != 0)
    {
        bail!("TokenContract {token_contract} has contradictory ordinary deal capacity shape");
    }
    if !state.funded {
        bail!("TokenContract {token_contract} is not funded");
    }
    if state.disputed {
        bail!("TokenContract {token_contract} is disputed; refusing to serve");
    }
    if !state.opened && state.probe_accepted {
        bail!(
            "TokenContract {token_contract} reports accepted probe while not open and not terminal"
        );
    }
    if deal.funded_tokens == 0 {
        bail!("TokenContract {token_contract} fundedTokens is zero");
    }
    if state.tokens_pending > deal.funded_tokens {
        bail!(
            "TokenContract {token_contract} tokensPending {} exceeds fundedTokens {}",
            state.tokens_pending,
            deal.funded_tokens
        );
    }
    if state.probe_accepted {
        if state.tokens_pending < TICK_SIZE {
            bail!(
                "TokenContract {token_contract} accepted probe has tokensPending {} below TICK_SIZE {}",
                state.tokens_pending,
                TICK_SIZE
            );
        }
    } else if state.tokens_pending != 0 {
        bail!(
            "TokenContract {token_contract} pre-probe tokensPending must be zero, got {}",
            state.tokens_pending
        );
    }
    let cap = authoritative_cap(state, deal)?;
    if state.tokens_pending > cap {
        bail!(
            "TokenContract {token_contract} tokensPending {} exceeds current authoritative cap {}",
            state.tokens_pending,
            cap
        );
    }
    Ok(())
}

fn validate_record(record: &DurableCapacityRecord) -> Result<()> {
    if record.version != CAPACITY_RECORD_VERSION {
        bail!(
            "seller capacity {} has version {}; expected {}",
            record.token_contract,
            record.version,
            CAPACITY_RECORD_VERSION
        );
    }
    if record.token_contract.trim().is_empty() {
        bail!("seller capacity record has empty token_contract");
    }
    let snapshot = CapacitySnapshot::from(record);
    let committed = snapshot.committed()?;
    if committed > snapshot.authoritative_cap {
        bail!(
            "seller capacity invariant violated: pending {} + local {} + reserved {} = {} > cap {}",
            snapshot.tokens_pending_anchor,
            snapshot.local_delivered_after_anchor,
            snapshot.outstanding_reservation,
            committed,
            snapshot.authoritative_cap
        );
    }
    if snapshot.authoritative_cap > snapshot.funded_tokens {
        bail!(
            "seller capacity invariant violated: cap {} > fundedTokens {}",
            snapshot.authoritative_cap,
            snapshot.funded_tokens
        );
    }
    Ok(())
}

fn capacity_path(directory: &Path, token_contract: &str) -> PathBuf {
    let safe = token_contract
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    directory.join(format!("deal-{safe}-seller-capacity.json"))
}

fn load_record(path: &Path) -> Result<Option<DurableCapacityRecord>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(anyhow!("read seller capacity {}: {error}", path.display())),
    };
    if bytes.is_empty() {
        bail!("seller capacity {} is empty", path.display());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| anyhow!("parse seller capacity {}: {error}", path.display()))
}

fn persist_candidate(path: Option<&Path>, record: &DurableCapacityRecord) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("seller capacity path {} has no parent", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow!("create seller capacity dir {}: {error}", parent.display()))?;
    let bytes = serde_json::to_vec_pretty(record)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("seller-capacity.json");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow!("system clock before epoch: {error}"))?
        .as_nanos();
    let temporary = parent.join(format!(".{name}.tmp.{}.{nanos}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, READ_CONTROL, WRITE_DAC};
        options.access_mode(GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
        options.share_mode(FILE_SHARE_DELETE);
    }
    let mut file = options.open(&temporary).map_err(|error| {
        anyhow!(
            "create seller capacity temp {}: {error}",
            temporary.display()
        )
    })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow!(
            "write seller capacity temp {}: {error}",
            temporary.display()
        ));
    }
    if let Err(error) = atomic_replace(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow!(
            "commit seller capacity {} from {}: {error}",
            path.display(),
            temporary.display()
        ));
    }
    sync_parent(parent)?;
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both paths are NUL-terminated and remain alive for the duration of the call.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| anyhow!("sync seller capacity dir {}: {error}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_parent(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow!(
            "remove terminal seller capacity {}: {error}",
            path.display()
        )),
    }
}

mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dexdo_core::SUBSCRIPTION_WEEKS;
    use proptest::prelude::*;
    use std::sync::Barrier;

    const WEEK_QUOTA: u128 = 2 * TICK_SIZE;
    const FUNDED: u128 = (SUBSCRIPTION_WEEKS as u128) * WEEK_QUOTA;
    const ORDINARY_FUNDED: u128 = 10 * TICK_SIZE;
    /// What the model really produced for the trial request in the live run: far below one tick.
    const PROBE_OUTPUT: u64 = 29_354;

    fn state(probe_accepted: bool, pending: u128) -> DealChainState {
        DealChainState {
            funded: true,
            opened: true,
            probe_accepted,
            disputed: false,
            deposit: 1,
            finalized_owed: 0,
            tokens_final: pending,
            tokens_superseded: pending,
            tokens_pending: pending,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        }
    }

    fn subscription(week_index: u8, week_base_tokens: u128) -> DealSubscription {
        DealSubscription {
            deal_flags: flags::SUBSCRIPTION,
            sub_weeks: SUBSCRIPTION_WEEKS,
            week_index,
            tokens_per_week: WEEK_QUOTA,
            funded_tokens: FUNDED,
            tokens_paid: u128::from(week_index) * WEEK_QUOTA,
            period_start: 1,
            week_base_tokens,
        }
    }

    fn ordinary(funded_tokens: u128) -> DealSubscription {
        DealSubscription {
            deal_flags: 0,
            sub_weeks: 0,
            week_index: 0,
            tokens_per_week: funded_tokens,
            funded_tokens,
            tokens_paid: 0,
            period_start: 0,
            week_base_tokens: 0,
        }
    }

    fn assert_invariant(snapshot: CapacitySnapshot) {
        assert!(snapshot.committed().unwrap() <= snapshot.authoritative_cap);
        assert!(snapshot.authoritative_cap <= snapshot.funded_tokens);
    }

    #[test]
    fn sequential_requests_share_one_cumulative_limit() {
        let manager = CapacityManager::in_memory();
        let tc = "0:sequential".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let first = manager.reserve(&tc, 600_000).unwrap();
        first.record_delivered(600_000).unwrap();
        first.finish_exact().unwrap();
        let second = manager.reserve(&tc, 600_000).unwrap();
        assert_eq!(second.amount(), 400_000);
        second.record_delivered(400_000).unwrap();
        second.finish_exact().unwrap();
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));
    }

    #[test]
    fn simultaneous_requests_cannot_reserve_the_same_last_capacity() {
        let manager = Arc::new(CapacityManager::in_memory());
        let tc = "0:race".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let manager = manager.clone();
            let tc = tc.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                manager.reserve(&tc, 750_000).unwrap()
            }));
        }
        barrier.wait();
        let reservations = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            reservations
                .iter()
                .map(CapacityReservation::amount)
                .sum::<u64>(),
            TICK_SIZE as u64
        );
        assert_invariant(manager.snapshot(&tc).unwrap().unwrap());
    }

    #[test]
    fn probe_is_one_tick_and_acceptance_never_counts_it_twice() {
        let manager = CapacityManager::in_memory();
        let tc = "0:probe".to_string();
        manager
            .reconcile_deal(&tc, state(false, 0), subscription(0, 0))
            .unwrap();
        let probe = manager.reserve(&tc, u64::MAX).unwrap();
        assert_eq!(probe.amount(), TICK_SIZE as u64);
        probe.record_delivered(TICK_SIZE as u64).unwrap();
        probe.finish_exact().unwrap();

        let after_accept = manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap()
            .unwrap();
        assert_eq!(after_accept.tokens_pending_anchor, TICK_SIZE);
        assert_eq!(after_accept.local_delivered_after_anchor, 0);
        assert_eq!(after_accept.authoritative_cap, WEEK_QUOTA);
        assert_eq!(after_accept.available().unwrap(), TICK_SIZE);
    }

    /// The two live deal shapes that both register a pre-probe anchor of zero and then cross into
    /// `probeAccepted`: label, deal shape, and the authoritative cap the crossing opens.
    fn probe_shapes() -> [(&'static str, DealSubscription, u128); 2] {
        [
            ("ordinary", ordinary(ORDINARY_FUNDED), ORDINARY_FUNDED),
            ("subscription", subscription(0, 0), WEEK_QUOTA),
        ]
    }

    #[test]
    fn accepted_probe_seed_is_not_an_unbacked_delivery_advance() {
        for (label, deal, cap) in probe_shapes() {
            let manager = CapacityManager::in_memory();
            let tc = format!("0:probe-seed-{label}");
            manager
                .reconcile_deal(&tc, state(false, 0), deal)
                .unwrap()
                .unwrap();
            let probe = manager.reserve(&tc, u64::MAX).unwrap();
            assert_eq!(probe.amount(), TICK_SIZE as u64, "{label}");
            probe.record_delivered(PROBE_OUTPUT).unwrap();
            probe.finish_exact().unwrap();

            let accepted = manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), deal)
                .unwrap()
                .unwrap();
            assert_eq!(accepted.tokens_pending_anchor, TICK_SIZE, "{label}");
            assert_eq!(accepted.local_delivered_after_anchor, 0, "{label}");
            assert_eq!(accepted.outstanding_reservation, 0, "{label}");
            assert_eq!(accepted.authoritative_cap, cap, "{label}");
            assert_eq!(accepted.available().unwrap(), cap - TICK_SIZE, "{label}");
            assert_invariant(accepted);

            // Serving continues past the acceptance instead of the deal dying on it.
            assert_eq!(
                manager.reserve(&tc, 4_096).unwrap().amount(),
                4_096,
                "{label}"
            );
        }
    }

    #[test]
    fn advance_beyond_delivered_output_after_the_probe_still_fails_closed() {
        for (label, deal, _cap) in probe_shapes() {
            let manager = CapacityManager::in_memory();
            let tc = format!("0:probe-seed-overclaim-{label}");
            manager
                .reconcile_deal(&tc, state(false, 0), deal)
                .unwrap()
                .unwrap();
            let probe = manager.reserve(&tc, u64::MAX).unwrap();
            probe.record_delivered(PROBE_OUTPUT).unwrap();
            probe.finish_exact().unwrap();
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), deal)
                .unwrap()
                .unwrap();

            let served = manager.reserve(&tc, 5_000).unwrap();
            served.record_delivered(5_000).unwrap();
            served.finish_exact().unwrap();

            let error = manager
                .reconcile_deal(&tc, state(true, TICK_SIZE + 5_001), deal)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("beyond durable local delivery 5000"),
                "{label}: {error:#}"
            );

            // Exactly what was delivered is still acknowledged without complaint.
            let exact = manager
                .reconcile_deal(&tc, state(true, TICK_SIZE + 5_000), deal)
                .unwrap()
                .unwrap();
            assert_eq!(exact.local_delivered_after_anchor, 0, "{label}");
            assert_invariant(exact);
        }
    }

    #[test]
    fn probe_seed_is_credited_exactly_once_across_repeats_and_restarts() {
        for (label, deal, cap) in probe_shapes() {
            // Crash between serving the trial request and observing the acceptance: the durable record
            // still carries the pre-probe anchor, so the restarted observer performs the crossing itself.
            let directory = tempfile::tempdir().unwrap();
            let tc = format!("0:probe-seed-restart-{label}");
            {
                let manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
                manager
                    .reconcile_deal(&tc, state(false, 0), deal)
                    .unwrap()
                    .unwrap();
                let probe = manager.reserve(&tc, u64::MAX).unwrap();
                probe.record_delivered(PROBE_OUTPUT).unwrap();
                probe.finish_exact().unwrap();
            }

            let manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
            let crossed = manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), deal)
                .unwrap()
                .unwrap();
            assert_eq!(crossed.tokens_pending_anchor, TICK_SIZE, "{label}");
            assert_eq!(crossed.local_delivered_after_anchor, 0, "{label}");
            assert_eq!(crossed.available().unwrap(), cap - TICK_SIZE, "{label}");

            // The same observation again is a no-op, not a second seed.
            let repeated = manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), deal)
                .unwrap()
                .unwrap();
            assert_eq!(repeated, crossed, "{label}");

            // Neither is a restart from the durable record that already carries the crossed anchor.
            drop(manager);
            let restarted = CapacityManager::in_deals_dir(directory.path().to_path_buf());
            let after_restart = restarted
                .reconcile_deal(&tc, state(true, TICK_SIZE), deal)
                .unwrap()
                .unwrap();
            assert_eq!(after_restart, crossed, "{label}");

            // A second seed-sized advance is a plain unbacked advance: nothing was delivered since.
            let error = restarted
                .reconcile_deal(&tc, state(true, 2 * TICK_SIZE), deal)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("beyond durable local delivery 0"),
                "{label}: {error:#}"
            );
        }
    }

    #[test]
    fn only_authoritative_week_base_opens_one_no_rollover_quota() {
        let manager = CapacityManager::in_memory();
        let tc = "0:week".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let first = manager.reserve(&tc, TICK_SIZE as u64).unwrap();
        first.record_delivered(TICK_SIZE as u64).unwrap();
        first.finish_exact().unwrap();
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));

        // Wall clock is intentionally absent from this API: the same strict state cannot reopen capacity.
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));

        let next = manager
            .reconcile_deal(
                &tc,
                state(true, 2 * TICK_SIZE),
                subscription(1, 2 * TICK_SIZE),
            )
            .unwrap()
            .unwrap();
        assert_eq!(next.authoritative_cap, 4 * TICK_SIZE);
        assert_eq!(next.available().unwrap(), 2 * TICK_SIZE);
    }

    #[test]
    fn final_subscription_boundary_preserves_commitment_and_opens_no_capacity() {
        let manager = CapacityManager::in_memory();
        let tc = "0:final-boundary".to_string();
        let pending = 5 * TICK_SIZE;
        manager
            .reconcile_deal(&tc, state(true, pending), subscription(3, pending))
            .unwrap();
        let in_flight = manager.reserve(&tc, 300).unwrap();
        in_flight.record_delivered(100).unwrap();
        drop(in_flight);

        let final_snapshot = manager
            .reconcile_deal(
                &tc,
                state(true, pending),
                subscription(SUBSCRIPTION_WEEKS, pending),
            )
            .unwrap()
            .unwrap();
        assert_eq!(final_snapshot.tokens_pending_anchor, pending);
        assert_eq!(final_snapshot.local_delivered_after_anchor, 100);
        assert_eq!(final_snapshot.outstanding_reservation, 200);
        assert_eq!(final_snapshot.authoritative_cap, pending + 300);
        assert_eq!(final_snapshot.available().unwrap(), 0);
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));
    }

    #[test]
    fn post_term_chain_growth_cannot_leave_cached_pre_term_capacity_open() {
        let manager = CapacityManager::in_memory();
        let tc = "0:post-term-growth".to_string();
        let pending = 5 * TICK_SIZE;
        manager
            .reconcile_deal(&tc, state(true, pending), subscription(3, pending))
            .unwrap();
        let in_flight = manager.reserve(&tc, 300).unwrap();
        in_flight.record_delivered(100).unwrap();
        drop(in_flight);

        let post_term_pending = pending + 500;
        let final_snapshot = manager
            .reconcile_deal(
                &tc,
                state(true, post_term_pending),
                subscription(SUBSCRIPTION_WEEKS, pending),
            )
            .unwrap()
            .unwrap();
        assert_eq!(final_snapshot.tokens_pending_anchor, post_term_pending);
        assert_eq!(final_snapshot.local_delivered_after_anchor, 0);
        assert_eq!(final_snapshot.outstanding_reservation, 200);
        assert_eq!(final_snapshot.authoritative_cap, post_term_pending + 200);
        assert_eq!(final_snapshot.available().unwrap(), 0);
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));
    }

    #[test]
    fn exact_short_or_interrupted_completion_releases_only_unused_reservation() {
        let manager = CapacityManager::in_memory();
        let tc = "0:short".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let reservation = manager.reserve(&tc, 80).unwrap();
        reservation.record_delivered(20).unwrap();
        reservation.finish_exact().unwrap();
        let snapshot = manager.snapshot(&tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 20);
        assert_eq!(snapshot.outstanding_reservation, 0);
        assert_eq!(snapshot.available().unwrap(), TICK_SIZE - 20);
    }

    #[test]
    fn ambiguous_usage_retains_the_unresolved_upper_bound() {
        let manager = CapacityManager::in_memory();
        let tc = "0:ambiguous".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let reservation = manager.reserve(&tc, 80).unwrap();
        reservation.record_delivered(20).unwrap();
        reservation.finish_ambiguous().unwrap();
        let snapshot = manager.snapshot(&tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 20);
        assert_eq!(snapshot.outstanding_reservation, 60);
        assert_eq!(snapshot.available().unwrap(), TICK_SIZE - 80);
    }

    #[test]
    fn error_before_any_forwarded_output_releases_the_whole_reservation() {
        let manager = CapacityManager::in_memory();
        let tc = "0:no-output".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let reservation = manager.reserve(&tc, 80).unwrap();
        reservation.finish_exact().unwrap();
        assert_eq!(
            manager.snapshot(&tc).unwrap().unwrap().available().unwrap(),
            TICK_SIZE
        );
    }

    #[test]
    fn lost_claim_response_reconciles_h_h_plus_k_and_h_plus_n_without_reopening() {
        for acknowledged in [0, 40, 100] {
            let manager = CapacityManager::in_memory();
            let tc = format!("0:lost-{acknowledged}");
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
                .unwrap();
            let reservation = manager.reserve(&tc, 100).unwrap();
            reservation.record_delivered(100).unwrap();
            reservation.finish_exact().unwrap();
            let available_before = manager.snapshot(&tc).unwrap().unwrap().available().unwrap();
            let after = manager
                .reconcile_deal(
                    &tc,
                    state(true, TICK_SIZE + acknowledged),
                    subscription(0, 0),
                )
                .unwrap()
                .unwrap();
            assert_eq!(after.available().unwrap(), available_before);
            assert_eq!(after.local_delivered_after_anchor, 100 - acknowledged);
            assert_invariant(after);
        }
    }

    #[test]
    fn restart_loads_local_delivery_and_outstanding_reservation_before_serving() {
        let directory = tempfile::tempdir().unwrap();
        let tc = "0:restart".to_string();
        {
            let manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
                .unwrap();
            let delivered = manager.reserve(&tc, 100).unwrap();
            delivered.record_delivered(40).unwrap();
            // Crash: neither the delivered remainder nor the outstanding reservation is released.
        }
        let restarted = CapacityManager::in_deals_dir(directory.path().to_path_buf());
        let snapshot = restarted
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 40);
        assert_eq!(snapshot.outstanding_reservation, 60);
        assert_eq!(snapshot.available().unwrap(), TICK_SIZE - 100);
    }

    #[test]
    fn crash_after_reservation_before_upstream_remains_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let tc = "0:pre-upstream-crash".to_string();
        {
            let manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
                .unwrap();
            let _reservation = manager.reserve(&tc, TICK_SIZE as u64).unwrap();
        }
        let restarted = CapacityManager::in_deals_dir(directory.path().to_path_buf());
        let snapshot = restarted
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.outstanding_reservation, TICK_SIZE);
        assert!(matches!(
            restarted.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));
    }

    #[test]
    fn malformed_regressing_and_overflowing_states_fail_closed() {
        let manager = CapacityManager::in_memory();
        let tc = "0:bad".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE + 10), subscription(0, 0))
            .unwrap();
        let regression = manager
            .reconcile_deal(&tc, state(true, TICK_SIZE + 9), subscription(0, 0))
            .unwrap_err();
        assert!(
            regression.to_string().contains("regressed"),
            "{regression:#}"
        );

        let overflow = authoritative_cap(
            state(true, TICK_SIZE),
            DealSubscription {
                deal_flags: flags::SUBSCRIPTION,
                sub_weeks: 4,
                week_index: 1,
                tokens_per_week: 1,
                funded_tokens: u128::MAX,
                tokens_paid: 1,
                period_start: 1,
                week_base_tokens: u128::MAX,
            },
        )
        .unwrap_err();
        assert!(overflow.to_string().contains("overflows"), "{overflow:#}");
    }

    #[test]
    fn ordinary_deal_is_bounded_by_actual_funded_volume() {
        let manager = CapacityManager::in_memory();
        let tc = "0:ordinary".to_string();
        let funded = TICK_SIZE + 125;
        let registered = manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(funded))
            .unwrap()
            .unwrap();
        assert_eq!(registered.authoritative_cap, funded);
        assert_eq!(registered.available().unwrap(), 125);
        let exact_remainder = manager.reserve(&tc, u64::MAX).unwrap();
        assert_eq!(exact_remainder.amount(), 125);
        exact_remainder.record_delivered(125).unwrap();
        exact_remainder.finish_exact().unwrap();
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));
    }

    #[test]
    fn ordinary_probe_opens_only_one_tick_then_exact_funded_remainder() {
        let manager = CapacityManager::in_memory();
        let tc = "0:ordinary-probe".to_string();
        let funded = 3 * TICK_SIZE;
        manager
            .reconcile_deal(&tc, state(false, 0), ordinary(funded))
            .unwrap();
        let probe = manager.reserve(&tc, u64::MAX).unwrap();
        assert_eq!(probe.amount(), TICK_SIZE as u64);
        probe.record_delivered(TICK_SIZE as u64).unwrap();
        probe.finish_exact().unwrap();

        let accepted = manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(funded))
            .unwrap()
            .unwrap();
        assert_eq!(accepted.local_delivered_after_anchor, 0);
        assert_eq!(accepted.authoritative_cap, funded);
        assert_eq!(accepted.available().unwrap(), 2 * TICK_SIZE);
    }

    #[test]
    fn ordinary_sequential_requests_share_the_funded_total() {
        let manager = CapacityManager::in_memory();
        let tc = "0:ordinary-sequential".to_string();
        let funded = TICK_SIZE + 900;
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(funded))
            .unwrap();
        let first = manager.reserve(&tc, 600).unwrap();
        first.record_delivered(600).unwrap();
        first.finish_exact().unwrap();
        let second = manager.reserve(&tc, 600).unwrap();
        assert_eq!(second.amount(), 300);
        second.record_delivered(300).unwrap();
        second.finish_exact().unwrap();
        assert!(matches!(
            manager.reserve(&tc, 1),
            Err(ReserveError::Exhausted)
        ));
    }

    #[test]
    fn ordinary_concurrent_requests_cannot_share_the_same_remainder() {
        let manager = Arc::new(CapacityManager::in_memory());
        let tc = "0:ordinary-race".to_string();
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(TICK_SIZE + 1_000))
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let manager = manager.clone();
            let tc = tc.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                manager.reserve(&tc, 750).unwrap()
            }));
        }
        barrier.wait();
        let reservations = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            reservations
                .iter()
                .map(CapacityReservation::amount)
                .sum::<u64>(),
            1_000
        );
        assert_invariant(manager.snapshot(&tc).unwrap().unwrap());
    }

    #[test]
    fn ordinary_restart_retains_local_and_ambiguous_capacity_debt() {
        let directory = tempfile::tempdir().unwrap();
        let tc = "0:ordinary-restart".to_string();
        let funded = TICK_SIZE + 1_000;
        {
            let manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(funded))
                .unwrap();
            let reservation = manager.reserve(&tc, 800).unwrap();
            reservation.record_delivered(300).unwrap();
            reservation.finish_ambiguous().unwrap();
        }
        let restarted = CapacityManager::in_deals_dir(directory.path().to_path_buf());
        let snapshot = restarted
            .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(funded))
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 300);
        assert_eq!(snapshot.outstanding_reservation, 500);
        assert_eq!(snapshot.available().unwrap(), 200);
        assert_invariant(snapshot);
    }

    #[test]
    fn terminal_state_removes_durable_capacity_record() {
        let directory = tempfile::tempdir().unwrap();
        let tc = "0:terminal".to_string();
        let manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
        manager
            .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
            .unwrap();
        let reservation = manager.reserve(&tc, 1).unwrap();
        reservation.finish_ambiguous().unwrap();
        let mut terminal = state(true, TICK_SIZE);
        terminal.opened = false;
        terminal.deposit = 0;
        assert!(manager
            .reconcile_deal(&tc, terminal, subscription(0, 0))
            .unwrap()
            .is_none());
        assert!(manager.snapshot(&tc).unwrap().is_none());
        assert_eq!(
            std::fs::read_dir(directory.path().join("seller-capacity"))
                .unwrap()
                .count(),
            0
        );
    }

    proptest! {
        #[test]
        fn arbitrary_weekly_underuse_never_becomes_post_term_capacity(
            weekly_delivery_after_probe in (
                0_u32..=(WEEK_QUOTA - TICK_SIZE) as u32,
                0_u32..=WEEK_QUOTA as u32,
                0_u32..=WEEK_QUOTA as u32,
                0_u32..=WEEK_QUOTA as u32,
            )
        ) {
            let (week_zero, week_one, week_two, week_three) = weekly_delivery_after_probe;
            let pending = TICK_SIZE
                + u128::from(week_zero)
                + u128::from(week_one)
                + u128::from(week_two)
                + u128::from(week_three);
            let manager = CapacityManager::in_memory();
            let tc = "0:post-term-property".to_string();
            let snapshot = manager
                .reconcile_deal(
                    &tc,
                    state(true, pending),
                    subscription(SUBSCRIPTION_WEEKS, pending),
                )
                .unwrap()
                .unwrap();

            prop_assert_eq!(snapshot.tokens_pending_anchor, pending);
            prop_assert_eq!(snapshot.authoritative_cap, pending);
            prop_assert_eq!(snapshot.available().unwrap(), 0);
            prop_assert!(matches!(
                manager.reserve(&tc, 1),
                Err(ReserveError::Exhausted)
            ));
        }
    }

    proptest! {
        #[test]
        fn capacity_invariant_survives_request_interleavings(
            operations in prop::collection::vec((0_u8..4, 1_u16..40), 1..120)
        ) {
            let manager = CapacityManager::in_memory();
            let tc = "0:property".to_string();
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), subscription(0, 0))
                .unwrap();
            let mut reservations: Vec<CapacityReservation> = Vec::new();
            for (operation, amount) in operations {
                match operation {
                    0 => {
                        if let Ok(reservation) = manager.reserve(&tc, u64::from(amount)) {
                            reservations.push(reservation);
                        }
                    }
                    1 => {
                        if let Some(reservation) = reservations.first() {
                            let delivered = reservation.remaining().min(u64::from(amount));
                            if delivered > 0 {
                                reservation.record_delivered(delivered).unwrap();
                            }
                        }
                    }
                    2 => {
                        if !reservations.is_empty() {
                            reservations.remove(0).finish_exact().unwrap();
                        }
                    }
                    _ => {
                        if !reservations.is_empty() {
                            reservations.remove(0).finish_ambiguous().unwrap();
                        }
                    }
                }
                let snapshot = manager.snapshot(&tc).unwrap().unwrap();
                prop_assert!(snapshot.committed().unwrap() <= snapshot.authoritative_cap);
                prop_assert!(snapshot.authoritative_cap <= snapshot.funded_tokens);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn capacity_invariant_survives_durable_crash_and_restart_points(
            operations in prop::collection::vec((1_u16..200, 0_u16..200, 0_u8..3, 0_u16..200), 1..40)
        ) {
            let directory = tempfile::tempdir().unwrap();
            let tc = "0:durable-property".to_string();
            let mut pending = TICK_SIZE;
            let mut manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
            manager
                .reconcile_deal(&tc, state(true, pending), subscription(0, 0))
                .unwrap();

            for (requested, delivered, finish, acknowledged) in operations {
                if let Ok(reservation) = manager.reserve(&tc, u64::from(requested)) {
                    let delivered = reservation.remaining().min(u64::from(delivered));
                    if delivered > 0 {
                        reservation.record_delivered(delivered).unwrap();
                    }
                    match finish {
                        0 => reservation.finish_exact().unwrap(),
                        1 => reservation.finish_ambiguous().unwrap(),
                        _ => drop(reservation),
                    }
                }
                let before = manager.snapshot(&tc).unwrap().unwrap();
                assert_invariant(before);
                let acknowledged =
                    before.local_delivered_after_anchor.min(u128::from(acknowledged));
                pending += acknowledged;

                drop(manager);
                manager = CapacityManager::in_deals_dir(directory.path().to_path_buf());
                let after = manager
                    .reconcile_deal(&tc, state(true, pending), subscription(0, 0))
                    .unwrap()
                    .unwrap();
                prop_assert_eq!(after.available().unwrap(), before.available().unwrap());
                prop_assert!(after.committed().unwrap() <= after.authoritative_cap);
                prop_assert!(after.authoritative_cap <= after.funded_tokens);
            }
        }
    }

    proptest! {
        #[test]
        fn ordinary_capacity_invariant_survives_request_interleavings(
            funded_remainder in 1_u16..2_000,
            operations in prop::collection::vec((0_u8..4, 1_u16..100), 1..80),
        ) {
            let manager = CapacityManager::in_memory();
            let tc = "0:ordinary-property".to_string();
            let funded = TICK_SIZE + u128::from(funded_remainder);
            manager
                .reconcile_deal(&tc, state(true, TICK_SIZE), ordinary(funded))
                .unwrap();
            let mut reservations: Vec<CapacityReservation> = Vec::new();
            for (operation, amount) in operations {
                match operation {
                    0 => {
                        if let Ok(reservation) = manager.reserve(&tc, u64::from(amount)) {
                            reservations.push(reservation);
                        }
                    }
                    1 => {
                        if let Some(reservation) = reservations.first() {
                            let delivered = reservation.remaining().min(u64::from(amount));
                            if delivered > 0 {
                                reservation.record_delivered(delivered).unwrap();
                            }
                        }
                    }
                    2 => {
                        if !reservations.is_empty() {
                            reservations.remove(0).finish_exact().unwrap();
                        }
                    }
                    _ => {
                        if !reservations.is_empty() {
                            reservations.remove(0).finish_ambiguous().unwrap();
                        }
                    }
                }
                let snapshot = manager.snapshot(&tc).unwrap().unwrap();
                prop_assert!(snapshot.committed().unwrap() <= snapshot.authoritative_cap);
                prop_assert!(snapshot.authoritative_cap <= snapshot.funded_tokens);
            }
        }
    }
}
