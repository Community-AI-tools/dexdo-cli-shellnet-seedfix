//! Regression and invariant coverage for the version-3 Vault -> Hot funding journal.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use super::providers::{AckinackiVaultProvider, QueuedTransfer, VaultChain, VaultQueueEvent};
use super::*;

const SHELL: u32 = dexdo_core::params::SHELL_CURRENCY_ID;
const CREATED: u64 = 1_800_000_000;

fn hex64(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn hot_address() -> String {
    format!("{}::{}", hex64(0xa1), hex64(0xa1))
}

fn request(native: u128, shell: u128, other: u128) -> FundingRequest {
    let mut shortfall = BTreeMap::new();
    if shell > 0 {
        shortfall.insert(SHELL, shell);
    }
    if other > 0 {
        shortfall.insert(7, other);
    }
    FundingRequest {
        provider: WalletProvider::AckinackiWallet,
        network: "net-a".to_string(),
        vault_address: Some(format!("{}::{}", hex64(0xb2), hex64(0xb2))),
        hot_address: hot_address(),
        hot_dapp_id: hex64(0xa1),
        creator_pubkey: hex64(0xc3),
        required: shortfall.clone(),
        required_native: native,
        shortfall,
        native_shortfall: native,
    }
}

fn records(dir: &Path) -> Vec<FundingJournalRecord> {
    load_funding_journal_records(dir, "net-a", &hot_address())
        .expect("read journal")
        .unwrap_or_default()
}

fn was_prepared(selection: FundingJournalSelection) -> bool {
    matches!(selection, FundingJournalSelection::Prepared(_))
}

#[test]
fn an_exact_amount_is_reused_through_the_deadline_and_replaced_one_second_later() {
    let dir = tempfile::tempdir().expect("temp data dir");
    let amount = request(41, 900, 3);
    let lifetime = dexdo_core::params::VAULT_FUNDING_REQUEST_LIFETIME.as_secs();

    assert!(was_prepared(
        select_or_prepare_funding_request(dir.path(), &amount, CREATED).expect("first request")
    ));
    let at_deadline =
        select_or_prepare_funding_request(dir.path(), &amount, CREATED.saturating_add(lifetime))
            .expect("request at deadline");
    assert!(
        matches!(at_deadline, FundingJournalSelection::Existing(ref record) if record.generation == 1),
        "an exact request is still live at its deadline"
    );
    assert_eq!(records(dir.path()).len(), 1);

    let after_deadline = select_or_prepare_funding_request(
        dir.path(),
        &amount,
        CREATED.saturating_add(lifetime).saturating_add(1),
    )
    .expect("request after deadline");
    assert!(
        matches!(after_deadline, FundingJournalSelection::Prepared(ref record) if record.generation == 2),
        "one second after the deadline the old request is removed and a new generation is prepared"
    );
    let remaining = records(dir.path());
    assert_eq!(remaining.len(), 1, "the expired generation was cleaned");
    assert_eq!(remaining[0].generation, 2);
}

#[test]
fn one_raw_unit_in_either_amount_creates_a_distinct_live_request() {
    let dir = tempfile::tempdir().expect("temp data dir");
    let base = request(41, 900, 3);
    let native_differs = request(42, 900, 3);
    let currency_differs = request(41, 901, 3);

    assert!(was_prepared(
        select_or_prepare_funding_request(dir.path(), &base, CREATED).expect("base request")
    ));
    assert!(was_prepared(
        select_or_prepare_funding_request(dir.path(), &native_differs, CREATED + 1)
            .expect("native differs")
    ));
    assert!(was_prepared(
        select_or_prepare_funding_request(dir.path(), &currency_differs, CREATED + 2)
            .expect("currency differs")
    ));

    let live = records(dir.path());
    assert_eq!(live.len(), 3);
    assert_eq!(live[0].fingerprint.value, 41);
    assert_eq!(live[1].fingerprint.value, 42);
    assert_eq!(live[2].fingerprint.cc.get(&SHELL), Some(&901));
}

#[test]
fn creating_a_new_amount_removes_every_expired_record_and_keeps_every_live_one() {
    let dir = tempfile::tempdir().expect("temp data dir");
    let lifetime = dexdo_core::params::VAULT_FUNDING_REQUEST_LIFETIME.as_secs();

    select_or_prepare_funding_request(dir.path(), &request(10, 100, 0), CREATED)
        .expect("older request");
    select_or_prepare_funding_request(dir.path(), &request(20, 200, 0), CREATED + 2)
        .expect("newer request");
    let now = CREATED.saturating_add(lifetime).saturating_add(1);
    select_or_prepare_funding_request(dir.path(), &request(30, 300, 0), now)
        .expect("third request");

    let remaining = records(dir.path());
    assert_eq!(remaining.len(), 2);
    assert_eq!(
        remaining[0].generation, 2,
        "the request at its deadline remains live"
    );
    assert_eq!(remaining[1].generation, 3);
}

#[derive(Default)]
struct ConcurrentVault {
    queue: Mutex<Vec<QueuedTransfer>>,
    submits: AtomicUsize,
}

#[async_trait::async_trait(?Send)]
impl VaultChain for Arc<ConcurrentVault> {
    async fn queue(&self) -> Result<Vec<QueuedTransfer>> {
        Ok(self.queue.lock().expect("queue lock").clone())
    }

    async fn history(&self) -> Result<Vec<VaultQueueEvent>> {
        Ok(Vec::new())
    }

    async fn delivery_message_id(
        &self,
        _sent_event_message_id: &str,
        _destination: &str,
        _destination_dapp_id: &str,
    ) -> Result<Option<String>> {
        Ok(None)
    }

    async fn submit(&self, fingerprint: &FundingFingerprint) -> Result<SubmitOutcome> {
        let id = self.submits.fetch_add(1, Ordering::SeqCst) as u64 + 1;
        self.queue.lock().expect("queue lock").push(QueuedTransfer {
            id,
            creator_pubkey: Some(fingerprint.creator.clone()),
            dest: fingerprint.dest.clone(),
            value: fingerprint.value,
            cc: fingerprint.cc.clone(),
            send_flags: fingerprint.send_flags,
            bounce: fingerprint.bounce,
            dapp_id: fingerprint.dapp_id.clone(),
            payload: None,
        });
        Ok(SubmitOutcome::Accepted {
            transaction_hash: Some(format!("tx-{id}")),
            pending_transaction_id: Some(id.to_string()),
        })
    }
}

struct EmptyHot;

#[async_trait::async_trait(?Send)]
impl HotBalanceReader for EmptyHot {
    async fn hot_balances(&self, _hot: &CanonicalAddress) -> Result<HotBalances> {
        Ok(HotBalances::default())
    }
}

#[test]
fn two_concurrent_commands_with_one_shortfall_arrange_only_one_request() {
    let dir = tempfile::tempdir().expect("temp data dir");
    let path = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(3));
    let vault = Arc::new(ConcurrentVault::default());
    let mut workers = Vec::new();

    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let vault = Arc::clone(&vault);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("current-thread runtime");
            runtime.block_on(async {
                let binding = HotFundingBinding {
                    provider: WalletProvider::AckinackiWallet,
                    network: "net-a".to_string(),
                    hot_address: hot_address(),
                    vault_address: Some(format!("{}::{}", hex64(0xb2), hex64(0xb2))),
                };
                let requirements = FundingRequirements {
                    required_native: 41,
                    required: [(SHELL, 900), (7, 3)].into_iter().collect(),
                };
                let provider = AckinackiVaultProvider::new(vault, None);
                let _ = ensure_hot_funded(
                    &HotFundingContext {
                        binding: &binding,
                        requirements: &requirements,
                        operation: "note deploy",
                        creator_pubkey: &hex64(0xc3),
                        data_dir: &path,
                        bounds: FundingWaitBounds {
                            timeout: Duration::ZERO,
                            poll: Duration::from_millis(1),
                            lock_timeout: Duration::from_secs(2),
                            lock_poll: Duration::from_millis(1),
                        },
                    },
                    &EmptyHot,
                    &provider,
                )
                .await;
            });
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().expect("worker");
    }

    assert_eq!(
        vault.submits.load(Ordering::SeqCst),
        1,
        "the production arrangement path submits exactly once"
    );
    let records = records(dir.path());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, FundingState::Submitted);
}

#[test]
fn version_two_is_migrated_in_memory_then_written_as_version_three() {
    let dir = tempfile::tempdir().expect("temp data dir");
    ensure_funding_requests_dir(dir.path()).expect("journal dir");
    let path = funding_journal_path(dir.path(), "net-a", &hot_address());
    let record = FundingJournalRecord::open_generation(&request(41, 900, 3), CREATED, 7);
    let mut value = serde_json::to_value(&record).expect("serialize old record");
    let object = value.as_object_mut().expect("record object");
    object.remove("expires_at_unix");
    object.insert("version".to_string(), serde_json::Value::from(2));
    let old_bytes = serde_json::to_vec_pretty(&value).expect("serialize v2");
    std::fs::write(&path, &old_bytes).expect("write v2");

    let migrated = load_funding_journal_records(dir.path(), "net-a", &hot_address())
        .expect("read v2")
        .expect("one migrated record");
    assert_eq!(migrated.len(), 1);
    assert_eq!(migrated[0].generation, 7);
    assert_eq!(
        migrated[0].expires_at_unix,
        funding_request_deadline(CREATED)
    );
    assert_eq!(
        std::fs::read(&path).expect("read untouched v2"),
        old_bytes,
        "reading performs no mutation"
    );

    store_funding_journal(dir.path(), &migrated[0]).expect("persist v3");
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read v3")).expect("parse v3");
    assert_eq!(written["version"], 3);
    assert_eq!(written["requests"].as_array().map(Vec::len), Some(1));
    assert_eq!(written["requests"][0]["created_at_unix"], CREATED);
    assert_eq!(
        written["requests"][0]["expires_at_unix"],
        funding_request_deadline(CREATED)
    );
}

#[test]
fn unknown_or_inconsistent_journals_are_refused_without_rewrite() {
    let dir = tempfile::tempdir().expect("temp data dir");
    ensure_funding_requests_dir(dir.path()).expect("journal dir");
    let path = funding_journal_path(dir.path(), "net-a", &hot_address());

    let mut bad_deadline = FundingJournalRecord::open_generation(&request(41, 900, 3), CREATED, 1);
    bad_deadline.expires_at_unix = 0;
    let bad_deadline = serde_json::to_vec_pretty(&FundingJournal {
        version: FUNDING_JOURNAL_VERSION,
        requests: vec![bad_deadline],
    })
    .expect("serialize inconsistent deadline");

    let first = FundingJournalRecord::open_generation(&request(41, 900, 3), CREATED, 1);
    let mut duplicate = first.clone();
    duplicate.generation = 2;
    let duplicate_live_amount = serde_json::to_vec_pretty(&FundingJournal {
        version: FUNDING_JOURNAL_VERSION,
        requests: vec![first, duplicate],
    })
    .expect("serialize duplicate live amount");

    for bytes in [
        br#"{"version":99999,"written_by":"newer"}"#.to_vec(),
        bad_deadline,
        duplicate_live_amount,
        b"not json at all".to_vec(),
    ] {
        std::fs::write(&path, &bytes).expect("write refused journal");
        let before = std::fs::read(&path).expect("read before");
        assert!(
            select_or_prepare_funding_request(dir.path(), &request(41, 900, 3), CREATED).is_err()
        );
        assert_eq!(std::fs::read(&path).expect("read after"), before);
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

    #[test]
    fn arbitrary_request_sequences_never_create_two_live_exact_amounts(
        operations in proptest::collection::vec((0u16..8, 0u16..8, 0u16..8, 0u16..4000), 1..40)
    ) {
        let dir = tempfile::tempdir().expect("temp data dir");
        let mut now = CREATED;

        for (native, shell, other, advance) in operations {
            now = now.saturating_add(u64::from(advance));
            select_or_prepare_funding_request(
                dir.path(),
                &request(u128::from(native), u128::from(shell), u128::from(other)),
                now,
            )
            .expect("select request");
            let current = records(dir.path());
            let mut live_amounts = BTreeMap::new();
            for record in current.iter().filter(|record| {
                matches!(record.state, FundingState::Prepared | FundingState::Submitted)
                    && now
                        <= record.created_at_unix.saturating_add(
                            dexdo_core::params::VAULT_FUNDING_REQUEST_LIFETIME.as_secs(),
                        )
            }) {
                *live_amounts
                    .entry((record.fingerprint.value, record.fingerprint.cc.clone()))
                    .or_insert(0usize) += 1;
            }
            proptest::prop_assert!(
                live_amounts.values().all(|count| *count <= 1),
                "duplicate live exact amount after raw sequence: {:?}",
                live_amounts
            );
        }
    }
}
