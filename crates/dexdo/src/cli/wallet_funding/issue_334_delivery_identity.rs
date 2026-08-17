//! re-audit item 2, second reading: a grown balance is not the identity of a delivery.
//! `Executed` is a fact about the VAULT - the message left it. Retiring that generation and opening
//! the next one needs a second fact: that THIS transfer is what credited the Hot. An aggregated
//! balance cannot carry it. Any incoming transfer of the same size produces exactly the same reading,
//! so a Hot topped up from anywhere else while the Vault delivery is still in flight looks identical
//! to a Hot the delivery has reached - and the replacement generation opened from it asks the Vault
//! for the same shortfall a second time. When the original delivery lands, the Hot holds both.
//! What carries the identity is on chain. The queued path runs `txn.dest.transfer(...)` and then
//! `emit TransactionSent(...)` inside ONE Vault transaction, so the event message is an anchor to
//! that transaction and the delivery is its sibling out-message addressed to the Hot. That sibling's
//! id, checked through the destination's own finalized receipt, is the fact - and it is recorded on
//! [`FundingEvidence`] as its own field rather than inside a sentence, because a decision is taken
//! from it.
//! Every test here drives the real entry point [`ensure_hot_funded_with_turn`] through the real
//! production provider [`AckinackiVaultProvider`], composed the way a money command composes it.
//! Generation 1 is always created by the mechanism itself; the only thing a test changes afterwards
//! is what the chain reports.

use std::cell::{Cell, RefCell};

use super::providers::{
    AckinackiVaultProvider, QueuedTransfer, VaultChain, VaultQueueEvent, VaultQueueEventKind,
};
use super::*;

const SHELL: u32 = 2;
/// What the first command needs, and therefore what generation 1 carries.
const FIRST_REQUIREMENT: u128 = 400;
/// What the next command needs. Larger, so the requirement stays unmet and the executed generation
/// has to be reconciled rather than simply closed.
const SECOND_REQUIREMENT: u128 = 1_000;
const WINDOW: u64 = 3_600;
const QUEUED_AT: u64 = 1_000_000;

fn hex64(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn hot_address() -> String {
    format!("{}::{}", hex64(0xa1), hex64(0xa1))
}

fn vault_address() -> String {
    format!("{}::{}", hex64(0xb2), hex64(0xb2))
}

fn creator() -> String {
    hex64(0xc3)
}

fn binding() -> HotFundingBinding {
    HotFundingBinding {
        provider: WalletProvider::AckinackiWallet,
        network: "shellnet".to_string(),
        hot_address: hot_address(),
        vault_address: Some(vault_address()),
    }
}

/// One check-and-arrange pass, then give up - one run of the command, as an operator repeats it.
fn one_pass_bounds() -> FundingWaitBounds {
    FundingWaitBounds {
        timeout: Duration::ZERO,
        poll: Duration::from_millis(1),
        lock_timeout: Duration::from_millis(200),
        lock_poll: Duration::from_millis(1),
    }
}

fn sent_event(id: u64, at: u64) -> VaultQueueEvent {
    VaultQueueEvent {
        kind: VaultQueueEventKind::Sent,
        transaction_id: id,
        dest: hot_address(),
        value: 0,
        dapp_id: hex64(0xa1),
        message_id: format!("msg-sent-{id}"),
        created_at: at,
    }
}

/// What the chain can say about the internal message behind an executed transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// The sibling is there and the Hot's own receipt for it is finalized.
    Proven,
    /// The anchor, the sibling or the receipt is not readable yet: no sibling addressed to the Hot,
    /// two of them, or a destination transaction that has not finalized.
    Unproven,
    /// The read itself failed. Not an answer about money at all.
    Unreadable,
}

/// A scripted Vault. Every answer is a fact some real chain could return; nothing here decides.
struct FakeVault {
    queue: RefCell<Vec<QueuedTransfer>>,
    history: RefCell<Vec<VaultQueueEvent>>,
    delivery: Cell<Delivery>,
    now: Cell<u64>,
    submits: Cell<usize>,
    submitted: RefCell<Vec<FundingFingerprint>>,
    next_id: Cell<u64>,
}

impl FakeVault {
    fn with_delivery(delivery: Delivery) -> Self {
        Self {
            queue: RefCell::new(Vec::new()),
            history: RefCell::new(Vec::new()),
            delivery: Cell::new(delivery),
            now: Cell::new(QUEUED_AT),
            submits: Cell::new(0),
            submitted: RefCell::new(Vec::new()),
            next_id: Cell::new(7),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl VaultChain for &FakeVault {
    async fn queue(&self) -> Result<Vec<QueuedTransfer>> {
        Ok(self.queue.borrow().clone())
    }

    async fn history(&self) -> Result<Vec<VaultQueueEvent>> {
        Ok(self.history.borrow().clone())
    }

    async fn delivery_message_id(
        &self,
        sent_event_message_id: &str,
        destination: &str,
        destination_dapp_id: &str,
    ) -> Result<Option<String>> {
        assert_eq!(
            destination,
            hot_address(),
            "a delivery may only ever be proven at the destination the generation froze"
        );
        assert_eq!(destination_dapp_id, hex64(0xa1));
        match self.delivery.get() {
            Delivery::Proven => Ok(Some(format!("delivery-of-{sent_event_message_id}"))),
            Delivery::Unproven => Ok(None),
            Delivery::Unreadable => bail!("the delivery message could not be read"),
        }
    }

    async fn expiration_window_secs(&self) -> Result<u64> {
        Ok(WINDOW)
    }

    async fn chain_time_secs(&self) -> Result<u64> {
        Ok(self.now.get())
    }

    async fn submit(&self, fingerprint: &FundingFingerprint) -> Result<SubmitOutcome> {
        self.submits.set(self.submits.get() + 1);
        self.submitted.borrow_mut().push(fingerprint.clone());
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        // A real Vault takes the request into its queue and records that it did.
        self.queue.borrow_mut().push(QueuedTransfer {
            id,
            creator_pubkey: Some(creator()),
            dest: hot_address(),
            value: fingerprint.value,
            cc: fingerprint.cc.clone(),
            send_flags: VAULT_TO_HOT_SEND_FLAGS,
            bounce: VAULT_TO_HOT_BOUNCE,
            dapp_id: hex64(0xa1),
            payload: None,
        });
        self.history.borrow_mut().push(VaultQueueEvent {
            kind: VaultQueueEventKind::Submitted,
            transaction_id: id,
            dest: hot_address(),
            value: fingerprint.value,
            dapp_id: hex64(0xa1),
            message_id: format!("msg-submitted-{id}"),
            created_at: self.now.get(),
        });
        Ok(SubmitOutcome::Accepted {
            transaction_hash: Some(format!("tx-{id}")),
            pending_transaction_id: Some(id.to_string()),
        })
    }
}

/// A Hot whose balances are whatever the chain would report at that moment.
struct FakeHot {
    shell: u128,
}

impl FakeHot {
    /// A Hot with every native unit this money path can attach, holding `shell` ECC[2]. The native
    /// leg is deliberately never the refusal here: what is under test is the SHELL identity.
    fn holding(shell: u128) -> Self {
        Self { shell }
    }
}

#[async_trait::async_trait(?Send)]
impl HotBalanceReader for FakeHot {
    async fn hot_balances(&self, _hot: &CanonicalAddress) -> Result<HotBalances> {
        Ok(HotBalances::new(
            vault_to_hot_native_value(),
            [(SHELL, self.shell)],
        ))
    }
}

fn record_of(dir: &Path) -> Option<FundingJournalRecord> {
    load_funding_journal(dir, "shellnet", &hot_address()).expect("read journal")
}

fn temp() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp data dir")
}

/// One run of a money command's funding step, composed exactly as production composes it: read the
/// journal under the held turn, hand what it recorded to the provider, then run the mechanism.
async fn money_command_run(
    dir: &Path,
    vault: &FakeVault,
    hot: &FakeHot,
    required: u128,
) -> Result<FundedHot> {
    let recorded = record_of(dir)
        .filter(FundingJournalRecord::is_open)
        .map(|record| record.recorded_request());
    let provider = AckinackiVaultProvider::new(vault, recorded);
    let binding = binding();
    ensure_hot_funded_with_turn(
        &HotFundingContext {
            binding: &binding,
            requirements: &FundingRequirements::new([(SHELL, required)]),
            operation: "note deploy",
            creator_pubkey: &creator(),
            data_dir: dir,
            bounds: one_pass_bounds(),
        },
        HotTurn::AcquireOwn,
        hot,
        &provider,
    )
    .await
}

/// Run 1 through the real mechanism: an empty Hot, one generation created for the whole shortfall.
async fn generation_one(dir: &Path, vault: &FakeVault) {
    let hot = FakeHot::holding(0);
    let _ = money_command_run(dir, vault, &hot, FIRST_REQUIREMENT).await;
    assert_eq!(vault.submits.get(), 1, "the first run creates the request");
    let first = record_of(dir).expect("run 1 left a record");
    assert_eq!(first.generation, 1);
    assert_eq!(first.state, FundingState::Submitted);
    assert_eq!(first.pending_transaction_id.as_deref(), Some("7"));
    assert_eq!(
        first.fingerprint.cc.get(&SHELL),
        Some(&FIRST_REQUIREMENT),
        "generation 1 carries the whole shortfall it was sized for"
    );
}

/// The human confirms the request: the queue drops the entry and finalized history proves that exact
/// id EXECUTED. Nothing here says the Hot has been credited.
fn the_vault_transfer_executes(vault: &FakeVault) {
    vault.queue.borrow_mut().clear();
    vault.history.borrow_mut().push(sent_event(7, QUEUED_AT + 60));
}

// ---------------------------------------------------------------------------------------------
// The defect: a balance that grew by the right amount, for the wrong reason
// ---------------------------------------------------------------------------------------------

/// Someone else's transfer arrives while ours is still in flight.
/// The Hot now reads exactly what it would read had our delivery landed: the balance generation 1
/// was sized against, plus the amount generation 1 carries. Sizing generation 2 from that reading
/// asks the Vault for the remaining shortfall while the Vault still owes the first one - and once
/// the original delivery lands, the Hot has been credited twice out of a cold Vault.
/// Only the delivery's own identity separates the two readings, and here the chain cannot yet name
/// it. So nothing is submitted.
#[tokio::test]
async fn an_unrelated_credit_of_the_expected_size_opens_no_second_generation() {
    let dir = temp();
    let vault = FakeVault::with_delivery(Delivery::Unproven);
    generation_one(dir.path(), &vault).await;
    the_vault_transfer_executes(&vault);

    // The balance the OLD aggregate test accepts as proof of delivery: pre-delivery balance(0)
    // plus exactly what generation 1 carries(400). It came from somewhere else.
    let hot = FakeHot::holding(FIRST_REQUIREMENT);
    let _ = money_command_run(dir.path(), &vault, &hot, SECOND_REQUIREMENT).await;

    assert_eq!(
        vault.submits.get(),
        1,
        "an aggregated balance that grew by the carried amount does not identify WHICH transfer \
         grew it; while the delivery cannot be named, a replacement generation would ask the Vault \
         for a shortfall it is already sending"
    );
    let after = record_of(dir.path()).expect("the executed generation stays recorded");
    assert_eq!(
        after.generation, 1,
        "no generation may be opened while the executed one's delivery is unidentified"
    );
    assert_eq!(after.state, FundingState::Executed);
    let evidence = after.evidence.expect("the execution verdict is recorded");
    assert_eq!(
        evidence.delivery_message_id, None,
        "an unproven delivery must be recorded as unproven, never inferred from the balance"
    );
}

/// The same observation with the one fact that separates it: the chain names the internal message
/// that carried our transfer to the Hot, and the Hot's own receipt for it is finalized.
/// This is the half that keeps the refusal above honest. A fix that simply stopped opening
/// replacement generations would pass that test and leave a Hot that was underfunded once
/// permanently unfundable, which is worse than the defect.
#[tokio::test]
async fn a_delivery_the_chain_can_name_opens_the_next_generation_for_the_exact_remainder() {
    let dir = temp();
    let vault = FakeVault::with_delivery(Delivery::Proven);
    generation_one(dir.path(), &vault).await;
    the_vault_transfer_executes(&vault);

    let hot = FakeHot::holding(FIRST_REQUIREMENT);
    let _ = money_command_run(dir.path(), &vault, &hot, SECOND_REQUIREMENT).await;

    assert_eq!(
        vault.submits.get(),
        2,
        "a delivery proven by the destination's own receipt retires its generation, and an unmet \
         requirement must then open exactly one replacement"
    );
    let after = record_of(dir.path()).expect("run 2 opened a replacement record");
    assert_eq!(after.generation, 2);
    assert_eq!(after.state, FundingState::Submitted);
    assert_eq!(
        after.fingerprint.cc.get(&SHELL),
        Some(&(SECOND_REQUIREMENT - FIRST_REQUIREMENT)),
        "the replacement carries the exact remaining shortfall, not the original amount"
    );
    assert_eq!(
        vault.submitted.borrow().len(),
        2,
        "exactly two transfers were ever put on the wire"
    );
}

/// The delivery message id is a fact a later audit has to be able to read back, so it is recorded as
/// its own field. A phrase inside `source` or `detail` would be prose: the mechanism itself takes a
/// decision from this, and prose is not a decidable record.
#[tokio::test]
async fn the_proven_delivery_is_recorded_as_its_own_journal_field() {
    let dir = temp();
    let vault = FakeVault::with_delivery(Delivery::Proven);
    generation_one(dir.path(), &vault).await;
    the_vault_transfer_executes(&vault);

    // A requirement the delivery already meets, so the run stops on the executed verdict itself and
    // the record keeps it rather than being replaced by the next generation's.
    let hot = FakeHot::holding(0);
    let _ = money_command_run(dir.path(), &vault, &hot, FIRST_REQUIREMENT).await;

    let evidence = record_of(dir.path())
        .expect("record")
        .evidence
        .expect("the execution verdict is recorded");
    assert_eq!(
        evidence.delivery_message_id.as_deref(),
        Some("delivery-of-msg-sent-7"),
        "the internal message that carried the money is what the journal has to keep"
    );
    assert_ne!(
        evidence.source, "delivery-of-msg-sent-7",
        "`source` names the ext-out EVENT message, which is a different message from the delivery"
    );
}

// ---------------------------------------------------------------------------------------------
// A read that failed is not an answer about money
// ---------------------------------------------------------------------------------------------

/// The queue proves execution and the delivery read fails. Two different facts are now missing at
/// once, and neither may be guessed: the verdict falls back to `Unknown`, which submits nothing and
/// retires nothing. Reading a failed read as "no delivery" would be the same double transfer by a
/// different route.
#[tokio::test]
async fn a_delivery_read_that_failed_leaves_the_verdict_unknown_and_submits_nothing() {
    let dir = temp();
    let vault = FakeVault::with_delivery(Delivery::Unreadable);
    generation_one(dir.path(), &vault).await;
    the_vault_transfer_executes(&vault);

    let hot = FakeHot::holding(FIRST_REQUIREMENT);
    let _ = money_command_run(dir.path(), &vault, &hot, SECOND_REQUIREMENT).await;

    assert_eq!(
        vault.submits.get(),
        1,
        "a chain read that failed authorizes nothing"
    );
    let after = record_of(dir.path()).expect("the record survives an unreadable chain");
    assert_eq!(after.generation, 1);
    assert_eq!(
        after.state,
        FundingState::Submitted,
        "an unknown verdict must not advance the record to a finalized one"
    );
}
