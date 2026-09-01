//! Regression for the restart contract of a session that is past its one-time QR.

//! A bee session is cryptographic connection state, and the prepared `agent_onboard_request` is
//! published into the context of the same `AuthProfile` the `wallet_hello` came from. That makes
//! restart a reconciliation, not a retry: republishing a re-formed request would burn a sequence
//! number and desynchronise the ratchet, and rebuilding the session would need an invitation that
//! cannot be scanned twice.

//! Driven from a `request_prepared` state file in the exact shape of a real one. Every value is
//! synthetic: a live session's signing and DH secrets must never enter the repository.

use std::cell::{Cell, RefCell};
use std::time::Duration;

use anyhow::{bail, Result};
use async_trait::async_trait;
use bee_connect::{ResultOfCreateSharedKeySession, ResultOfWaitWalletHello};

use super::{
    BeeSessionIo, ObservedContextEvent, OnboardingSession, PreparedRequest, SessionLimits,
    SessionPhase,
};

const ENVELOPE: &str = concat!(
    r#"{"v":"bee_connect.msg/1","session_id":"fixture-session-id","dir":"c2w","#,
    r#""seq":1000000000002,"type":"agent_onboard_request","ts":1000000000,"#,
    r#""dh_public":"6666666666666666666666666666666666666666666666666666666666666666"}"#
);

/// One clock reading for the whole test binary, not one per call.

/// This fixture is built TWICE by tests that compare a session before and after -- `load()` at the
/// top, `load()` again for the expectation -- and it used to call `SystemTime::now()` each time. A
/// run that crossed a second boundary between the two produced `created_at` values one apart and
/// failed on a diff that was pure clock. Observed on CI: `1787851233` against `1787851232`,
/// `expires_at` likewise, everything else identical.

/// A test that fails once a minute by construction is worse than no test: it teaches the reader to
/// re-run instead of to look. `OnceLock` makes the two loads the same fixture, which is what the
/// comparison was always claiming to be about.
fn fixture_now() -> u64 {
    static NOW: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *NOW.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    })
}

fn request_prepared_state() -> String {
    let now = fixture_now();
    let filler = |byte: char| byte.to_string().repeat(64);
    serde_json::to_string(&serde_json::json!({
        "file_version": 1,
        "agent_name": "fixture-agent",
        "network": "mainnet",
        "endpoint": "https://net-b.example",
        "hot_pubkey": filler('a'),
        "phase": {
            "name": "request_prepared",
            "request": {
                "profile_address": format!("0:{}", filler('f')),
                "session_id": "fixture-session-id",
                "hello_event_id": filler('7'),
                "context_created_at_from": now - 60,
                "envelope_json": ENVELOPE,
                "session_state": {
                    "encryption_root": filler('1'),
                    "my_dh_secret": filler('2'),
                    "peer_dh_public": filler('3'),
                    "signing_public": filler('4'),
                    "signing_secret": filler('5'),
                    "created_at": now - 120,
                    "expires_at": now + 3600,
                    "last_seen_seq": 1_000_000_000_001u64,
                    "last_sent_seq": 1_000_000_000_002u64,
                },
            },
        },
    }))
    .unwrap()
}

fn load() -> OnboardingSession {
    serde_json::from_str(&request_prepared_state()).expect("the fixture is a valid state file")
}

fn limits() -> SessionLimits {
    SessionLimits {
        session_ttl: Duration::from_secs(3600),
        hello_poll_attempts: 3,
        hello_poll_interval: Duration::from_millis(1),
        response_poll_attempts: 3,
        response_poll_interval: Duration::from_millis(1),
        context_event_limit: 50,
        timestamp_future_skew: Duration::from_secs(60),
        agent_name_max_chars: 64,
    }
}

/// The prepared request exactly as it sits on disk, as JSON, so a single comparison covers the
/// envelope, the sequence numbers and every key in the session state at once.
fn stored_request(session: &OnboardingSession) -> serde_json::Value {
    serde_json::to_value(&session.phase).unwrap()["request"].clone()
}

fn carried_request(session: &OnboardingSession) -> serde_json::Value {
    let SessionPhase::AwaitingWalletsResponse { .. } = &session.phase else {
        panic!(
            "a reconciled request must be waiting for the response, not in `{}`",
            session.phase_name()
        );
    };
    serde_json::to_value(&session.phase).unwrap()["request"].clone()
}

#[derive(Default)]
struct RecordingIo {
    already_in_profile: bool,
    hello_calls: Cell<usize>,
    exists_queries: RefCell<Vec<String>>,
    publishes: RefCell<Vec<String>>,
    response_waits: Cell<usize>,
}

impl RecordingIo {
    fn with_request_already_published(already_in_profile: bool) -> Self {
        Self {
            already_in_profile,
            ..Self::default()
        }
    }
}

#[async_trait(?Send)]
impl BeeSessionIo for RecordingIo {
    async fn wait_wallet_hello(
        &self,
        _invitation: &ResultOfCreateSharedKeySession,
        _limits: SessionLimits,
    ) -> Result<ResultOfWaitWalletHello> {
        self.hello_calls.set(self.hello_calls.get() + 1);
        bail!("a resumed session must never wait for a second wallet_hello")
    }

    async fn request_exists(
        &self,
        request: &PreparedRequest,
        _limits: SessionLimits,
    ) -> Result<bool> {
        self.exists_queries
            .borrow_mut()
            .push(request.envelope_json.clone());
        Ok(self.already_in_profile)
    }

    async fn publish_request(&self, request: &PreparedRequest) -> Result<()> {
        self.publishes
            .borrow_mut()
            .push(request.envelope_json.clone());
        Ok(())
    }

    async fn wait_wallets_response(
        &self,
        _request: &PreparedRequest,
        _limits: SessionLimits,
    ) -> Result<ObservedContextEvent> {
        self.response_waits.set(self.response_waits.get() + 1);
        bail!("not reached while reconciling a prepared request")
    }
}

#[tokio::test]
async fn a_request_already_in_the_profile_is_not_published_again() {
    let before = load();
    let io = RecordingIo::with_request_already_published(true);
    let after = load().advance_after_restart(&io, limits()).await.unwrap();

    assert!(
        io.publishes.borrow().is_empty(),
        "the request was already in the AuthProfile; publishing it again would burn a sequence number"
    );
    assert_eq!(
        io.exists_queries.borrow().as_slice(),
        [ENVELOPE.to_string()],
        "reconciliation must ask about the exact stored envelope"
    );
    assert_eq!(
        carried_request(&after),
        stored_request(&before),
        "the session must carry the same prepared request forward, unaltered"
    );
    assert_eq!(io.hello_calls.get(), 0);
    assert_eq!(io.response_waits.get(), 0);
}

#[tokio::test]
async fn an_unpublished_request_is_published_once_and_unchanged() {
    let before = load();
    let io = RecordingIo::with_request_already_published(false);
    let after = load().advance_after_restart(&io, limits()).await.unwrap();

    assert_eq!(
        io.publishes.borrow().as_slice(),
        [ENVELOPE.to_string()],
        "exactly the stored envelope, published exactly once -- no rekey, no new seq, no newly formed request"
    );
    assert_eq!(
        carried_request(&after),
        stored_request(&before),
        "publication must not alter the request the session carries"
    );
    assert_eq!(
        io.exists_queries.borrow().len(),
        limits().response_poll_attempts as usize,
        "an absent request is reconciled across the eventually consistent index before publishing"
    );
    assert_eq!(
        io.hello_calls.get(),
        0,
        "a resumed session must never rebuild itself or emit a second invitation"
    );
    assert_eq!(io.response_waits.get(), 0);
}

/// The reconciliation asks first and publishes second, never the other way round. An indeterminate
/// send result must be settled against the exact envelope before anything is sent again.
#[tokio::test]
async fn reconciliation_queries_before_it_publishes() {
    struct OrderedIo {
        events: RefCell<Vec<&'static str>>,
    }

    #[async_trait(?Send)]
    impl BeeSessionIo for OrderedIo {
        async fn wait_wallet_hello(
            &self,
            _invitation: &ResultOfCreateSharedKeySession,
            _limits: SessionLimits,
        ) -> Result<ResultOfWaitWalletHello> {
            self.events.borrow_mut().push("hello");
            bail!("never")
        }

        async fn request_exists(
            &self,
            _request: &PreparedRequest,
            _limits: SessionLimits,
        ) -> Result<bool> {
            self.events.borrow_mut().push("exists");
            Ok(false)
        }

        async fn publish_request(&self, _request: &PreparedRequest) -> Result<()> {
            self.events.borrow_mut().push("publish");
            Ok(())
        }

        async fn wait_wallets_response(
            &self,
            _request: &PreparedRequest,
            _limits: SessionLimits,
        ) -> Result<ObservedContextEvent> {
            self.events.borrow_mut().push("response");
            bail!("never")
        }
    }

    let io = OrderedIo {
        events: RefCell::new(Vec::new()),
    };
    load().advance_after_restart(&io, limits()).await.unwrap();

    let events = io.events.borrow();
    assert_eq!(
        events.last(),
        Some(&"publish"),
        "publication must come last: {events:?}"
    );
    assert!(
        events.iter().take(events.len() - 1).all(|e| *e == "exists"),
        "nothing but reconciliation may precede the publish: {events:?}"
    );
}
