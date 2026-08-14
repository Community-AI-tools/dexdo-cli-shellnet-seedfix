use super::*;
use dexdo_core::{LocalNote, Note};
use std::any::Any;
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

const ISSUED_POISON_PANIC: &str = " intentional issued-lock poison";
const BUYER_PUBKEYS_POISON_PANIC: &str = " intentional buyer-pubkeys-lock poison";

fn panic_text(payload: &(dyn Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
}

fn poison_issued(registry: &Arc<AuthRegistry>) {
    let registry = Arc::clone(registry);
    let first_failure = std::thread::spawn(move || {
        let _guard = registry.issued.lock().expect("issued lock starts healthy");
        panic!("{ISSUED_POISON_PANIC}");
    })
    .join()
    .expect_err("the first lock-holder failure must remain a real panic");
    assert_eq!(
        panic_text(first_failure.as_ref()),
        Some(ISSUED_POISON_PANIC),
        "the first panic must remain observable and attributable"
    );
}

fn poison_buyer_pubkeys(registry: &Arc<AuthRegistry>) {
    let registry = Arc::clone(registry);
    let first_failure = std::thread::spawn(move || {
        let _guard = registry
            .buyer_pubkeys
            .lock()
            .expect("buyer pubkeys lock starts healthy");
        panic!("{BUYER_PUBKEYS_POISON_PANIC}");
    })
    .join()
    .expect_err("the first lock-holder failure must remain a real panic");
    assert_eq!(
        panic_text(first_failure.as_ref()),
        Some(BUYER_PUBKEYS_POISON_PANIC),
        "the first panic must remain observable and attributable"
    );
}

#[test]
fn issue_1157_verify_response_fails_closed_after_issued_lock_poison() {
    let registry = Arc::new(AuthRegistry::new());
    let buyer = LocalNote::generate();
    let token_contract = "tc-1157-verify";
    let nonce = b"nonce-1157-verify";
    registry.register(token_contract, buyer.pubkey());
    registry.issue_challenge(token_contract, nonce.to_vec());
    let signature = buyer.sign(&challenge_bytes(token_contract, nonce));

    poison_issued(&registry);

    let (verification, output) = capture_error_output(|| {
        panic::catch_unwind(AssertUnwindSafe(|| {
            registry.verify_response(token_contract, nonce, &signature)
        }))
        .expect("verify_response must not panic on a poisoned issued lock")
    });
    assert!(
        !verification,
        "a poisoned anti-replay lock must fail closed"
    );
    assert!(
        output.contains("seller runtime lock poisoned: seller auth issued"),
        "the fail-closed record must name the poisoned lock; output: {output:?}"
    );
}

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock stays healthy")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_error_output<T>(action: impl FnOnce() -> T) -> (T, String) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&output);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::ERROR)
        .with_writer(move || SharedWriter(Arc::clone(&captured)))
        .finish();
    let result = tracing::subscriber::with_default(subscriber, action);
    let output = String::from_utf8(output.lock().expect("read captured tracing output").clone())
        .expect("tracing output is utf8");
    (result, output)
}

#[test]
fn issue_1157_discard_challenge_records_issued_lock_poison() {
    let registry = Arc::new(AuthRegistry::new());
    let token_contract = "tc-1157-discard";
    let nonce = b"nonce-1157-discard";
    registry.issue_challenge(token_contract, nonce.to_vec());
    poison_issued(&registry);

    let (discarded, output) = capture_error_output(|| {
        panic::catch_unwind(AssertUnwindSafe(|| {
            registry.discard_challenge(token_contract, nonce)
        }))
        .expect("discard_challenge must not panic on a poisoned issued lock")
    });
    assert!(!discarded, "a poisoned anti-replay lock must fail closed");
    assert!(
        output.contains("seller runtime lock poisoned: seller auth issued"),
        "the fail-closed record must name the poisoned lock; output: {output:?}"
    );
}

#[test]
fn issue_1157_verify_response_records_buyer_pubkeys_lock_poison() {
    let registry = Arc::new(AuthRegistry::new());
    let buyer = LocalNote::generate();
    let token_contract = "tc-1157-buyer-pubkeys";
    let nonce = b"nonce-1157-buyer-pubkeys";
    registry.register(token_contract, buyer.pubkey());
    registry.issue_challenge(token_contract, nonce.to_vec());
    let signature = buyer.sign(&challenge_bytes(token_contract, nonce));
    poison_buyer_pubkeys(&registry);

    let (verification, output) = capture_error_output(|| {
        panic::catch_unwind(AssertUnwindSafe(|| {
            registry.verify_response(token_contract, nonce, &signature)
        }))
        .expect("verify_response must not panic on a poisoned buyer-pubkeys lock")
    });
    assert!(!verification, "a poisoned buyer registry must fail closed");
    assert!(
        output.contains("seller runtime lock poisoned: seller auth buyer_pubkeys"),
        "the fail-closed record must name the poisoned lock; output: {output:?}"
    );
}

#[test]
fn issue_1157_issue_challenge_recovers_and_records_the_poisoned_lock() {
    let registry = Arc::new(AuthRegistry::new());
    poison_issued(&registry);

    let token_contract = "tc-1157-recover";
    let nonce = b"nonce-1157-recover".to_vec();

    let (_, output) = capture_error_output(|| {
        panic::catch_unwind(AssertUnwindSafe(|| {
            registry.issue_challenge(token_contract, nonce.clone());
        }))
        .expect("issue_challenge must recover instead of panicking");
    });

    let recovered = registry
        .issued
        .lock()
        .expect_err("the standard mutex remains marked poisoned")
        .into_inner();
    assert!(
        recovered
            .get(token_contract)
            .is_some_and(|nonces| nonces.contains(&nonce)),
        "issue_challenge must continue through poison"
    );
    assert!(
        output.contains("seller runtime lock poisoned: seller auth issued"),
        "the recovery record must name the poisoned lock; output: {output:?}"
    );
}
