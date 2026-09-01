//! Regressions for the `intent=agent_onboard` query parameter on the connect deeplink.

//! The wallet owner specified the final link verbatim:

//! ```text
//! https://links.gosh.sh/deeplinks/wallet/v1/connect?payload=<payload>&client_dh_public=<client_dh_public>&intent=agent_onboard
//! ```

//! Three separate claims are pinned here, because the requirement is not one property:
//! the intent is on the FINAL link, it is there exactly once even when the link already carried it,
//! and it is NOT inside `ConnectPayload` -- the bee payload is unchanged and still identifies
//! DEXDO CLI by its `app_id`.

use ed25519_dalek::SigningKey;

use super::{
    with_agent_onboard_intent, OnboardingSession, SessionLimits, SessionPhase,
    AGENT_ONBOARD_INTENT_QUERY, DEXDO_CLI_BEE_APP_ID,
};
use std::time::Duration;

const CONNECT_LINK_PREFIX: &str = "https://links.gosh.sh/deeplinks/wallet/v1/connect?payload=";

fn limits() -> SessionLimits {
    SessionLimits {
        session_ttl: Duration::from_secs(3_600),
        hello_poll_attempts: 2,
        hello_poll_interval: Duration::from_millis(1),
        response_poll_attempts: 2,
        response_poll_interval: Duration::from_millis(1),
        context_event_limit: 50,
        timestamp_future_skew: Duration::from_secs(30),
        agent_name_max_chars: 64,
    }
}

fn public_of(secret: [u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
}

fn fresh_session() -> OnboardingSession {
    OnboardingSession::create(
        "intent-test-agent",
        "net-a",
        "net-a.example",
        &public_of([3u8; 32]),
        None,
        &public_of([4u8; 32]),
        limits(),
    )
    .expect("a fresh onboarding session is created offline")
}

#[test]
fn a_new_session_deeplink_ends_with_exactly_one_agent_onboard_intent() {
    let session = fresh_session();
    let link = session
        .deep_link()
        .expect("a fresh onboarding exposes its invitation link");

    assert!(link.starts_with(CONNECT_LINK_PREFIX), "{link}");
    assert!(
        link.ends_with(&format!("&{AGENT_ONBOARD_INTENT_QUERY}")),
        "the intent is the last query parameter of the final link: {link}"
    );
    assert_eq!(
        link.matches(AGENT_ONBOARD_INTENT_QUERY).count(),
        1,
        "the intent must appear exactly once: {link}"
    );
    // The base link keeps its own two parameters, and gained no second `?`.
    assert_eq!(link.matches('?').count(), 1, "{link}");
    assert!(link.contains("&client_dh_public="), "{link}");
}

#[test]
fn the_intent_is_appended_to_the_link_and_never_put_inside_connect_payload() {
    let session = fresh_session();
    let SessionPhase::AwaitingWalletHello { invitation, .. } = &session.phase else {
        panic!("a new onboarding must await wallet_hello")
    };

    let payload_b64url = invitation
        .deep_link
        .split_once("?payload=")
        .and_then(|(_, query)| query.split_once("&client_dh_public="))
        .map(|(payload, _)| payload)
        .expect("the connect deeplink must carry its payload");
    let payload = bee_connect::decode_connect_payload_b64url(payload_b64url)
        .expect("the payload segment still decodes as a ConnectPayload");

    // The bee payload is untouched: same app_id, and no trace of the intent anywhere in it.
    assert_eq!(payload.app_id, DEXDO_CLI_BEE_APP_ID);
    assert_eq!(payload.description, invitation.description);
    assert!(
        !invitation.payload_json.contains("agent_onboard"),
        "the intent must not be carried inside ConnectPayload: {}",
        invitation.payload_json
    );
    assert!(
        !invitation.payload_json.contains("intent"),
        "the intent must not be carried inside ConnectPayload: {}",
        invitation.payload_json
    );
    // Everything before the intent is exactly the link bee produced.
    let base = invitation
        .deep_link
        .strip_suffix(&format!("&{AGENT_ONBOARD_INTENT_QUERY}"))
        .expect("the intent is appended, not spliced in");
    assert_eq!(
        base,
        format!(
            "{CONNECT_LINK_PREFIX}{payload_b64url}&client_dh_public={}",
            invitation.client_dh_public
        )
    );
}

#[test]
fn appending_the_intent_to_a_link_that_already_declares_it_does_not_duplicate_it() {
    let session = fresh_session();
    let already_final = session
        .deep_link()
        .expect("a fresh onboarding exposes its invitation link")
        .to_string();

    let reapplied = with_agent_onboard_intent(&already_final);

    assert_eq!(reapplied, already_final);
    assert_eq!(reapplied.matches(AGENT_ONBOARD_INTENT_QUERY).count(), 1);
}

#[test]
fn a_parameter_that_merely_spells_the_intent_is_not_mistaken_for_it() {
    // A value ending in the same bytes is a different parameter and must still get the real one.
    let link = "https://links.gosh.sh/deeplinks/wallet/v1/connect?payload=xintent=agent_onboard";

    let final_link = with_agent_onboard_intent(link);

    assert_eq!(final_link, format!("{link}&{AGENT_ONBOARD_INTENT_QUERY}"));
    assert_eq!(
        final_link
            .split(['?', '&'])
            .filter(|parameter| *parameter == AGENT_ONBOARD_INTENT_QUERY)
            .count(),
        1
    );
}
