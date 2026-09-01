//! Handover payload -- a stable format that is encrypted to the
//! buyer's pubkey and placed in the endpoints file / `token_contract`
//! . It is the same blob; only the source that fills the file changes.

//! Carries the **gateway endpoint** and the **TLS certificate fingerprint**: the
//! buyer, after decrypting with the note, pins the fingerprint on the TLS connection -- a
//! MITM with a foreign certificate is rejected, because the genuine fingerprint arrived over
//! the channel encrypted to the note.

use serde::{Deserialize, Serialize};

/// Decrypted handover payload. Serialized to JSON, then encrypted to the buyer's
/// pubkey (`Note::encrypt_to`). The format is stable between directives 1 and 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handover {
    /// Seller's gateway endpoint (points at the gateway, not the upstream; R15).
    pub endpoint: String,
    /// Fingerprint of the gateway's self-signed TLS certificate: SHA-256 over DER, hex.
    pub tls_fingerprint: String,
}

/// The on-chain wire shape: the handover fields plus the deal they were written for.
/// Flattened, so the JSON stays a superset of [`Handover`] and [`Handover::from_bytes`]
/// keeps parsing it.
#[derive(Serialize, Deserialize)]
struct DealBoundHandover {
    #[serde(flatten)]
    handover: Handover,
    #[serde(default, with = "crate::address::serde_self_dapp_opt")]
    token_contract: Option<String>,
}

/// Why decrypted bytes are not THIS deal's handover (E2E-OPEN-07).
#[derive(Debug)]
pub enum HandoverDealError {
    /// The bytes are not a handover payload at all.
    Payload(serde_json::Error),
    /// The payload names no deal, so it cannot be attributed to this one.
    Unattributed,
    /// The payload was written for another deal -- a replayed ciphertext.
    OtherDeal {
        /// The deal the seller encrypted this payload for.
        written_for: String,
        /// The deal it was read from.
        read_from: String,
    },
}

impl std::fmt::Display for HandoverDealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Payload(error) => write!(f, "{error}"),
            Self::Unattributed => write!(f, "no deal identity in the payload"),
            Self::OtherDeal {
                written_for,
                read_from,
            } => write!(
                f,
                "written for deal {}, not {}",
                crate::address::display_self_dapp(written_for),
                crate::address::display_self_dapp(read_from)
            ),
        }
    }
}

impl std::error::Error for HandoverDealError {}

impl Handover {
    /// Serialize to bytes for encryption (`encrypt_to`).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("handover serializes")
    }

    /// Parse decrypted bytes back into the payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Serialize for encryption, naming the deal this handover is written for.
    /// The AEAD authenticates only the ciphertext, never the `TokenContract` it is stored on, so
    /// without this the same bytes replayed onto another deal of the same buyer decrypt and parse
    /// exactly like the original.
    pub fn to_deal_bytes(&self, token_contract: &str) -> Vec<u8> {
        serde_json::to_vec(&DealBoundHandover {
            handover: self.clone(),
            token_contract: Some(token_contract.to_string()),
        })
        .expect("handover serializes")
    }

    /// Parse decrypted bytes, accepting them ONLY as `token_contract`'s handover. The counterpart
    /// of [`Handover::to_deal_bytes`]: a payload naming another deal, or naming none, is refused
    /// before the caller can treat the deal as opened.
    pub fn from_deal_bytes(bytes: &[u8], token_contract: &str) -> Result<Self, HandoverDealError> {
        let bound: DealBoundHandover =
            serde_json::from_slice(bytes).map_err(HandoverDealError::Payload)?;
        match bound.token_contract {
            Some(written_for) if written_for.eq_ignore_ascii_case(token_contract) => {
                Ok(bound.handover)
            }
            Some(written_for) => Err(HandoverDealError::OtherDeal {
                written_for,
                read_from: token_contract.to_string(),
            }),
            None => Err(HandoverDealError::Unattributed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handover() -> Handover {
        Handover {
            endpoint: "https://gw.example:8443".to_string(),
            tls_fingerprint: "aa:bb".to_string(),
        }
    }

    #[test]
    fn deal_bound_handover_round_trips_for_its_own_deal() {
        let bytes = handover().to_deal_bytes("0:aaaa");
        assert_eq!(
            Handover::from_deal_bytes(&bytes, "0:AAAA").unwrap(),
            handover()
        );
        // The wire stays a superset: a plain read still sees the same endpoint/fingerprint.
        assert_eq!(Handover::from_bytes(&bytes).unwrap(), handover());
    }

    #[test]
    fn deal_bound_handover_refuses_a_replay_into_another_deal() {
        // E2E-OPEN-07 "wrong deal identity": the byte-exact valid ciphertext of one deal, read
        // from another deal of the same buyer, must not resolve into an endpoint.
        let bytes = handover().to_deal_bytes("0:aaaa");
        let error = Handover::from_deal_bytes(&bytes, "0:bbbb").unwrap_err();
        assert!(
            matches!(&error, HandoverDealError::OtherDeal { written_for, .. } if written_for == "0:aaaa"),
            "{error}"
        );
    }

    #[test]
    fn handover_without_a_deal_identity_is_refused() {
        let error = Handover::from_deal_bytes(&handover().to_bytes(), "0:aaaa").unwrap_err();
        assert!(matches!(error, HandoverDealError::Unattributed), "{error}");
    }
}
