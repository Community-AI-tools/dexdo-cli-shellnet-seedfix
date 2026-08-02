//! Canonical Acki Nacki addresses: `<dapp_id>::<account_id>`.
//! The legacy TVM form `0:<account_id>` names only the workchain and drops the DApp identity, so it is
//! not sufficient as the address a user reads, pastes, or stores. Everything dexdo shows or persists uses
//! the canonical form; the legacy form stays accepted on input and in files written by older versions, and
//! is normalized before it is displayed again.
//! Two directions, deliberately separate:
//! - **out**([`display`], [`to_canonical`]) - the public form, `<dapp_id>::<account_id>`;
//! - **in**([`CanonicalAddress::parse`], [`to_chain_param`], `parse_chain_address`) - accepts both forms
//! and yields the workchain form the chain client and the contract parameters take.
//! A supplied DApp id is never discarded: it is carried on [`CanonicalAddress`] and re-emitted on output.

use std::fmt;

/// The dexdo DApp id in canonical 64-hex form.
/// dexdo contracts - private notes, order books, root models, token contracts - all live in the system
/// Dex DApp(`4`). This is protocol-defined, not a per-deployment guess: it is what
/// `contracts/deployed.shellnet.json` pins as `dapp_id` and what the deployed contracts compile in as
/// `ROOT_PN_DAPP_ID`. It is the DApp assumed for a legacy `0:<account_id>` that carries no DApp of its own.
pub const DEXDO_DAPP_ID: &str = "0000000000000000000000000000000000000000000000000000000000000004";

/// A blockchain address in canonical form: a DApp id plus an account id, both 256-bit.
/// Built by [`CanonicalAddress::parse`], which accepts the canonical `<dapp_id>::<account_id>` and the
/// legacy `0:<account_id>`. Renders canonical through [`fmt::Display`]; [`CanonicalAddress::legacy`]
/// renders the workchain form the chain client and contract parameters still take.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalAddress {
    dapp_id: String,
    account_id: String,
}

impl CanonicalAddress {
    /// Parse either accepted form, fail-loud on anything else.
    /// - `<dapp_id>::<account_id>` - both halves exactly 64 hex chars; the DApp id is kept.
    /// - `0:<account_id>` - the legacy form; the account must be exactly 64 hex chars and the DApp is
    /// taken to be [`DEXDO_DAPP_ID`], the DApp every dexdo contract lives in.
    /// Both halves are lowercased. A short/over-long half, a bare hex without a prefix, non-hex, and
    /// extra `::` are rejected rather than being coerced into an address that would move money elsewhere.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some((dapp_id, account_id)) = s.split_once("::") {
            let (dapp_id, account_id) = (dapp_id.trim(), account_id.trim());
            if !is_hex64(dapp_id) || !is_hex64(account_id) {
                return Err(format!(
                    "invalid address `{s}`: canonical `<dapp_id>::<account_id>` takes two 64-hex \
                     (256-bit) halves"
                ));
            }
            return Ok(Self {
                dapp_id: dapp_id.to_ascii_lowercase(),
                account_id: account_id.to_ascii_lowercase(),
            });
        }
        if let Some(account_id) = s.strip_prefix("0:") {
            if !is_hex64(account_id) {
                return Err(format!(
                    "invalid address `{s}`: the legacy `0:<hex>` account must be exactly 64 hex chars"
                ));
            }
            return Ok(Self {
                dapp_id: DEXDO_DAPP_ID.to_string(),
                account_id: account_id.to_ascii_lowercase(),
            });
        }
        Err(format!(
            "invalid address `{s}`: expected canonical `<dapp_id>::<account_id>` (64-hex halves) or \
             legacy `0:<64 hex>`"
        ))
    }

    /// The DApp the account belongs to, 64-hex lowercase.
    pub fn dapp_id(&self) -> &str {
        &self.dapp_id
    }

    /// The account id, 64-hex lowercase, with no prefix.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The legacy workchain form `0:<account_id>` - what the chain client and contract address
    /// parameters take. The DApp id is not part of it, which is exactly why it is not the public form.
    pub fn legacy(&self) -> String {
        format!("0:{}", self.account_id)
    }
}

impl fmt::Display for CanonicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.dapp_id, self.account_id)
    }
}

/// Normalize any accepted form to the canonical public form, fail-loud on anything else.
pub fn to_canonical(s: &str) -> Result<String, String> {
    Ok(CanonicalAddress::parse(s)?.to_string())
}

/// Normalize any accepted form to the workchain form `0:<account_id>` for the chain client and contract
/// parameters, fail-loud on anything else. The canonical form is accepted here so a user may paste it
/// wherever an address is taken.
pub fn to_chain_param(s: &str) -> Result<String, String> {
    Ok(CanonicalAddress::parse(s)?.legacy())
}

/// Render an address for output in the canonical public form.
/// This is the display seam: it upgrades a stored/legacy `0:<account_id>` to `<dapp_id>::<account_id>`
/// and leaves an already-canonical address alone. A value that is not an address at all (a placeholder,
/// a `-`, a name) is passed through trimmed rather than being hidden behind an error - output must never
/// be less informative than the value it has.
pub fn display(s: &str) -> String {
    match CanonicalAddress::parse(s) {
        Ok(addr) => addr.to_string(),
        Err(_) => s.trim().to_string(),
    }
}

/// [`display`] over an optional address, with `placeholder` for `None`(the `-` a table column shows).
pub fn display_opt(s: Option<&str>, placeholder: &str) -> String {
    s.map_or_else(|| placeholder.to_string(), display)
}

/// Parse any accepted form into a chain [`Address`](crate::Address).
/// A strict widening of `Address::parse`: everything the SDK already accepts (`0:<hex>`, `0x<hex>`, bare
/// hex) still parses, and the canonical `<dapp_id>::<account_id>` - which the SDK reads as workchain
/// `<dapp_id>` and rejects - is accepted too. Use this wherever an address arrives from a person or a
/// file(a CLI argument, a manifest, a deal handle) instead of `Address::parse`.
#[cfg(feature = "shellnet")]
pub fn parse_chain_address(s: &str) -> anyhow::Result<crate::Address> {
    let s = s.trim();
    if s.contains("::") {
        let canonical = CanonicalAddress::parse(s).map_err(|e| anyhow::anyhow!(e))?;
        return crate::Address::parse(&canonical.legacy());
    }
    crate::Address::parse(s)
}

/// Serde for an address field that is **written** canonically and **read** in either form.
/// Serialization emits `<dapp_id>::<account_id>`, so every newly written file carries the public form.
/// Deserialization accepts a file written either way and yields the workchain form the rest of the
/// client passes to the chain, so an existing `0:<account_id>` file keeps working unchanged. A value
/// that is not an address is carried through untouched, so a hand-written or future manifest never
/// becomes unreadable or unwritable because of this field.
pub mod serde_canonical {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Emit the canonical public form.
    pub fn serialize<S: Serializer>(value: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::display(value))
    }

    /// Accept either form; keep the workchain form in memory.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(super::CanonicalAddress::parse(&raw)
            .map(|addr| addr.legacy())
            .unwrap_or(raw))
    }
}

/// [`serde_canonical`] for an optional address field(`Option<String>`); `null`/absent is untouched.
pub mod serde_canonical_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Emit the canonical public form, or `null`.
    pub fn serialize<S: Serializer>(
        value: &Option<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&super::display(value)),
            None => serializer.serialize_none(),
        }
    }

    /// Accept either form; keep the workchain form in memory.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.map(|raw| {
            super::CanonicalAddress::parse(&raw)
                .map(|addr| addr.legacy())
                .unwrap_or(raw)
        }))
    }
}

/// Exactly 64 hex chars - a 256-bit DApp id or account id.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h64(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    /// The DApp id is protocol-defined, not a guess: it is the `dapp_id` the deployed-contracts manifest
    /// pins, in the 64-hex form the canonical address uses. If the chain moves dexdo to another DApp this
    /// test fails instead of the client quietly printing a wrong identity.
    #[test]
    fn dapp_id_matches_the_deployed_contracts_manifest() {
        let deployed: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/deployed.shellnet.json"))
                .unwrap();
        assert_eq!(deployed["dapp_id"].as_str(), Some(DEXDO_DAPP_ID));
        assert!(is_hex64(DEXDO_DAPP_ID), "{DEXDO_DAPP_ID}");
    }

    /// Canonical in, canonical out: parsing then rendering is the identity on a canonical address, and
    /// the supplied DApp id survives it instead of being replaced by the dexdo default.
    #[test]
    fn canonical_round_trips_and_keeps_the_supplied_dapp_id() {
        let dapp = h64('7');
        let account = h64('b');
        let canonical = format!("{dapp}::{account}");

        let addr = CanonicalAddress::parse(&canonical).unwrap();
        assert_eq!(addr.dapp_id(), dapp);
        assert_eq!(addr.account_id(), account);
        assert_eq!(addr.to_string(), canonical);
        assert_eq!(to_canonical(&canonical).unwrap(), canonical);
        assert_eq!(display(&canonical), canonical);
        // Re-parsing our own output is stable.
        assert_eq!(CanonicalAddress::parse(&addr.to_string()).unwrap(), addr);
        // A DApp that is not dexdo's is carried, not rewritten.
        assert_ne!(addr.dapp_id(), DEXDO_DAPP_ID);
    }

    /// Legacy in, canonical out: a `0:<account>` address is upgraded to the dexdo DApp and keeps its
    /// account id, and going back to the chain form returns exactly the input.
    #[test]
    fn legacy_round_trips_through_canonical() {
        let account = h64('a');
        let legacy = format!("0:{account}");
        let canonical = format!("{DEXDO_DAPP_ID}::{account}");

        assert_eq!(to_canonical(&legacy).unwrap(), canonical);
        assert_eq!(display(&legacy), canonical);
        let addr = CanonicalAddress::parse(&legacy).unwrap();
        assert_eq!(addr.dapp_id(), DEXDO_DAPP_ID);
        assert_eq!(addr.account_id(), account);
        assert_eq!(addr.legacy(), legacy);
        // canonical -> chain form -> canonical is lossless for a dexdo-DApp address.
        assert_eq!(to_chain_param(&canonical).unwrap(), legacy);
        assert_eq!(
            to_canonical(&to_chain_param(&canonical).unwrap()).unwrap(),
            canonical
        );
    }

    /// Case and surrounding whitespace are normalized, so the same address never appears twice in two
    /// spellings in output or in a file.
    #[test]
    fn parse_normalizes_case_and_whitespace() {
        let account_upper = format!("ABCD{}", "0".repeat(60));
        let dapp_upper = format!("EF{}", "1".repeat(62));
        let canonical = format!(
            "{}::{}",
            dapp_upper.to_ascii_lowercase(),
            account_upper.to_ascii_lowercase()
        );
        assert_eq!(
            to_canonical(&format!("  {dapp_upper} :: {account_upper}  ")).unwrap(),
            canonical
        );
        assert_eq!(
            to_canonical(&format!("  0:{account_upper} ")).unwrap(),
            format!("{DEXDO_DAPP_ID}::{}", account_upper.to_ascii_lowercase())
        );
    }

    /// Fail-loud on anything that is not one of the two accepted forms - a truncated half, a bare hex, a
    /// non-zero workchain, extra `::`. Coercing any of these would name a different account.
    #[test]
    fn rejects_malformed_addresses() {
        let h = h64('a');
        for bad in [
            "",
            "0:",
            "0:dead",
            "0:nothex",
            "dead",
            &h64('a'),
            "xyz",
            "a::b::c",
            "aaaa::bbbb",
            "1:0000",
        ] {
            assert!(
                CanonicalAddress::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
        assert!(CanonicalAddress::parse(&format!("{h}::beef")).is_err());
        assert!(CanonicalAddress::parse(&format!("beef::{h}")).is_err());
        assert!(CanonicalAddress::parse(&format!("0:{h}ff")).is_err());
        assert!(CanonicalAddress::parse(&format!("{h}::{h}ff")).is_err());
    }

    /// `display` is a rendering helper, not a validator: a placeholder or a name that is not an address
    /// must survive it, or a table column would lose the only value it has.
    #[test]
    fn display_passes_non_addresses_through() {
        assert_eq!(display("-"), "-");
        assert_eq!(display("  none  "), "none");
        assert_eq!(display("qwen--qwen3--32b"), "qwen--qwen3--32b");
        assert_eq!(display_opt(None, "-"), "-");
        assert_eq!(
            display_opt(Some(&format!("0:{}", h64('c'))), "-"),
            format!("{DEXDO_DAPP_ID}::{}", h64('c'))
        );
    }

    /// The serde seam writes canonical and reads both forms, so a file written by an older version keeps
    /// loading and a file written now carries the DApp identity.
    #[test]
    fn serde_writes_canonical_and_reads_both_forms() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
        struct Holder {
            #[serde(with = "serde_canonical")]
            address: String,
        }

        let account = h64('d');
        let legacy = format!("0:{account}");
        let canonical = format!("{DEXDO_DAPP_ID}::{account}");

        // Written canonically, whichever form is held in memory.
        let held_legacy = Holder {
            address: legacy.clone(),
        };
        let json = serde_json::to_string(&held_legacy).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["address"],
            serde_json::Value::String(canonical.clone())
        );

        // Both forms read back to the chain form the rest of the client uses.
        for stored in [&legacy, &canonical] {
            let read: Holder =
                serde_json::from_str(&format!("{{\"address\":\"{stored}\"}}")).unwrap();
            assert_eq!(read.address, legacy);
        }

        // A non-address value is neither rejected nor rewritten.
        let odd: Holder = serde_json::from_str("{\"address\":\"pending\"}").unwrap();
        assert_eq!(odd.address, "pending");
        assert_eq!(
            serde_json::to_string(&odd).unwrap(),
            "{\"address\":\"pending\"}"
        );
    }

    /// The optional variant behaves the same and leaves an absent address absent.
    #[test]
    fn serde_opt_writes_canonical_and_keeps_none() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
        struct Holder {
            #[serde(with = "serde_canonical_opt")]
            address: Option<String>,
        }

        let account = h64('f');
        let legacy = format!("0:{account}");
        let canonical = format!("{DEXDO_DAPP_ID}::{account}");

        let some = Holder {
            address: Some(legacy.clone()),
        };
        assert_eq!(
            serde_json::to_string(&some).unwrap(),
            format!("{{\"address\":\"{canonical}\"}}")
        );
        for stored in [&legacy, &canonical] {
            let read: Holder =
                serde_json::from_str(&format!("{{\"address\":\"{stored}\"}}")).unwrap();
            assert_eq!(read.address.as_deref(), Some(legacy.as_str()));
        }

        let none = Holder { address: None };
        assert_eq!(serde_json::to_string(&none).unwrap(), "{\"address\":null}");
        assert_eq!(
            serde_json::from_str::<Holder>("{\"address\":null}").unwrap(),
            none
        );
    }
}
