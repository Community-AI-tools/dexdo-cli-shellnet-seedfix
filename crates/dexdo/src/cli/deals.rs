//! Local deal handles: small public JSON records that let operators run
//! `deals`/`status`/`close` without reassembling low-level addresses.

use anyhow::{bail, Result};
use dexdo_core::MarketManifest;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const DEAL_HANDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DealHandleRole {
    Buyer,
    Seller,
}

impl DealHandleRole {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Buyer => "buyer",
            Self::Seller => "seller",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DealEndpointInfo {
    pub(crate) kind: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DealHandle {
    pub(crate) version: u32,
    pub(crate) handle: String,
    pub(crate) role: DealHandleRole,
    pub(crate) network: String,
    pub(crate) token_contract: String,
    pub(crate) note_addr: String,
    pub(crate) frame_model: String,
    pub(crate) model_hash: Option<String>,
    pub(crate) order_book: Option<String>,
    pub(crate) root_model: Option<String>,
    pub(crate) market: Option<MarketManifest>,
    pub(crate) contracts: String,
    pub(crate) endpoint: Option<DealEndpointInfo>,
    pub(crate) created_order_ids: Vec<u128>,
    pub(crate) created_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) enum DealStateKind {
    Placed,
    FundedButNeverOpened,
    Probe,
    Streaming,
    Stopped,
    Disputed,
}

impl DealStateKind {
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Placed => "placed",
            Self::FundedButNeverOpened => "funded-but-never-opened",
            Self::Probe => "probe",
            Self::Streaming => "streaming",
            Self::Stopped => "stopped",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DealStateSummary {
    pub(crate) kind: DealStateKind,
    pub(crate) funded: bool,
    pub(crate) opened: bool,
    pub(crate) disputed: bool,
    pub(crate) probe_accepted: bool,
    pub(crate) deposit: u128,
    pub(crate) prepaid: u128,
    pub(crate) frozen: u128,
    pub(crate) finalized_owed: u128,
    pub(crate) funded_time: Option<u64>,
    pub(crate) last_advance: u64,
}

impl DealStateSummary {
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    pub(crate) fn buyer_locked(&self) -> u128 {
        self.deposit
            .saturating_add(self.prepaid)
            .saturating_add(self.frozen)
    }
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn classify_deal_state(state: &serde_json::Value) -> DealStateSummary {
    let funded = state["funded"].as_bool().unwrap_or(false);
    let opened = state["opened"].as_bool().unwrap_or(false);
    let disputed = state["disputed"].as_bool().unwrap_or(false);
    let probe_accepted = state["probeAccepted"].as_bool().unwrap_or(false);
    let deposit = u128_field(state, "deposit");
    let prepaid = u128_field(state, "prepaid");
    let frozen = u128_field(state, "frozen");
    let finalized_owed = u128_field(state, "finalizedOwed");
    let settled = funded
        && !opened
        && !disputed
        && deposit == 0
        && prepaid == 0
        && frozen == 0
        && finalized_owed == 0;
    let kind = if disputed {
        DealStateKind::Disputed
    } else if opened && probe_accepted {
        DealStateKind::Streaming
    } else if opened {
        DealStateKind::Probe
    } else if settled || funded && probe_accepted {
        DealStateKind::Stopped
    } else if funded {
        DealStateKind::FundedButNeverOpened
    } else {
        DealStateKind::Placed
    };
    DealStateSummary {
        kind,
        funded,
        opened,
        disputed,
        probe_accepted,
        deposit,
        prepaid,
        frozen,
        finalized_owed,
        funded_time: u64_opt_field(state, "fundedTime"),
        last_advance: u64_opt_field(state, "lastAdvance").unwrap_or(0),
    }
}

pub(crate) fn default_deals_dir() -> Result<PathBuf> {
    let proj = directories::ProjectDirs::from("ai", "gosh", "dexdo").ok_or_else(|| {
        anyhow::anyhow!("could not determine the platform data directory; pass --deals-dir")
    })?;
    Ok(proj.data_dir().join("deals"))
}

pub(crate) fn resolve_deals_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    Ok(match explicit {
        Some(p) => p.to_path_buf(),
        None => default_deals_dir()?,
    })
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn make_token_contract_id(token_contract: &str) -> String {
    let clean = token_contract
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("deal-{clean}")
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn make_handle_id(token_contract: &str, role: DealHandleRole) -> String {
    format!(
        "{}-{}",
        make_token_contract_id(token_contract),
        role.as_str()
    )
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn handle_path(dir: &Path, handle: &str) -> PathBuf {
    dir.join(format!("{handle}.json"))
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn save_deal_handle(dir: &Path, handle: &DealHandle) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("create deals dir {}: {e}", dir.display()))?;
    let path = handle_path(dir, &handle.handle);
    let bytes = serde_json::to_vec_pretty(handle)?;
    write_private_atomic(&path, &bytes)?;
    Ok(path)
}

pub(crate) fn load_deal_handle(path: &Path) -> Result<DealHandle> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read deal handle {}: {e}", path.display()))?;
    let h: DealHandle = serde_json::from_str(&s)
        .map_err(|e| anyhow::anyhow!("parse deal handle {}: {e}", path.display()))?;
    validate_deal_handle(&h)?;
    Ok(h)
}

pub(crate) fn list_deal_handles(dir: &Path) -> Result<Vec<(PathBuf, DealHandle)>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("read deals dir {}: {e}", dir.display()))?
    {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json")
            || !p
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|stem| stem.starts_with("deal-"))
        {
            continue;
        }
        out.push((p.clone(), load_deal_handle(&p)?));
    }
    out.sort_by(|a, b| a.1.created_at_unix.cmp(&b.1.created_at_unix));
    Ok(out)
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn resolve_deal_ref(
    input: &str,
    dir: &Path,
    explicit_role: Option<DealHandleRole>,
    explicit_note_addr: Option<&str>,
) -> Result<Option<(PathBuf, DealHandle)>> {
    let direct = Path::new(input);
    if direct.exists() {
        let handle = load_deal_handle(direct)?;
        validate_explicit_handle_args(&handle, explicit_role, explicit_note_addr)?;
        return Ok(Some((direct.to_path_buf(), handle)));
    }
    let by_handle = handle_path(dir, input);
    if by_handle.exists() {
        let handle = load_deal_handle(&by_handle)?;
        validate_explicit_handle_args(&handle, explicit_role, explicit_note_addr)?;
        return Ok(Some((by_handle, handle)));
    }

    let handles = list_deal_handles(dir)?;
    let mut by_id = handles.iter().filter(|(_, handle)| handle.handle == input);
    if let Some((path, handle)) = by_id.next() {
        if by_id.next().is_some() {
            bail!("deal handle id `{input}` is ambiguous; pass an exact handle path");
        }
        validate_explicit_handle_args(handle, explicit_role, explicit_note_addr)?;
        return Ok(Some((path.clone(), handle.clone())));
    }

    let wanted = normalize_addr(input);
    let matches = handles
        .into_iter()
        .filter(|(_, handle)| normalize_addr(&handle.token_contract) == wanted)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Ok(None);
    }

    let Some(role) = explicit_role else {
        if matches.len() > 1 {
            bail!(
                "deal reference `{input}` is ambiguous: multiple local handles match this TokenContract; pass --role buyer|seller"
            );
        }
        let (path, handle) = matches.into_iter().next().expect("one handle");
        validate_explicit_handle_args(&handle, None, explicit_note_addr)?;
        return Ok(Some((path, handle)));
    };

    let role_matches = matches
        .into_iter()
        .filter(|(_, handle)| handle.role == role)
        .collect::<Vec<_>>();
    if role_matches.is_empty() {
        return Ok(None);
    }
    let matching = match explicit_note_addr {
        Some(note_addr) => role_matches
            .iter()
            .filter(|(_, handle)| normalize_addr(&handle.note_addr) == normalize_addr(note_addr))
            .cloned()
            .collect::<Vec<_>>(),
        None => role_matches.clone(),
    };
    if matching.is_empty() {
        let (_, handle) = &role_matches[0];
        bail!(
            "--note-addr {} does not match handle {} note {}",
            explicit_note_addr.expect("note filter"),
            handle.handle,
            handle.note_addr
        );
    }
    if matching.len() > 1 {
        let (_, first) = &matching[0];
        let same_logical_side = matching.iter().all(|(_, handle)| {
            normalize_addr(&handle.token_contract) == normalize_addr(&first.token_contract)
                && handle.role == first.role
                && normalize_addr(&handle.note_addr) == normalize_addr(&first.note_addr)
        });
        if same_logical_side {
            if let Some((path, handle)) = matching.iter().find(|(_, handle)| {
                handle.handle == make_handle_id(&handle.token_contract, handle.role)
            }) {
                return Ok(Some((path.clone(), handle.clone())));
            }
        }
        bail!(
            "deal reference `{input}` is ambiguous for role {}; pass an exact handle path",
            role.as_str()
        );
    }
    Ok(matching.into_iter().next())
}

fn validate_explicit_handle_args(
    handle: &DealHandle,
    explicit_role: Option<DealHandleRole>,
    explicit_note_addr: Option<&str>,
) -> Result<()> {
    if explicit_role.is_some_and(|role| role != handle.role) {
        bail!(
            "--role {} does not match handle {} role {}",
            explicit_role.expect("mismatched role").as_str(),
            handle.handle,
            handle.role.as_str()
        );
    }
    if explicit_note_addr
        .is_some_and(|note_addr| normalize_addr(note_addr) != normalize_addr(&handle.note_addr))
    {
        bail!(
            "--note-addr {} does not match handle {} note {}",
            explicit_note_addr.expect("mismatched note"),
            handle.handle,
            handle.note_addr
        );
    }
    Ok(())
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_secs())
}

pub(crate) fn normalize_addr(s: &str) -> String {
    dexdo_core::normalize_wallet_address(s).unwrap_or_else(|_| s.trim().to_ascii_lowercase())
}

pub(crate) fn validate_deal_handle(h: &DealHandle) -> Result<()> {
    if h.version != DEAL_HANDLE_VERSION {
        bail!(
            "deal handle {} has unsupported version {}; expected {}",
            h.handle,
            h.version,
            DEAL_HANDLE_VERSION
        );
    }
    if h.handle.trim().is_empty() {
        bail!("deal handle has empty handle id");
    }
    if h.token_contract.trim().is_empty() {
        bail!("deal handle {} has empty token_contract", h.handle);
    }
    if h.note_addr.trim().is_empty() {
        bail!("deal handle {} has empty note_addr", h.handle);
    }
    if let Some(market) = &h.market {
        market
            .validate()
            .map_err(|e| anyhow::anyhow!("deal handle {} market: {e}", h.handle))?;
        if normalize_addr(&market.token_contract) != normalize_addr(&h.token_contract) {
            bail!(
                "deal handle {} market token_contract {} != handle token_contract {}",
                h.handle,
                market.token_contract,
                h.token_contract
            );
        }
    }
    let json = serde_json::to_value(h)?;
    if let Some(field) = first_secret_field_name(&json, "") {
        bail!(
            "deal handle {} contains forbidden secret-bearing field `{field}`",
            h.handle
        );
    }
    Ok(())
}

fn first_secret_field_name(value: &serde_json::Value, path: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let field = if path.is_empty() {
                    k.to_string()
                } else {
                    format!("{path}.{k}")
                };
                if is_secret_field_name(k) {
                    return Some(field);
                }
                if let Some(found) = first_secret_field_name(v, &field) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, v)| first_secret_field_name(v, &format!("{path}[{i}]"))),
        _ => None,
    }
}

fn is_secret_field_name(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        key.as_str(),
        "secret"
            | "seed"
            | "mnemonic"
            | "owner_key"
            | "note_key"
            | "private_key"
            | "priv_key"
            | "multisig_key"
    ) || key.contains("secret")
        || key.ends_with("_seed")
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
fn u128_field(v: &serde_json::Value, key: &str) -> u128 {
    v[key]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v[key].as_u64().map(u128::from))
        .unwrap_or(0)
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
fn u64_opt_field(v: &serde_json::Value, key: &str) -> Option<u64> {
    v[key]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v[key].as_u64())
}

#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("deal.json");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_nanos();
    let tmp = dir.join(format!(".{name}.tmp.{}.{nanos}", std::process::id()));
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, READ_CONTROL, WRITE_DAC};
        opts.access_mode(GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
        opts.share_mode(FILE_SHARE_DELETE);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| anyhow::anyhow!("create temp handle {}: {e}", tmp.display()))?;
    #[cfg(windows)]
    if let Err(error) = crate::cli::windows_secret_file::protect_owner_only(&f, &tmp) {
        drop(f);
        return match std::fs::remove_file(&tmp) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "{error}; remove empty temp handle {} after ACL failure: {cleanup_error}",
                tmp.display()
            )),
        };
    }
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!("write temp handle {}: {e}", tmp.display()));
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("rename {} -> {}: {e}", tmp.display(), path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_market() -> MarketManifest {
        MarketManifest {
            network: "shellnet".into(),
            frame_model: "qwen/qwen3-32b".into(),
            model_hash: dexdo_core::model_hash_for("qwen/qwen3-32b"),
            inference_order_book: "0:11".into(),
            root_model: "0:22".into(),
            token_contract: "0:33".into(),
            seller_note: "0:44".into(),
            nonce: 7,
            price_per_tick: 1000,
            max_ticks: 1024,
        }
    }

    fn sample_handle() -> DealHandle {
        DealHandle {
            version: DEAL_HANDLE_VERSION,
            handle: make_handle_id("0:33", DealHandleRole::Seller),
            role: DealHandleRole::Seller,
            network: "shellnet".into(),
            token_contract: "0:33".into(),
            note_addr: "0:44".into(),
            frame_model: "qwen/qwen3-32b".into(),
            model_hash: Some(dexdo_core::model_hash_for("qwen/qwen3-32b")),
            order_book: Some("0:11".into()),
            root_model: Some("0:22".into()),
            market: Some(sample_market()),
            contracts: "contracts/deployed.shellnet.json".into(),
            endpoint: Some(DealEndpointInfo {
                kind: "gateway".into(),
                value: "127.0.0.1:8443".into(),
            }),
            created_order_ids: vec![],
            created_at_unix: 1,
        }
    }

    #[test]
    fn deal_handle_roundtrip_carries_no_secret_markers() {
        let h = sample_handle();
        validate_deal_handle(&h).unwrap();
        let json = serde_json::to_string(&h).unwrap();
        assert!(!json.contains("note_key"), "{json}");
        assert!(!json.to_ascii_lowercase().contains("secret"), "{json}");
        let parsed: DealHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, h);
    }

    #[cfg(unix)]
    #[test]
    fn deal_handle_file_remains_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let path = save_deal_handle(temp.path(), &sample_handle()).unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "deal handle must remain 0600");
    }

    #[test]
    fn deal_handle_allows_public_paths_with_private_words() {
        let mut h = sample_handle();
        h.contracts = "/tmp/private-inference/contracts/deployed.shellnet.json".into();
        validate_deal_handle(&h).unwrap();
    }

    #[test]
    fn deal_handle_rejects_unknown_secret_fields() {
        let mut v = serde_json::to_value(sample_handle()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("note_key".into(), serde_json::json!("/tmp/note.key"));
        let err = serde_json::from_value::<DealHandle>(v).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn deal_state_classification_distinguishes_lifecycle_states() {
        let st = serde_json::json!({"funded": false, "opened": false, "disputed": false});
        assert_eq!(classify_deal_state(&st).kind, DealStateKind::Placed);
        let st = serde_json::json!({
            "funded": true, "opened": false, "probeAccepted": false, "deposit": "10"
        });
        assert_eq!(
            classify_deal_state(&st).kind,
            DealStateKind::FundedButNeverOpened
        );
        let st = serde_json::json!({"funded": true, "opened": true, "probeAccepted": false});
        assert_eq!(classify_deal_state(&st).kind, DealStateKind::Probe);
        let st = serde_json::json!({"funded": true, "opened": true, "probeAccepted": true});
        assert_eq!(classify_deal_state(&st).kind, DealStateKind::Streaming);
        let st = serde_json::json!({"funded": true, "opened": false, "probeAccepted": true});
        assert_eq!(classify_deal_state(&st).kind, DealStateKind::Stopped);
        let st = serde_json::json!({
            "funded": true,
            "opened": false,
            "probeAccepted": false,
            "deposit": "0",
            "prepaid": "0",
            "frozen": "0",
            "finalizedOwed": "0"
        });
        assert_eq!(
            classify_deal_state(&st).kind,
            DealStateKind::Stopped,
            "a post-STOP deal with returned escrow is terminal, not never-opened"
        );
        let st = serde_json::json!({"disputed": true});
        assert_eq!(classify_deal_state(&st).kind, DealStateKind::Disputed);
    }

    #[test]
    fn deal_ref_resolves_by_handle_and_token_contract() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let h = sample_handle();
        let p = save_deal_handle(base, &h).unwrap();
        assert_eq!(
            resolve_deal_ref(&h.handle, base, None, None)
                .unwrap()
                .unwrap()
                .1,
            h
        );
        assert_eq!(
            resolve_deal_ref("0:33", base, None, None)
                .unwrap()
                .unwrap()
                .0,
            p
        );
    }

    fn buyer_handle() -> DealHandle {
        let mut h = sample_handle();
        h.handle = make_handle_id(&h.token_contract, DealHandleRole::Buyer);
        h.role = DealHandleRole::Buyer;
        h.note_addr = "0:55".into();
        h
    }

    #[test]
    fn buyer_and_seller_handles_for_one_token_contract_coexist() {
        let temp = tempfile::tempdir().unwrap();
        let buyer = buyer_handle();
        let seller = sample_handle();

        let buyer_path = save_deal_handle(temp.path(), &buyer).unwrap();
        let seller_path = save_deal_handle(temp.path(), &seller).unwrap();

        assert_eq!(
            buyer_path.file_name().and_then(|name| name.to_str()),
            Some("deal-0-33-buyer.json")
        );
        assert_eq!(
            seller_path.file_name().and_then(|name| name.to_str()),
            Some("deal-0-33-seller.json")
        );
        assert_eq!(load_deal_handle(&buyer_path).unwrap(), buyer);
        assert_eq!(load_deal_handle(&seller_path).unwrap(), seller);
    }

    #[test]
    fn raw_token_contract_with_explicit_buyer_selects_buyer_after_seller_write() {
        let temp = tempfile::tempdir().unwrap();
        let buyer = buyer_handle();
        save_deal_handle(temp.path(), &buyer).unwrap();
        save_deal_handle(temp.path(), &sample_handle()).unwrap();

        let (_, selected) = resolve_deal_ref(
            "0:33",
            temp.path(),
            Some(DealHandleRole::Buyer),
            Some("0:55"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected, buyer);
    }

    #[test]
    fn explicit_owner_prefers_scoped_duplicate_over_legacy_handle() {
        let temp = tempfile::tempdir().unwrap();
        let scoped = buyer_handle();
        let mut legacy = scoped.clone();
        legacy.token_contract = " 0:33 ".into();
        legacy.note_addr = " 0:55 ".into();
        legacy.handle = make_token_contract_id(&legacy.token_contract);
        save_deal_handle(temp.path(), &legacy).unwrap();
        let scoped_path = save_deal_handle(temp.path(), &scoped).unwrap();

        let (selected_path, selected) = resolve_deal_ref(
            "0:33",
            temp.path(),
            Some(DealHandleRole::Buyer),
            Some("0:55"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(selected_path, scoped_path);
        assert_eq!(selected, scoped);
    }

    #[test]
    fn other_role_handle_does_not_block_explicit_raw_owner() {
        let temp = tempfile::tempdir().unwrap();
        save_deal_handle(temp.path(), &sample_handle()).unwrap();

        assert!(resolve_deal_ref(
            "0:33",
            temp.path(),
            Some(DealHandleRole::Buyer),
            Some("0:55"),
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn raw_token_contract_with_two_roles_is_ambiguous_without_role() {
        let temp = tempfile::tempdir().unwrap();
        save_deal_handle(temp.path(), &buyer_handle()).unwrap();
        save_deal_handle(temp.path(), &sample_handle()).unwrap();

        let err = resolve_deal_ref("0:33", temp.path(), None, None).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err:#}");
        assert!(err.to_string().contains("--role"), "{err:#}");
    }

    #[test]
    fn exact_handle_rejects_conflicting_role_and_note() {
        let temp = tempfile::tempdir().unwrap();
        let seller = sample_handle();
        let path = save_deal_handle(temp.path(), &seller).unwrap();

        let err = resolve_deal_ref(
            path.to_str().unwrap(),
            temp.path(),
            Some(DealHandleRole::Buyer),
            Some(&seller.note_addr),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--role buyer"), "{err:#}");

        let err = resolve_deal_ref(
            &seller.handle,
            temp.path(),
            Some(DealHandleRole::Seller),
            Some("0:66"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--note-addr 0:66"), "{err:#}");
    }

    #[test]
    fn legacy_unscoped_handle_remains_readable() {
        let temp = tempfile::tempdir().unwrap();
        let mut legacy = sample_handle();
        legacy.handle = make_token_contract_id(&legacy.token_contract);
        let path = save_deal_handle(temp.path(), &legacy).unwrap();

        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("deal-0-33.json")
        );
        assert_eq!(
            resolve_deal_ref(&legacy.handle, temp.path(), None, None)
                .unwrap()
                .unwrap()
                .1,
            legacy
        );
        assert_eq!(
            resolve_deal_ref("0:33", temp.path(), None, None)
                .unwrap()
                .unwrap()
                .0,
            path
        );
    }
}
