//! Note-management command handlers(Track C8/C9/C12, move-only).

use crate::cli::args::{NoteBalanceArgs, NoteDeployArgs, NoteRecoverArgs, NoteWithdrawArgs};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    is_note_deploy_wallet_busy_error, note_deploy_error, note_deploy_fold_state_into_pool,
    note_deploy_multisig_secret_hex, note_deploy_now_unix, note_deploy_recovery_pool_guard,
    note_deploy_same_file_pool_guard, note_endpoint_url, shellnet_doctor_preflight,
    shellnet_doctor_preflight_with_endpoint, unix_now_secs, validate_existing_pool_if_present,
};
#[cfg(feature = "shellnet")]
use crate::cli::support::read_secret_hex;
use anyhow::bail;
use anyhow::Result;
#[cfg(feature = "shellnet")]
use dexdo_core::params::{
    HERMEZ_SRS_HASH_BUFFER_BYTES, HERMEZ_SRS_HTTP_TIMEOUT, HERMEZ_SRS_MAX_ATTEMPTS,
    HERMEZ_SRS_PROGRESS_STEP_PERCENT, HERMEZ_SRS_RETRY_INITIAL_BACKOFF, HERMEZ_SRS_SIZE_BYTES,
    NOTE_DEPLOY_ACTIVE_POLL_INTERVAL, NOTE_DEPLOY_ACTIVE_TIMEOUT,
    NOTE_DEPLOY_EXISTING_SHELL_FUNDING_TIMEOUT, NOTE_DEPLOY_LOCK_TIMEOUT_SECS,
    NOTE_DEPLOY_PROVER_LOCK_POLL_INTERVAL, NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL,
    NOTE_DEPLOY_SHELL_FUNDING_TIMEOUT, NOTE_DEPLOY_SUBMIT_NATIVE_VALUE,
    NOTE_DEPLOY_VOUCHER_EVENT_TIMEOUT, NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS,
    NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS, NOTE_DEPLOY_WALLET_LOCK_POLL_INTERVAL, SHELL_CURRENCY_ID,
};
#[cfg(feature = "shellnet")]
use std::io::{Read as _, Write as _};

#[cfg(feature = "shellnet")]
pub(crate) async fn run_note_recover(args: NoteRecoverArgs) -> Result<()> {
    use crate::cli::note::{
        ensure_recovery_owner_matches_target_note, load_note_deploy_recovery,
        resolve_private_file_path,
    };
    use dexdo_core::{private_note::artifacts::PRIVATE_NOTE_ABI_JSON, Address, ChainClient};

    let pool_path = resolve_private_file_path(&args.pool, "--pool")?;
    let recovery_path = resolve_private_file_path(&args.recovery, "--recovery")?;
    note_deploy_recovery_pool_guard(&pool_path, &recovery_path)?;
    validate_existing_pool_if_present(&pool_path)?;
    let recovery = load_note_deploy_recovery(&recovery_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "note recover: recovery file {} not found",
            recovery_path.display()
        )
    })?;
    recovery.ensure_ready_for_pool()?;
    let state = recovery.to_onboard_state()?;
    let note_addr = state
        .pn_address
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("note recover: recovery state has no pn_address"))?
        .to_string();
    let client = ChainClient::connect(&recovery.endpoint)?;
    let note_address = Address::parse(&note_addr)
        .map_err(|e| anyhow::anyhow!("recovered note {note_addr}: {e}"))?;
    let details = client
        .run_getter(
            &note_address,
            PRIVATE_NOTE_ABI_JSON,
            "getDetails",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| anyhow::anyhow!("verify recovered PrivateNote {note_addr} owner key: {e}"))?;
    ensure_recovery_owner_matches_target_note(
        &recovery_path,
        &recovery,
        details.as_ref().and_then(|d| d["ephemeralPubkey"].as_str()),
    )?;
    let n =
        note_deploy_fold_state_into_pool(&pool_path, &state, &recovery.funding_multisig_address)?;
    std::fs::remove_file(&recovery_path).map_err(|e| {
        anyhow::anyhow!(
            "note recover: remove consumed recovery file {}: {e}",
            recovery_path.display()
        )
    })?;
    println!(
        "note recovered -> PrivateNote {note_addr}; folded into --pool {} ({} note(s)) from recovery {}. \
         No wallet spend was submitted.",
        pool_path.display(),
        n,
        recovery_path.display()
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_note_recover(_args: NoteRecoverArgs) -> Result<()> {
    bail!("note recover unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
const HERMEZ_SRS_NAME: &str = "hermez_kzg_srs_k19.bin";
#[cfg(feature = "shellnet")]
const HERMEZ_SRS_URL: &str = "https://binaries.gosh.sh/dexdo/hermez_kzg_bn254_19.srs";
#[cfg(feature = "shellnet")]
const HERMEZ_SRS_SHA256: &str = "9ebbbbfc3d4899435ef254c915c62f5aa94c539bde1cec52ca7d45679d2adf4a";
#[cfg(feature = "shellnet")]
const HERMEZ_SRS_MARKER_NAME: &str = ".hermez_srs_sha256";
#[cfg(feature = "shellnet")]
const HERMEZ_SRS_PENDING_MARKER_NAME: &str = ".hermez_srs_sha256.pending";
#[cfg(feature = "shellnet")]
const PROVER_CACHE_ARTIFACTS: [&str; 3] =
    ["pk_cache.bin", "vk_cache.bin", "break_points_cache.bin"];

#[cfg(feature = "shellnet")]
struct NoteDeployWalletLock {
    path: std::path::PathBuf,
}

#[cfg(feature = "shellnet")]
impl Drop for NoteDeployWalletLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(feature = "shellnet")]
fn note_deploy_lock_path(funding_multisig_address: &str) -> std::path::PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(funding_multisig_address.as_bytes());
    std::env::temp_dir().join(format!(
        "dexdo-note-deploy-wallet-{}.lock",
        &hex::encode(digest)[..16]
    ))
}

#[cfg(feature = "shellnet")]
fn acquire_note_deploy_wallet_lock(funding_multisig_address: &str) -> Result<NoteDeployWalletLock> {
    let path = note_deploy_lock_path(funding_multisig_address);
    let timeout = note_deploy_lock_timeout();
    let started = std::time::Instant::now();
    let mut announced = false;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                writeln!(
                    file,
                    "pid={} wallet={} created_at_unix={}",
                    std::process::id(),
                    funding_multisig_address,
                    unix_now_secs()
                )
                .ok();
                return Ok(NoteDeployWalletLock { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if started.elapsed().as_secs() >= timeout {
                    bail!(
                        "note deploy wallet busy: another `dexdo note deploy` appears to be using funding wallet \
                         {funding_multisig_address}; lock {} remained for {timeout}s. Retry after the previous \
                         deploy reaches a terminal state, or remove the lock only after confirming no deploy is \
                         running.",
                        path.display()
                    );
                }
                if !announced {
                    eprintln!(
                        "note deploy: funding wallet {funding_multisig_address} is already in use locally; \
                         waiting for {} (timeout {timeout}s)",
                        path.display()
                    );
                    announced = true;
                }
                std::thread::sleep(NOTE_DEPLOY_WALLET_LOCK_POLL_INTERVAL);
            }
            Err(e) => bail!("create note deploy wallet lock {}: {e}", path.display()),
        }
    }
}

#[cfg(feature = "shellnet")]
fn note_deploy_lock_timeout() -> u64 {
    std::env::var("DEXDO_NOTE_DEPLOY_LOCK_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(NOTE_DEPLOY_LOCK_TIMEOUT_SECS)
}

#[cfg(feature = "shellnet")]
#[derive(Debug)]
struct NoteDeployProverCacheLock {
    file: std::fs::File,
}

#[cfg(feature = "shellnet")]
impl Drop for NoteDeployProverCacheLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(feature = "shellnet")]
fn acquire_note_deploy_prover_cache_lock(
    prover_cache_dir: &std::path::Path,
) -> Result<NoteDeployProverCacheLock> {
    acquire_note_deploy_prover_cache_lock_with_timeout(
        prover_cache_dir,
        std::time::Duration::from_secs(note_deploy_lock_timeout()),
    )
}

#[cfg(feature = "shellnet")]
fn acquire_note_deploy_prover_cache_lock_with_timeout(
    prover_cache_dir: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<NoteDeployProverCacheLock> {
    std::fs::create_dir_all(prover_cache_dir).map_err(|e| {
        anyhow::anyhow!(
            "create prover cache dir {} for lock: {e}",
            prover_cache_dir.display()
        )
    })?;
    let path = prover_cache_dir.join(".dexdo-prover.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open prover cache lock {}: {e}", path.display()))?;
    let started = std::time::Instant::now();
    let mut announced = false;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(NoteDeployProverCacheLock { file }),
            Err(error) if note_deploy_lock_is_contended(&error) => {
                if started.elapsed() >= timeout {
                    let waited = started.elapsed().as_secs();
                    bail!(
                        "note deploy prover cache busy: waited {waited}s for {}; another note deploy is \
                         generating or using the shared prover cache. Retry after it finishes, or set \
                         DEXDO_NOTE_DEPLOY_LOCK_TIMEOUT_SECS to a larger bounded wait.",
                        path.display()
                    );
                }
                if !announced {
                    eprintln!(
                        "note deploy: prover cache busy, waited 0s; waiting for {} (timeout {}s)",
                        path.display(),
                        timeout.as_secs()
                    );
                    announced = true;
                }
                let remaining = timeout.saturating_sub(started.elapsed());
                std::thread::sleep(remaining.min(NOTE_DEPLOY_PROVER_LOCK_POLL_INTERVAL));
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "try lock prover cache {}: {error}",
                    path.display()
                ));
            }
        }
    }
}

#[cfg(feature = "shellnet")]
fn note_deploy_lock_is_contended(error: &std::io::Error) -> bool {
    error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

#[cfg(feature = "shellnet")]
fn note_deploy_multisig_keys(args: &NoteDeployArgs) -> Result<dexdo_core::KeyPair> {
    let (source, secret_hex) = note_deploy_multisig_secret_hex(args)?;
    dexdo_core::KeyPair::from_secret_hex(secret_hex.trim())
        .map_err(|e| anyhow::anyhow!("{source} (SDK secret hex): {e:?}"))
}

#[cfg(feature = "shellnet")]
trait NoteDeployFundingKeyLoader {
    fn load_funding_wallet_keys(&self) -> Result<dexdo_core::KeyPair>;
}

#[cfg(feature = "shellnet")]
impl NoteDeployFundingKeyLoader for NoteDeployArgs {
    fn load_funding_wallet_keys(&self) -> Result<dexdo_core::KeyPair> {
        note_deploy_multisig_keys(self)
    }
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Copy, Default)]
struct NoteDeployVoucherFailpoints {
    before_voucher_event_wait: bool,
    after_deposit_submit: bool,
    after_deposit_event: bool,
    after_shell_submit: bool,
    after_deploy_before_note_record: bool,
}

#[cfg(feature = "shellnet")]
impl NoteDeployVoucherFailpoints {
    fn after_submit(self, kind: crate::cli::note::NoteDeployVoucherKind) -> bool {
        match kind {
            crate::cli::note::NoteDeployVoucherKind::Deposit => self.after_deposit_submit,
            crate::cli::note::NoteDeployVoucherKind::ShellGas => self.after_shell_submit,
        }
    }

    fn after_event(self, kind: crate::cli::note::NoteDeployVoucherKind) -> bool {
        match kind {
            crate::cli::note::NoteDeployVoucherKind::Deposit => self.after_deposit_event,
            crate::cli::note::NoteDeployVoucherKind::ShellGas => false,
        }
    }
}

#[cfg(feature = "shellnet")]
const NOTE_DEPLOY_GENERIC_MULTISIG_CODE_HASH: &str =
    "3a7a53248ff39fde936a4274eab143b5fac94feac0d8e2e2748aac5e74538d5f";

#[cfg(feature = "shellnet")]
fn ensure_note_deploy_update_custodian_code_hash(code_hash: &str) -> Result<()> {
    let code_hash = code_hash.trim();
    let code_hash = code_hash
        .strip_prefix("0x")
        .or_else(|| code_hash.strip_prefix("0X"))
        .unwrap_or(code_hash)
        .to_ascii_lowercase();
    if code_hash == dexdo_core::canonical_multisig::CODE_HASH {
        return Ok(());
    }
    let wallet_family = if code_hash == NOTE_DEPLOY_GENERIC_MULTISIG_CODE_HASH {
        "generic Multisig"
    } else {
        "unknown"
    };
    bail!(
        "unsupported funding wallet family {wallet_family}, code_hash {code_hash}; \
         dexdo note deploy supports only {} {} code_hash {}; \
         preflight rejected before submit; no transaction was submitted and no funds moved",
        dexdo_core::canonical_multisig::CONTRACT_NAME,
        dexdo_core::canonical_multisig::VERSION,
        dexdo_core::canonical_multisig::CODE_HASH,
    )
}

#[cfg(feature = "shellnet")]
fn note_deploy_update_custodian_submit_transaction_params(
    root_pn: &dexdo_core::Address,
    cc: serde_json::Map<String, serde_json::Value>,
    voucher_body: String,
) -> serde_json::Value {
    dexdo_core::canonical_multisig::submit_transaction_params(
        root_pn.with_workchain(),
        NOTE_DEPLOY_SUBMIT_NATIVE_VALUE,
        cc,
        true,
        1,
        voucher_body,
    )
}

#[cfg(feature = "shellnet")]
fn normalize_multisig_pubkey(pubkey: &str) -> Option<String> {
    let pubkey = pubkey
        .trim()
        .strip_prefix("0x")
        .or_else(|| pubkey.trim().strip_prefix("0X"))
        .unwrap_or_else(|| pubkey.trim());
    if pubkey.is_empty()
        || pubkey.len() > 64
        || !pubkey.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(format!("{pubkey:0>64}").to_ascii_lowercase())
}

#[cfg(feature = "shellnet")]
fn multisig_custodian_pubkeys(custodians: &serde_json::Value) -> Vec<String> {
    custodians
        .get("custodians")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|custodian| custodian.get("owner_pubkey"))
        .filter_map(serde_json::Value::as_str)
        .filter_map(normalize_multisig_pubkey)
        .collect()
}

#[cfg(feature = "shellnet")]
fn ensure_multisig_key_is_custodian(
    funding_wallet: &str,
    derived_pubkey: &str,
    custodians: &serde_json::Value,
) -> Result<()> {
    custodians
        .get("custodians")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "funding wallet {funding_wallet} is Active, but getCustodians returned no \
                 `custodians` array (ABI/getter output mismatch)"
            )
        })?;

    let derived = normalize_multisig_pubkey(derived_pubkey)
        .unwrap_or_else(|| derived_pubkey.trim().to_ascii_lowercase());
    let pubkeys = multisig_custodian_pubkeys(custodians);
    if pubkeys.is_empty() {
        bail!(
            "funding wallet {funding_wallet} has zero pubkey custodians in getCustodians output; \
             UpdateCustodianMultisigWallet_v2.submitTransaction requires a matching pubkey custodian"
        );
    }
    if pubkeys.contains(&derived) {
        return Ok(());
    }
    bail!(
        "--multisig-key derives pubkey 0x{derived}, but it is not a custodian of funding wallet \
         {funding_wallet}. Provide a custodian key \
         (--multisig-key / --multisig-seed-file); no wallet message was submitted."
    )
}

#[cfg(feature = "shellnet")]
fn require_get_custodians_output(
    funding_wallet: &str,
    output: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    match output {
        Some(output)
            if output
                .get("custodians")
                .and_then(serde_json::Value::as_array)
                .is_some() =>
        {
            Ok(output)
        }
        _ => bail!(
            "funding wallet {funding_wallet} is Active, but getCustodians returned no custodians \
             output (ABI/getter output mismatch)"
        ),
    }
}

#[cfg(feature = "shellnet")]
fn require_get_parameters_output(
    funding_wallet: &str,
    output: Option<serde_json::Value>,
) -> Result<u8> {
    let output = output.ok_or_else(|| {
        anyhow::anyhow!(
            "funding wallet {funding_wallet} is Active, but getParameters returned no output \
             (ABI/getter output mismatch)"
        )
    })?;
    let value = output.get("requiredTxnConfirms").ok_or_else(|| {
        anyhow::anyhow!(
            "funding wallet {funding_wallet} is Active, but getParameters returned no \
             requiredTxnConfirms (ABI/getter output mismatch)"
        )
    })?;
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "funding wallet {funding_wallet} returned invalid requiredTxnConfirms \
                 {value} (ABI/getter output mismatch)"
            )
        })
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
trait NoteDeployFundingWalletReader {
    async fn funding_wallet_code_hash(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<String>;

    async fn funding_wallet_custodians(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<serde_json::Value>;

    async fn funding_wallet_required_txn_confirms(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<u8>;

    async fn funding_wallet_ecc_balances(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<Vec<(u32, u128)>>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
impl NoteDeployFundingWalletReader for dexdo_core::ChainClient {
    async fn funding_wallet_code_hash(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<String> {
        let funding_multisig_address = multisig_address.with_workchain();
        let funding_wallet = self
            .get_account(multisig_address)
            .await
            .map_err(|e| anyhow::anyhow!("read funding wallet {funding_multisig_address}: {e}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("funding wallet {funding_multisig_address} not found")
            })?;
        if !funding_wallet.is_active() {
            bail!(
                "funding wallet {funding_multisig_address} is not Active (acc_type={})",
                funding_wallet.status
            );
        }
        let wallet_code_hash = funding_wallet.code_hash.as_deref().ok_or_else(|| {
            anyhow::anyhow!("funding wallet {funding_multisig_address} has no code_hash")
        })?;
        Ok(wallet_code_hash.to_string())
    }

    async fn funding_wallet_custodians(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<serde_json::Value> {
        let funding_multisig_address = multisig_address.with_workchain();
        let output = self
            .run_getter(
                multisig_address,
                dexdo_core::canonical_multisig::MULTISIG_ABI_JSON,
                "getCustodians",
                serde_json::json!({}),
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!("read custodians of funding wallet {funding_multisig_address}: {e}")
            })?;
        require_get_custodians_output(&funding_multisig_address, output)
    }

    async fn funding_wallet_required_txn_confirms(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<u8> {
        let funding_multisig_address = multisig_address.with_workchain();
        let output = self
            .run_getter(
                multisig_address,
                dexdo_core::canonical_multisig::MULTISIG_ABI_JSON,
                "getParameters",
                serde_json::json!({}),
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "read transaction threshold of funding wallet \
                     {funding_multisig_address}: {e}"
                )
            })?;
        require_get_parameters_output(&funding_multisig_address, output)
    }

    async fn funding_wallet_ecc_balances(
        &self,
        multisig_address: &dexdo_core::Address,
    ) -> Result<Vec<(u32, u128)>> {
        let funding_multisig_address = multisig_address.with_workchain();
        let funding_wallet = self
            .get_account(multisig_address)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "read ECC balances of funding wallet {funding_multisig_address}: {e}"
                )
            })?
            .ok_or_else(|| {
                anyhow::anyhow!("funding wallet {funding_multisig_address} not found")
            })?;
        if !funding_wallet.is_active() {
            bail!(
                "funding wallet {funding_multisig_address} is not Active (acc_type={})",
                funding_wallet.status
            );
        }
        Ok(funding_wallet.ecc)
    }
}

#[cfg(feature = "shellnet")]
async fn note_deploy_preflight_key_owns_wallet(
    wallet_reader: &dyn NoteDeployFundingWalletReader,
    multisig_address: &dexdo_core::Address,
    multisig_keys: &dexdo_core::KeyPair,
) -> Result<()> {
    let funding_multisig_address = multisig_address.with_workchain();
    let code_hash = wallet_reader
        .funding_wallet_code_hash(multisig_address)
        .await?;
    ensure_note_deploy_update_custodian_code_hash(&code_hash)?;
    let custodians = wallet_reader
        .funding_wallet_custodians(multisig_address)
        .await?;
    ensure_multisig_key_is_custodian(
        &funding_multisig_address,
        multisig_keys.public_hex(),
        &custodians,
    )?;
    let required_txn_confirms = wallet_reader
        .funding_wallet_required_txn_confirms(multisig_address)
        .await?;
    if required_txn_confirms != 1 {
        bail!(
            "funding wallet {funding_multisig_address} requires {required_txn_confirms} transaction \
             confirmations; dexdo note deploy requires a Hot wallet with reqConfirms=1 and submitted \
             no transaction. For a Vault, first confirm the Vault -> Hot transfer manually, then run \
             note deploy against the funded Hot wallet."
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn note_deploy_ecc_name(
    kind: crate::cli::note::NoteDeployVoucherKind,
    requested_token_type: u32,
    currency_id: u32,
) -> String {
    match currency_id {
        SHELL_CURRENCY_ID
            if kind == crate::cli::note::NoteDeployVoucherKind::Deposit
                && requested_token_type == SHELL_CURRENCY_ID =>
        {
            "requested token and SHELL ECC[2]".to_string()
        }
        SHELL_CURRENCY_ID => "SHELL ECC[2]".to_string(),
        id => format!("requested token ECC[{id}]"),
    }
}

#[cfg(feature = "shellnet")]
async fn note_deploy_preflight_wallet_ecc(
    wallet_reader: &dyn NoteDeployFundingWalletReader,
    multisig_address: &dexdo_core::Address,
    kind: crate::cli::note::NoteDeployVoucherKind,
    recovery: &crate::cli::note::NoteDeployRecoveryState,
    voucher_token_type: u32,
    voucher_value: u64,
) -> Result<Vec<(u32, u128)>> {
    let wallet = multisig_address.with_workchain();
    let balances = wallet_reader
        .funding_wallet_ecc_balances(multisig_address)
        .await?;
    let shell = recovery.ecc_shell_deposit as u128;
    let require = |currency_id: u32, amount: u128| -> Result<()> {
        let available = balances
            .iter()
            .find(|(id, _)| *id == currency_id)
            .map(|(_, value)| *value)
            .unwrap_or(0);
        if available < amount {
            let missing = amount - available;
            let currency = note_deploy_ecc_name(kind, recovery.token_type, currency_id);
            bail!(
                "funding wallet {wallet} has insufficient {currency}: available={available} raw, \
                 required={amount} raw, missing={missing} raw; no wallet POST was submitted. Fund \
                 {currency} and retry the same `dexdo note deploy --recovery` command."
            );
        }
        Ok(())
    };
    let requested = if kind == crate::cli::note::NoteDeployVoucherKind::Deposit
        && voucher_token_type == SHELL_CURRENCY_ID
    {
        (voucher_value as u128)
            .checked_add(shell)
            .ok_or_else(|| anyhow::anyhow!("note deploy required ECC[2] amount overflow"))?
    } else {
        voucher_value as u128
    };
    require(voucher_token_type, requested)?;
    if kind == crate::cli::note::NoteDeployVoucherKind::Deposit
        && voucher_token_type != SHELL_CURRENCY_ID
    {
        require(SHELL_CURRENCY_ID, shell)?;
    }
    Ok(balances)
}

#[cfg(feature = "shellnet")]
fn note_deploy_persist_voucher_checkpoint(
    recovery_path: &std::path::Path,
    recovery: &mut crate::cli::note::NoteDeployRecoveryState,
    kind: crate::cli::note::NoteDeployVoucherKind,
    checkpoint: crate::cli::note::NoteDeployVoucherCheckpoint,
) -> Result<()> {
    recovery.set_voucher_checkpoint(kind, checkpoint)?;
    crate::cli::note::write_note_deploy_recovery(recovery_path, recovery)
}

#[cfg(feature = "shellnet")]
async fn note_deploy_build_voucher_submit_boc(
    multisig_address: &dexdo_core::Address,
    multisig_keys: &dexdo_core::KeyPair,
    root_pn: &dexdo_core::Address,
    checkpoint: &crate::cli::note::NoteDeployVoucherCheckpoint,
) -> Result<String> {
    use dexdo_core::{
        airegistry::{
            calls::{encode_external_call, encode_internal_payload},
            deploy::local_context,
        },
        private_note::artifacts::ROOT_PN_ABI_JSON,
    };

    let ctx = local_context()?;
    let voucher_body = encode_internal_payload(
        &ctx,
        ROOT_PN_ABI_JSON,
        "generateVoucher",
        serde_json::json!({
            "skUCommit": format!("0x{}", checkpoint.sk_u_commit_hex),
            "isFee": checkpoint.is_fee,
        }),
    )
    .await
    .map_err(|e| anyhow::anyhow!("encode RootPN.generateVoucher body: {e}"))?;

    let mut cc = serde_json::Map::new();
    cc.insert(
        checkpoint.token_type.to_string(),
        serde_json::Value::String(checkpoint.raw_value.to_string()),
    );
    let boc = encode_external_call(
        &ctx,
        dexdo_core::canonical_multisig::MULTISIG_ABI_JSON,
        &multisig_address.with_workchain(),
        "submitTransaction",
        note_deploy_update_custodian_submit_transaction_params(root_pn, cc, voucher_body),
        multisig_keys.public_hex(),
        multisig_keys.secret_hex(),
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "encode UpdateCustodianMultisigWallet_v2.submitTransaction -> RootPN.generateVoucher: {e}"
        )
    })?;
    Ok(boc)
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
trait NoteDeployVoucherBocBuilder {
    async fn build_voucher_submit_boc(
        &self,
        multisig_address: &dexdo_core::Address,
        multisig_keys: &dexdo_core::KeyPair,
        root_pn: &dexdo_core::Address,
        checkpoint: &crate::cli::note::NoteDeployVoucherCheckpoint,
    ) -> Result<String>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
impl NoteDeployVoucherBocBuilder for dexdo_core::ChainClient {
    async fn build_voucher_submit_boc(
        &self,
        multisig_address: &dexdo_core::Address,
        multisig_keys: &dexdo_core::KeyPair,
        root_pn: &dexdo_core::Address,
        checkpoint: &crate::cli::note::NoteDeployVoucherCheckpoint,
    ) -> Result<String> {
        note_deploy_build_voucher_submit_boc(multisig_address, multisig_keys, root_pn, checkpoint)
            .await
    }
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone)]
struct NoteDeployWalletActionReceipt {
    transaction_hash: String,
    compute_exit_code: Option<i64>,
    aborted: bool,
    action_result_code: i64,
    outmsg_count: u64,
    wallet_ecc_balances: Option<Vec<(u32, u128)>>,
}

#[cfg(feature = "shellnet")]
async fn note_deploy_submit_voucher_boc(
    endpoint: &str,
    multisig_address: &dexdo_core::Address,
    boc: &str,
    http: &reqwest::Client,
) -> Result<Option<NoteDeployWalletActionReceipt>> {
    use dexdo_core::ackinacki_wallet::query::send_message_routed;
    dexdo_core::shellnet_clock_skew_preflight(endpoint).await?;
    send_message_routed(
        http,
        endpoint,
        boc,
        multisig_address.bare(),
        multisig_address.bare(),
        None,
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "submit UpdateCustodianMultisigWallet_v2.submitTransaction -> RootPN.generateVoucher: {e}"
        )
    })?;
    dexdo_core::shellnet::observe_note_deploy_wallet_action(
        http,
        endpoint,
        boc,
        multisig_address.bare(),
        multisig_address.bare(),
    )
    .await
    .map(|receipt| {
        receipt.map(|receipt| NoteDeployWalletActionReceipt {
            transaction_hash: receipt.transaction_hash,
            compute_exit_code: None,
            aborted: receipt.aborted,
            action_result_code: receipt.action_result_code,
            outmsg_count: receipt.outmsg_count,
            wallet_ecc_balances: receipt.wallet_ecc_balances,
        })
    })
    .map_err(|e| anyhow::anyhow!("observe finalized note-deploy wallet action: {e}"))
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
trait NoteDeployVoucherSubmitter {
    async fn submit_voucher_boc(
        &self,
        endpoint: &str,
        multisig_address: &dexdo_core::Address,
        boc: &str,
        http: &reqwest::Client,
    ) -> Result<Option<NoteDeployWalletActionReceipt>>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
impl NoteDeployVoucherSubmitter for dexdo_core::ChainClient {
    async fn submit_voucher_boc(
        &self,
        endpoint: &str,
        multisig_address: &dexdo_core::Address,
        boc: &str,
        http: &reqwest::Client,
    ) -> Result<Option<NoteDeployWalletActionReceipt>> {
        note_deploy_submit_voucher_boc(endpoint, multisig_address, boc, http).await
    }
}

#[cfg(feature = "shellnet")]
fn note_deploy_action_failed(aborted: bool, action_result_code: i64) -> bool {
    aborted || action_result_code != 0
}

#[cfg(feature = "shellnet")]
fn note_deploy_verify_failed_action_had_no_effect(
    receipt: &NoteDeployWalletActionReceipt,
    before_ecc: &[(u32, u128)],
    kind: crate::cli::note::NoteDeployVoucherKind,
    voucher_token_type: u32,
) -> Result<()> {
    if receipt.outmsg_count != 0 {
        bail!(
            "wallet transaction produced {} outbound message(s), so absence of a matching \
             RootPN voucher effect is not proven",
            receipt.outmsg_count
        );
    }
    let wallet_ecc_balances = receipt.wallet_ecc_balances.as_deref().ok_or_else(|| {
        anyhow::anyhow!("finalized failed wallet action has no exact wallet ECC state")
    })?;
    let balance = |balances: &[(u32, u128)], currency_id| {
        balances
            .iter()
            .find(|(id, _)| *id == currency_id)
            .map_or(0, |(_, value)| *value)
    };
    let mut currency_ids = vec![voucher_token_type];
    if kind == crate::cli::note::NoteDeployVoucherKind::Deposit
        && voucher_token_type != SHELL_CURRENCY_ID
    {
        currency_ids.push(SHELL_CURRENCY_ID);
    }
    for currency_id in currency_ids {
        let before = balance(before_ecc, currency_id);
        let after = balance(wallet_ecc_balances, currency_id);
        if before != after {
            bail!(
                "wallet ECC[{currency_id}] changed from {before} to {after}, so absence of the \
                 corresponding voucher effect is not proven"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn note_deploy_action_result_label(code: i64) -> Option<&'static str> {
    (code == 38).then_some("NOT_ENOUGH_EXTRA")
}

#[cfg(feature = "shellnet")]
fn is_note_deploy_wallet_submit_busy_error(error: &anyhow::Error) -> bool {
    error.to_string().contains(
        "submit UpdateCustodianMultisigWallet_v2.submitTransaction -> RootPN.generateVoucher:",
    ) && is_note_deploy_wallet_busy_error(error)
}

#[cfg(feature = "shellnet")]
fn note_deploy_resume_error(funding_multisig_address: &str, error: anyhow::Error) -> anyhow::Error {
    note_deploy_error(funding_multisig_address, error)
}

#[cfg(feature = "shellnet")]
async fn run_note_deploy_with_wallet_busy_retry<T, Op, Sleep>(
    funding_multisig_address: &str,
    mut op: Op,
    mut sleeper: Sleep,
) -> Result<T>
where
    Op: AsyncFnMut(u64) -> Result<T>,
    Sleep: AsyncFnMut(std::time::Duration),
{
    let mut attempt = 1u64;
    loop {
        match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if is_note_deploy_wallet_submit_busy_error(&error)
                    && attempt < NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS
                {
                    let backoff_secs =
                        attempt.saturating_mul(NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS);
                    eprintln!(
                        "note deploy: funding wallet {funding_multisig_address} looks busy/out-of-sync; retrying \
                         attempt {} after {backoff_secs}s",
                        attempt + 1
                    );
                    sleeper(std::time::Duration::from_secs(backoff_secs)).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                return Err(note_deploy_resume_error(funding_multisig_address, error));
            }
        }
    }
}

#[cfg(feature = "shellnet")]
#[allow(clippy::too_many_arguments)]
async fn note_deploy_mint_voucher_recoverable(
    client: &dexdo_core::ChainClient,
    recovery_path: &std::path::Path,
    recovery: &mut crate::cli::note::NoteDeployRecoveryState,
    kind: crate::cli::note::NoteDeployVoucherKind,
    multisig_address: &dexdo_core::Address,
    funding_key_loader: &dyn NoteDeployFundingKeyLoader,
    wallet_reader: &dyn NoteDeployFundingWalletReader,
    voucher_boc_builder: &dyn NoteDeployVoucherBocBuilder,
    voucher_submitter: &dyn NoteDeployVoucherSubmitter,
    recipient_ephemeral_pubkey_hex: &str,
    voucher_token_type: u32,
    voucher_value: u64,
    is_fee: bool,
    halo2_paths: &dexdo_core::private_note::Halo2Paths,
    failpoints: NoteDeployVoucherFailpoints,
) -> Result<dexdo_core::private_note::halo2::live::Halo2Proof> {
    use dexdo_core::private_note::{
        artifacts::ROOT_PN_ADDRESS,
        halo2::{
            live::{prove_voucher_for_event, ProveVoucherForEventParams},
            sk_commit::compute_sk_u_commit_hex,
        },
        proof, voucher_event,
    };
    let endpoint = client.endpoint();
    let root_pn = dexdo_core::Address::parse(ROOT_PN_ADDRESS)?;
    let recipient_ephemeral_pubkey_hex = proof::strip_0x(recipient_ephemeral_pubkey_hex);
    let mut guarded_funding_keys = None;
    let mut checkpoint = match recovery.voucher_checkpoint(kind).cloned() {
        Some(checkpoint) => {
            checkpoint.ensure_matches(
                kind,
                recipient_ephemeral_pubkey_hex,
                voucher_token_type,
                voucher_value,
                is_fee,
            )?;
            checkpoint
        }
        None => {
            let funding_keys = funding_key_loader.load_funding_wallet_keys()?;
            note_deploy_preflight_key_owns_wallet(wallet_reader, multisig_address, &funding_keys)
                .await?;
            guarded_funding_keys = Some(funding_keys);

            let recovery_was_persisted = recovery_path.exists();
            let sk_u_hex = proof::random_secret_key();
            let sk_u_commit_hex = compute_sk_u_commit_hex(&sk_u_hex)
                .map_err(|e| anyhow::anyhow!("compute {} voucher skUCommit: {e}", kind.label()))?;
            let checkpoint = crate::cli::note::NoteDeployVoucherCheckpoint::new(
                recipient_ephemeral_pubkey_hex,
                voucher_token_type,
                voucher_value,
                is_fee,
                sk_u_hex,
                sk_u_commit_hex,
            )?;
            note_deploy_persist_voucher_checkpoint(
                recovery_path,
                recovery,
                kind,
                checkpoint.clone(),
            )?;
            if !recovery_was_persisted {
                eprintln!(
                    "{}",
                    crate::cli::note::recovery_owner_key_written_message(recovery_path)
                );
            }
            eprintln!(
                "note deploy recovery: recorded {} voucher checkpoint in {} before wallet spend.",
                kind.label(),
                recovery_path.display()
            );
            checkpoint
        }
    };

    if let Some(proof) = checkpoint
        .proof
        .as_ref()
        .filter(|_| !checkpoint.current_proof_is_rejected())
    {
        eprintln!(
            "note deploy recovery: reusing persisted {} voucher proof from {}; no wallet spend will be submitted.",
            kind.label(),
            recovery_path.display()
        );
        return Ok(proof.to_halo2());
    }
    if checkpoint.current_proof_is_rejected() {
        eprintln!(
            "note deploy recovery: persisted {} proof layer {} was rejected with exact 403; \
             rebuilding the same paid voucher without another wallet spend.",
            kind.label(),
            checkpoint
                .proof
                .as_ref()
                .map(|proof| proof.layer_number)
                .unwrap_or_default()
        );
    }

    let http = reqwest::Client::new();
    if checkpoint.event.is_none() {
        if !checkpoint.submit_maybe_sent {
            if guarded_funding_keys.is_none() {
                let funding_keys = funding_key_loader.load_funding_wallet_keys()?;
                note_deploy_preflight_key_owns_wallet(
                    wallet_reader,
                    multisig_address,
                    &funding_keys,
                )
                .await?;
                guarded_funding_keys = Some(funding_keys);
            }
            let funding_keys = guarded_funding_keys.as_ref().ok_or_else(|| {
                anyhow::anyhow!("fresh voucher submit is missing its guarded funding key")
            })?;
            let before_wallet_ecc = note_deploy_preflight_wallet_ecc(
                wallet_reader,
                multisig_address,
                kind,
                recovery,
                voucher_token_type,
                voucher_value,
            )
            .await?;
            let boc = voucher_boc_builder
                .build_voucher_submit_boc(multisig_address, funding_keys, &root_pn, &checkpoint)
                .await?;
            checkpoint.submit_maybe_sent = true;
            note_deploy_persist_voucher_checkpoint(
                recovery_path,
                recovery,
                kind,
                checkpoint.clone(),
            )?;
            eprintln!(
                "note deploy recovery: marked {} voucher wallet submit as uncertain in {}; reruns will not submit a second wallet spend.",
                kind.label(),
                recovery_path.display()
            );
            let receipt = voucher_submitter
                .submit_voucher_boc(endpoint, multisig_address, &boc, &http)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "{} voucher wallet POST outcome is ambiguous: {error}; recovery {} remains \
                         submit_maybe_sent and will not submit a second wallet POST. Inspect the \
                         exact wallet transaction/account state and matching RootPN voucher evidence \
                         before manual recovery.",
                        kind.label(),
                        recovery_path.display()
                    )
                })?;
            let receipt = receipt.ok_or_else(|| {
                anyhow::anyhow!(
                    "{} voucher wallet POST has no bounded finalized receipt; recovery {} remains \
                     submit_maybe_sent and will not submit a second wallet POST. Inspect the exact \
                     wallet transaction/account state and matching RootPN voucher evidence before \
                     manual recovery.",
                    kind.label(),
                    recovery_path.display()
                )
            })?;
            if note_deploy_action_failed(receipt.aborted, receipt.action_result_code) {
                note_deploy_verify_failed_action_had_no_effect(
                    &receipt,
                    &before_wallet_ecc,
                    kind,
                    checkpoint.token_type,
                )
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "{} voucher wallet transaction {} failed definitively, but voucher \
                             effect absence could not be proven: {error}; recovery {} remains \
                             submit_maybe_sent and will not submit a second wallet POST. Inspect the \
                             exact wallet transaction/account state and matching RootPN voucher \
                             evidence before manual recovery.",
                            kind.label(),
                            receipt.transaction_hash,
                            recovery_path.display()
                        )
                    })?;
                checkpoint.submit_maybe_sent = false;
                note_deploy_persist_voucher_checkpoint(
                    recovery_path,
                    recovery,
                    kind,
                    checkpoint.clone(),
                )?;
                let label = note_deploy_action_result_label(receipt.action_result_code)
                    .map(|label| format!(" ({label})"))
                    .unwrap_or_default();
                let compute_exit = receipt
                    .compute_exit_code
                    .map_or_else(|| "<unavailable>".to_string(), |code| code.to_string());
                let currency =
                    note_deploy_ecc_name(kind, recovery.token_type, checkpoint.token_type);
                bail!(
                    "funding wallet {} {} voucher transaction {} failed definitively: \
                     compute_exit_code={compute_exit}, aborted={}, action_result_code={}{}; the exact \
                     wallet action produced zero outbound messages and left the required ECC unchanged, \
                     so no corresponding RootPN voucher effect occurred. Fund {currency} and retry \
                     `dexdo note deploy --recovery {}`.",
                    multisig_address.with_workchain(),
                    kind.label(),
                    receipt.transaction_hash,
                    receipt.aborted,
                    receipt.action_result_code,
                    label,
                    recovery_path.display()
                );
            }
            if failpoints.after_submit(kind) {
                bail!(
                    "simulated interruption after {} voucher wallet submit. Recovery state is at {}; rerun `dexdo note deploy --recovery <this-file> --pool <pool>` to resume without a second wallet spend.",
                    kind.label(),
                    recovery_path.display()
                );
            }
        } else {
            eprintln!(
                "note deploy recovery: resuming {} voucher from {}; waiting/proving the existing skUCommit without submitting another wallet spend.",
                kind.label(),
                recovery_path.display()
            );
        }

        if failpoints.before_voucher_event_wait {
            bail!("simulated interruption before voucher event wait");
        }
        let event = voucher_event::wait_for_voucher_event_by_sk_u_commit(
            &http,
            endpoint,
            &root_pn,
            &format!("0x{}", checkpoint.sk_u_commit_hex),
            NOTE_DEPLOY_VOUCHER_EVENT_TIMEOUT,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "wait for {} VoucherGenerated from persisted wallet submit: {e}; refusing to submit a second wallet spend for recovery {}",
                kind.label(),
                recovery_path.display()
            )
        })?;
        checkpoint.event = Some(crate::cli::note::NoteDeployVoucherEvent::from_sdk(event));
        note_deploy_persist_voucher_checkpoint(recovery_path, recovery, kind, checkpoint.clone())?;
        eprintln!(
            "note deploy recovery: recorded {} VoucherGenerated event in {}; reruns will prove this voucher without a second wallet spend.",
            kind.label(),
            recovery_path.display()
        );
        if failpoints.after_event(kind) {
            bail!(
                "simulated interruption after {} VoucherGenerated event before proof/deploy. Recovery state is at {}; rerun `dexdo note deploy --recovery <this-file> --pool <pool>` to resume without a second wallet spend.",
                kind.label(),
                recovery_path.display()
            );
        }
    }

    let event = checkpoint
        .event
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("{} voucher event missing after recovery wait", kind.label())
        })?
        .to_sdk();
    let proof = {
        // The pinned prover publishes PK/VK/BP non-atomically. Serialize only the cache preflight,
        // proof/keygen, and marker publication; wallet submissions and chain waits stay outside this lock.
        let _prover_cache_lock =
            acquire_note_deploy_prover_cache_lock(&halo2_paths.prover_cache_dir)?;
        halo2_paths.ensure_srs();
        ensure_hermez_srs_and_valid_pk_cache(&halo2_paths.prover_cache_dir).await?;
        let params = ProveVoucherForEventParams {
            endpoint: endpoint.to_string(),
            event,
            sk_u_hex: checkpoint.sk_u_hex.to_string(),
            sk_u_commit_hex: checkpoint.sk_u_commit_hex.clone(),
            voucher_value,
            voucher_token_type,
            ephemeral_pubkey_hex: recipient_ephemeral_pubkey_hex.to_string(),
            history_proof_window_size: None,
            paths: halo2_paths,
        };
        let proof = if checkpoint.current_proof_is_rejected() {
            let Some(next_layer) = checkpoint.next_sdk_proof_layer() else {
                bail!(
                    "{} voucher history layer plan exhausted; paid voucher recovery remains at {}. \
                     action=resume_same_paid_voucher_later; do not fund a new voucher.",
                    kind.label(),
                    recovery_path.display()
                );
            };
            let previous_layers = std::env::var_os("HALO2_ATTEMPT_LAYERS");
            std::env::set_var("HALO2_ATTEMPT_LAYERS", next_layer.to_string());
            let result = prove_voucher_for_event(params).await;
            match previous_layers {
                Some(value) => std::env::set_var("HALO2_ATTEMPT_LAYERS", value),
                None => std::env::remove_var("HALO2_ATTEMPT_LAYERS"),
            }
            result.map_err(|e| {
                anyhow::anyhow!(
                    "prove {} paid voucher on next layer {next_layer}: {e}; \
                     action=resume_same_paid_voucher_later; recovery={}; no new wallet spend is permitted",
                    kind.label(),
                    recovery_path.display()
                )
            })?
        } else {
            prove_voucher_for_event(params)
                .await
                .map_err(|e| anyhow::anyhow!("prove {} voucher: {e}", kind.label()))?
        };
        // A successful proof is the cache commit point. Later chain retries and pool finalization must
        // never depend on cache metadata or on PK/VK/BP still being present.
        promote_hermez_srs_pending_marker(
            &halo2_paths.prover_cache_dir,
            HERMEZ_SRS_SIZE_BYTES,
            HERMEZ_SRS_SHA256,
        )?;
        proof
    };
    let persisted_proof = crate::cli::note::NoteDeployVoucherProof::from_halo2(&proof);
    if checkpoint.current_proof_is_rejected() {
        checkpoint.replace_rejected_proof(persisted_proof)?;
    } else {
        checkpoint.proof = Some(persisted_proof);
    }
    note_deploy_persist_voucher_checkpoint(recovery_path, recovery, kind, checkpoint)?;
    eprintln!(
        "note deploy recovery: recorded {} voucher proof in {}; reruns will not re-spend this voucher.",
        kind.label(),
        recovery_path.display()
    );
    Ok(proof)
}

#[cfg(feature = "shellnet")]
#[derive(Debug)]
struct NoteDeployFinalizedRootPnExitCode(i64);

#[cfg(feature = "shellnet")]
impl std::fmt::Display for NoteDeployFinalizedRootPnExitCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "finalized RootPN exit code {}", self.0)
    }
}

#[cfg(feature = "shellnet")]
impl std::error::Error for NoteDeployFinalizedRootPnExitCode {}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_has_exact_finalized_rootpn_exit_code(
    error: &anyhow::Error,
    wanted: i64,
) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<NoteDeployFinalizedRootPnExitCode>()
            .is_some_and(|code| code.0 == wanted)
    })
}

#[cfg(feature = "shellnet")]
async fn note_deploy_submit_proof_once<EffectPresent, Submit>(
    proof: &dexdo_core::private_note::halo2::live::Halo2Proof,
    mut effect_present: EffectPresent,
    mut submit: Submit,
) -> Result<bool>
where
    EffectPresent: AsyncFnMut(&dexdo_core::private_note::halo2::live::Halo2Proof) -> Result<bool>,
    Submit: AsyncFnMut(&dexdo_core::private_note::halo2::live::Halo2Proof) -> Result<()>,
{
    match submit(proof).await {
        Ok(()) => Ok(true),
        Err(error) => {
            if effect_present(proof).await? {
                Ok(true)
            } else if note_deploy_has_exact_finalized_rootpn_exit_code(&error, 403) {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(feature = "shellnet")]
async fn note_deploy_run_reproof_loop<SubmitOnce, PersistAndReproof>(
    mut proof: dexdo_core::private_note::halo2::live::Halo2Proof,
    mut submit_once: SubmitOnce,
    mut persist_and_reproof: PersistAndReproof,
) -> Result<dexdo_core::private_note::halo2::live::Halo2Proof>
where
    SubmitOnce: AsyncFnMut(&dexdo_core::private_note::halo2::live::Halo2Proof) -> Result<bool>,
    PersistAndReproof: AsyncFnMut(
        &dexdo_core::private_note::halo2::live::Halo2Proof,
    ) -> Result<dexdo_core::private_note::halo2::live::Halo2Proof>,
{
    while !submit_once(&proof).await? {
        proof = persist_and_reproof(&proof).await?;
    }
    Ok(proof)
}

#[cfg(feature = "shellnet")]
fn note_deploy_persist_rejected_proof(
    recovery_path: &std::path::Path,
    recovery: &mut crate::cli::note::NoteDeployRecoveryState,
    kind: crate::cli::note::NoteDeployVoucherKind,
    proof: &dexdo_core::private_note::halo2::live::Halo2Proof,
) -> Result<()> {
    let mut checkpoint = recovery.voucher_checkpoint(kind).cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "{} voucher checkpoint disappeared after exact 403",
            kind.label()
        )
    })?;
    let returned = crate::cli::note::NoteDeployVoucherProof::from_halo2(proof);
    if checkpoint.proof.as_ref() != Some(&returned) {
        bail!(
            "{} voucher proof returned by prover does not match durable recovery state",
            kind.label()
        );
    }
    let rejected_layer = checkpoint.reject_current_proof()?;
    note_deploy_persist_voucher_checkpoint(recovery_path, recovery, kind, checkpoint)?;
    eprintln!(
        "note deploy recovery: {} proof layer {rejected_layer} rejected with exact 403 and \
         no on-chain effect; persisted rejection in {} before re-proving the same paid voucher.",
        kind.label(),
        recovery_path.display()
    );
    Ok(())
}

#[cfg(feature = "shellnet")]
fn note_deploy_rootpn_action_result(
    method: &str,
    submit_error: Option<anyhow::Error>,
    receipt: Option<dexdo_core::shellnet::NoteDeployRootPnActionObservation>,
) -> Result<()> {
    let Some(receipt) = receipt else {
        if let Some(error) = submit_error {
            return Err(anyhow::anyhow!(
                "RootPN.{method}: {error}; no bounded finalized receipt"
            ));
        }
        bail!("RootPN.{method}: no bounded finalized receipt");
    };
    if receipt.aborted
        || receipt.compute_exit_code != 0
        || receipt.action_result_code.is_some_and(|code| code != 0)
    {
        let context = format!(
            "RootPN.{method}: finalized transaction {} exit_code={} aborted={} action_result_code={}",
            receipt.transaction_hash,
            receipt.compute_exit_code,
            receipt.aborted,
            receipt
                .action_result_code
                .map_or_else(|| "<unavailable>".to_string(), |code| code.to_string())
        );
        return Err(anyhow::Error::new(NoteDeployFinalizedRootPnExitCode(
            receipt.compute_exit_code,
        ))
        .context(context));
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn note_deploy_submit_rootpn_call(
    client: &dexdo_core::ChainClient,
    root_pn: &dexdo_core::Address,
    method: &str,
    args: serde_json::Value,
    pn_keys: &dexdo_core::KeyPair,
) -> Result<()> {
    use dexdo_core::{
        ackinacki_wallet::query::{fetch_dapp_id, send_message_routed},
        airegistry::{calls::encode_external_call, deploy::local_context},
        private_note::artifacts::ROOT_PN_ABI_JSON,
    };

    dexdo_core::shellnet_clock_skew_preflight(client.endpoint()).await?;
    let boc = encode_external_call(
        &local_context()?,
        ROOT_PN_ABI_JSON,
        &root_pn.with_workchain(),
        method,
        args,
        pn_keys.public_hex(),
        pn_keys.secret_hex(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("encode RootPN.{method}: {error}"))?;
    let http = reqwest::Client::new();
    let dapp_id = fetch_dapp_id(&http, client.endpoint(), root_pn.bare()).await?;
    let submit_error = send_message_routed(
        &http,
        client.endpoint(),
        &boc,
        root_pn.bare(),
        &dapp_id,
        None,
    )
    .await
    .err()
    .map(|error| anyhow::anyhow!(error));
    let receipt = match dexdo_core::shellnet::observe_note_deploy_rootpn_action(
        &http,
        client.endpoint(),
        &boc,
        root_pn.bare(),
        &dapp_id,
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(observe_error) => {
            let submit_context = submit_error.as_ref().map_or_else(
                || "POST returned success".to_string(),
                |error| format!("POST returned {error}"),
            );
            return Err(observe_error.context(format!(
                "observe finalized RootPN.{method} receipt after {submit_context}"
            )));
        }
    };
    note_deploy_rootpn_action_result(method, submit_error, receipt)
}

#[cfg(feature = "shellnet")]
async fn note_deploy_submit_private_note(
    client: &dexdo_core::ChainClient,
    root_pn: &dexdo_core::Address,
    pn_keys: &dexdo_core::KeyPair,
    deposit_zk: &dexdo_core::private_note::halo2::live::Halo2Proof,
    deposit_identifier_hash: &str,
) -> Result<()> {
    use dexdo_core::private_note::proof::{hex_u256_to_dec, pubkey_to_dec};

    note_deploy_submit_rootpn_call(
        client,
        root_pn,
        "deployPrivateNote",
        serde_json::json!({
            "zkproof": deposit_zk.proof,
            "depositIdentifierHash": deposit_identifier_hash,
            "finalLayerHistoricalHashRoot": hex_u256_to_dec(&deposit_zk.final_layer_historical_hash_root_hex)?,
            "voucherNominalFr": hex_u256_to_dec(&deposit_zk.voucher_nominal_fr_hex)?,
            "tokenTypeFr": hex_u256_to_dec(&deposit_zk.token_type_fr_hex)?,
            "ephemeralPubkey": pubkey_to_dec(pn_keys.public_hex())?,
            "value": deposit_zk.voucher_value,
            "tokenType": deposit_zk.voucher_token_type,
            "layerNumber": deposit_zk.layer_number,
        }),
        pn_keys,
    )
    .await
}

#[cfg(feature = "shellnet")]
#[allow(clippy::too_many_arguments)]
async fn deploy_private_note_from_multisig_recoverable(
    client: &dexdo_core::ChainClient,
    recovery_path: &std::path::Path,
    recovery: &mut crate::cli::note::NoteDeployRecoveryState,
    multisig_address: &dexdo_core::Address,
    funding_key_loader: &dyn NoteDeployFundingKeyLoader,
    pn_keys: &dexdo_core::KeyPair,
    halo2_paths: &dexdo_core::private_note::Halo2Paths,
    failpoints: NoteDeployVoucherFailpoints,
) -> Result<crate::cli::note::OnboardPnState> {
    use dexdo_core::private_note::{
        artifacts::{PRIVATE_NOTE_ABI_JSON, ROOT_PN_ADDRESS},
        proof::{hex_u256_to_dec, pubkey_to_dec, CURRENCY_ID_SHELL, ECC_SHELL_DEPOSIT_RAW},
    };
    use dexdo_core::Address;
    use serde_json::json;
    use std::time::Duration;

    if recovery.shell_funded && recovery.sanity_checked {
        recovery.ensure_ready_for_pool()?;
        return recovery.to_onboard_state();
    }

    let root_pn = Address::parse(ROOT_PN_ADDRESS)?;
    let mut resumed_existing_note = false;
    let (pn_address, deposit_identifier_hash) = match (
        recovery.pn_address.clone(),
        recovery.deposit_identifier_hash.clone(),
    ) {
        (Some(pn_address), Some(deposit_identifier_hash)) => {
            resumed_existing_note = true;
            eprintln!(
                "note deploy recovery: PrivateNote {pn_address} is already recorded in {}; skipping \
                 deployPrivateNote spend and resuming later steps.",
                recovery_path.display()
            );
            (pn_address, deposit_identifier_hash)
        }
        (None, None) => {
            eprintln!(
                "note deploy recovery: no on-chain PrivateNote recorded yet; continuing deploy with the \
                 persisted owner key in {}.",
                recovery_path.display()
            );
            let deposit_token_type = recovery.token_type;
            let deposit_raw_value = recovery.raw_value;
            let had_persisted_deposit_proof = recovery
                .voucher_checkpoint(crate::cli::note::NoteDeployVoucherKind::Deposit)
                .and_then(|checkpoint| checkpoint.proof.as_ref())
                .is_some();
            let deposit_zk = note_deploy_mint_voucher_recoverable(
                client,
                recovery_path,
                recovery,
                crate::cli::note::NoteDeployVoucherKind::Deposit,
                multisig_address,
                funding_key_loader,
                client,
                client,
                client,
                pn_keys.public_hex(),
                deposit_token_type,
                deposit_raw_value,
                false,
                halo2_paths,
                failpoints,
            )
            .await
            .map_err(|e| anyhow::anyhow!("halo2 deposit voucher: {e}"))?;

            let dih_dec = hex_u256_to_dec(&deposit_zk.deposit_identifier_hash_hex)?;
            let pn_address = note_deploy_private_note_address(client, &root_pn, &dih_dec)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("RootPN.getPrivateNoteAddress before deployPrivateNote: {e}")
                })?;
            let pn = Address::parse(&pn_address)?;
            let recovered_active = had_persisted_deposit_proof
                && note_deploy_wait_existing_active(client, &pn, NOTE_DEPLOY_ACTIVE_TIMEOUT)
                    .await?;
            if recovered_active {
                resumed_existing_note = true;
                eprintln!(
                    "note deploy recovery: recovered active PrivateNote {pn_address} from persisted \
                     deposit proof in {}; skipping repeat deployPrivateNote submit.",
                    recovery_path.display()
                );
            } else {
                if had_persisted_deposit_proof {
                    eprintln!(
                        "note deploy recovery: persisted deposit proof in {} has no active PrivateNote yet; \
                         submitting deployPrivateNote once.",
                        recovery_path.display()
                    );
                }
                note_deploy_run_reproof_loop(
                    deposit_zk,
                    async |proof| {
                        note_deploy_submit_proof_once(
                            proof,
                            async |_proof| {
                                note_deploy_wait_existing_active(client, &pn, Duration::ZERO).await
                            },
                            async |proof| {
                                note_deploy_submit_private_note(
                                    client, &root_pn, pn_keys, proof, &dih_dec,
                                )
                                .await
                            },
                        )
                        .await
                    },
                    async |rejected_proof| {
                        note_deploy_persist_rejected_proof(
                            recovery_path,
                            recovery,
                            crate::cli::note::NoteDeployVoucherKind::Deposit,
                            rejected_proof,
                        )?;
                        note_deploy_mint_voucher_recoverable(
                            client,
                            recovery_path,
                            recovery,
                            crate::cli::note::NoteDeployVoucherKind::Deposit,
                            multisig_address,
                            funding_key_loader,
                            client,
                            client,
                            client,
                            pn_keys.public_hex(),
                            deposit_token_type,
                            deposit_raw_value,
                            false,
                            halo2_paths,
                            failpoints,
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("halo2 deposit voucher: {e}"))
                    },
                )
                .await?;

                note_deploy_wait_active(client, &pn, NOTE_DEPLOY_ACTIVE_TIMEOUT).await?;
                if failpoints.after_deploy_before_note_record {
                    bail!(
                        "simulated interruption after deployPrivateNote active before recovery note record. \
                         Recovery state is at {}; rerun `dexdo note deploy --recovery <this-file> --pool <pool>` \
                         to discover the active PrivateNote without repeating deployPrivateNote.",
                        recovery_path.display()
                    );
                }
            }
            let deployed_at_unix = note_deploy_now_unix()?;
            recovery.mark_private_note_deployed(
                pn_address.clone(),
                dih_dec.clone(),
                deployed_at_unix,
            )?;
            crate::cli::note::write_note_deploy_recovery(recovery_path, recovery)?;
            if !recovered_active {
                eprintln!(
                    "note deploy recovery: recorded deployed PrivateNote {pn_address} in {}; a later recovery \
                     will not repeat deployPrivateNote.",
                    recovery_path.display()
                );
            }
            (pn_address, dih_dec)
        }
        _ => {
            bail!(
                "note deploy recovery {} is inconsistent: pn_address and deposit_identifier_hash must both be \
                 present or both absent",
                recovery_path.display()
            );
        }
    };

    if !recovery.shell_funded {
        let pn = Address::parse(&pn_address)?;
        let expected_shell = recovery.ecc_shell_deposit as u128;
        let already_funded = resumed_existing_note
            && note_deploy_wait_existing_shell_funding(
                client,
                &pn,
                expected_shell,
                NOTE_DEPLOY_EXISTING_SHELL_FUNDING_TIMEOUT,
            )
            .await?;
        if already_funded {
            eprintln!(
                "note deploy recovery: PrivateNote {pn_address} already has expected ECC[2] funding; \
                 skipping sendEccShellToPrivateNote spend."
            );
        } else {
            let gas_zk = note_deploy_mint_voucher_recoverable(
                client,
                recovery_path,
                recovery,
                crate::cli::note::NoteDeployVoucherKind::ShellGas,
                multisig_address,
                funding_key_loader,
                client,
                client,
                client,
                pn_keys.public_hex(),
                CURRENCY_ID_SHELL,
                ECC_SHELL_DEPOSIT_RAW,
                true,
                halo2_paths,
                failpoints,
            )
            .await
            .map_err(|e| anyhow::anyhow!("halo2 SHELL gas voucher: {e}"))?;

            note_deploy_run_reproof_loop(
                gas_zk,
                async |proof| {
                    note_deploy_submit_proof_once(
                        proof,
                        async |_proof| {
                            note_deploy_wait_existing_shell_funding(
                                client,
                                &pn,
                                expected_shell,
                                Duration::ZERO,
                            )
                            .await
                        },
                        async |proof| {
                            note_deploy_submit_rootpn_call(
                                client,
                                &root_pn,
                                "sendEccShellToPrivateNote",
                                json!({
                                    "proof": proof.proof,
                                    "nullifierHash": hex_u256_to_dec(&proof.deposit_identifier_hash_hex)?,
                                    "depositIdentifierHash": deposit_identifier_hash,
                                    "finalLayerHistoricalHashRoot": hex_u256_to_dec(&proof.final_layer_historical_hash_root_hex)?,
                                    "voucherNominalFr": hex_u256_to_dec(&proof.voucher_nominal_fr_hex)?,
                                    "tokenTypeFr": hex_u256_to_dec(&proof.token_type_fr_hex)?,
                                    "value": proof.voucher_value,
                                    "layerNumber": proof.layer_number,
                                    "recipientEphemeralPubkey": pubkey_to_dec(pn_keys.public_hex())?,
                                }),
                                pn_keys,
                            )
                            .await
                        },
                    )
                    .await
                },
                async |rejected_proof| {
                    note_deploy_persist_rejected_proof(
                        recovery_path,
                        recovery,
                        crate::cli::note::NoteDeployVoucherKind::ShellGas,
                        rejected_proof,
                    )?;
                    note_deploy_mint_voucher_recoverable(
                        client,
                        recovery_path,
                        recovery,
                        crate::cli::note::NoteDeployVoucherKind::ShellGas,
                        multisig_address,
                        funding_key_loader,
                        client,
                        client,
                        client,
                        pn_keys.public_hex(),
                        CURRENCY_ID_SHELL,
                        ECC_SHELL_DEPOSIT_RAW,
                        true,
                        halo2_paths,
                        failpoints,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("halo2 SHELL gas voucher: {e}"))
                },
            )
            .await?;
            if !note_deploy_wait_existing_shell_funding(
                client,
                &pn,
                expected_shell,
                NOTE_DEPLOY_SHELL_FUNDING_TIMEOUT,
            )
            .await?
            {
                bail!(
                    "PrivateNote {pn_address} did not show expected ECC[2] funding {expected_shell} within \
                     {}s after sendEccShellToPrivateNote; recovery state was left unfinalized so rerun \
                     `dexdo note deploy --recovery {}` before pooling.",
                    NOTE_DEPLOY_SHELL_FUNDING_TIMEOUT.as_secs(),
                    recovery_path.display()
                );
            }
        }
    }

    let pn = Address::parse(&pn_address)?;
    client
        .run_getter(&pn, PRIVATE_NOTE_ABI_JSON, "getDetails", json!({}))
        .await?
        .ok_or_else(|| anyhow::anyhow!("PrivateNote.getDetails returned no output"))?;
    recovery.mark_shell_funded_and_checked()?;
    crate::cli::note::write_note_deploy_recovery(recovery_path, recovery)?;
    recovery.to_onboard_state()
}

#[cfg(feature = "shellnet")]
async fn note_deploy_wait_existing_shell_funding(
    client: &dexdo_core::ChainClient,
    note: &dexdo_core::Address,
    expected_shell_ecc: u128,
    timeout: std::time::Duration,
) -> Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(acc) = client.get_account(note).await? {
            if acc.ecc_balance(SHELL_CURRENCY_ID) >= expected_shell_ecc {
                return Ok(true);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL).await;
    }
}

#[cfg(feature = "shellnet")]
async fn note_deploy_wait_existing_active(
    client: &dexdo_core::ChainClient,
    note: &dexdo_core::Address,
    timeout: std::time::Duration,
) -> Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(acc) = client.get_account(note).await? {
            if acc.is_active() {
                return Ok(true);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(NOTE_DEPLOY_ACTIVE_POLL_INTERVAL).await;
    }
}

#[cfg(feature = "shellnet")]
async fn note_deploy_private_note_address(
    client: &dexdo_core::ChainClient,
    root_pn: &dexdo_core::Address,
    deposit_identifier_hash: &str,
) -> Result<String> {
    use dexdo_core::private_note::artifacts::ROOT_PN_ABI_JSON;
    let out = client
        .run_getter(
            root_pn,
            ROOT_PN_ABI_JSON,
            "getPrivateNoteAddress",
            serde_json::json!({ "depositIdentifierHash": deposit_identifier_hash }),
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("RootPN.getPrivateNoteAddress returned no output"))?;
    out.get("privateNoteAddress")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!("RootPN.getPrivateNoteAddress missing privateNoteAddress: {out}")
        })
}

#[cfg(feature = "shellnet")]
async fn note_deploy_wait_active(
    client: &dexdo_core::ChainClient,
    address: &dexdo_core::Address,
    timeout: std::time::Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(acc) = client.get_account(address).await? {
            if acc.is_active() {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "{address} did not become Active within {}s",
                timeout.as_secs()
            ));
        }
        tokio::time::sleep(NOTE_DEPLOY_ACTIVE_POLL_INTERVAL).await;
    }
}

#[cfg(all(feature = "shellnet", test))]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(feature = "shellnet")]
fn sha256_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("open {} for SHA-256: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HERMEZ_SRS_HASH_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| anyhow::anyhow!("read {} for SHA-256: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(feature = "shellnet")]
fn hermez_srs_file_matches(
    path: &std::path::Path,
    expected_size: u64,
    expected_sha256: &str,
) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() == expected_size)
        && sha256_file(path).is_ok_and(|sha256| sha256 == expected_sha256)
}

#[cfg(feature = "shellnet")]
fn invalidate_stale_pk_cache(prover_cache_dir: &std::path::Path) -> Result<()> {
    invalidate_stale_pk_cache_with(prover_cache_dir, |path| std::fs::remove_file(path))
}

#[cfg(feature = "shellnet")]
fn invalidate_stale_pk_cache_with<F>(
    prover_cache_dir: &std::path::Path,
    mut remove_file: F,
) -> Result<()>
where
    F: FnMut(&std::path::Path) -> std::io::Result<()>,
{
    for name in PROVER_CACHE_ARTIFACTS {
        let path = prover_cache_dir.join(name);
        match remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "remove stale prover artifact {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn atomic_replace(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        std::fs::rename(source, destination)
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination_wide: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: both buffers are NUL-terminated and remain alive for the duration of the Win32 call.
        let replaced = unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "shellnet")]
fn write_file_atomically(path: &std::path::Path, bytes: &[u8], label: &str) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("{label} destination has no printable file name"))?;
    let temp_name = format!(".{file_name}.tmp-{}-{temp_id}", std::process::id());
    let temp_path = path.with_file_name(temp_name);
    let install = || -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| anyhow::anyhow!("create {label} temp {}: {e}", temp_path.display()))?;
        file.write_all(bytes)
            .map_err(|e| anyhow::anyhow!("write {label} temp {}: {e}", temp_path.display()))?;
        file.sync_all()
            .map_err(|e| anyhow::anyhow!("sync {label} temp {}: {e}", temp_path.display()))?;
        atomic_replace(&temp_path, path).map_err(|e| {
            anyhow::anyhow!(
                "publish {label} {} from {}: {e}",
                path.display(),
                temp_path.display()
            )
        })
    };
    let result = install();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(feature = "shellnet")]
fn remove_file_if_exists(path: &std::path::Path, label: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "remove {label} {}: {error}",
            path.display()
        )),
    }
}

#[cfg(feature = "shellnet")]
fn publish_hermez_srs_part(
    part_path: &std::path::Path,
    srs_path: &std::path::Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<()> {
    let size = std::fs::metadata(part_path)
        .map_err(|error| anyhow::anyhow!("inspect {}: {error}", part_path.display()))?
        .len();
    if size != expected_size {
        if size > expected_size {
            remove_file_if_exists(part_path, "oversized Hermez SRS partial")?;
        }
        bail!(
            "Hermez SRS size mismatch in {}: got {size}, expected {expected_size}",
            part_path.display()
        );
    }
    let sha256 = sha256_file(part_path)?;
    if sha256 != expected_sha256 {
        remove_file_if_exists(part_path, "incompatible Hermez SRS partial")?;
        bail!(
            "Hermez SRS sha256 mismatch: got {sha256}, expected {expected_sha256}; \
             removed incompatible partial {}",
            part_path.display()
        );
    }

    std::fs::OpenOptions::new()
        .write(true)
        .open(part_path)
        .and_then(|file| file.sync_all())
        .map_err(|error| anyhow::anyhow!("sync {}: {error}", part_path.display()))?;
    atomic_replace(part_path, srs_path)
        .map_err(|error| anyhow::anyhow!("publish {}: {error}", srs_path.display()))
}

#[cfg(feature = "shellnet")]
fn marker_matches(path: &std::path::Path, expected_sha256: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|value| value.trim() == expected_sha256)
        .unwrap_or(false)
}

#[cfg(feature = "shellnet")]
fn prover_cache_artifacts_complete(prover_cache_dir: &std::path::Path) -> bool {
    PROVER_CACHE_ARTIFACTS.iter().all(|name| {
        std::fs::metadata(prover_cache_dir.join(name))
            .map(|metadata| metadata.is_file() && metadata.len() > 0)
            .unwrap_or(false)
    })
}

#[cfg(feature = "shellnet")]
fn promote_hermez_srs_pending_marker(
    prover_cache_dir: &std::path::Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<()> {
    let pending = prover_cache_dir.join(HERMEZ_SRS_PENDING_MARKER_NAME);
    if !pending.exists() {
        return Ok(());
    }
    if !marker_matches(&pending, expected_sha256) {
        bail!(
            "refuse to publish prover cache marker: pending marker {} does not match pinned Hermez SRS",
            pending.display()
        );
    }
    let srs_path = prover_cache_dir.join(HERMEZ_SRS_NAME);
    if !hermez_srs_file_matches(&srs_path, expected_size, expected_sha256) {
        bail!(
            "refuse to publish prover cache marker: Hermez SRS {} is missing or corrupt",
            srs_path.display()
        );
    }
    if !prover_cache_artifacts_complete(prover_cache_dir) {
        bail!(
            "refuse to publish prover cache marker: PK/VK/break-points cache is incomplete in {}",
            prover_cache_dir.display()
        );
    }
    let marker = prover_cache_dir.join(HERMEZ_SRS_MARKER_NAME);
    atomic_replace(&pending, &marker).map_err(|error| {
        anyhow::anyhow!(
            "promote pending SRS marker {} to {}: {error}",
            pending.display(),
            marker.display()
        )
    })
}

#[cfg(feature = "shellnet")]
fn transient_reqwest_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
}

#[cfg(feature = "shellnet")]
fn hermez_srs_progress_line(
    attempt: usize,
    downloaded: u64,
    total: u64,
    resumed_offset: u64,
) -> String {
    let percent = downloaded.saturating_mul(100) / total;
    format!(
        "note deploy: Hermez SRS progress attempt={attempt}/{HERMEZ_SRS_MAX_ATTEMPTS} \
         downloaded={downloaded} total={total} percent={percent}% resumed_offset={resumed_offset}"
    )
}

#[cfg(feature = "shellnet")]
fn validate_hermez_content_range(
    response: &reqwest::Response,
    requested_offset: u64,
    expected_size: u64,
) -> Result<()> {
    let value = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .ok_or_else(|| anyhow::anyhow!("download Hermez SRS: HTTP 206 missing Content-Range"))?
        .to_str()
        .map_err(|_| anyhow::anyhow!("download Hermez SRS: non-text Content-Range"))?;
    let (range, total) = value
        .strip_prefix("bytes ")
        .ok_or_else(|| anyhow::anyhow!("download Hermez SRS: invalid Content-Range unit"))?
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("download Hermez SRS: invalid Content-Range"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("download Hermez SRS: invalid Content-Range"))?;
    if start.parse() != Ok(requested_offset)
        || end.parse() != Ok(expected_size - 1)
        || total.parse() != Ok(expected_size)
    {
        bail!(
            "download Hermez SRS: invalid Content-Range; expected bytes \
             {requested_offset}-{}/{expected_size}",
            expected_size - 1
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn hermez_srs_partial_len(part_path: &std::path::Path, expected_size: u64) -> Result<u64> {
    let metadata = match std::fs::metadata(part_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => bail!("inspect {}: {error}", part_path.display()),
    };
    if !metadata.is_file() {
        bail!("Hermez SRS partial {} is not a file", part_path.display());
    }
    let size = metadata.len();
    if size > expected_size {
        remove_file_if_exists(part_path, "oversized Hermez SRS partial")?;
        bail!(
            "download Hermez SRS: oversized partial {} has {size} bytes, expected at most \
             {expected_size}; removed it",
            part_path.display()
        );
    }
    Ok(size)
}

#[cfg(feature = "shellnet")]
fn sync_hermez_srs_partial(file: &mut std::fs::File) -> Result<()> {
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn fetch_hermez_srs_attempt(
    client: &reqwest::Client,
    url: &str,
    part_path: &std::path::Path,
    expected_size: u64,
    attempt: usize,
    range_restart_used: &mut bool,
) -> std::result::Result<(), (bool, anyhow::Error)> {
    use futures::StreamExt as _;

    let requested_offset =
        hermez_srs_partial_len(part_path, expected_size).map_err(|error| (false, error))?;
    if requested_offset == expected_size {
        return Ok(());
    }

    let mut request = client.get(url);
    if requested_offset > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={requested_offset}-"));
    }
    let response = request.send().await.map_err(|error| {
        (
            transient_reqwest_error(&error),
            anyhow::anyhow!("download Hermez SRS: {error}"),
        )
    })?;
    let status = response.status();
    if status != reqwest::StatusCode::OK && status != reqwest::StatusCode::PARTIAL_CONTENT {
        let transient =
            status.is_server_error() || status.as_u16() == 408 || status.as_u16() == 429;
        return Err((
            transient,
            anyhow::anyhow!("download Hermez SRS: HTTP {status}"),
        ));
    }

    let (effective_offset, append) = if status == reqwest::StatusCode::PARTIAL_CONTENT {
        validate_hermez_content_range(&response, requested_offset, expected_size)
            .map_err(|error| (false, error))?;
        eprintln!(
            "note deploy: Hermez SRS response attempt={attempt}/{HERMEZ_SRS_MAX_ATTEMPTS} \
             status=206 content_range=bytes {requested_offset}-{}/{expected_size}",
            expected_size - 1
        );
        (requested_offset, true)
    } else {
        if requested_offset > 0 {
            if *range_restart_used {
                return Err((
                    false,
                    anyhow::anyhow!(
                        "download Hermez SRS: server ignored Range more than once; preserving partial {}",
                        part_path.display()
                    ),
                ));
            }
            *range_restart_used = true;
            eprintln!(
                "note deploy: Hermez SRS response attempt={attempt}/{HERMEZ_SRS_MAX_ATTEMPTS} \
                 status=200 ignored Range bytes={requested_offset}-; restarting once from byte 0"
            );
        }
        (0, false)
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .open(part_path)
        .map_err(|error| {
            (
                false,
                anyhow::anyhow!("open {}: {error}", part_path.display()),
            )
        })?;
    eprintln!(
        "{}",
        hermez_srs_progress_line(attempt, effective_offset, expected_size, effective_offset)
    );
    let mut downloaded = effective_offset;
    let mut last_percent = downloaded.saturating_mul(100) / expected_size;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                if let Err(sync_error) = sync_hermez_srs_partial(&mut file) {
                    return Err((false, sync_error));
                }
                return Err((true, anyhow::anyhow!("download Hermez SRS body: {error}")));
            }
        };
        let next_len = downloaded.saturating_add(chunk.len() as u64);
        if next_len > expected_size {
            file.set_len(effective_offset)
                .map_err(|error| (false, anyhow::anyhow!("truncate partial: {error}")))?;
            sync_hermez_srs_partial(&mut file).map_err(|error| (false, error))?;
            return Err((
                false,
                anyhow::anyhow!("download Hermez SRS: body exceeds expected {expected_size} bytes"),
            ));
        }
        file.write_all(&chunk).map_err(|error| {
            (
                false,
                anyhow::anyhow!("write {}: {error}", part_path.display()),
            )
        })?;
        downloaded = next_len;
        let percent = downloaded.saturating_mul(100) / expected_size;
        if percent >= last_percent.saturating_add(HERMEZ_SRS_PROGRESS_STEP_PERCENT)
            || downloaded == expected_size
        {
            eprintln!(
                "{}",
                hermez_srs_progress_line(attempt, downloaded, expected_size, effective_offset)
            );
            last_percent = percent;
        }
    }
    sync_hermez_srs_partial(&mut file).map_err(|error| (false, error))?;
    if downloaded != expected_size {
        return Err((
            true,
            anyhow::anyhow!(
                "download Hermez SRS: premature EOF at {downloaded} of {expected_size} bytes"
            ),
        ));
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn fetch_hermez_srs_with_retry(
    client: &reqwest::Client,
    url: &str,
    part_path: &std::path::Path,
    expected_size: u64,
) -> Result<()> {
    let mut range_restart_used = false;
    for attempt in 1..=HERMEZ_SRS_MAX_ATTEMPTS {
        match fetch_hermez_srs_attempt(
            client,
            url,
            part_path,
            expected_size,
            attempt,
            &mut range_restart_used,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err((false, error)) => return Err(error),
            Err((true, error)) if attempt == HERMEZ_SRS_MAX_ATTEMPTS => {
                return Err(anyhow::anyhow!(
                    "download Hermez SRS failed after {HERMEZ_SRS_MAX_ATTEMPTS} attempts: {error}; \
                     partial download kept at {}; rerun `dexdo note deploy` to resume",
                    part_path.display()
                ))
            }
            Err((true, error)) => {
                let delay = HERMEZ_SRS_RETRY_INITIAL_BACKOFF.saturating_mul(1 << (attempt - 1));
                eprintln!(
                    "note deploy: transient Hermez SRS download error on attempt \
                     {attempt}/{HERMEZ_SRS_MAX_ATTEMPTS}; retrying in {}s from partial {}: {error}",
                    delay.as_secs(),
                    part_path.display()
                );
                tokio::time::sleep(if cfg!(test) {
                    std::time::Duration::ZERO
                } else {
                    delay
                })
                .await;
            }
        }
    }
    unreachable!("bounded Hermez SRS download loop must return")
}

/// Mitigates for the `dexdo note deploy` path. Its deposit and SHELL voucher proof steps use the Hermez KZG
/// prover(`generate_proof` -> `Prover::new_with_srs_from_url`), whose cache miss performs blocking HTTP from
/// async proving and whose PK cache is not keyed to the SRS. The canonical SDK/prover async-and-SRS fix for
/// non-CLI callers is tracked separately.
#[cfg(feature = "shellnet")]
pub(crate) async fn ensure_hermez_srs_and_valid_pk_cache(
    prover_cache_dir: &std::path::Path,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(HERMEZ_SRS_HTTP_TIMEOUT)
        .build()
        .map_err(|e| anyhow::anyhow!("build Hermez SRS HTTP client: {e}"))?;
    ensure_hermez_srs_and_valid_pk_cache_with_options(
        prover_cache_dir,
        HERMEZ_SRS_SIZE_BYTES,
        HERMEZ_SRS_SHA256,
        move |part_path| async move {
            fetch_hermez_srs_with_retry(&client, HERMEZ_SRS_URL, &part_path, HERMEZ_SRS_SIZE_BYTES)
                .await
        },
        invalidate_stale_pk_cache,
    )
    .await
}

#[cfg(feature = "shellnet")]
async fn ensure_hermez_srs_and_valid_pk_cache_with_options<F, Fut, I>(
    prover_cache_dir: &std::path::Path,
    expected_size: u64,
    expected_sha256: &str,
    fetch: F,
    invalidate: I,
) -> Result<()>
where
    F: FnOnce(std::path::PathBuf) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
    I: FnOnce(&std::path::Path) -> Result<()>,
{
    std::fs::create_dir_all(prover_cache_dir).map_err(|e| {
        anyhow::anyhow!(
            "create prover cache dir {}: {e}",
            prover_cache_dir.display()
        )
    })?;
    let srs_path = prover_cache_dir.join(HERMEZ_SRS_NAME);
    if !hermez_srs_file_matches(&srs_path, expected_size, expected_sha256) {
        let part_path = prover_cache_dir.join(format!("{HERMEZ_SRS_NAME}.part"));
        let partial_size = std::fs::metadata(&part_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        eprintln!(
            "note deploy: fetching/resuming Hermez KZG SRS partial={} downloaded={} total={} \
             final={}",
            part_path.display(),
            partial_size,
            expected_size,
            srs_path.display(),
        );
        fetch(part_path.clone()).await?;
        publish_hermez_srs_part(&part_path, &srs_path, expected_size, expected_sha256)?;
    }

    // The final marker certifies a successful proof, not merely successful invalidation. A pending marker makes
    // interrupted non-atomic SDK keygen output fail closed on the next startup.
    let marker = prover_cache_dir.join(HERMEZ_SRS_MARKER_NAME);
    let pending = prover_cache_dir.join(HERMEZ_SRS_PENDING_MARKER_NAME);
    let cache_is_committed = marker_matches(&marker, expected_sha256)
        && !pending.exists()
        && prover_cache_artifacts_complete(prover_cache_dir);
    if !cache_is_committed {
        // Publish pending first: a crash at any later point causes the next pre-flight to invalidate again.
        write_file_atomically(&pending, expected_sha256.as_bytes(), "pending SRS marker")?;
        remove_file_if_exists(&marker, "committed SRS marker")?;
        invalidate(prover_cache_dir)?;
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn note_deploy_recovery_needs_new_proof(
    recovery: &crate::cli::note::NoteDeployRecoveryState,
) -> bool {
    use crate::cli::note::NoteDeployVoucherKind;

    if recovery.shell_funded && recovery.sanity_checked {
        return false;
    }
    let proof_is_persisted = |kind| {
        recovery
            .voucher_checkpoint(kind)
            .and_then(|checkpoint| checkpoint.proof.as_ref())
            .is_some()
    };
    let deposit_proof_needed =
        recovery.pn_address.is_none() && !proof_is_persisted(NoteDeployVoucherKind::Deposit);
    let shell_proof_needed =
        !recovery.shell_funded && !proof_is_persisted(NoteDeployVoucherKind::ShellGas);
    deposit_proof_needed || shell_proof_needed
}

#[cfg(feature = "shellnet")]
fn note_deploy_generation_mismatch(error: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "{}: {error:#}",
        crate::cli::machine::NOTE_DEPLOY_GENERATION_MISMATCH_MARKER
    )
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
trait NoteDeployResolvedOps {
    async fn preflight_doctor(&mut self) -> Result<()>;

    async fn load_recovery(&mut self) -> Result<crate::cli::note::NoteDeployRecoveryState>;

    async fn preflight_prover(&mut self) -> Result<()>;

    async fn resume_chain(
        &mut self,
        recovery: &mut crate::cli::note::NoteDeployRecoveryState,
    ) -> Result<crate::cli::note::OnboardPnState>;

    async fn finalize_pool(
        &mut self,
        recovery: &crate::cli::note::NoteDeployRecoveryState,
        state: &crate::cli::note::OnboardPnState,
    ) -> Result<()>;
}

#[cfg(feature = "shellnet")]
async fn run_note_deploy_resolved<O>(ops: &mut O) -> Result<()>
where
    O: NoteDeployResolvedOps,
{
    ops.preflight_doctor().await?;
    // After the read-only generation guard, recovery loading is the first stateful action. Cache/SRS work is
    // allowed only if the persisted state proves that this run can reach a new proof. Completed and
    // persisted-proof recoveries must remain able to finish chain recovery and pool finalization with a missing
    // or contended cache.
    let mut recovery = ops.load_recovery().await?;
    recovery.validate()?;
    if note_deploy_recovery_needs_new_proof(&recovery) {
        ops.preflight_prover().await?;
    }
    let state = ops.resume_chain(&mut recovery).await?;
    ops.finalize_pool(&recovery, &state).await
}

#[cfg(feature = "shellnet")]
struct NoteDeployProductionOps<'a> {
    args: &'a NoteDeployArgs,
    client: &'a dexdo_core::ChainClient,
    recovery_path: &'a std::path::Path,
    pool_path: &'a std::path::Path,
    funding_multisig_address: &'a str,
    recovery_request: crate::cli::note::NoteDeployRecoveryRequest<'a>,
    pn_keys: Option<dexdo_core::KeyPair>,
    halo2_paths: &'a dexdo_core::private_note::Halo2Paths,
    voucher_failpoints: NoteDeployVoucherFailpoints,
}

#[cfg(feature = "shellnet")]
#[derive(serde::Serialize)]
struct NoteDeployResult<'a> {
    schema: &'static str,
    status: &'static str,
    note_addr: &'a str,
    nominal: &'a str,
    token_type: u32,
    pool_path: String,
    note_count: usize,
    error: Option<&'a str>,
}

#[cfg(feature = "shellnet")]
fn note_deploy_json_result(
    note_addr: &str,
    nominal: &str,
    token_type: u32,
    pool_path: &std::path::Path,
    note_count: usize,
) -> Result<String> {
    Ok(serde_json::to_string(&NoteDeployResult {
        schema: crate::cli::machine::NOTE_DEPLOY_SCHEMA,
        status: "deployed",
        note_addr,
        nominal,
        token_type,
        pool_path: pool_path.display().to_string(),
        note_count,
        error: None,
    })?)
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
impl NoteDeployResolvedOps for NoteDeployProductionOps<'_> {
    async fn preflight_doctor(&mut self) -> Result<()> {
        shellnet_doctor_preflight_with_endpoint(
            &self.args.contracts,
            Some(self.recovery_request.endpoint),
            None,
        )
        .await
        .map_err(note_deploy_generation_mismatch)
    }

    async fn load_recovery(&mut self) -> Result<crate::cli::note::NoteDeployRecoveryState> {
        use crate::cli::note::{
            load_note_deploy_recovery, recovery_owner_key_written_message, NoteDeployRecoveryState,
        };

        let (recovery, already_persisted) = match load_note_deploy_recovery(self.recovery_path)? {
            Some(state) => {
                state.ensure_matches_request(self.recovery_request)?;
                eprintln!(
                    "note deploy recovery: using existing state file {}.",
                    self.recovery_path.display()
                );
                (state, true)
            }
            None => {
                let pn_keys = dexdo_core::KeyPair::generate();
                let state = NoteDeployRecoveryState::new(
                    self.recovery_request,
                    pn_keys.public_hex(),
                    pn_keys.secret_hex(),
                )?;
                // Keep a brand-new recovery in memory until the funding wallet passes the exact
                // UpdateCustodian/sole-custodian guard. The first voucher checkpoint persists the owner
                // key and checkpoint together before any signed BOC or wallet submit.
                (state, false)
            }
        };
        if already_persisted {
            eprintln!("{}", recovery_owner_key_written_message(self.recovery_path));
        }
        self.pn_keys = Some(
            dexdo_core::KeyPair::from_secret_hex(&recovery.owner_secret_key_hex)
                .map_err(|e| anyhow::anyhow!("note deploy recovery owner key: {e:?}"))?,
        );
        Ok(recovery)
    }

    async fn preflight_prover(&mut self) -> Result<()> {
        // This early check is allowed only after recovery routing says a new proof is still needed. It prevents
        // a fresh wallet spend from starting when proving cannot run, while funded/persisted-proof recovery never
        // waits for or mutates unrelated cache state.
        let _prover_cache_lock =
            acquire_note_deploy_prover_cache_lock(&self.halo2_paths.prover_cache_dir)?;
        self.halo2_paths.ensure_srs();
        ensure_hermez_srs_and_valid_pk_cache(&self.halo2_paths.prover_cache_dir).await
    }

    async fn resume_chain(
        &mut self,
        recovery: &mut crate::cli::note::NoteDeployRecoveryState,
    ) -> Result<crate::cli::note::OnboardPnState> {
        let pn_keys = self.pn_keys.as_ref().ok_or_else(|| {
            anyhow::anyhow!("note deploy recovery was not loaded before chain resume")
        })?;
        run_note_deploy_with_wallet_busy_retry(
            self.funding_multisig_address,
            async |_attempt| {
                let multisig_address = dexdo_core::Address::parse(self.funding_multisig_address)
                    .map_err(|e| anyhow::anyhow!("--multisig-address: {e}"))?;
                deploy_private_note_from_multisig_recoverable(
                    self.client,
                    self.recovery_path,
                    recovery,
                    &multisig_address,
                    self.args,
                    pn_keys,
                    self.halo2_paths,
                    self.voucher_failpoints,
                )
                .await
            },
            async |duration| tokio::time::sleep(duration).await,
        )
        .await
    }

    async fn finalize_pool(
        &mut self,
        recovery: &crate::cli::note::NoteDeployRecoveryState,
        state: &crate::cli::note::OnboardPnState,
    ) -> Result<()> {
        use crate::cli::note::{
            derive_owner_pubkey_from_secret_hex, ensure_onchain_owner_matches_pool_key,
            refresh_note_deploy_recovery_after_success,
        };
        use dexdo_core::{private_note::artifacts::PRIVATE_NOTE_ABI_JSON, Address};

        let note_addr = state
            .pn_address
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!("pn_state has no pn_address -- note deploy did not complete")
            })?
            .to_string();
        let owner_secret = state.owner_secret_key_hex.as_deref().ok_or_else(|| {
            anyhow::anyhow!("pn_state has no owner_secret_key_hex -- incomplete note deploy")
        })?;
        let derived_owner = derive_owner_pubkey_from_secret_hex(owner_secret)?;
        let note_address = Address::parse(&note_addr)
            .map_err(|e| anyhow::anyhow!("deployed note {note_addr}: {e}"))?;
        let details = self
            .client
            .run_getter(
                &note_address,
                PRIVATE_NOTE_ABI_JSON,
                "getDetails",
                serde_json::json!({}),
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!("verify deployed PrivateNote {note_addr} owner key: {e}")
            })?;
        ensure_onchain_owner_matches_pool_key(
            "note deploy",
            &note_addr,
            details.as_ref().and_then(|d| d["ephemeralPubkey"].as_str()),
            &derived_owner,
        )?;
        if self.args.simulate_interrupt_after_spend_before_pool {
            bail!(
                "simulated interruption after on-chain spend before final pool write. Recovery state is complete at {}; \
                 run `dexdo note recover --recovery {} --pool {}` to finalize without re-spending.",
                self.recovery_path.display(),
                self.recovery_path.display(),
                self.pool_path.display()
            );
        }

        let n =
            note_deploy_fold_state_into_pool(self.pool_path, state, self.funding_multisig_address)?;
        refresh_note_deploy_recovery_after_success(self.recovery_path, recovery).map_err(|e| {
            anyhow::anyhow!(
                "deployed PrivateNote {note_addr} is preserved in --pool {}, but the recovery file refresh was \
                 refused: {e}",
                self.pool_path.display()
            )
        })?;
        if self.args.json {
            println!(
                "{}",
                note_deploy_json_result(
                    &note_addr,
                    &state.nominal,
                    state.token_type,
                    self.pool_path,
                    n,
                )?
            );
        } else {
            println!(
                "note deployed -> PrivateNote {note_addr} ({} {}); folded into --pool {} ({} note(s)). Recovery state is \
                 at {}. The owner secret is stored in the pool for the seller/buyer -- keep both files private.",
                state.nominal,
                state.token_type,
                self.pool_path.display(),
                n,
                self.recovery_path.display()
            );
        }
        Ok(())
    }
}

/// `dexdo note deploy` -- deploy a wallet-funded `PrivateNote` on shellnet in-process through
/// `gosh.ackinacki`, then fold its result into a `DEXDO_PN_POOL` the `seller`/`buyer` consume. The wallet funding
/// secret is read from `--multisig-key` or derived from `--multisig-seed-file`, then passed directly to the SDK.
/// The seed phrase is never printed/logged/stored. The owner secret lands in the pool file(the consumers need it)
/// but is NEVER printed/logged.
#[cfg(feature = "shellnet")]
pub(crate) async fn run_note_deploy(args: NoteDeployArgs) -> Result<()> {
    use crate::cli::note::{
        default_note_deploy_recovery_path, resolve_private_file_path, NoteDeployRecoveryRequest,
    };
    use dexdo_core::{
        params::SHELL_CURRENCY_LABEL,
        private_note::{proof::ECC_SHELL_DEPOSIT_RAW, Halo2Paths, Nominal, TokenType},
        ChainClient,
    };

    if args.token_type != SHELL_CURRENCY_LABEL {
        anyhow::bail!(
            "note deploy: --token-type `{}` is unsupported; dexdo markets require `{SHELL_CURRENCY_LABEL}`",
            args.token_type
        );
    }
    let pool_path = resolve_private_file_path(&args.pool, "--pool")?;
    note_deploy_same_file_pool_guard(std::env::var_os("DEXDO_PN_POOL").as_deref(), &pool_path)?;
    validate_existing_pool_if_present(&pool_path)?;
    let funding_multisig_address = dexdo_core::normalize_wallet_address(&args.multisig_address)
        .map_err(|e| anyhow::anyhow!("--multisig-address: {e}"))?;
    let nominal = Nominal::parse(&args.nominal)?;
    let token_type = TokenType::parse(&args.token_type)?;
    let nominal_label = nominal.label().to_string();
    let token_type_label = token_type.label().to_string();
    let endpoint = note_endpoint_url(&args.endpoint)?;
    dexdo_core::shellnet_clock_skew_preflight(&endpoint).await?;
    let client = ChainClient::connect(&endpoint)?;
    let _wallet_lock = acquire_note_deploy_wallet_lock(&funding_multisig_address)?;
    let recovery_path = args
        .recovery
        .clone()
        .unwrap_or_else(|| default_note_deploy_recovery_path(&pool_path));
    let recovery_path = resolve_private_file_path(&recovery_path, "--recovery")?;
    note_deploy_recovery_pool_guard(&pool_path, &recovery_path)?;
    let recovery_request = NoteDeployRecoveryRequest {
        endpoint: &endpoint,
        nominal: &nominal_label,
        token_type: token_type.id(),
        raw_value: nominal.raw_value(token_type),
        ecc_shell_deposit: ECC_SHELL_DEPOSIT_RAW,
        funding_multisig_address: &funding_multisig_address,
    };
    let halo2_paths = Halo2Paths::from_env();

    eprintln!(
        "note deploy: in-process gosh.ackinacki -- wallet {} funds a {} {} PrivateNote on {} ...",
        funding_multisig_address, nominal_label, token_type_label, endpoint
    );
    let voucher_failpoints = NoteDeployVoucherFailpoints {
        before_voucher_event_wait: false,
        after_deposit_submit: args.simulate_interrupt_after_deposit_voucher_submit,
        after_deposit_event: args.simulate_interrupt_after_deposit_voucher_event,
        after_shell_submit: args.simulate_interrupt_after_shell_voucher_submit,
        after_deploy_before_note_record: args.simulate_interrupt_after_deploy_before_note_record,
    };
    let mut ops = NoteDeployProductionOps {
        args: &args,
        client: &client,
        recovery_path: &recovery_path,
        pool_path: &pool_path,
        funding_multisig_address: &funding_multisig_address,
        recovery_request,
        pn_keys: None,
        halo2_paths: &halo2_paths,
        voucher_failpoints,
    };
    run_note_deploy_resolved(&mut ops).await
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_note_deploy(_args: NoteDeployArgs) -> Result<()> {
    bail!("note deploy unavailable: build with `--features shellnet`")
}

/// `dexdo note balance`: address-only, read-only PrivateNote balance diagnostics.
#[cfg(feature = "shellnet")]
pub(crate) async fn run_note_balance(args: NoteBalanceArgs) -> Result<()> {
    use crate::cli::note::{
        build_note_balance_view, note_getter_balance_maps, render_note_balance,
        unknown_note_getter_balance_maps, NoteAccountSnapshot,
    };
    use dexdo_core::{Address, RealChainBackend};

    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let note = Address::parse(&args.note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {}: {e}", args.note_addr))?;
    let note_display = note.with_workchain();
    let chain = RealChainBackend::connect_with_endpoint(manifest, args.endpoint.as_deref())?;
    let account = chain
        .client()
        .get_account(&note)
        .await
        .map_err(|e| anyhow::anyhow!("read PrivateNote account {note_display}: {e}"))?;
    chain.assert_note_balance_private_note_account(&note, account.as_ref())?;
    let details = match chain.private_note_details(&note).await {
        Ok(details) => note_getter_balance_maps(details.as_ref()),
        Err(e) => unknown_note_getter_balance_maps(format!("getDetails error: {e}")),
    };
    let account = account.map(|a| NoteAccountSnapshot {
        address: a.address.with_workchain(),
        status: a.status,
        native_raw: a.balance,
        ecc: a.ecc,
        code_hash: a.code_hash,
    });
    let view = build_note_balance_view(&note_display, account, details)?;
    print!("{}", render_note_balance(&view));
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_note_balance(_args: NoteBalanceArgs) -> Result<()> {
    bail!("note balance unavailable: build with `--features shellnet`")
}

/// `dexdo note withdraw`: submit owner-signed `PrivateNote.withdrawTokens(destWalletAddr, dapp_id)` for a note's
/// available token balances. It is one-shot and not a blanket proof that every native/ECC balance is retired
/// without by-fact evidence on the current contract. `--to` accepts `half1::half2` or `0:<hex>`.
#[cfg(feature = "shellnet")]
pub(crate) async fn run_note_withdraw(args: NoteWithdrawArgs) -> Result<()> {
    use dexdo_core::{normalize_wallet_address, Address, KeyPair, RealChainBackend};
    let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-addr (the note to withdraw from) is required")
    })?;
    let note_key =
        args.identity.note_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("real shellnet: --note-key (note owner key) is required")
        })?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    // Normalize the destination before touching the chain.
    let dest = normalize_wallet_address(&args.to).map_err(|e| anyhow::anyhow!("--to: {e}"))?;
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let seed = read_secret_hex(note_key, "--note-key")?;
    let chain = RealChainBackend::connect(manifest)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note =
        Address::parse(&note_addr).map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let dest_addr = Address::parse(&dest).map_err(|e| anyhow::anyhow!("--to {dest}: {e}"))?;
    chain
        .assert_note_owner_matches("note withdraw", &note, &keys)
        .await?;
    // Fund-safety: a note from a previous contract generation accepts withdrawTokens,
    // zeroes its balance, but never credits the destination -- the SHELL is lost. Fail closed before
    // any on-chain write when the note's code_hash is not the current generation.
    chain.assert_note_withdraw_generation(&note).await?;
    println!("withdrawing note {note_addr} token balances -> {dest}");
    chain.withdraw_note_tokens(&note, &keys, &dest_addr).await?;
    println!("withdrawTokens submitted for note {note_addr} -> {dest}");
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_note_withdraw(_args: NoteWithdrawArgs) -> Result<()> {
    bail!("note withdraw unavailable: build with `--features shellnet`")
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shellnet")]
    use dexdo_core::params::{
        NOTE_DEPLOY_SUBMIT_NATIVE_VALUE, NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS,
        NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS, SHELL_CURRENCY_ID,
    };

    #[test]
    fn note_deploy_runtime_policy_is_owned_by_core_params() {
        let note_source = include_str!("note_cmd.rs");
        let note_production = note_source
            .split_once("#[cfg(test)]\nmod tests")
            .expect("note_cmd unit-test module boundary")
            .0;
        for name in [
            "NOTE_DEPLOY_LOCK_TIMEOUT_SECS",
            "NOTE_DEPLOY_WALLET_LOCK_POLL_INTERVAL",
            "NOTE_DEPLOY_PROVER_LOCK_POLL_INTERVAL",
            "NOTE_DEPLOY_SUBMIT_NATIVE_VALUE",
            "NOTE_DEPLOY_VOUCHER_EVENT_TIMEOUT",
            "NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS",
            "NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS",
            "NOTE_DEPLOY_ACTIVE_TIMEOUT",
            "NOTE_DEPLOY_EXISTING_SHELL_FUNDING_TIMEOUT",
            "NOTE_DEPLOY_SHELL_FUNDING_TIMEOUT",
            "NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL",
            "NOTE_DEPLOY_ACTIVE_POLL_INTERVAL",
            "HERMEZ_SRS_HASH_BUFFER_BYTES",
            "HERMEZ_SRS_PROGRESS_STEP_PERCENT",
            "HERMEZ_SRS_HTTP_TIMEOUT",
        ] {
            assert!(
                note_production.matches(name).count() >= 2,
                "note deploy must import and consume params::{name}"
            );
            assert!(
                !note_production.contains(&format!("const {name}")),
                "note deploy must not redeclare params::{name}"
            );
        }

        let support = include_str!("support.rs");
        for name in ["MIN_DEPLOY_SHELLS", "DEFAULT_DEPOSIT_SHELLS"] {
            assert!(
                support.matches(name).count() >= 2,
                "funding helpers must consume params::{name}"
            );
            assert!(
                !support.contains(&format!("pub(crate) const {name}")),
                "funding helpers must not redeclare params::{name}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn unsafe_clock_produces_zero_posts_in_note_deploy_direct_send() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for chain_offset in [60_i64, -300] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let posts = Arc::new(AtomicUsize::new(0));
            let server_posts = Arc::clone(&posts);
            let task = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = [0_u8; 8192];
                    let read = socket.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..read]);
                    if request.starts_with("POST /v2/messages ") {
                        server_posts.fetch_add(1, Ordering::SeqCst);
                    }
                    let local = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let chain = (local + chain_offset) as u64;
                    let body = serde_json::json!({"data":{"blockchain":{"blocks":{"edges":[{"node":{"gen_utime":chain}}]}}}}).to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let wallet = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64))).unwrap();
            let error = super::note_deploy_submit_voucher_boc(
                &endpoint,
                &wallet,
                "not-posted",
                &reqwest::Client::new(),
            )
            .await
            .unwrap_err();
            assert!(format!("{error:#}").contains("CLOCK_SKEW"));
            assert_eq!(
                posts.load(Ordering::SeqCst),
                0,
                "no message POST is permitted"
            );
            task.abort();
        }
    }

    #[cfg(feature = "shellnet")]
    fn invalid_existing_pool_cases() -> [(&'static str, serde_json::Value); 3] {
        [
            ("missing", serde_json::json!({"notes": []})),
            (
                "malformed",
                serde_json::json!({"token_type": "2", "notes": []}),
            ),
            (
                "non-shell",
                serde_json::json!({"token_type": 1, "notes": []}),
            ),
        ]
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_rejects_existing_bad_currency_before_network_or_wallet() {
        let temp = tempfile::tempdir().expect("temp dir");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind network trap");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());

        for (case, pool) in invalid_existing_pool_cases() {
            let pool_path = temp.path().join(format!("{case}.pool.json"));
            let original = serde_json::to_vec_pretty(&pool).unwrap();
            std::fs::write(&pool_path, &original).unwrap();
            let recovery_path = temp.path().join(format!("{case}.recovery.json"));
            let args = super::NoteDeployArgs {
                json: false,
                multisig_address: "not-a-wallet".to_string(),
                multisig_key: Some(temp.path().join("must-not-read.key")),
                multisig_seed_file: None,
                nominal: "N100".to_string(),
                token_type: dexdo_core::params::SHELL_CURRENCY_LABEL.to_string(),
                endpoint: endpoint.clone(),
                contracts: temp.path().join("must-not-read-contracts.json"),
                pool: pool_path.clone(),
                recovery: Some(recovery_path.clone()),
                simulate_interrupt_after_spend_before_pool: false,
                simulate_interrupt_after_deposit_voucher_submit: false,
                simulate_interrupt_after_deposit_voucher_event: false,
                simulate_interrupt_after_shell_voucher_submit: false,
                simulate_interrupt_after_deploy_before_note_record: false,
            };

            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                super::run_note_deploy(args),
            )
            .await
            .expect("pool currency rejection must not wait for network")
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("DEXDO_PN_POOL token_type"),
                "{case}: {error}"
            );
            assert!(
                error.contains(&format!("SHELL currency id {SHELL_CURRENCY_ID}")),
                "{case}: {error}"
            );
            assert_eq!(
                std::fs::read(&pool_path).unwrap(),
                original,
                "{case}: pool must remain unchanged"
            );
            assert!(
                !recovery_path.exists(),
                "{case}: recovery write means wallet work started"
            );
        }

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "invalid existing pools must produce zero network requests"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_recover_rejects_existing_bad_currency_before_getter() {
        let temp = tempfile::tempdir().expect("temp dir");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind network trap");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let recovery_path = temp.path().join("ready.recovery.json");
        let mut recovery = test_recovery_state();
        recovery.endpoint = endpoint;
        recovery
            .mark_private_note_deployed(format!("0:{}", "b".repeat(64)), "c".repeat(64), 1)
            .unwrap();
        recovery.mark_shell_funded_and_checked().unwrap();
        crate::cli::note::write_note_deploy_recovery(&recovery_path, &recovery).unwrap();
        let original_recovery = std::fs::read(&recovery_path).unwrap();

        for (case, pool) in invalid_existing_pool_cases() {
            let pool_path = temp.path().join(format!("{case}.recover.pool.json"));
            let original_pool = serde_json::to_vec_pretty(&pool).unwrap();
            std::fs::write(&pool_path, &original_pool).unwrap();

            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                super::run_note_recover(super::NoteRecoverArgs {
                    recovery: recovery_path.clone(),
                    pool: pool_path.clone(),
                }),
            )
            .await
            .expect("pool currency rejection must not wait for getter")
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("DEXDO_PN_POOL token_type"),
                "{case}: {error}"
            );
            assert!(
                error.contains(&format!("SHELL currency id {SHELL_CURRENCY_ID}")),
                "{case}: {error}"
            );
            assert_eq!(
                std::fs::read(&pool_path).unwrap(),
                original_pool,
                "{case}: pool must remain unchanged"
            );
            assert_eq!(
                std::fs::read(&recovery_path).unwrap(),
                original_recovery,
                "{case}: recovery must remain unconsumed"
            );
        }

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "invalid existing pools must produce zero getter requests"
        );
    }

    #[cfg(feature = "shellnet")]
    struct FixedFundingKeyLoader {
        secret_hex: Option<String>,
        failure: Option<&'static str>,
        calls: std::cell::Cell<usize>,
    }

    #[cfg(feature = "shellnet")]
    impl FixedFundingKeyLoader {
        fn returning(keys: &dexdo_core::KeyPair) -> Self {
            Self {
                secret_hex: Some(keys.secret_hex().to_string()),
                failure: None,
                calls: std::cell::Cell::new(0),
            }
        }

        fn failing(message: &'static str) -> Self {
            Self {
                secret_hex: None,
                failure: Some(message),
                calls: std::cell::Cell::new(0),
            }
        }
    }

    #[cfg(feature = "shellnet")]
    impl super::NoteDeployFundingKeyLoader for FixedFundingKeyLoader {
        fn load_funding_wallet_keys(&self) -> anyhow::Result<dexdo_core::KeyPair> {
            self.calls.set(self.calls.get() + 1);
            if let Some(message) = self.failure {
                anyhow::bail!("{message}");
            }
            dexdo_core::KeyPair::from_secret_hex(
                self.secret_hex
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("fixed key loader has no secret"))?,
            )
            .map_err(|error| anyhow::anyhow!("fixed funding key: {error:?}"))
        }
    }

    #[cfg(feature = "shellnet")]
    struct FixedFundingWalletReader {
        code_hash: Option<String>,
        custodians: Option<serde_json::Value>,
        required_txn_confirms: Option<u8>,
        ecc_balances: Option<Vec<(u32, u128)>>,
        failure: Option<&'static str>,
        code_hash_calls: std::cell::Cell<usize>,
        custodian_calls: std::cell::Cell<usize>,
        threshold_calls: std::cell::Cell<usize>,
    }

    #[cfg(feature = "shellnet")]
    impl FixedFundingWalletReader {
        fn returning(custodians: serde_json::Value) -> Self {
            Self::with_code_hash(dexdo_core::canonical_multisig::CODE_HASH, custodians)
        }

        fn with_code_hash(code_hash: &str, custodians: serde_json::Value) -> Self {
            Self {
                code_hash: Some(code_hash.to_string()),
                custodians: Some(custodians),
                required_txn_confirms: Some(1),
                ecc_balances: Some(vec![(1, u128::MAX), (2, u128::MAX)]),
                failure: None,
                code_hash_calls: std::cell::Cell::new(0),
                custodian_calls: std::cell::Cell::new(0),
                threshold_calls: std::cell::Cell::new(0),
            }
        }

        fn with_required_txn_confirms(mut self, required_txn_confirms: u8) -> Self {
            self.required_txn_confirms = Some(required_txn_confirms);
            self
        }

        fn with_balances(mut self, ecc_balances: Vec<(u32, u128)>) -> Self {
            self.ecc_balances = Some(ecc_balances);
            self
        }

        fn failing(message: &'static str) -> Self {
            Self {
                code_hash: None,
                custodians: None,
                required_txn_confirms: None,
                ecc_balances: None,
                failure: Some(message),
                code_hash_calls: std::cell::Cell::new(0),
                custodian_calls: std::cell::Cell::new(0),
                threshold_calls: std::cell::Cell::new(0),
            }
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait(?Send)]
    impl super::NoteDeployFundingWalletReader for FixedFundingWalletReader {
        async fn funding_wallet_code_hash(
            &self,
            _multisig_address: &dexdo_core::Address,
        ) -> anyhow::Result<String> {
            self.code_hash_calls.set(self.code_hash_calls.get() + 1);
            if let Some(message) = self.failure {
                anyhow::bail!("{message}");
            }
            self.code_hash
                .clone()
                .ok_or_else(|| anyhow::anyhow!("fixed wallet reader has no code hash"))
        }

        async fn funding_wallet_custodians(
            &self,
            _multisig_address: &dexdo_core::Address,
        ) -> anyhow::Result<serde_json::Value> {
            self.custodian_calls.set(self.custodian_calls.get() + 1);
            if let Some(message) = self.failure {
                anyhow::bail!("{message}");
            }
            self.custodians
                .clone()
                .ok_or_else(|| anyhow::anyhow!("fixed wallet reader has no custodians"))
        }

        async fn funding_wallet_required_txn_confirms(
            &self,
            _multisig_address: &dexdo_core::Address,
        ) -> anyhow::Result<u8> {
            self.threshold_calls.set(self.threshold_calls.get() + 1);
            if let Some(message) = self.failure {
                anyhow::bail!("{message}");
            }
            self.required_txn_confirms
                .ok_or_else(|| anyhow::anyhow!("fixed wallet reader has no transaction threshold"))
        }

        async fn funding_wallet_ecc_balances(
            &self,
            _multisig_address: &dexdo_core::Address,
        ) -> anyhow::Result<Vec<(u32, u128)>> {
            if let Some(message) = self.failure {
                anyhow::bail!("{message}");
            }
            self.ecc_balances
                .clone()
                .ok_or_else(|| anyhow::anyhow!("fixed wallet reader has no ECC balances"))
        }
    }

    #[cfg(feature = "shellnet")]
    #[derive(Default)]
    struct CountingVoucherBocBuilder {
        calls: std::cell::Cell<usize>,
        saw_nonempty_boc: std::cell::Cell<bool>,
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait(?Send)]
    impl super::NoteDeployVoucherBocBuilder for CountingVoucherBocBuilder {
        async fn build_voucher_submit_boc(
            &self,
            multisig_address: &dexdo_core::Address,
            multisig_keys: &dexdo_core::KeyPair,
            root_pn: &dexdo_core::Address,
            checkpoint: &crate::cli::note::NoteDeployVoucherCheckpoint,
        ) -> anyhow::Result<String> {
            self.calls.set(self.calls.get() + 1);
            let boc = super::note_deploy_build_voucher_submit_boc(
                multisig_address,
                multisig_keys,
                root_pn,
                checkpoint,
            )
            .await?;
            self.saw_nonempty_boc.set(!boc.is_empty());
            Ok(boc)
        }
    }

    #[cfg(feature = "shellnet")]
    struct CountingVoucherSubmitter {
        calls: std::cell::Cell<usize>,
        saw_nonempty_boc: std::cell::Cell<bool>,
        outcome: Result<Option<super::NoteDeployWalletActionReceipt>, &'static str>,
    }

    #[cfg(feature = "shellnet")]
    impl Default for CountingVoucherSubmitter {
        fn default() -> Self {
            Self::returning(Some(issue_678_receipt(false, 0)))
        }
    }

    #[cfg(feature = "shellnet")]
    impl CountingVoucherSubmitter {
        fn returning(receipt: Option<super::NoteDeployWalletActionReceipt>) -> Self {
            Self {
                calls: std::cell::Cell::new(0),
                saw_nonempty_boc: std::cell::Cell::new(false),
                outcome: Ok(receipt),
            }
        }

        fn failing(message: &'static str) -> Self {
            Self {
                outcome: Err(message),
                ..Self::returning(None)
            }
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait(?Send)]
    impl super::NoteDeployVoucherSubmitter for CountingVoucherSubmitter {
        async fn submit_voucher_boc(
            &self,
            _endpoint: &str,
            _multisig_address: &dexdo_core::Address,
            boc: &str,
            _http: &reqwest::Client,
        ) -> anyhow::Result<Option<super::NoteDeployWalletActionReceipt>> {
            self.calls.set(self.calls.get() + 1);
            self.saw_nonempty_boc.set(!boc.is_empty());
            self.outcome.clone().map_err(anyhow::Error::msg)
        }
    }

    #[cfg(feature = "shellnet")]
    fn preflight_fixture_keys() -> dexdo_core::KeyPair {
        dexdo_core::KeyPair::from_secret_hex(&"3a".repeat(32)).expect("fixture funding key")
    }

    #[cfg(feature = "shellnet")]
    fn issue_678_wallet_reader(ecc_balances: Vec<(u32, u128)>) -> FixedFundingWalletReader {
        let keys = preflight_fixture_keys();
        FixedFundingWalletReader::returning(serde_json::json!({
            "custodians": [{
                "index": "0",
                "owner_pubkey": format!("0x{}", keys.public_hex()),
            }]
        }))
        .with_balances(ecc_balances)
    }

    #[cfg(feature = "shellnet")]
    fn issue_678_receipt(
        aborted: bool,
        action_result_code: i64,
    ) -> super::NoteDeployWalletActionReceipt {
        super::NoteDeployWalletActionReceipt {
            transaction_hash: "issue-678-transaction".to_string(),
            compute_exit_code: Some(0),
            aborted,
            action_result_code,
            outmsg_count: 0,
            wallet_ecc_balances: Some(vec![(SHELL_CURRENCY_ID, 200_000_000_000)]),
        }
    }

    #[cfg(feature = "shellnet")]
    async fn run_issue_678_deposit(
        recovery_path: &std::path::Path,
        recovery: &mut crate::cli::note::NoteDeployRecoveryState,
        wallet_reader: &FixedFundingWalletReader,
        submitter: &CountingVoucherSubmitter,
        failpoints: super::NoteDeployVoucherFailpoints,
    ) -> anyhow::Result<dexdo_core::private_note::halo2::live::Halo2Proof> {
        use crate::cli::note::NoteDeployVoucherKind;

        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")?;
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))?;
        let key_loader = FixedFundingKeyLoader::returning(&preflight_fixture_keys());
        let boc_builder = CountingVoucherBocBuilder::default();
        let owner = recovery.owner_public_key_hex.clone();
        let token_type = recovery.token_type;
        let raw_value = recovery.raw_value;
        super::note_deploy_mint_voucher_recoverable(
            &client,
            recovery_path,
            recovery,
            NoteDeployVoucherKind::Deposit,
            &multisig_address,
            &key_loader,
            wallet_reader,
            &boc_builder,
            submitter,
            &owner,
            token_type,
            raw_value,
            false,
            &dexdo_core::private_note::Halo2Paths::from_env(),
            failpoints,
        )
        .await
    }

    #[cfg(feature = "shellnet")]
    async fn run_preflight_with_fixed_custodians(
        custodians: serde_json::Value,
    ) -> anyhow::Result<()> {
        let wallet = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let keys = preflight_fixture_keys();
        let reader = FixedFundingWalletReader::returning(custodians);
        let result = super::note_deploy_preflight_key_owns_wallet(&reader, &wallet, &keys).await;
        assert_eq!(
            reader.code_hash_calls.get(),
            1,
            "pre-flight must read the funding-wallet code hash exactly once"
        );
        assert_eq!(
            reader.custodian_calls.get(),
            1,
            "pre-flight must read getCustodians exactly once"
        );
        result
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_preflight_rejects_zero_pubkey_custodians() {
        let error = run_preflight_with_fixed_custodians(serde_json::json!({
            "custodians": [{
                "index": "0",
                "owner_pubkey": null,
                "owner_address": format!("0:{}", "b".repeat(64)),
            }]
        }))
        .await
        .expect_err("an address-only custodian cannot authorize a pubkey-signed submit")
        .to_string();
        assert!(error.contains("zero pubkey custodians"), "{error}");
        assert!(error.contains("matching pubkey custodian"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_preflight_accepts_matching_multi_custodian_hot() {
        let keys = preflight_fixture_keys();
        run_preflight_with_fixed_custodians(serde_json::json!({
            "custodians": [
                {
                    "index": "0",
                    "owner_pubkey": format!("0x{}", keys.public_hex()),
                },
                {
                    "index": "1",
                    "owner_pubkey": format!("0x{}", "11".repeat(32)),
                }
            ]
        }))
        .await
        .expect("a matching custodian with reqConfirms=1 must pass");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_preflight_rejects_key_absent_from_custodians() {
        let error = run_preflight_with_fixed_custodians(serde_json::json!({
            "custodians": [{
                "index": "0",
                "owner_pubkey": format!("0x{}", "11".repeat(32)),
            }]
        }))
        .await
        .expect_err("a funding key absent from custodians must fail closed")
        .to_string();
        assert!(error.contains("is not a custodian"), "{error}");
        assert!(error.contains("no wallet message was submitted"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_preflight_accepts_matching_sole_custodian() {
        let keys = preflight_fixture_keys();
        run_preflight_with_fixed_custodians(serde_json::json!({
            "custodians": [{
                "index": "0",
                "owner_pubkey": format!("0X{}", keys.public_hex().to_ascii_uppercase()),
            }]
        }))
        .await
        .expect("the matching sole pubkey custodian must pass");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_issue_678_ecc_preflight_stops_exact_shortfalls_before_post() {
        let temp = tempfile::tempdir().expect("temp dir");
        let wallet = format!("0:{}", "a".repeat(64));
        let raw = 100_000_000_000u128;
        for (case, balances, currency, available, required) in [(
            "combined-ecc-2",
            vec![(SHELL_CURRENCY_ID, raw * 2 - 1)],
            "requested token and SHELL ECC[2]",
            raw * 2 - 1,
            raw * 2,
        )] {
            let mut recovery = test_recovery_state();
            let reader = issue_678_wallet_reader(balances);
            let submitter = CountingVoucherSubmitter::default();
            let recovery_path = temp.path().join(format!("{case}.json"));

            let error = run_issue_678_deposit(
                &recovery_path,
                &mut recovery,
                &reader,
                &submitter,
                Default::default(),
            )
            .await
            .expect_err("insufficient ECC must fail before wallet POST")
            .to_string();

            assert_eq!(
                error,
                format!(
                    "funding wallet {wallet} has insufficient {currency}: available={} raw, \
                     required={required} raw, missing=1 raw; no wallet POST was submitted. Fund \
                     {currency} and retry the same `dexdo note deploy --recovery` command.",
                    available
                ),
                "{case}"
            );
            assert_eq!(submitter.calls.get(), 0, "{case}");
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_get_custodians_none_or_empty_reports_abi_output_error() {
        let wallet = format!("0:{}", "a".repeat(64));
        for output in [None, Some(serde_json::json!({}))] {
            let error = super::require_get_custodians_output(&wallet, output)
                .expect_err("None/empty getter output must fail as an ABI/getter diagnostic")
                .to_string();
            assert!(error.contains("is Active"), "{error}");
            assert!(error.contains("getCustodians"), "{error}");
            assert!(error.contains("no custodians output"), "{error}");
            assert!(!error.contains("is not Active"), "{error}");
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_update_custodian_v2_is_the_only_wallet_canon() {
        let abi: serde_json::Value =
            serde_json::from_str(dexdo_core::canonical_multisig::MULTISIG_ABI_JSON)
                .expect("parse canonical UpdateCustodianMultisigWallet_v2 ABI");
        let functions = abi["functions"].as_array().expect("ABI functions");
        let submit_transaction = functions
            .iter()
            .find(|function| function["name"] == "submitTransaction")
            .expect("canonical submitTransaction function");
        assert_eq!(
            submit_transaction["inputs"],
            serde_json::json!([
                { "name": "dest", "type": "address" },
                { "name": "value", "type": "uint128" },
                { "name": "cc", "type": "map(uint32,varuint32)" },
                { "name": "bounce", "type": "bool" },
                { "name": "flag", "type": "uint8" },
                { "name": "payload", "type": "cell" },
                { "name": "dapp_id", "type": "uint256" }
            ]),
            "canonical UpdateCustodianMultisigWallet_v2 submitTransaction shape"
        );
        let get_custodians = functions
            .iter()
            .find(|function| function["name"] == "getCustodians")
            .expect("canonical getCustodians function");
        assert_eq!(get_custodians["inputs"], serde_json::json!([]));
        assert_eq!(
            get_custodians["outputs"],
            serde_json::json!([{
                "name": "custodians",
                "type": "tuple[]",
                "components": [
                    { "name": "owner_pubkey", "type": "optional(uint256)" },
                    { "name": "owner_address", "type": "optional(address)" },
                    { "name": "index", "type": "uint8" }
                ]
            }]),
            "SDK canonical getCustodians getter shape"
        );
        let root_pn = dexdo_core::Address::parse(&format!("0:{}", "b".repeat(64)))
            .expect("parse RootPN fixture");
        let get_parameters = functions
            .iter()
            .find(|function| function["name"] == "getParameters")
            .expect("canonical getParameters function");
        assert_eq!(get_parameters["inputs"], serde_json::json!([]));
        assert!(get_parameters["outputs"]
            .as_array()
            .expect("getParameters outputs")
            .iter()
            .any(|output| output["name"] == "requiredTxnConfirms"));
        let params = super::note_deploy_update_custodian_submit_transaction_params(
            &root_pn,
            serde_json::Map::new(),
            "fixture-body".to_string(),
        );
        let fields = params.as_object().expect("wallet-forward params object");
        assert_eq!(
            fields.len(),
            7,
            "UpdateCustodianMultisigWallet_v2 submitTransaction has seven inputs"
        );
        assert_eq!(fields["flag"], 1);
        assert_eq!(fields["value"], NOTE_DEPLOY_SUBMIT_NATIVE_VALUE.to_string());
        assert!(!fields.contains_key("flags"));
        assert_eq!(
            fields["dapp_id"], "4",
            "RootPN wallet forward must carry the canonical system dapp_id"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_get_parameters_requires_exact_transaction_threshold() {
        let wallet = format!("0:{}", "a".repeat(64));
        for value in [serde_json::json!(1), serde_json::json!("1")] {
            assert_eq!(
                super::require_get_parameters_output(
                    &wallet,
                    Some(serde_json::json!({ "requiredTxnConfirms": value }))
                )
                .expect("numeric or ABI-string threshold"),
                1
            );
        }
        for output in [
            None,
            Some(serde_json::json!({})),
            Some(serde_json::json!({ "requiredTxnConfirms": "bad" })),
            Some(serde_json::json!({ "requiredTxnConfirms": 256 })),
        ] {
            let error = super::require_get_parameters_output(&wallet, output)
                .expect_err("missing or invalid threshold must fail closed")
                .to_string();
            assert!(error.contains("getParameters") || error.contains("requiredTxnConfirms"));
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_accepts_only_update_custodian_v2_code_hash() {
        super::ensure_note_deploy_update_custodian_code_hash(&format!(
            "0X{}",
            dexdo_core::canonical_multisig::CODE_HASH.to_ascii_uppercase()
        ))
        .expect("canonical UpdateCustodianMultisigWallet_v2 hash");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_rejects_every_obsolete_or_unknown_wallet_code_hash() {
        for (case, wallet_family, code_hash) in [
            (
                "old UpdateCustodianMultisigWallet",
                "unknown",
                "8470e1da28a2b4c742b5f7edefdd97db81c79e726f8a8b0be78d921adaf32414",
            ),
            (
                "old managed UpdateCustodianMultisigWallet",
                "unknown",
                "f2f4e7171bfbf21493dec3f5ad93b61813d46ada75d4bc1ab6bd7be60192c571",
            ),
            (
                "candidate v2.1.0 UpdateCustodianMultisigWallet",
                "unknown",
                "31e402bb4fc2bb740634ab00b074f2e4ae772f0744d8aabb7c51d44f430d86e3",
            ),
            (
                "generic Multisig",
                "generic Multisig",
                super::NOTE_DEPLOY_GENERIC_MULTISIG_CODE_HASH,
            ),
            (
                "unknown",
                "unknown",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let error = super::ensure_note_deploy_update_custodian_code_hash(code_hash)
                .expect_err(case)
                .to_string();
            assert!(error.contains(code_hash), "{case}: {error}");
            assert!(
                error.contains(&format!("family {wallet_family}")),
                "{case}: {error}"
            );
            assert!(
                error.contains(dexdo_core::canonical_multisig::CONTRACT_NAME),
                "{case}: {error}"
            );
            assert!(
                error.contains(dexdo_core::canonical_multisig::CODE_HASH),
                "{case}: {error}"
            );
            assert!(
                error.contains(
                    "preflight rejected before submit; no transaction was submitted and no funds moved"
                ),
                "{case}: {error}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_missing_recovery_remains_in_memory_before_wallet_preflight() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recovery_path = temp.path().join("fresh.recovery.json");
        let pool_path = temp.path().join("fresh.pool.json");
        let key_path = temp.path().join("funding.secret.hex");
        let funding_wallet = format!("0:{}", "a".repeat(64));
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let halo2_paths = dexdo_core::private_note::Halo2Paths::from_env();
        let args = super::NoteDeployArgs {
            json: false,
            multisig_address: funding_wallet.clone(),
            multisig_key: Some(key_path),
            multisig_seed_file: None,
            nominal: "N100".to_string(),
            token_type: "shell".to_string(),
            endpoint: "http://127.0.0.1:9".to_string(),
            contracts: std::path::PathBuf::from("contracts/deployed.shellnet.json"),
            pool: pool_path.clone(),
            recovery: Some(recovery_path.clone()),
            simulate_interrupt_after_spend_before_pool: false,
            simulate_interrupt_after_deposit_voucher_submit: false,
            simulate_interrupt_after_deposit_voucher_event: false,
            simulate_interrupt_after_shell_voucher_submit: false,
            simulate_interrupt_after_deploy_before_note_record: false,
        };
        let recovery_request = crate::cli::note::NoteDeployRecoveryRequest {
            endpoint: "http://127.0.0.1:9",
            nominal: "N100",
            token_type: dexdo_core::params::SHELL_CURRENCY_ID,
            raw_value: 100_000_000_000,
            ecc_shell_deposit: 100_000_000_000,
            funding_multisig_address: &funding_wallet,
        };
        let mut ops = super::NoteDeployProductionOps {
            args: &args,
            client: &client,
            recovery_path: &recovery_path,
            pool_path: &pool_path,
            funding_multisig_address: &funding_wallet,
            recovery_request,
            pn_keys: None,
            halo2_paths: &halo2_paths,
            voucher_failpoints: Default::default(),
        };

        let recovery = super::NoteDeployResolvedOps::load_recovery(&mut ops)
            .await
            .expect("create fresh recovery in memory");
        assert!(
            ops.pn_keys.is_some(),
            "fresh owner key must remain available in memory"
        );
        assert!(recovery.deposit_voucher.is_none());
        assert!(recovery.shell_voucher.is_none());
        assert!(
            !recovery_path.exists(),
            "fresh journal must wait for wallet preflight"
        );
        assert!(!pool_path.exists(), "fresh pool must not exist");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_fresh_path_rejects_non_custodian_or_vault_before_submit() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let multisig_keys =
            dexdo_core::KeyPair::from_secret_hex(&"3a".repeat(32)).expect("fixture funding key");
        let halo2_paths = dexdo_core::private_note::Halo2Paths::from_env();
        let cases = [
            (
                "key-absent",
                serde_json::json!({
                    "custodians": [{
                        "index": "0",
                        "owner_pubkey": format!("0x{}", "11".repeat(32)),
                    }]
                }),
                1,
                "is not a custodian",
            ),
            (
                "key-absent-multi",
                serde_json::json!({
                    "custodians": [
                        {
                            "index": "0",
                            "owner_pubkey": format!("0x{}", "11".repeat(32)),
                        },
                        {
                            "index": "1",
                            "owner_pubkey": format!("0x{}", "22".repeat(32)),
                        }
                    ]
                }),
                1,
                "is not a custodian",
            ),
            (
                "vault",
                serde_json::json!({
                    "custodians": [
                        {
                            "index": "0",
                            "owner_pubkey": format!("0x{}", multisig_keys.public_hex()),
                        },
                        {
                            "index": "1",
                            "owner_pubkey": format!("0x{}", "11".repeat(32)),
                        }
                    ]
                }),
                2,
                "first confirm the Vault -> Hot transfer manually",
            ),
        ];

        for (case, custodians, required_txn_confirms, expected_error) in cases {
            let key_loader = FixedFundingKeyLoader::returning(&multisig_keys);
            let wallet_reader = FixedFundingWalletReader::returning(custodians)
                .with_required_txn_confirms(required_txn_confirms);
            let boc_builder = CountingVoucherBocBuilder::default();
            let submitter = CountingVoucherSubmitter::default();
            let mut recovery = test_recovery_state();
            let owner = recovery.owner_public_key_hex.clone();
            let token_type = recovery.token_type;
            let raw_value = recovery.raw_value;
            let recovery_path = temp.path().join(format!("{case}.recovery.json"));

            let error = super::note_deploy_mint_voucher_recoverable(
                &client,
                &recovery_path,
                &mut recovery,
                NoteDeployVoucherKind::Deposit,
                &multisig_address,
                &key_loader,
                &wallet_reader,
                &boc_builder,
                &submitter,
                &owner,
                token_type,
                raw_value,
                false,
                &halo2_paths,
                Default::default(),
            )
            .await
            .expect_err("the real fresh path must reject an absent key or Vault")
            .to_string();

            assert!(error.contains(expected_error), "{case}: {error}");
            assert_eq!(key_loader.calls.get(), 1, "{case}");
            assert_eq!(wallet_reader.code_hash_calls.get(), 1, "{case}");
            assert_eq!(wallet_reader.custodian_calls.get(), 1, "{case}");
            assert_eq!(
                wallet_reader.threshold_calls.get(),
                usize::from(case == "vault"),
                "{case}"
            );
            assert_eq!(
                boc_builder.calls.get(),
                0,
                "{case}: rejected wallet must not create a signed wallet BOC"
            );
            assert_eq!(
                submitter.calls.get(),
                0,
                "{case}: rejected wallet must create zero wallet transactions"
            );
            assert!(
                recovery
                    .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                    .is_none(),
                "{case}: rejection must precede checkpoint creation"
            );
            assert!(
                !recovery_path.exists(),
                "{case}: rejection must precede journal creation"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_fresh_path_rejects_non_v2_wallets_before_all_artifacts_and_submit() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let multisig_keys =
            dexdo_core::KeyPair::from_secret_hex(&"3a".repeat(32)).expect("fixture funding key");
        let halo2_paths = dexdo_core::private_note::Halo2Paths::from_env();
        for (case, wallet_family, code_hash) in [
            (
                "old-update-custodian",
                "unknown",
                "8470e1da28a2b4c742b5f7edefdd97db81c79e726f8a8b0be78d921adaf32414",
            ),
            (
                "old-managed-update-custodian",
                "unknown",
                "f2f4e7171bfbf21493dec3f5ad93b61813d46ada75d4bc1ab6bd7be60192c571",
            ),
            (
                "candidate-v2.1.0",
                "unknown",
                "31e402bb4fc2bb740634ab00b074f2e4ae772f0744d8aabb7c51d44f430d86e3",
            ),
            (
                "generic-multisig",
                "generic Multisig",
                super::NOTE_DEPLOY_GENERIC_MULTISIG_CODE_HASH,
            ),
        ] {
            let wallet_reader = FixedFundingWalletReader::with_code_hash(
                code_hash,
                serde_json::json!({
                    "custodians": [{
                        "index": "0",
                        "owner_pubkey": format!("0x{}", multisig_keys.public_hex()),
                    }]
                }),
            );
            let key_loader = FixedFundingKeyLoader::returning(&multisig_keys);
            let boc_builder = CountingVoucherBocBuilder::default();
            let submitter = CountingVoucherSubmitter::default();
            let mut recovery = test_recovery_state();
            let owner = recovery.owner_public_key_hex.clone();
            let owner_secret = recovery.owner_secret_key_hex.to_string();
            let token_type = recovery.token_type;
            let raw_value = recovery.raw_value;
            let recovery_path = temp.path().join(format!("{case}-recovery.json"));

            let error = super::note_deploy_mint_voucher_recoverable(
                &client,
                &recovery_path,
                &mut recovery,
                NoteDeployVoucherKind::Deposit,
                &multisig_address,
                &key_loader,
                &wallet_reader,
                &boc_builder,
                &submitter,
                &owner,
                token_type,
                raw_value,
                false,
                &halo2_paths,
                Default::default(),
            )
            .await
            .expect_err("every non-v2 funding wallet must fail closed")
            .to_string();

            assert!(error.contains(code_hash), "{case}: {error}");
            assert!(
                error.contains(&format!("family {wallet_family}")),
                "{case}: {error}"
            );
            assert!(
                error.contains(dexdo_core::canonical_multisig::CONTRACT_NAME),
                "{case}: {error}"
            );
            assert!(
                error.contains(
                    "preflight rejected before submit; no transaction was submitted and no funds moved"
                ),
                "{case}: {error}"
            );
            assert!(
                !error.contains(multisig_keys.secret_hex()),
                "{case}: funding secret leaked: {error}"
            );
            assert!(
                !error.contains(&owner_secret),
                "{case}: note owner secret leaked: {error}"
            );
            assert_eq!(key_loader.calls.get(), 1, "{case}");
            assert_eq!(wallet_reader.code_hash_calls.get(), 1, "{case}");
            assert_eq!(
                wallet_reader.custodian_calls.get(),
                0,
                "{case}: unsupported code must stop before getter"
            );
            assert_eq!(wallet_reader.threshold_calls.get(), 0, "{case}");
            assert_eq!(boc_builder.calls.get(), 0, "{case}");
            assert_eq!(submitter.calls.get(), 0, "{case}");
            assert!(
                recovery
                    .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                    .is_none(),
                "{case}"
            );
            assert!(!recovery_path.exists(), "{case}");
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_issue_678_action_38_persists_no_effect_and_funded_recovery_posts_once() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let recovery_path = temp.path().join("action-38-recovery.json");
        let raw = 100_000_000_000u128;
        let reader = issue_678_wallet_reader(vec![(SHELL_CURRENCY_ID, raw * 2)]);
        let failed_submitter =
            CountingVoucherSubmitter::returning(Some(issue_678_receipt(true, 38)));
        let failpoints = super::NoteDeployVoucherFailpoints {
            before_voucher_event_wait: true,
            ..Default::default()
        };
        let mut recovery = test_recovery_state();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_issue_678_deposit(
                &recovery_path,
                &mut recovery,
                &reader,
                &failed_submitter,
                failpoints,
            ),
        )
        .await
        .expect("definitive action failure must not enter the 480s VoucherGenerated wait")
        .expect_err("aborted action result 38 must fail")
        .to_string();

        for fact in [
            "deposit voucher transaction",
            "compute_exit_code=0",
            "aborted=true",
            "action_result_code=38 (NOT_ENOUGH_EXTRA)",
            "exact wallet action produced zero outbound messages",
            "required ECC unchanged",
            "Fund requested token and SHELL ECC[2]",
        ] {
            assert!(error.contains(fact), "missing {fact}: {error}");
        }
        assert!(!error.contains("simulated interruption"), "{error}");
        assert_eq!(failed_submitter.calls.get(), 1);

        let failed = recovery
            .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
            .expect("failed checkpoint");
        assert!(!failed.submit_maybe_sent);
        let deterministic_identity = (
            failed.sk_u_hex.to_string(),
            failed.sk_u_commit_hex.clone(),
            failed.recipient_ephemeral_pubkey_hex.clone(),
        );

        let mut recovery = crate::cli::note::load_note_deploy_recovery(&recovery_path)
            .expect("reload finalized failure")
            .expect("persisted recovery");
        let funded_reader = issue_678_wallet_reader(vec![(SHELL_CURRENCY_ID, u128::MAX)]);
        let successful_submitter = CountingVoucherSubmitter::default();
        let resumed_error = run_issue_678_deposit(
            &recovery_path,
            &mut recovery,
            &funded_reader,
            &successful_submitter,
            failpoints,
        )
        .await
        .expect_err("fixture stops at the existing VoucherGenerated wait boundary")
        .to_string();

        assert!(
            resumed_error.contains("simulated interruption before voucher event wait"),
            "{resumed_error}"
        );
        assert_eq!(successful_submitter.calls.get(), 1);
        let resumed = recovery
            .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
            .expect("resumed checkpoint");
        assert!(resumed.submit_maybe_sent);
        assert_eq!(
            (
                resumed.sk_u_hex.to_string(),
                resumed.sk_u_commit_hex.clone(),
                resumed.recipient_ephemeral_pubkey_hex.clone(),
            ),
            deterministic_identity
        );
    }

    #[cfg(feature = "shellnet")]
    /// the established passed-in multisig path still reaches the signed wallet submit seam.
    #[tokio::test]
    async fn note_deploy_unsubmitted_checkpoint_rejects_generic_wallet_before_first_submit() {
        use crate::cli::note::{NoteDeployVoucherCheckpoint, NoteDeployVoucherKind};

        let temp = tempfile::tempdir().expect("temp dir");
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let multisig_keys = preflight_fixture_keys();
        let key_loader = FixedFundingKeyLoader::returning(&multisig_keys);
        let wallet_reader = FixedFundingWalletReader::with_code_hash(
            super::NOTE_DEPLOY_GENERIC_MULTISIG_CODE_HASH,
            serde_json::json!({
                "custodians": [{
                    "index": "0",
                    "owner_pubkey": format!("0x{}", multisig_keys.public_hex()),
                }]
            }),
        );
        let boc_builder = CountingVoucherBocBuilder::default();
        let submitter = CountingVoucherSubmitter::default();
        let halo2_paths = dexdo_core::private_note::Halo2Paths::from_env();

        let mut recovery = test_recovery_state();
        let owner = recovery.owner_public_key_hex.clone();
        let token_type = recovery.token_type;
        let raw_value = recovery.raw_value;
        let checkpoint = NoteDeployVoucherCheckpoint::new(
            &owner,
            token_type,
            raw_value,
            false,
            "b".repeat(64),
            "c".repeat(64),
        )
        .expect("fixture unsubmitted checkpoint");
        assert!(!checkpoint.submit_maybe_sent);
        recovery
            .set_voucher_checkpoint(NoteDeployVoucherKind::Deposit, checkpoint)
            .expect("persist unsubmitted checkpoint");
        let recovery_path = temp.path().join("unsubmitted-recovery.json");
        crate::cli::note::write_note_deploy_recovery(&recovery_path, &recovery)
            .expect("write unsubmitted recovery");
        let before = std::fs::read(&recovery_path).expect("read recovery before preflight");

        let error = super::note_deploy_mint_voucher_recoverable(
            &client,
            &recovery_path,
            &mut recovery,
            NoteDeployVoucherKind::Deposit,
            &multisig_address,
            &key_loader,
            &wallet_reader,
            &boc_builder,
            &submitter,
            &owner,
            token_type,
            raw_value,
            false,
            &halo2_paths,
            Default::default(),
        )
        .await
        .expect_err("Generic funding wallet must fail before the first submit")
        .to_string();

        assert!(error.contains("family generic Multisig"), "{error}");
        assert!(
            error.contains(
                "preflight rejected before submit; no transaction was submitted and no funds moved"
            ),
            "{error}"
        );
        assert!(!error.contains(multisig_keys.secret_hex()), "{error}");
        assert!(
            !error.contains(recovery.owner_secret_key_hex.as_str()),
            "{error}"
        );
        assert!(
            !error.contains(
                recovery
                    .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                    .expect("persisted unsubmitted checkpoint")
                    .sk_u_hex
                    .as_str()
            ),
            "{error}"
        );
        assert_eq!(key_loader.calls.get(), 1);
        assert_eq!(wallet_reader.code_hash_calls.get(), 1);
        assert_eq!(
            wallet_reader.custodian_calls.get(),
            0,
            "unsupported code must stop before getter"
        );
        assert_eq!(
            boc_builder.calls.get(),
            0,
            "unsupported wallet must not build a voucher BOC"
        );
        assert_eq!(
            submitter.calls.get(),
            0,
            "unsupported wallet must not submit a voucher BOC"
        );
        assert!(
            !recovery
                .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                .expect("persisted unsubmitted checkpoint")
                .submit_maybe_sent,
            "preflight rejection must not mark submit_maybe_sent"
        );
        assert_eq!(
            std::fs::read(&recovery_path).expect("read recovery after preflight"),
            before,
            "preflight rejection must not write a wallet spend checkpoint"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_multi_custodian_hot_waits_for_downstream_voucher_result() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let multisig_keys = preflight_fixture_keys();
        let wallet_reader = FixedFundingWalletReader::returning(serde_json::json!({
            "custodians": [
                {
                    "index": "0",
                    "owner_pubkey": format!("0x{}", "11".repeat(32)),
                },
                {
                    "index": "1",
                    "owner_pubkey": format!("0x{}", multisig_keys.public_hex()),
                }
            ]
        }));
        let key_loader = FixedFundingKeyLoader::returning(&multisig_keys);
        let boc_builder = CountingVoucherBocBuilder::default();
        let submitter = CountingVoucherSubmitter::default();
        let halo2_paths = dexdo_core::private_note::Halo2Paths::from_env();
        let failpoints = super::NoteDeployVoucherFailpoints {
            before_voucher_event_wait: true,
            ..Default::default()
        };
        let mut recovery = test_recovery_state();
        let owner = recovery.owner_public_key_hex.clone();
        let token_type = recovery.token_type;
        let raw_value = recovery.raw_value;
        let recovery_path = temp.path().join("matching-custodian-recovery.json");

        let error = super::note_deploy_mint_voucher_recoverable(
            &client,
            &recovery_path,
            &mut recovery,
            NoteDeployVoucherKind::Deposit,
            &multisig_address,
            &key_loader,
            &wallet_reader,
            &boc_builder,
            &submitter,
            &owner,
            token_type,
            raw_value,
            false,
            &halo2_paths,
            failpoints,
        )
        .await
        .expect_err("fixture stops at the downstream VoucherGenerated wait boundary")
        .to_string();

        assert!(
            error.contains("simulated interruption before voucher event wait"),
            "{error}"
        );
        assert_eq!(key_loader.calls.get(), 1);
        assert_eq!(wallet_reader.code_hash_calls.get(), 1);
        assert_eq!(wallet_reader.custodian_calls.get(), 1);
        assert_eq!(wallet_reader.threshold_calls.get(), 1);
        assert_eq!(boc_builder.calls.get(), 1);
        assert!(
            boc_builder.saw_nonempty_boc.get(),
            "matching Hot custodian must produce a signed BOC"
        );
        assert_eq!(
            submitter.calls.get(),
            1,
            "matching Hot custodian must reach wallet submit"
        );
        assert!(
            submitter.saw_nonempty_boc.get(),
            "submit seam must receive a signed BOC"
        );
        assert!(
            recovery_path.exists(),
            "guarded checkpoint must be durable before submit"
        );
        assert!(
            recovery
                .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                .expect("guarded checkpoint")
                .submit_maybe_sent,
            "submit intent must be durable before transport"
        );
    }

    #[cfg(feature = "shellnet")]
    async fn assert_issue_678_restart_never_posts(recovery_path: &std::path::Path) {
        use crate::cli::note::NoteDeployVoucherKind;

        let before = std::fs::read(recovery_path).expect("read recovery before restart");
        let mut recovery = crate::cli::note::load_note_deploy_recovery(recovery_path)
            .expect("load ambiguous recovery")
            .expect("ambiguous recovery exists");
        let owner = recovery.owner_public_key_hex.clone();
        let token_type = recovery.token_type;
        let raw_value = recovery.raw_value;
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let key_loader =
            FixedFundingKeyLoader::failing("submitted recovery must not load funding key");
        let wallet_reader =
            FixedFundingWalletReader::failing("submitted recovery must not read funding wallet");
        let boc_builder = CountingVoucherBocBuilder::default();
        let submitter = CountingVoucherSubmitter::default();
        let failpoints = super::NoteDeployVoucherFailpoints {
            before_voucher_event_wait: true,
            ..Default::default()
        };

        let error = super::note_deploy_mint_voucher_recoverable(
            &client,
            recovery_path,
            &mut recovery,
            NoteDeployVoucherKind::Deposit,
            &multisig_address,
            &key_loader,
            &wallet_reader,
            &boc_builder,
            &submitter,
            &owner,
            token_type,
            raw_value,
            false,
            &dexdo_core::private_note::Halo2Paths::from_env(),
            failpoints,
        )
        .await
        .expect_err("fixture must stop before the live event wait")
        .to_string();
        assert!(
            error.contains("simulated interruption before voucher event wait"),
            "{error}"
        );
        assert!(!error.contains("submitted recovery must"), "{error}");
        assert_eq!(key_loader.calls.get(), 0);
        assert_eq!(wallet_reader.code_hash_calls.get(), 0);
        assert_eq!(wallet_reader.custodian_calls.get(), 0);
        assert_eq!(boc_builder.calls.get(), 0);
        assert_eq!(submitter.calls.get(), 0);
        assert_eq!(
            std::fs::read(recovery_path).expect("read recovery after restart"),
            before,
            "restart must not rewrite ambiguous recovery state"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_issue_678_ambiguous_observer_persists_and_restart_never_posts_twice() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let resumed_recovery_path = temp.path().join("ambiguous-recovery.json");
        let first_reader = issue_678_wallet_reader(vec![(SHELL_CURRENCY_ID, u128::MAX)]);
        let first_submitter =
            CountingVoucherSubmitter::failing("transport/observer timeout containing text 38");
        let mut resumed_recovery = test_recovery_state();
        let ambiguous_error = run_issue_678_deposit(
            &resumed_recovery_path,
            &mut resumed_recovery,
            &first_reader,
            &first_submitter,
            Default::default(),
        )
        .await
        .expect_err("transport/observer failure must remain ambiguous")
        .to_string();

        assert!(
            ambiguous_error.contains("transport/observer timeout containing text 38"),
            "{ambiguous_error}"
        );
        assert!(
            !ambiguous_error.contains("NOT_ENOUGH_EXTRA"),
            "{ambiguous_error}"
        );
        assert_eq!(first_submitter.calls.get(), 1);
        let ambiguous = resumed_recovery
            .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
            .expect("ambiguous checkpoint");
        assert!(ambiguous.submit_maybe_sent);

        assert_issue_678_restart_never_posts(&resumed_recovery_path).await;
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_issue_678_ok_none_receipt_persists_and_restart_posts_zero() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let recovery_path = temp.path().join("no-finalized-receipt.json");
        let reader = issue_678_wallet_reader(vec![(SHELL_CURRENCY_ID, u128::MAX)]);
        let submitter = CountingVoucherSubmitter::returning(None);
        let mut recovery = test_recovery_state();

        let error = run_issue_678_deposit(
            &recovery_path,
            &mut recovery,
            &reader,
            &submitter,
            Default::default(),
        )
        .await
        .expect_err("Ok(None) finalized receipt must remain ambiguous")
        .to_string();

        assert!(error.contains("no bounded finalized receipt"), "{error}");
        assert!(
            error.contains("will not submit a second wallet POST"),
            "{error}"
        );
        assert!(
            error.contains("Inspect the exact wallet transaction"),
            "{error}"
        );
        assert_eq!(submitter.calls.get(), 1);
        assert!(
            recovery
                .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                .expect("ambiguous checkpoint")
                .submit_maybe_sent
        );
        assert_issue_678_restart_never_posts(&recovery_path).await;
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_issue_678_matching_effect_never_clears_submit_guard() {
        use crate::cli::note::NoteDeployVoucherKind;

        let raw = 100_000_000_000u128;
        let mut outbound_effect = issue_678_receipt(true, 38);
        outbound_effect.outmsg_count = 1;
        let mut matching_ecc_effect = issue_678_receipt(true, 38);
        matching_ecc_effect.wallet_ecc_balances = Some(vec![(SHELL_CURRENCY_ID, raw * 2 - 1)]);
        let mut missing_ecc = issue_678_receipt(true, 38);
        missing_ecc.wallet_ecc_balances = None;

        for (case, receipt, expected) in [
            (
                "outbound-effect",
                outbound_effect,
                "produced 1 outbound message(s)",
            ),
            ("matching-ecc-effect", matching_ecc_effect, "ECC[2] changed"),
            ("missing-ecc", missing_ecc, "no exact wallet ECC state"),
        ] {
            let temp = tempfile::tempdir().expect("temp dir");
            let recovery_path = temp.path().join(format!("{case}.json"));
            let reader = issue_678_wallet_reader(vec![(SHELL_CURRENCY_ID, raw * 2)]);
            let submitter = CountingVoucherSubmitter::returning(Some(receipt));
            let mut recovery = test_recovery_state();

            let error = run_issue_678_deposit(
                &recovery_path,
                &mut recovery,
                &reader,
                &submitter,
                Default::default(),
            )
            .await
            .expect_err("unproven no-effect state must fail closed")
            .to_string();

            assert!(
                error.contains("effect absence could not be proven"),
                "{case}: {error}"
            );
            assert!(error.contains(expected), "{case}: {error}");
            assert!(
                error.contains("will not submit a second wallet POST"),
                "{case}: {error}"
            );
            assert_eq!(submitter.calls.get(), 1, "{case}");
            assert!(
                recovery
                    .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                    .expect("guarded checkpoint")
                    .submit_maybe_sent,
                "{case}"
            );
            assert_issue_678_restart_never_posts(&recovery_path).await;
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_later_fresh_shell_voucher_is_gated_after_submitted_deposit() {
        use crate::cli::note::{NoteDeployVoucherCheckpoint, NoteDeployVoucherKind};
        use dexdo_core::private_note::proof::{CURRENCY_ID_SHELL, ECC_SHELL_DEPOSIT_RAW};

        let temp = tempfile::tempdir().expect("temp dir");
        let client = dexdo_core::ChainClient::connect("http://127.0.0.1:9")
            .expect("connect offline fixture endpoint");
        let multisig_address = dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64)))
            .expect("parse fixture wallet");
        let multisig_keys = preflight_fixture_keys();
        let key_loader = FixedFundingKeyLoader::returning(&multisig_keys);
        let wallet_reader = FixedFundingWalletReader::returning(serde_json::json!({
            "custodians": [{
                "index": "0",
                "owner_pubkey": format!("0x{}", "11".repeat(32)),
            }]
        }));
        let boc_builder = CountingVoucherBocBuilder::default();
        let submitter = CountingVoucherSubmitter::default();
        let halo2_paths = dexdo_core::private_note::Halo2Paths::from_env();

        let mut recovery = test_recovery_state();
        let owner = recovery.owner_public_key_hex.clone();
        let mut deposit = NoteDeployVoucherCheckpoint::new(
            &owner,
            recovery.token_type,
            recovery.raw_value,
            false,
            "b".repeat(64),
            "c".repeat(64),
        )
        .expect("fixture deposit checkpoint");
        deposit.submit_maybe_sent = true;
        recovery
            .set_voucher_checkpoint(NoteDeployVoucherKind::Deposit, deposit)
            .expect("persist prior deposit checkpoint");
        let recovery_path = temp.path().join("later-shell-recovery.json");
        crate::cli::note::write_note_deploy_recovery(&recovery_path, &recovery)
            .expect("write recovery with submitted deposit");
        let before = std::fs::read(&recovery_path).expect("read recovery before SHELL leg");

        let error = super::note_deploy_mint_voucher_recoverable(
            &client,
            &recovery_path,
            &mut recovery,
            NoteDeployVoucherKind::ShellGas,
            &multisig_address,
            &key_loader,
            &wallet_reader,
            &boc_builder,
            &submitter,
            &owner,
            CURRENCY_ID_SHELL,
            ECC_SHELL_DEPOSIT_RAW,
            true,
            &halo2_paths,
            Default::default(),
        )
        .await
        .expect_err("a later fresh voucher leg must run the wallet guard")
        .to_string();

        assert!(error.contains("is not a custodian"), "{error}");
        assert_eq!(key_loader.calls.get(), 1);
        assert_eq!(wallet_reader.code_hash_calls.get(), 1);
        assert_eq!(wallet_reader.custodian_calls.get(), 1);
        assert_eq!(boc_builder.calls.get(), 0);
        assert_eq!(submitter.calls.get(), 0);
        assert!(
            recovery
                .voucher_checkpoint(NoteDeployVoucherKind::ShellGas)
                .is_none(),
            "rejection must precede the fresh SHELL checkpoint"
        );
        assert!(
            recovery
                .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                .is_some(),
            "the prior submitted deposit checkpoint must remain intact"
        );
        assert_eq!(
            std::fs::read(&recovery_path).expect("read recovery after rejected SHELL leg"),
            before,
            "rejected later leg must not rewrite the existing journal"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_issue_678_action_result_38_label_uses_only_the_exact_numeric_code() {
        assert!(super::note_deploy_action_failed(true, 0));
        assert!(super::note_deploy_action_failed(false, 38));
        assert!(!super::note_deploy_action_failed(false, 0));
        assert_eq!(
            super::note_deploy_action_result_label(38),
            Some("NOT_ENOUGH_EXTRA")
        );
        for code in [380, 138, 0] {
            assert_eq!(super::note_deploy_action_result_label(code), None);
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_wallet_replay_conflict_is_busy_retryable_and_actionable() {
        let raw = anyhow::anyhow!(
            "submit UpdateCustodianMultisigWallet_v2.submitTransaction -> RootPN.generateVoucher: block manager rejected \
             message code=TVM_ERROR; exit-code:52 nonce desynchronized"
        );

        assert!(crate::cli::commands::is_note_deploy_wallet_busy_error(&raw));
        assert!(super::is_note_deploy_wallet_submit_busy_error(&raw));
        let error = crate::cli::commands::note_deploy_error("0:wallet", raw).to_string();
        assert!(error.contains("wallet busy/out-of-sync"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_exit_code_520_is_not_wallet_busy() {
        let raw = anyhow::anyhow!("wallet submit failed with exit code 520");

        assert!(!crate::cli::commands::is_note_deploy_wallet_busy_error(
            &raw
        ));
        assert!(!super::is_note_deploy_wallet_submit_busy_error(&raw));
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_root_pn_compute_revert_is_not_wallet_busy_and_keeps_cause() {
        let raw = anyhow::anyhow!(
            "deployPrivateNote reverted: tvm_error exit_code=60 contract execution failed"
        );

        assert!(!crate::cli::commands::is_note_deploy_wallet_busy_error(
            &raw
        ));
        let error = crate::cli::commands::note_deploy_error("0:wallet", raw).to_string();
        assert!(error.contains("exit_code=60"), "{error}");
        assert!(!error.contains("wallet busy"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    fn finalized_rootpn_error(method: &str, code: i64) -> anyhow::Error {
        super::note_deploy_rootpn_action_result(
            method,
            None,
            Some(dexdo_core::shellnet::NoteDeployRootPnActionObservation {
                transaction_hash: format!("tx-{method}-{code}"),
                compute_exit_code: code,
                aborted: true,
                action_result_code: None,
            }),
        )
        .expect_err("finalized RootPN failure")
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_rootpn_final_receipt_overrides_block_manager_wrapper() {
        let error = super::note_deploy_rootpn_action_result(
            "deployPrivateNote",
            Some(anyhow::anyhow!(
                "block manager rejected message [TVM_ERROR]"
            )),
            Some(dexdo_core::shellnet::NoteDeployRootPnActionObservation {
                transaction_hash: "tx403".to_string(),
                compute_exit_code: 403,
                aborted: true,
                action_result_code: None,
            }),
        )
        .expect_err("the exact finalized compute abort must be returned");
        assert!(
            super::note_deploy_has_exact_finalized_rootpn_exit_code(&error, 403),
            "{error:#}"
        );

        super::note_deploy_rootpn_action_result(
            "deployPrivateNote",
            Some(anyhow::anyhow!(
                "block manager rejected message [TVM_ERROR]"
            )),
            Some(dexdo_core::shellnet::NoteDeployRootPnActionObservation {
                transaction_hash: "tx-ok".to_string(),
                compute_exit_code: 0,
                aborted: false,
                action_result_code: Some(0),
            }),
        )
        .expect("the exact successful receipt is authoritative");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_history_proof_403_is_actionable_without_relabeling_other_errors() {
        for method in ["deployPrivateNote", "sendEccShellToPrivateNote"] {
            let receipt_error = finalized_rootpn_error(method, 403);
            let raw = receipt_error.to_string();
            let error =
                crate::cli::commands::note_deploy_error("0:wallet", receipt_error).to_string();
            assert!(
                error.contains("history proof expired (exit 403)"),
                "{error}"
            );
            assert!(
                error.contains("action=resume_same_paid_voucher_later"),
                "{error}"
            );
            assert!(error.contains("Do not fund a new voucher"), "{error}");
            assert!(!error.contains("HALO2_ATTEMPT_LAYERS"), "{error}");
            assert!(
                error.contains(&raw),
                "raw SDK error must be retained: {error}"
            );
        }

        let raw = "RootPN.deployPrivateNote: network request timed out";
        let error =
            crate::cli::commands::note_deploy_error("0:wallet", anyhow::anyhow!(raw)).to_string();
        assert_eq!(
            error,
            format!("deploy PrivateNote from wallet 0:wallet: {raw}")
        );
        assert!(!error.contains("history proof expired"), "{error}");
        assert!(!error.contains("Re-run"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_unrelated_errors_are_not_relabeled_as_history_proof_expired() {
        for raw in [
            "UpdateCustodianMultisigWallet_v2.submitTransaction failed: exit_code=403",
            "RootPN.deployPrivateNote: block manager rejected message; exit_code=403",
            "RootPN.deployPrivateNote failed: ERR_INVALID_HISTORY_PROOF",
            "prove deposit voucher: ERR_INVALID_ZKPROOF in halo2 prover",
            "wallet submit failed: exit_code=52 replay protection exception",
            "generic SDK transport error",
        ] {
            let error = crate::cli::commands::note_deploy_error("0:wallet", anyhow::anyhow!(raw))
                .to_string();
            assert!(!error.contains("history proof expired"), "{error}");
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_reproof_routes_only_typed_finalized_403() {
        assert!(super::note_deploy_has_exact_finalized_rootpn_exit_code(
            &finalized_rootpn_error("deployPrivateNote", 403),
            403
        ));
        for code in [4030, 1403, 137] {
            assert!(
                !super::note_deploy_has_exact_finalized_rootpn_exit_code(
                    &finalized_rootpn_error("deployPrivateNote", code),
                    403
                ),
                "{code}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_prover_and_later_stage_replay_errors_are_not_relabeled() {
        let prover = anyhow::anyhow!("prove deposit voucher: ERR_INVALID_ZKPROOF in halo2 prover");
        assert!(!crate::cli::commands::is_note_deploy_wallet_busy_error(
            &prover
        ));
        let prover_error = crate::cli::commands::note_deploy_error("0:wallet", prover).to_string();
        assert!(
            prover_error.contains("ERR_INVALID_ZKPROOF"),
            "{prover_error}"
        );
        assert!(!prover_error.contains("wallet busy"), "{prover_error}");
        assert!(
            !prover_error.contains("history proof expired"),
            "{prover_error}"
        );

        let later_stage = anyhow::anyhow!(
            "RootPN.deployPrivateNote: block manager rejected message code=TVM_ERROR; \
             exit_code=52 replay protection exception"
        );
        assert!(!crate::cli::commands::is_note_deploy_wallet_busy_error(
            &later_stage
        ));
        assert!(!super::is_note_deploy_wallet_submit_busy_error(
            &later_stage
        ));
        let later_stage_error =
            super::note_deploy_resume_error("0:wallet", later_stage).to_string();
        assert!(later_stage_error.contains("RootPN.deployPrivateNote"));
        assert!(!later_stage_error.contains("wallet busy"));
        assert!(!later_stage_error.contains("history proof expired"));
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_wallet_submit_retry_loop_succeeds_on_final_canonical_attempt() {
        let mut attempts = Vec::new();
        let mut backoffs = Vec::new();

        let state = super::run_note_deploy_with_wallet_busy_retry(
            "0:wallet",
            async |attempt| {
                attempts.push(attempt);
                if attempt < NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS {
                    Err(anyhow::anyhow!(
                        "submit UpdateCustodianMultisigWallet_v2.submitTransaction -> RootPN.generateVoucher: \
                         tvm_error exit-code:52 nonce desynchronized"
                    ))
                } else {
                    Ok("deployed")
                }
            },
            async |duration| backoffs.push(duration),
        )
        .await
        .expect("wallet-submit retry should succeed on the final canonical attempt");

        assert_eq!(state, "deployed");
        assert_eq!(
            attempts,
            (1..=NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS).collect::<Vec<_>>()
        );
        assert_eq!(
            backoffs,
            (1..NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS)
                .map(|attempt| std::time::Duration::from_secs(
                    attempt.saturating_mul(NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS)
                ))
                .collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_wallet_submit_retry_loop_exhausts_canonical_attempt_budget() {
        let mut attempts = Vec::new();
        let mut backoffs = Vec::new();

        let result: anyhow::Result<()> = super::run_note_deploy_with_wallet_busy_retry(
            "0:wallet",
            async |attempt| {
                attempts.push(attempt);
                Err(anyhow::anyhow!(
                    "submit UpdateCustodianMultisigWallet_v2.submitTransaction -> RootPN.generateVoucher: \
                     tvm_error exit-code:52 nonce desynchronized"
                ))
            },
            async |duration| backoffs.push(duration),
        )
        .await;

        let error = result.expect_err("wallet-submit retry should stop after its canonical budget");
        assert!(error.to_string().contains("wallet busy/out-of-sync"));
        assert_eq!(
            attempts,
            (1..=NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS).collect::<Vec<_>>()
        );
        assert_eq!(
            backoffs,
            (1..NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS)
                .map(|attempt| std::time::Duration::from_secs(
                    attempt.saturating_mul(NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS)
                ))
                .collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_retry_loop_does_not_retry_root_pn_exit_52() {
        let mut attempts = Vec::new();
        let mut backoffs = Vec::new();

        let result: anyhow::Result<()> = super::run_note_deploy_with_wallet_busy_retry(
            "0:wallet",
            async |attempt| {
                attempts.push(attempt);
                Err(anyhow::anyhow!(
                    "RootPN.deployPrivateNote reverted: tvm_error exit-code:52 replay protection"
                ))
            },
            async |duration| backoffs.push(duration),
        )
        .await;

        let error = result.expect_err("non-wallet RootPN exit 52 must fail immediately");
        let message = error.to_string();
        assert!(message.contains("exit-code:52"), "{message}");
        assert!(!message.contains("wallet busy"), "{message}");
        assert_eq!(attempts, vec![1]);
        assert!(backoffs.is_empty());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_retry_loop_does_not_retry_downstream_tvm_exit_60() {
        let mut attempts = Vec::new();
        let mut backoffs = Vec::new();

        let result: anyhow::Result<()> = super::run_note_deploy_with_wallet_busy_retry(
            "0:wallet",
            async |attempt| {
                attempts.push(attempt);
                Err(anyhow::anyhow!(
                    "downstream deploy failed: tvm_error exit_code=60"
                ))
            },
            async |duration| backoffs.push(duration),
        )
        .await;

        let error = result.expect_err("downstream TVM exit 60 must fail immediately");
        let message = error.to_string();
        assert!(message.contains("tvm_error exit_code=60"), "{message}");
        assert!(!message.contains("wallet busy"), "{message}");
        assert_eq!(attempts, vec![1]);
        assert!(backoffs.is_empty());
    }

    #[cfg(feature = "shellnet")]
    fn write_test_file(dir: &std::path::Path, name: &str, bytes: &[u8]) {
        std::fs::write(dir.join(name), bytes).expect("write test fixture");
    }

    #[cfg(feature = "shellnet")]
    fn test_recovery_state() -> crate::cli::note::NoteDeployRecoveryState {
        use crate::cli::note::{NoteDeployRecoveryRequest, NoteDeployRecoveryState};

        let owner = dexdo_core::KeyPair::from_secret_hex(&"2a".repeat(32)).expect("test owner key");
        NoteDeployRecoveryState::new(
            NoteDeployRecoveryRequest {
                endpoint: "http://127.0.0.1:9",
                nominal: "N100",
                token_type: dexdo_core::params::SHELL_CURRENCY_ID,
                raw_value: 100_000_000_000,
                ecc_shell_deposit: 100_000_000_000,
                funding_multisig_address: &format!("0:{}", "a".repeat(64)),
            },
            owner.public_hex(),
            owner.secret_hex(),
        )
        .expect("test recovery state")
    }

    #[cfg(feature = "shellnet")]
    fn persisted_voucher_checkpoint(
        owner_public_key_hex: &str,
        token_type: u32,
        raw_value: u64,
        is_fee: bool,
        fixture_digit: char,
    ) -> crate::cli::note::NoteDeployVoucherCheckpoint {
        use crate::cli::note::{
            NoteDeployVoucherCheckpoint, NoteDeployVoucherEvent, NoteDeployVoucherProof,
        };

        let sk_u_hex = fixture_digit.to_string().repeat(64);
        let sk_u_commit_hex = if fixture_digit == 'b' {
            "c".repeat(64)
        } else {
            "d".repeat(64)
        };
        let mut checkpoint = NoteDeployVoucherCheckpoint::new(
            owner_public_key_hex,
            token_type,
            raw_value,
            is_fee,
            sk_u_hex.clone(),
            sk_u_commit_hex.clone(),
        )
        .expect("voucher checkpoint");
        checkpoint.submit_maybe_sent = true;
        checkpoint.event = Some(NoteDeployVoucherEvent {
            id: format!("event-{fixture_digit}"),
            boc: "fixture-boc".into(),
            body: "fixture-body".into(),
            dst: format!("0:{}", "e".repeat(64)),
            created_at: 1,
            block_id: Some("fixture-block".into()),
        });
        checkpoint.proof = Some(NoteDeployVoucherProof {
            proof: format!("fixture-proof-{fixture_digit}"),
            deposit_identifier_hash_hex: fixture_digit.to_string().repeat(64),
            final_layer_historical_hash_root_hex: "1".repeat(64),
            voucher_nominal_fr_hex: "2".repeat(64),
            token_type_fr_hex: "3".repeat(64),
            ephemeral_pubkey_hex: owner_public_key_hex.to_string(),
            voucher_value: raw_value,
            voucher_token_type: token_type,
            layer_number: 1,
            sk_u_hex: sk_u_hex.into(),
            sk_u_commit_hex,
        });
        checkpoint
            .validate("persisted test voucher")
            .expect("valid persisted voucher");
        checkpoint
    }

    #[cfg(feature = "shellnet")]
    fn install_fixture_replacement(
        recovery_path: &std::path::Path,
        recovery: &mut crate::cli::note::NoteDeployRecoveryState,
        kind: crate::cli::note::NoteDeployVoucherKind,
    ) -> anyhow::Result<dexdo_core::private_note::halo2::live::Halo2Proof> {
        let mut checkpoint = recovery
            .voucher_checkpoint(kind)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("fixture voucher checkpoint missing"))?;
        if !checkpoint.current_proof_is_rejected() {
            return checkpoint
                .proof
                .as_ref()
                .map(crate::cli::note::NoteDeployVoucherProof::to_halo2)
                .ok_or_else(|| anyhow::anyhow!("fixture voucher proof missing"));
        }
        let next_layer = checkpoint.next_sdk_proof_layer().ok_or_else(|| {
            anyhow::anyhow!("fixture history plan exhausted; action=resume_same_paid_voucher_later")
        })? as u8
            + 1;
        let mut replacement = checkpoint
            .proof
            .as_ref()
            .expect("rejected fixture proof")
            .to_halo2();
        replacement.proof = format!("fixture-replacement-layer-{next_layer}");
        replacement.final_layer_historical_hash_root_hex = "9".repeat(64);
        replacement.layer_number = next_layer;
        checkpoint.replace_rejected_proof(crate::cli::note::NoteDeployVoucherProof::from_halo2(
            &replacement,
        ))?;
        recovery.set_voucher_checkpoint(kind, checkpoint)?;
        crate::cli::note::write_note_deploy_recovery(recovery_path, recovery)?;
        Ok(replacement)
    }

    #[cfg(feature = "shellnet")]
    async fn assert_exact_403_reproof_for_kind(kind: crate::cli::note::NoteDeployVoucherKind) {
        use std::cell::{Cell, RefCell};

        let temp = tempfile::tempdir().expect("temp dir");
        let recovery_path = temp.path().join(format!("{}.recovery.json", kind.label()));
        let mut recovery = test_recovery_state();
        let owner = recovery.owner_public_key_hex.clone();
        let (token_type, raw_value, is_fee, fixture_digit) = match kind {
            crate::cli::note::NoteDeployVoucherKind::Deposit => {
                (recovery.token_type, recovery.raw_value, false, 'b')
            }
            crate::cli::note::NoteDeployVoucherKind::ShellGas => {
                (2, recovery.ecc_shell_deposit, true, 'f')
            }
        };
        let original =
            persisted_voucher_checkpoint(&owner, token_type, raw_value, is_fee, fixture_digit);
        recovery
            .set_voucher_checkpoint(kind, original.clone())
            .expect("persist original voucher");
        crate::cli::note::write_note_deploy_recovery(&recovery_path, &recovery)
            .expect("write original recovery");

        let wallet_submitter = CountingVoucherSubmitter::default();
        let wallet =
            dexdo_core::Address::parse(&format!("0:{}", "a".repeat(64))).expect("fixture wallet");
        super::NoteDeployVoucherSubmitter::submit_voucher_boc(
            &wallet_submitter,
            "http://127.0.0.1:9",
            &wallet,
            "paid-voucher-boc",
            &reqwest::Client::new(),
        )
        .await
        .expect("record the one paid wallet submit");

        let effect_reads = Cell::new(0_usize);
        let expected_effect_present = Cell::new(false);
        let submitted_layers = RefCell::new(Vec::new());
        let original_proof = original.proof.as_ref().expect("original proof").to_halo2();
        let accepted_proof = super::note_deploy_run_reproof_loop(
            original_proof,
            async |proof| {
                super::note_deploy_submit_proof_once(
                    proof,
                    async |_proof| {
                        effect_reads.set(effect_reads.get() + 1);
                        Ok(expected_effect_present.get())
                    },
                    async |proof| {
                        submitted_layers.borrow_mut().push(proof.layer_number);
                        if proof.layer_number == 1 {
                            let method = match kind {
                                crate::cli::note::NoteDeployVoucherKind::Deposit => {
                                    "deployPrivateNote"
                                }
                                crate::cli::note::NoteDeployVoucherKind::ShellGas => {
                                    "sendEccShellToPrivateNote"
                                }
                            };
                            return Err(finalized_rootpn_error(method, 403));
                        }
                        expected_effect_present.set(true);
                        Ok(())
                    },
                )
                .await
            },
            async |rejected_proof| {
                super::note_deploy_persist_rejected_proof(
                    &recovery_path,
                    &mut recovery,
                    kind,
                    rejected_proof,
                )?;
                install_fixture_replacement(&recovery_path, &mut recovery, kind)
            },
        )
        .await
        .expect("production reproof loop");

        assert_eq!(accepted_proof.layer_number, 2);
        assert_eq!(
            wallet_submitter.calls.get(),
            1,
            "wallet voucher spend must stay one"
        );
        assert_eq!(*submitted_layers.borrow(), [1, 2]);
        assert_eq!(effect_reads.get(), 1);
        assert!(
            expected_effect_present.get(),
            "{} replacement submit did not produce its expected effect",
            kind.label()
        );
        let checkpoint = recovery
            .voucher_checkpoint(kind)
            .expect("final voucher checkpoint");
        assert_eq!(checkpoint.last_rejected_proof_layer, Some(1));
        assert_eq!(
            checkpoint.proof.as_ref().expect("replacement").layer_number,
            2
        );
        assert_eq!(checkpoint.sk_u_hex, original.sk_u_hex);
        assert_eq!(checkpoint.sk_u_commit_hex, original.sk_u_commit_hex);
        assert_eq!(checkpoint.event, original.event);
        assert_eq!(
            checkpoint.recipient_ephemeral_pubkey_hex,
            original.recipient_ephemeral_pubkey_hex
        );
        assert_eq!(checkpoint.token_type, original.token_type);
        assert_eq!(checkpoint.raw_value, original.raw_value);
        assert_eq!(checkpoint.is_fee, original.is_fee);
        assert_eq!(
            checkpoint
                .proof
                .as_ref()
                .expect("replacement")
                .deposit_identifier_hash_hex,
            original
                .proof
                .as_ref()
                .expect("original proof")
                .deposit_identifier_hash_hex
        );
        let persisted = crate::cli::note::load_note_deploy_recovery(&recovery_path)
            .expect("load final recovery")
            .expect("final recovery exists");
        assert_eq!(persisted.voucher_checkpoint(kind), Some(checkpoint));
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_deposit_exact_403_reproofs_same_paid_voucher_once() {
        assert_exact_403_reproof_for_kind(crate::cli::note::NoteDeployVoucherKind::Deposit).await;
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_shell_exact_403_reproofs_same_paid_voucher_once() {
        assert_exact_403_reproof_for_kind(crate::cli::note::NoteDeployVoucherKind::ShellGas).await;
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_submit_error_with_effect_race_skips_reproof_and_resubmit() {
        use std::cell::{Cell, RefCell};

        for submit_error in [
            "RootPN.deployPrivateNote: exit_code=403",
            "RootPN.deployPrivateNote: transport timeout",
        ] {
            let mut recovery = test_recovery_state();
            let owner = recovery.owner_public_key_hex.clone();
            let checkpoint = persisted_voucher_checkpoint(
                &owner,
                recovery.token_type,
                recovery.raw_value,
                false,
                'b',
            );
            recovery
                .set_voucher_checkpoint(
                    crate::cli::note::NoteDeployVoucherKind::Deposit,
                    checkpoint.clone(),
                )
                .expect("persist voucher");

            let effect_reads = Cell::new(0_usize);
            let submitted_layers = RefCell::new(Vec::new());
            let proof = checkpoint.proof.as_ref().expect("proof").to_halo2();
            let accepted = super::note_deploy_submit_proof_once(
                &proof,
                async |_proof| {
                    effect_reads.set(effect_reads.get() + 1);
                    Ok(true)
                },
                async |proof| {
                    submitted_layers.borrow_mut().push(proof.layer_number);
                    anyhow::bail!("{submit_error}")
                },
            )
            .await
            .expect("effect appearing after submit error is success by fact");

            assert!(accepted);
            assert_eq!(effect_reads.get(), 1);
            assert_eq!(*submitted_layers.borrow(), [1]);
            assert_eq!(
                recovery
                    .deposit_voucher
                    .as_ref()
                    .expect("voucher")
                    .last_rejected_proof_layer,
                None
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_replacement_persisted_before_submit_resumes_without_old_layer() {
        use std::cell::RefCell;

        let temp = tempfile::tempdir().expect("temp dir");
        let recovery_path = temp.path().join("replacement-crash.recovery.json");
        let mut recovery = test_recovery_state();
        let owner = recovery.owner_public_key_hex.clone();
        let checkpoint = persisted_voucher_checkpoint(
            &owner,
            recovery.token_type,
            recovery.raw_value,
            false,
            'b',
        );
        recovery
            .set_voucher_checkpoint(
                crate::cli::note::NoteDeployVoucherKind::Deposit,
                checkpoint.clone(),
            )
            .expect("persist rejected layer");
        crate::cli::note::write_note_deploy_recovery(&recovery_path, &recovery)
            .expect("write recovery");
        let original_proof = checkpoint.proof.as_ref().expect("proof").to_halo2();
        super::note_deploy_persist_rejected_proof(
            &recovery_path,
            &mut recovery,
            crate::cli::note::NoteDeployVoucherKind::Deposit,
            &original_proof,
        )
        .expect("persist rejected proof");
        install_fixture_replacement(
            &recovery_path,
            &mut recovery,
            crate::cli::note::NoteDeployVoucherKind::Deposit,
        )
        .expect("persist replacement before submit");
        drop(recovery);
        let recovery = crate::cli::note::load_note_deploy_recovery(&recovery_path)
            .expect("load replacement after simulated restart")
            .expect("replacement recovery exists");
        assert_eq!(
            recovery
                .deposit_voucher
                .as_ref()
                .and_then(|voucher| voucher.proof.as_ref())
                .expect("persisted replacement")
                .layer_number,
            2
        );

        let submitted_layers = RefCell::new(Vec::new());
        let replacement = recovery
            .deposit_voucher
            .as_ref()
            .and_then(|voucher| voucher.proof.as_ref())
            .expect("persisted replacement")
            .to_halo2();
        let accepted = super::note_deploy_submit_proof_once(
            &replacement,
            async |_proof| Ok(false),
            async |proof| {
                submitted_layers.borrow_mut().push(proof.layer_number);
                Ok(())
            },
        )
        .await
        .expect("restart must submit the persisted replacement");
        assert!(accepted);
        assert_eq!(*submitted_layers.borrow(), [2]);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_non_403_and_observer_outage_preserve_proof_without_fallback() {
        use std::cell::Cell;

        for (case, effect_observer_fails, receipt_outcome, submit_error) in [
            (
                "non-403",
                false,
                "raw",
                "RootPN.deployPrivateNote: exit_code=137",
            ),
            (
                "transport",
                false,
                "raw",
                "RootPN.deployPrivateNote: transport timeout",
            ),
            (
                "effect-observer",
                true,
                "raw",
                "RootPN.deployPrivateNote: exit_code=403",
            ),
            (
                "missing-receipt",
                false,
                "missing",
                "block manager rejected message; exit_code=403",
            ),
            (
                "receipt-observer",
                false,
                "observer",
                "block manager rejected message; exit_code=403",
            ),
        ] {
            let mut recovery = test_recovery_state();
            let owner = recovery.owner_public_key_hex.clone();
            let checkpoint = persisted_voucher_checkpoint(
                &owner,
                recovery.token_type,
                recovery.raw_value,
                false,
                'b',
            );
            recovery
                .set_voucher_checkpoint(
                    crate::cli::note::NoteDeployVoucherKind::Deposit,
                    checkpoint.clone(),
                )
                .expect("persist voucher");
            let submits = Cell::new(0_usize);
            let proof = checkpoint.proof.as_ref().expect("proof").to_halo2();

            let error = super::note_deploy_submit_proof_once(
                &proof,
                async |_proof| {
                    if effect_observer_fails {
                        anyhow::bail!("effect observer outage")
                    }
                    Ok(false)
                },
                async |_proof| {
                    submits.set(submits.get() + 1);
                    let error = anyhow::anyhow!("{submit_error}");
                    match receipt_outcome {
                        "missing" => super::note_deploy_rootpn_action_result(
                            "deployPrivateNote",
                            Some(error),
                            None,
                        ),
                        "observer" => {
                            Err(anyhow::anyhow!("receipt observer outage").context(error))
                        }
                        _ => Err(error),
                    }
                },
            )
            .await
            .expect_err("ambiguous result must propagate instead of returning the re-proof signal");
            let user_error = crate::cli::commands::note_deploy_error("0:wallet", error).to_string();
            assert!(
                !user_error.contains("history proof expired"),
                "{case}: {user_error}"
            );
            assert_eq!(submits.get(), 1, "{case}");
            assert_eq!(
                recovery.deposit_voucher.as_ref().expect("voucher").proof,
                checkpoint.proof,
                "{case}"
            );
            assert_eq!(
                recovery
                    .deposit_voucher
                    .as_ref()
                    .expect("voucher")
                    .last_rejected_proof_layer,
                None
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[derive(Debug, Default)]
    struct FakeNoteDeployResolvedOps {
        recovery: Option<crate::cli::note::NoteDeployRecoveryState>,
        pool_path: std::path::PathBuf,
        cache_unavailable_or_contended: bool,
        doctor_preflight_error: Option<&'static str>,
        events: Vec<&'static str>,
        doctor_preflight_calls: usize,
        recovery_loads: usize,
        key_material_actions: usize,
        preflight_calls: usize,
        wallet_signs: usize,
        wallet_submits: usize,
        voucher_generations: usize,
        proof_calls: usize,
        chain_resumes: usize,
        pool_finalizations: usize,
        deposit_proof_preserved: bool,
        shell_proof_preserved: bool,
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait(?Send)]
    impl super::NoteDeployResolvedOps for FakeNoteDeployResolvedOps {
        async fn preflight_doctor(&mut self) -> anyhow::Result<()> {
            self.doctor_preflight_calls += 1;
            self.events.push("doctor_preflight");
            if let Some(error) = self.doctor_preflight_error {
                return Err(super::note_deploy_generation_mismatch(anyhow::anyhow!(
                    error
                )));
            }
            Ok(())
        }

        async fn load_recovery(
            &mut self,
        ) -> anyhow::Result<crate::cli::note::NoteDeployRecoveryState> {
            self.recovery_loads += 1;
            self.key_material_actions += 1;
            self.events.push("recovery_load");
            self.recovery
                .take()
                .ok_or_else(|| anyhow::anyhow!("fake recovery is missing"))
        }

        async fn preflight_prover(&mut self) -> anyhow::Result<()> {
            self.preflight_calls += 1;
            self.events.push("prover_preflight");
            if self.cache_unavailable_or_contended {
                anyhow::bail!("fake prover cache unavailable or contended");
            }
            Ok(())
        }

        async fn resume_chain(
            &mut self,
            recovery: &mut crate::cli::note::NoteDeployRecoveryState,
        ) -> anyhow::Result<crate::cli::note::OnboardPnState> {
            use crate::cli::note::NoteDeployVoucherKind;

            if recovery.shell_funded && recovery.sanity_checked {
                self.events.push("completed_recovery");
                return recovery.to_onboard_state();
            }

            let both_proofs_persisted = [
                NoteDeployVoucherKind::Deposit,
                NoteDeployVoucherKind::ShellGas,
            ]
            .into_iter()
            .all(|kind| {
                recovery
                    .voucher_checkpoint(kind)
                    .and_then(|checkpoint| checkpoint.proof.as_ref())
                    .is_some()
            });
            if both_proofs_persisted {
                self.events.push("chain_resume");
                self.chain_resumes += 1;
            } else {
                if self.preflight_calls != 1 {
                    anyhow::bail!("fresh recovery reached wallet submit before prover preflight");
                }
                self.events.push("wallet_submit");
                self.wallet_signs += 1;
                self.wallet_submits += 1;
                self.voucher_generations += 1;
                self.events.push("prove");
                self.proof_calls += 1;
                self.events.push("chain_resume");
                self.chain_resumes += 1;
            }

            recovery.mark_private_note_deployed(
                format!("0:{}", "6".repeat(64)),
                "7".repeat(64),
                2,
            )?;
            recovery.mark_shell_funded_and_checked()?;
            recovery.to_onboard_state()
        }

        async fn finalize_pool(
            &mut self,
            recovery: &crate::cli::note::NoteDeployRecoveryState,
            state: &crate::cli::note::OnboardPnState,
        ) -> anyhow::Result<()> {
            use crate::cli::note::NoteDeployVoucherKind;

            self.events.push("pool_finalize");
            self.pool_finalizations += 1;
            self.deposit_proof_preserved = recovery
                .voucher_checkpoint(NoteDeployVoucherKind::Deposit)
                .and_then(|checkpoint| checkpoint.proof.as_ref())
                .is_some();
            self.shell_proof_preserved = recovery
                .voucher_checkpoint(NoteDeployVoucherKind::ShellGas)
                .and_then(|checkpoint| checkpoint.proof.as_ref())
                .is_some();
            super::note_deploy_fold_state_into_pool(
                &self.pool_path,
                state,
                &recovery.funding_multisig_address,
            )?;
            Ok(())
        }
    }

    #[cfg(feature = "shellnet")]
    fn no_fetch(_part_path: std::path::PathBuf) -> std::future::Ready<anyhow::Result<()>> {
        std::future::ready(Err(anyhow::anyhow!("fetcher must not be called")))
    }

    #[cfg(feature = "shellnet")]
    struct SrsHttpReply {
        status: &'static str,
        content_range: Option<String>,
        content_length: usize,
        body: Vec<u8>,
    }

    #[cfg(feature = "shellnet")]
    impl SrsHttpReply {
        fn new(status: &'static str, content_range: Option<String>, body: Vec<u8>) -> Self {
            Self {
                status,
                content_range,
                content_length: body.len(),
                body,
            }
        }

        fn declared_length(mut self, content_length: usize) -> Self {
            self.content_length = content_length;
            self
        }
    }

    #[cfg(feature = "shellnet")]
    async fn download_srs_fixture(
        part_path: &std::path::Path,
        expected_size: u64,
        replies: Vec<SrsHttpReply>,
    ) -> (anyhow::Result<()>, Vec<String>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind SRS HTTP fixture");
        let url = format!("http://{}/srs", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut socket, _) = listener.accept().await.expect("accept SRS request");
                let mut request = vec![0_u8; 8192];
                let read = socket.read(&mut request).await.expect("read SRS request");
                requests.push(String::from_utf8_lossy(&request[..read]).to_ascii_lowercase());

                let mut headers = format!(
                    "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: {}\r\n",
                    reply.status, reply.content_length
                );
                if let Some(range) = reply.content_range {
                    headers.push_str(&format!("Content-Range: {range}\r\n"));
                }
                headers.push_str("\r\n");
                socket
                    .write_all(headers.as_bytes())
                    .await
                    .expect("write SRS response headers");
                socket
                    .write_all(&reply.body)
                    .await
                    .expect("write SRS response body");
            }
            requests
        });
        let result = super::fetch_hermez_srs_with_retry(
            &reqwest::Client::new(),
            &url,
            part_path,
            expected_size,
        )
        .await;
        let requests = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("SRS fixture received all expected requests")
            .expect("SRS fixture task");
        (result, requests)
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_hermez_interrupted_body_streams_partial_then_resumes_exact_range() {
        let temp = tempfile::tempdir().expect("temp dir");
        let expected = (0..16_384).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let cut = 4_096;
        let part_path = temp.path().join(format!("{}.part", super::HERMEZ_SRS_NAME));
        let (result, requests) = download_srs_fixture(
            &part_path,
            expected.len() as u64,
            vec![
                SrsHttpReply::new("200 OK", None, expected[..cut].to_vec())
                    .declared_length(expected.len()),
                SrsHttpReply::new(
                    "206 Partial Content",
                    Some(format!(
                        "bytes {cut}-{}/{}",
                        expected.len() - 1,
                        expected.len()
                    )),
                    expected[cut..].to_vec(),
                ),
            ],
        )
        .await;
        result.expect("resume interrupted SRS body");
        assert_eq!(std::fs::read(&part_path).unwrap(), expected);
        assert!(!requests[0].contains("\r\nrange:"));
        assert!(requests[1].contains(&format!("\r\nrange: bytes={cut}-\r\n")));
        assert!(!temp.path().join(super::HERMEZ_SRS_NAME).exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_hermez_process_restart_keeps_partial_and_exhausts_five_attempts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let expected = vec![0x5a; 4_096];
        let chunk = 128;
        let mut replies = Vec::new();
        for attempt in 0..super::HERMEZ_SRS_MAX_ATTEMPTS {
            let offset = attempt * chunk;
            replies.push(SrsHttpReply::new(
                if attempt == 0 {
                    "200 OK"
                } else {
                    "206 Partial Content"
                },
                (attempt > 0)
                    .then(|| format!("bytes {offset}-{}/{}", expected.len() - 1, expected.len())),
                expected[offset..offset + chunk].to_vec(),
            ));
        }
        let final_path = temp.path().join(super::HERMEZ_SRS_NAME);
        let part_path = temp.path().join(format!("{}.part", super::HERMEZ_SRS_NAME));

        let (result, requests) =
            download_srs_fixture(&part_path, expected.len() as u64, replies).await;
        let error = result.expect_err("five interrupted responses must exhaust retry budget");
        assert!(
            error.to_string().contains("failed after 5 attempts"),
            "{error:#}"
        );
        assert!(error.to_string().contains("premature EOF"), "{error:#}");
        assert!(error.to_string().contains("rerun `dexdo note deploy`"));
        assert_eq!(requests.len(), super::HERMEZ_SRS_MAX_ATTEMPTS);
        assert_eq!(
            std::fs::metadata(&part_path).unwrap().len(),
            (5 * chunk) as u64
        );
        assert!(!final_path.exists());

        let offset = 5 * chunk;
        let (result, requests) = download_srs_fixture(
            &part_path,
            expected.len() as u64,
            vec![SrsHttpReply::new(
                "206 Partial Content",
                Some(format!(
                    "bytes {offset}-{}/{}",
                    expected.len() - 1,
                    expected.len()
                )),
                expected[offset..].to_vec(),
            )],
        )
        .await;
        result.expect("restart resumes saved partial");
        assert!(requests[0].contains(&format!("\r\nrange: bytes={offset}-\r\n")));
        assert_eq!(std::fs::read(part_path).unwrap(), expected);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_hermez_range_ignored_once_restarts_without_append_corruption() {
        let temp = tempfile::tempdir().expect("temp dir");
        let expected = vec![0x3c; 2_048];
        let part_path = temp.path().join(format!("{}.part", super::HERMEZ_SRS_NAME));
        std::fs::write(&part_path, &expected[..333]).unwrap();
        let (result, requests) = download_srs_fixture(
            &part_path,
            expected.len() as u64,
            vec![SrsHttpReply::new("200 OK", None, expected.clone())],
        )
        .await;
        result.expect("one ignored Range restarts cleanly");
        assert!(requests[0].contains("\r\nrange: bytes=333-\r\n"));
        assert_eq!(std::fs::read(part_path).unwrap(), expected);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_hermez_bad_range_or_status_is_permanent_and_preserves_partial() {
        for (status, content_range, expected_error) in [
            ("206 Partial Content", None, "Content-Range"),
            (
                "206 Partial Content",
                Some("bytes 9-31/32".to_string()),
                "Content-Range",
            ),
            (
                "206 Partial Content",
                Some("bytes 8-31/33".to_string()),
                "Content-Range",
            ),
            ("404 Not Found", None, "404"),
        ] {
            let temp = tempfile::tempdir().expect("temp dir");
            let part_path = temp.path().join(format!("{}.part", super::HERMEZ_SRS_NAME));
            std::fs::write(&part_path, [7_u8; 8]).unwrap();
            let body = if status == "206 Partial Content" {
                vec![7; 24]
            } else {
                Vec::new()
            };
            let (result, requests) = download_srs_fixture(
                &part_path,
                32,
                vec![SrsHttpReply::new(status, content_range, body)],
            )
            .await;
            let error = result.expect_err("permanent response must fail");
            assert!(error.to_string().contains(expected_error), "{error:#}");
            assert_eq!(requests.len(), 1, "permanent response was retried");
            assert_eq!(std::fs::read(part_path).unwrap(), [7_u8; 8]);
            assert!(!temp.path().join(super::HERMEZ_SRS_NAME).exists());
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_hermez_oversize_partial_and_body_never_publish() {
        let temp = tempfile::tempdir().expect("temp dir");
        let part_path = temp.path().join(format!("{}.part", super::HERMEZ_SRS_NAME));
        std::fs::write(&part_path, [0_u8; 33]).unwrap();
        let error = super::fetch_hermez_srs_with_retry(
            &reqwest::Client::new(),
            "http://127.0.0.1:9/srs",
            &part_path,
            32,
        )
        .await
        .expect_err("oversized partial must fail before HTTP");
        assert!(error.to_string().contains("oversized partial"), "{error:#}");
        assert!(!part_path.exists());

        let (result, _) = download_srs_fixture(
            &part_path,
            32,
            vec![SrsHttpReply::new("200 OK", None, vec![0; 33])],
        )
        .await;
        let error = result.expect_err("oversized body must fail");
        assert!(error.to_string().contains("body exceeds"), "{error:#}");
        assert_eq!(std::fs::metadata(&part_path).unwrap().len(), 0);
        assert!(!temp.path().join(super::HERMEZ_SRS_NAME).exists());
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_hermez_progress_is_numeric_and_secret_free() {
        let fresh = super::hermez_srs_progress_line(1, 0, 1_000, 0);
        let resumed = super::hermez_srs_progress_line(2, 750, 1_000, 500);
        assert!(fresh.contains("attempt=1/5 downloaded=0 total=1000 percent=0% resumed_offset=0"));
        assert!(resumed
            .contains("attempt=2/5 downloaded=750 total=1000 percent=75% resumed_offset=500"));
        for line in [fresh, resumed] {
            assert!(!line.contains("http"));
            assert!(!line.contains("wallet"));
            assert!(!line.contains("note secret"));
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_committed_complete_cache_skips_fetch_and_invalidation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path();
        let srs = b"valid cached test SRS";
        let expected = super::sha256_hex(srs);
        write_test_file(dir, super::HERMEZ_SRS_NAME, srs);
        write_test_file(dir, super::HERMEZ_SRS_MARKER_NAME, expected.as_bytes());
        for name in super::PROVER_CACHE_ARTIFACTS {
            write_test_file(dir, name, format!("previously-proven-{name}").as_bytes());
        }

        super::ensure_hermez_srs_and_valid_pk_cache_with_options(
            dir,
            srs.len() as u64,
            &expected,
            no_fetch,
            super::invalidate_stale_pk_cache,
        )
        .await
        .expect("valid cache");

        for name in super::PROVER_CACHE_ARTIFACTS {
            assert!(dir.join(name).exists(), "{name} was unexpectedly removed");
        }
        assert!(!dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME).exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_wrong_hermez_srs_download_is_rejected_without_install() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path();
        let expected_srs = b"expected SRS";
        let expected = super::sha256_hex(expected_srs);

        let error = super::ensure_hermez_srs_and_valid_pk_cache_with_options(
            dir,
            expected_srs.len() as u64,
            &expected,
            |part_path| async move {
                std::fs::write(part_path, b"wrong SRS!!!")?;
                Ok(())
            },
            super::invalidate_stale_pk_cache,
        )
        .await
        .expect_err("wrong SRS must fail");

        assert!(error.to_string().contains("sha256 mismatch"), "{error:#}");
        assert!(!dir.join(super::HERMEZ_SRS_NAME).exists());
        assert!(!dir
            .join(format!("{}.part", super::HERMEZ_SRS_NAME))
            .exists());
        assert!(!dir.join(super::HERMEZ_SRS_MARKER_NAME).exists());
        assert!(!dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME).exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_marker_mismatch_removes_all_stale_pk_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path();
        let srs = b"valid test SRS";
        let expected = super::sha256_hex(srs);
        write_test_file(dir, super::HERMEZ_SRS_NAME, srs);
        write_test_file(dir, super::HERMEZ_SRS_MARKER_NAME, b"old-srs");
        for name in super::PROVER_CACHE_ARTIFACTS {
            write_test_file(dir, name, b"stale");
        }

        super::ensure_hermez_srs_and_valid_pk_cache_with_options(
            dir,
            srs.len() as u64,
            &expected,
            no_fetch,
            super::invalidate_stale_pk_cache,
        )
        .await
        .expect("invalidate stale artifacts");

        for name in super::PROVER_CACHE_ARTIFACTS {
            assert!(!dir.join(name).exists(), "{name} was not removed");
        }
        assert_eq!(
            std::fs::read_to_string(dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME))
                .expect("read pending marker"),
            expected
        );
        assert!(!dir.join(super::HERMEZ_SRS_MARKER_NAME).exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_interrupted_pk_publication_self_heals_before_keygen() {
        for initial_marker in [
            super::HERMEZ_SRS_MARKER_NAME,
            super::HERMEZ_SRS_PENDING_MARKER_NAME,
        ] {
            let temp = tempfile::tempdir().expect("temp dir");
            let dir = temp.path();
            let srs = b"valid interrupted-keygen SRS";
            let expected = super::sha256_hex(srs);
            write_test_file(dir, super::HERMEZ_SRS_NAME, srs);
            write_test_file(dir, initial_marker, expected.as_bytes());
            write_test_file(dir, "pk_cache.bin", b"partially-published-pk");

            super::ensure_hermez_srs_and_valid_pk_cache_with_options(
                dir,
                srs.len() as u64,
                &expected,
                no_fetch,
                super::invalidate_stale_pk_cache,
            )
            .await
            .expect("self-heal interrupted cache");

            for name in super::PROVER_CACHE_ARTIFACTS {
                assert!(!dir.join(name).exists(), "{name} was not invalidated");
            }
            assert!(!dir.join(super::HERMEZ_SRS_MARKER_NAME).exists());
            assert_eq!(
                std::fs::read_to_string(dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME))
                    .expect("read pending marker"),
                expected
            );

            for name in super::PROVER_CACHE_ARTIFACTS {
                write_test_file(dir, name, format!("clean-keygen-{name}").as_bytes());
            }
            super::promote_hermez_srs_pending_marker(dir, srs.len() as u64, &expected)
                .expect("commit successful proof cache");
            assert!(!dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME).exists());
            assert_eq!(
                std::fs::read_to_string(dir.join(super::HERMEZ_SRS_MARKER_NAME))
                    .expect("read committed marker"),
                expected
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_atomic_install_replaces_existing_corrupt_srs() {
        let temp = tempfile::tempdir().expect("temp dir");
        let srs_path = temp.path().join(super::HERMEZ_SRS_NAME);
        let part_path = temp.path().join(format!("{}.part", super::HERMEZ_SRS_NAME));
        let replacement = b"verified replacement";
        write_test_file(temp.path(), super::HERMEZ_SRS_NAME, b"corrupt");
        std::fs::write(&part_path, replacement).expect("write verified partial");

        super::publish_hermez_srs_part(
            &part_path,
            &srs_path,
            replacement.len() as u64,
            &super::sha256_hex(replacement),
        )
        .expect("replace existing SRS");

        assert_eq!(
            std::fs::read(&srs_path).expect("read replaced SRS"),
            b"verified replacement"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_marker_promotion_atomically_replaces_existing_destination() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path();
        let srs = b"valid promotion SRS";
        let expected = super::sha256_hex(srs);
        write_test_file(dir, super::HERMEZ_SRS_NAME, srs);
        write_test_file(dir, super::HERMEZ_SRS_MARKER_NAME, b"stale marker");
        write_test_file(
            dir,
            super::HERMEZ_SRS_PENDING_MARKER_NAME,
            expected.as_bytes(),
        );
        for name in super::PROVER_CACHE_ARTIFACTS {
            write_test_file(dir, name, format!("successful-proof-{name}").as_bytes());
        }

        super::promote_hermez_srs_pending_marker(dir, srs.len() as u64, &expected)
            .expect("atomically replace marker");

        assert!(!dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME).exists());
        assert_eq!(
            std::fs::read_to_string(dir.join(super::HERMEZ_SRS_MARKER_NAME))
                .expect("read promoted marker"),
            expected
        );
    }

    #[cfg(feature = "shellnet")]
    async fn assert_note_deploy_generation_rejected_before_writes(
        mut ops: FakeNoteDeployResolvedOps,
    ) -> anyhow::Error {
        let pool_path = ops.pool_path.clone();
        let error = super::run_note_deploy_resolved(&mut ops)
            .await
            .expect_err("stale or unreadable generation must reject note deploy");
        assert_eq!(ops.doctor_preflight_calls, 1);
        assert_eq!(ops.recovery_loads, 0);
        assert_eq!(ops.key_material_actions, 0);
        assert_eq!(ops.preflight_calls, 0);
        assert_eq!(ops.wallet_signs, 0);
        assert_eq!(ops.wallet_submits, 0);
        assert_eq!(ops.voucher_generations, 0);
        assert_eq!(ops.proof_calls, 0);
        assert_eq!(ops.chain_resumes, 0);
        assert_eq!(ops.pool_finalizations, 0);
        assert_eq!(ops.events, ["doctor_preflight"]);
        assert!(
            ops.recovery.is_some(),
            "recovery must not be loaded/mutated"
        );
        assert!(!pool_path.exists(), "pool must not be created or mutated");
        error
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_generation_failures_are_stable_and_precede_all_writes() {
        let cases = [
            (
                "stale RootPN",
                "dexdo doctor: FAIL network=shellnet\nchecks:\n  FAIL RootPN code hash \
                 expected=1111111111111111111111111111111111111111111111111111111111111111 \
                 actual=2222222222222222222222222222222222222222222222222222222222222222",
            ),
            (
                "stale PrivateNote",
                "dexdo doctor: FAIL network=shellnet\nchecks:\n  FAIL PrivateNote code hash (RootPN pin) \
                 expected=3333333333333333333333333333333333333333333333333333333333333333 \
                 actual=4444444444444444444444444444444444444444444444444444444444444444",
            ),
            (
                "mixed manifest",
                "dexdo doctor: FAIL network=shellnet\nchecks:\n  FAIL RootPN code hash \
                 expected=1111111111111111111111111111111111111111111111111111111111111111 \
                 actual=2222222222222222222222222222222222222222222222222222222222222222\n  \
                 FAIL PrivateNote code hash (RootPN pin) \
                 expected=3333333333333333333333333333333333333333333333333333333333333333 \
                 actual=4444444444444444444444444444444444444444444444444444444444444444",
            ),
            (
                "unreadable observation",
                "observe live RootPN/PrivateNote generation: shellnet returned unreadable account state",
            ),
        ];

        for (name, doctor_error) in cases {
            let temp = tempfile::tempdir().expect("temp dir");
            let ops = FakeNoteDeployResolvedOps {
                recovery: Some(test_recovery_state()),
                pool_path: temp.path().join(format!("{name}-pool.json")),
                doctor_preflight_error: Some(doctor_error),
                ..Default::default()
            };
            let error = assert_note_deploy_generation_rejected_before_writes(ops).await;
            let rendered = format!("{error:#}");
            assert!(
                rendered.starts_with(crate::cli::machine::NOTE_DEPLOY_GENERATION_MISMATCH_MARKER),
                "{name}: {rendered}"
            );
            assert!(rendered.contains(doctor_error), "{name}: {rendered}");

            let code =
                crate::cli::machine::classify_error(crate::cli::machine::OP_NOTE_DEPLOY, &error);
            assert_eq!(code, crate::cli::machine::ErrorCode::StaleClient, "{name}");
            assert_eq!(code.as_str(), "STALE_CLIENT", "{name}");
            assert_eq!(
                code.safe_message(),
                crate::cli::machine::NOTE_DEPLOY_GENERATION_MISMATCH_MESSAGE,
                "{name}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_orchestration_completed_recovery_bypasses_unavailable_cache_and_finalizes_pool(
    ) {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut recovery = test_recovery_state();
        recovery
            .mark_private_note_deployed(format!("0:{}", "4".repeat(64)), "5".repeat(64), 1)
            .expect("record active note");
        recovery
            .mark_shell_funded_and_checked()
            .expect("record completed funding");

        let mut ops = FakeNoteDeployResolvedOps {
            recovery: Some(recovery),
            pool_path: temp.path().join("completed-pool.json"),
            cache_unavailable_or_contended: true,
            ..Default::default()
        };
        super::run_note_deploy_resolved(&mut ops)
            .await
            .expect("completed recovery must finalize while the prover cache is unavailable");

        assert_eq!(ops.preflight_calls, 0);
        assert_eq!(ops.wallet_submits, 0);
        assert_eq!(ops.proof_calls, 0);
        assert_eq!(ops.chain_resumes, 0);
        assert_eq!(ops.pool_finalizations, 1);
        assert_eq!(
            ops.events,
            [
                "doctor_preflight",
                "recovery_load",
                "completed_recovery",
                "pool_finalize"
            ]
        );
        assert!(
            ops.pool_path.exists(),
            "completed recovery did not write pool"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_orchestration_persisted_proofs_bypass_contended_cache_and_resume_chain() {
        use crate::cli::note::NoteDeployVoucherKind;

        let temp = tempfile::tempdir().expect("temp dir");
        let mut recovery = test_recovery_state();
        let owner_public_key_hex = recovery.owner_public_key_hex.clone();
        recovery
            .set_voucher_checkpoint(
                NoteDeployVoucherKind::Deposit,
                persisted_voucher_checkpoint(
                    &owner_public_key_hex,
                    recovery.token_type,
                    recovery.raw_value,
                    false,
                    'b',
                ),
            )
            .expect("persist deposit proof");
        recovery
            .set_voucher_checkpoint(
                NoteDeployVoucherKind::ShellGas,
                persisted_voucher_checkpoint(
                    &owner_public_key_hex,
                    2,
                    recovery.ecc_shell_deposit,
                    true,
                    'f',
                ),
            )
            .expect("persist SHELL proof");

        let mut ops = FakeNoteDeployResolvedOps {
            recovery: Some(recovery),
            pool_path: temp.path().join("persisted-proofs-pool.json"),
            cache_unavailable_or_contended: true,
            ..Default::default()
        };
        super::run_note_deploy_resolved(&mut ops)
            .await
            .expect("persisted proofs must resume chain while the prover cache is contended");

        assert_eq!(ops.preflight_calls, 0);
        assert_eq!(ops.wallet_submits, 0);
        assert_eq!(ops.proof_calls, 0);
        assert_eq!(ops.chain_resumes, 1);
        assert_eq!(ops.pool_finalizations, 1);
        assert_eq!(
            ops.events,
            [
                "doctor_preflight",
                "recovery_load",
                "chain_resume",
                "pool_finalize"
            ]
        );
        assert!(ops.pool_path.exists(), "chain recovery did not write pool");
        assert!(ops.deposit_proof_preserved);
        assert!(ops.shell_proof_preserved);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_orchestration_fresh_recovery_preflights_before_first_wallet_submit() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut ops = FakeNoteDeployResolvedOps {
            recovery: Some(test_recovery_state()),
            pool_path: temp.path().join("fresh-pool.json"),
            ..Default::default()
        };

        super::run_note_deploy_resolved(&mut ops)
            .await
            .expect("fresh recovery should preflight, prove, resume, and finalize");

        assert_eq!(ops.preflight_calls, 1);
        assert_eq!(ops.doctor_preflight_calls, 1);
        assert_eq!(ops.recovery_loads, 1);
        assert_eq!(ops.key_material_actions, 1);
        assert_eq!(ops.wallet_signs, 1);
        assert_eq!(ops.wallet_submits, 1);
        assert_eq!(ops.voucher_generations, 1);
        assert_eq!(ops.proof_calls, 1);
        assert_eq!(ops.chain_resumes, 1);
        assert_eq!(ops.pool_finalizations, 1);
        assert_eq!(
            ops.events,
            [
                "doctor_preflight",
                "recovery_load",
                "prover_preflight",
                "wallet_submit",
                "prove",
                "chain_resume",
                "pool_finalize"
            ]
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_pk_removal_failure_never_publishes_marker() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path();
        let srs = b"valid removal-failure SRS";
        let expected = super::sha256_hex(srs);
        write_test_file(dir, super::HERMEZ_SRS_NAME, srs);
        write_test_file(dir, "pk_cache.bin", b"stale");

        let error = super::ensure_hermez_srs_and_valid_pk_cache_with_options(
            dir,
            srs.len() as u64,
            &expected,
            no_fetch,
            |cache_dir| {
                super::invalidate_stale_pk_cache_with(cache_dir, |path| {
                    if path.file_name().is_some_and(|name| name == "pk_cache.bin") {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "injected removal failure",
                        ))
                    } else {
                        std::fs::remove_file(path)
                    }
                })
            },
        )
        .await
        .expect_err("removal failure must fail pre-flight");

        assert!(
            error.to_string().contains("injected removal failure"),
            "{error:#}"
        );
        assert!(!dir.join(super::HERMEZ_SRS_MARKER_NAME).exists());
        assert!(dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME).exists());
        assert!(dir.join("pk_cache.bin").exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_deploy_failed_download_preserves_previous_srs_bytes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path();
        let previous_srs = b"previously valid SRS";
        write_test_file(dir, super::HERMEZ_SRS_NAME, previous_srs);
        let expected_new_sha = super::sha256_hex(b"new expected SRS");

        let error = super::ensure_hermez_srs_and_valid_pk_cache_with_options(
            dir,
            b"new expected SRS".len() as u64,
            &expected_new_sha,
            |_| async { Err(anyhow::anyhow!("injected interrupted download")) },
            super::invalidate_stale_pk_cache,
        )
        .await
        .expect_err("failed replacement download");

        assert!(
            error.to_string().contains("injected interrupted download"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(dir.join(super::HERMEZ_SRS_NAME)).expect("read previous SRS"),
            previous_srs
        );
        assert!(!dir.join(super::HERMEZ_SRS_MARKER_NAME).exists());
        assert!(!dir.join(super::HERMEZ_SRS_PENDING_MARKER_NAME).exists());
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_prover_cache_lock_serializes_times_out_and_releases_on_drop() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().to_path_buf();
        let lock = super::acquire_note_deploy_prover_cache_lock_with_timeout(
            &dir,
            std::time::Duration::from_secs(1),
        )
        .expect("first lock");
        let contender = std::thread::spawn(move || {
            super::acquire_note_deploy_prover_cache_lock_with_timeout(
                &dir,
                std::time::Duration::from_secs(1),
            )
            .expect_err("second acquirer must time out")
        });
        let error = contender.join().expect("contender thread");
        assert!(
            error.to_string().contains("prover cache busy: waited 1s"),
            "{error:#}"
        );

        drop(lock);
        super::acquire_note_deploy_prover_cache_lock_with_timeout(
            temp.path(),
            std::time::Duration::from_secs(1),
        )
        .expect("lock after guard drop");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_fs2_contended_lock_error_is_retryable_on_this_platform() {
        let error = fs2::lock_contended_error();
        assert!(
            super::note_deploy_lock_is_contended(&error),
            "fs2's platform-specific contention error must enter the bounded retry path"
        );
    }

    /// regression: note withdraw is an owner-signed PrivateNote write. A mismatched --note-key must
    /// hit the existing owner-key guidance before `withdrawTokens` can surface a bare ERR_INVALID_SENDER 101.
    #[test]
    fn note_withdraw_checks_owner_before_submit() {
        let source = include_str!("note_cmd.rs");
        let start = source
            .find("pub(crate) async fn run_note_withdraw")
            .expect("run_note_withdraw present");
        let end = source[start..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| start + offset)
            .expect("run_note_withdraw cfg end present");
        let body = &source[start..end];
        let guard = body
            .find("assert_note_owner_matches(\"note withdraw\"")
            .expect("note withdraw owner-key guard present");
        let submit = body
            .find("withdraw_note_tokens")
            .expect("note withdraw submit present");
        assert!(
            guard < submit,
            "note withdraw must check note owner key before submitting withdrawTokens"
        );
    }

    /// the command body is read-only and address-only: no key read and no signed/write helper.
    #[test]
    fn note_balance_command_path_is_read_only() {
        let source = include_str!("note_cmd.rs");
        let start = source
            .find("pub(crate) async fn run_note_balance")
            .expect("run_note_balance present");
        // Cover BOTH cfg variants (the shellnet implementation and the
        // not(shellnet) fallback stub): end at the next command handler.
        let end = source[start..]
            .find("/// `dexdo note withdraw`")
            .map(|offset| start + offset)
            .expect("run_note_balance end marker present");
        let body = &source[start..end];
        assert_eq!(
            body.matches("pub(crate) async fn run_note_balance").count(),
            2,
            "expected both run_note_balance variants in the inspected range: {body}"
        );
        assert!(body.contains(".get_account("), "{body}");
        assert!(
            body.contains(".assert_note_balance_private_note_account("),
            "{body}"
        );
        assert!(body.contains(".private_note_details("), "{body}");
        let get_account = body.find(".get_account(").unwrap();
        let identity_guard = body
            .find(".assert_note_balance_private_note_account(")
            .unwrap();
        let get_details = body.find(".private_note_details(").unwrap();
        let render = body.rfind("render_note_balance(&view)").unwrap();
        assert!(
            get_account < identity_guard && identity_guard < get_details && get_details < render,
            "identity guard must run after get_account and before getter/render: {body}"
        );
        for forbidden in [
            "read_secret_hex",
            "note_key",
            "KeyPair",
            ".submit(",
            ".call(",
            "withdraw_note_tokens",
        ] {
            assert!(
                !body.contains(forbidden),
                "run_note_balance contains forbidden write/key path {forbidden}: {body}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_json_is_one_object_with_documented_fields() {
        let rendered = super::note_deploy_json_result(
            "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "N100",
            dexdo_core::params::SHELL_CURRENCY_ID,
            std::path::Path::new("pn_pool.json"),
            1,
        )
        .expect("serialize note deploy result");
        assert_eq!(rendered.lines().count(), 1);
        let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON object");
        assert!(value.is_object());
        assert_eq!(value["schema"], "dexdo.note_deploy.v1");
        assert_eq!(value["status"], "deployed");
        assert_eq!(
            value["note_addr"],
            "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(value["nominal"], "N100");
        assert_eq!(value["token_type"], dexdo_core::params::SHELL_CURRENCY_ID);
        assert_eq!(value["pool_path"], "pn_pool.json");
        assert_eq!(value["note_count"], 1);
        assert!(value["error"].is_null());
        assert_eq!(value.as_object().expect("object").len(), 8);
    }
}
