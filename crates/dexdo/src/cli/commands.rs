//! `dexdo` CLI command handlers(`seller`/`buyer`/`monitor`/`provision`/`destroy`/`recover`), split out of
//! `main.rs`(PR3, move-only). Behavior-identical to the pre-split handlers.

pub(crate) use crate::cli::accumulator::run_accumulator;
pub(crate) use crate::cli::admin::{
    run_destroy, run_market_deploy, run_provision, run_provision_with_deal_gas_overhead,
};
use crate::cli::args::*;
pub(crate) use crate::cli::close::run_close;
use crate::cli::deals;
pub(crate) use crate::cli::market_views::{
    run_executable_book, run_market, run_market_data, run_quote,
};
pub(crate) use crate::cli::markets::run_markets;
pub(crate) use crate::cli::monitor::run_monitor;
pub(crate) use crate::cli::note_cmd::{
    run_note_balance, run_note_deploy, run_note_outstanding, run_note_recover, run_note_topup,
    run_note_transfer, run_note_wallet, run_note_withdraw,
};
pub(crate) use crate::cli::oracle::run_oracle;
pub(crate) use crate::cli::orders::run_orders;
#[cfg(feature = "shellnet")]
use crate::cli::policy;
pub(crate) use crate::cli::recover::{
    run_dispute, run_reclaim, run_recover, run_release_dispute, run_resolve_dispute_timeout,
    run_withdraw_shell,
};
pub(crate) use crate::cli::reports::{
    run_dashboard, run_deals, run_export, run_history, run_status,
};
pub(crate) use crate::cli::seller::{run_seller, run_seller_with_deal_gas_overhead};
pub(crate) use crate::cli::settlement_receipt::run_settlement_receipt;
use crate::cli::support::*;
use anyhow::{bail, Context as _, Result};
#[cfg(feature = "shellnet")]
use dexdo::registry::{
    default_model_registry_address, resolve_registered_model_identity, ModelRegistryReader,
};
#[cfg(feature = "shellnet")]
use dexdo::registry::{
    enforce_model_registry_policy as enforce_model_registry_policy_with_reader,
    ShellnetModelRegistryReader,
};
use dexdo::registry::{
    BuyerMissingBookPolicy, RegistryBookAction, RegistryRole, RegistryValidationInput,
    RegistryValidationPolicy,
};
#[cfg(feature = "shellnet")]
use dexdo_core::params::{
    DEFAULT_CONTRACTS_PATH, EXECUTABLE_READ_BACKOFF, POOL_LOCK_POLL_INTERVAL,
    POOL_LOCK_TIMEOUT_SECS,
};
#[cfg(feature = "shellnet")]
use dexdo_core::shellnet::LiveBookOrder;
#[cfg(feature = "shellnet")]
use dexdo_core::OrderBookSnapshot;
use dexdo_core::{
    model_hash_for, DobParams, MockChainBackend, OfferListing, OrderBookOrder, ProtocolConsts,
};
#[cfg(feature = "shellnet")]
use serde_json::{json, Value};
#[cfg(any(feature = "shellnet", test))]
use std::future::Future;
#[cfg(feature = "shellnet")]
use std::io::Write as _;
#[cfg(feature = "shellnet")]
use zeroize::Zeroizing;

#[cfg(any(feature = "shellnet", test))]
pub(crate) async fn direct_chain_read_with_timeout<T>(
    timeout_secs: u64,
    read: impl Future<Output = Result<T>>,
) -> Result<T> {
    let duration = std::time::Duration::from_secs(timeout_secs);
    match tokio::time::timeout(duration, read).await {
        Ok(result) => result,
        Err(_) => bail!(
            "chain read timed out after {timeout_secs}s; retry or use `dexdo market-data` where applicable"
        ),
    }
}

#[cfg(feature = "shellnet")]
pub(crate) struct DealTarget {
    pub(crate) handle: Option<deals::DealHandle>,
    pub(crate) token_contract: String,
    pub(crate) role: Option<deals::DealHandleRole>,
    pub(crate) note_addr: Option<String>,
    pub(crate) market: Option<dexdo_core::MarketManifest>,
}

pub(crate) struct RuntimeDealHandleInput<'a> {
    pub(crate) role: deals::DealHandleRole,
    pub(crate) deals_dir: Option<&'a std::path::Path>,
    pub(crate) token_contract: &'a str,
    pub(crate) note_addr: &'a str,
    pub(crate) frame_model: &'a str,
    pub(crate) market: Option<&'a dexdo_core::MarketManifest>,
    pub(crate) market_path: Option<&'a std::path::Path>,
    pub(crate) contracts: &'a std::path::Path,
    pub(crate) endpoint: Option<deals::DealEndpointInfo>,
    pub(crate) created_order_ids: Vec<u128>,
}

#[cfg(feature = "shellnet")]
pub(crate) struct PoolRecoveryInputs {
    pub(crate) note_addr: String,
    pub(crate) note_secret_hex: Zeroizing<String>,
    pub(crate) token_contract: String,
    pub(crate) pool_record: Option<PoolRecoveryRecord>,
}

#[cfg(feature = "shellnet")]
pub(crate) struct PoolRecoveryRecord {
    pub(crate) pool_path: std::path::PathBuf,
    pub(crate) note_addr: String,
    pub(crate) note_secret_hex: Zeroizing<String>,
    pub(crate) token_contract: String,
    pub(crate) role: String,
}

#[cfg(feature = "shellnet")]
pub(crate) struct PoolWriteLock {
    path: std::path::PathBuf,
    pool_path: std::path::PathBuf,
    /// The OS advisory lock on the sentinel file, held for exactly as long as the sentinel exists.
    /// The sentinel records a PID together with the OS host name whose process table gives that PID
    /// meaning. A PID still is not evidence by itself: it outlives the process that wrote it and it
    /// is reused. This handle makes same-host liveness observable -- the kernel drops an advisory
    /// lock when the process holding it dies, however it died, including under SIGKILL where no
    /// `Drop` runs. Reclaim therefore requires a same-host identity match before it trusts either
    /// the advisory lock or the PID probe.
    /// `fs2` is the mechanism this client already locks with -- `acquire_seller_pool_lock`
    /// (`crates/dexdo/src/cli/seller.rs`) and the note-deploy wallet lock
    /// (`crates/dexdo/src/cli/note_cmd.rs`) are the same call.
    file: Option<std::fs::File>,
}

#[cfg(feature = "shellnet")]
impl Drop for PoolWriteLock {
    fn drop(&mut self) {
        // Unlink BEFORE releasing, and this order is load-bearing. A recovery that opened
        // this sentinel while the advisory lock was still held is refused as contended, and one
        // that opens after the unlink finds nothing to reclaim and takes the lock the ordinary way.
        // Releasing first would leave a moment in which the sentinel is present and unlocked: a
        // recovery landing in that moment would claim it, and the next line here would then delete
        // the lock it had just legitimately taken.
        // The fallback is for the platform that refuses to remove a file while it is still open;
        // this handle is opened with the sharing that allows it, so the first attempt is expected
        // to succeed, and the sentinel must not survive an ordinary release either way -- one that
        // did would read to the next run as a crashed holder.
        let unlinked = std::fs::remove_file(&self.path).is_ok();
        self.file.take();
        if !unlinked {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn note_pubkey_id(pk: &dexdo_core::NotePubkey) -> String {
    pk.ed.iter().map(|b| format!("{b:02x}")).collect()
}

fn persist_runtime_deal_handle(
    input: RuntimeDealHandleInput<'_>,
    network: &str,
) -> Result<deals::DealHandle> {
    let market = match input.market {
        Some(market) => Some(market.clone()),
        None => input.market_path.map(load_market).transpose()?,
    };
    let h = deals::DealHandle {
        version: deals::DEAL_HANDLE_VERSION,
        handle: deals::make_handle_id(input.token_contract, input.role),
        role: input.role,
        network: network.to_string(),
        token_contract: input.token_contract.to_string(),
        note_addr: input.note_addr.to_string(),
        frame_model: input.frame_model.to_string(),
        model_hash: Some(model_hash_for(input.frame_model)),
        order_book: market.as_ref().map(|m| m.inference_order_book.clone()),
        root_model: market.as_ref().map(|m| m.root_model.clone()),
        market,
        contracts: input.contracts.display().to_string(),
        endpoint: input.endpoint,
        created_order_ids: input.created_order_ids,
        created_at_unix: deals::now_unix()?,
    };
    deals::validate_deal_handle(&h)?;
    let dir = deals::resolve_deals_dir(input.deals_dir)?;
    deals::save_deal_handle(&dir, &h)?;
    Ok(h)
}

pub(crate) fn save_mock_runtime_deal_handle(
    input: RuntimeDealHandleInput<'_>,
) -> Result<deals::DealHandle> {
    persist_runtime_deal_handle(input, "mock")
}

#[cfg(feature = "shellnet")]
pub(crate) fn load_pool_json(path: &std::path::Path) -> Result<Value> {
    let path = crate::cli::note::resolve_private_file_path(path, "DEXDO_PN_POOL")?;
    let bytes = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("read DEXDO_PN_POOL {}: {e}", path.display()))?;
    let pool = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse DEXDO_PN_POOL {}: {e}", path.display()))?;
    crate::cli::note::ensure_shell_pool_currency(&pool)?;
    Ok(pool)
}

#[cfg(feature = "shellnet")]
pub(crate) fn validate_existing_pool_if_present(path: &std::path::Path) -> Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => bail!("read --pool {}: {error}", path.display()),
    };
    let pool = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("--pool {} is not valid JSON: {error}", path.display()))?;
    crate::cli::note::ensure_shell_pool_currency(&pool)
}

#[cfg(feature = "shellnet")]
pub(crate) fn acquire_pool_write_lock(pool_path: &std::path::Path) -> Result<PoolWriteLock> {
    acquire_pool_write_lock_inner(pool_path, true)
}

#[cfg(feature = "shellnet")]
pub(crate) fn try_acquire_pool_write_lock(pool_path: &std::path::Path) -> Result<PoolWriteLock> {
    acquire_pool_write_lock_inner(pool_path, false)
}

/// The sentinel path for one pool file, and the resolved pool path itself.
/// One place, so the acquiring path and the recovery path can never disagree about which file the
/// lock IS.
#[cfg(feature = "shellnet")]
fn pool_write_lock_paths(
    pool_path: &std::path::Path,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let pool_path = crate::cli::note::resolve_private_file_path(pool_path, "DEXDO_PN_POOL")?;
    let mut lock_name = pool_path.as_os_str().to_os_string();
    lock_name.push(".lock");
    Ok((std::path::PathBuf::from(lock_name), pool_path))
}

/// Is this error the platform saying somebody else holds the advisory lock?
#[cfg(feature = "shellnet")]
fn pool_lock_is_contended(error: &std::io::Error) -> bool {
    error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        || error.kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(feature = "shellnet")]
#[derive(serde::Deserialize, serde::Serialize)]
struct PoolWriteLockHolder {
    pid: u32,
    host: String,
}

#[cfg(feature = "shellnet")]
enum RecordedPoolWriteLockHolder {
    HostAware(PoolWriteLockHolder),
    LegacyPid(u32),
}

#[cfg(feature = "shellnet")]
fn parse_pool_write_lock_holder(recorded: &str) -> Option<RecordedPoolWriteLockHolder> {
    if let Ok(pid) = recorded.parse::<u32>() {
        return Some(RecordedPoolWriteLockHolder::LegacyPid(pid));
    }
    serde_json::from_str::<PoolWriteLockHolder>(recorded)
        .ok()
        .filter(|holder| !holder.host.is_empty())
        .map(RecordedPoolWriteLockHolder::HostAware)
}

/// The operating system's name for this host.
/// Rust's standard library has no hostname query. The target-specific dependencies already used by
/// this crate expose the native query, so the lock does not need another identity crate or a
/// filesystem-dependent substitute.
#[cfg(feature = "shellnet")]
fn current_pool_lock_host_identity() -> Result<String> {
    #[cfg(unix)]
    {
        let mut identity = std::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: uname initializes the caller-owned utsname on success. The return value is
        // checked before the value is assumed initialized.
        if unsafe { libc::uname(identity.as_mut_ptr()) } != 0 {
            bail!(
                "query host identity with uname: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: the successful uname call above initialized every field.
        let identity = unsafe { identity.assume_init() };
        let end = identity
            .nodename
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                anyhow::anyhow!("uname returned a host identity without a terminator")
            })?;
        let bytes = identity.nodename[..end]
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        let host = String::from_utf8(bytes)
            .context("uname returned a host identity that is not valid UTF-8")?;
        if host.is_empty() {
            bail!("uname returned an empty host identity");
        }
        return Ok(host);
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::WindowsProgramming::{
            GetComputerNameW, MAX_COMPUTERNAME_LENGTH,
        };

        let mut identity = vec![0_u16; MAX_COMPUTERNAME_LENGTH as usize + 1];
        let mut length = identity.len() as u32;
        // SAFETY: the buffer is writable for length UTF-16 code units, and length points to an
        // initialized count. GetComputerNameW writes at most that many units and updates the count.
        if unsafe { GetComputerNameW(identity.as_mut_ptr(), &mut length) } == 0 {
            bail!(
                "query host identity with GetComputerNameW: {}",
                std::io::Error::last_os_error()
            );
        }
        let host = String::from_utf16(&identity[..length as usize])
            .context("GetComputerNameW returned an invalid host identity")?;
        if host.is_empty() {
            bail!("GetComputerNameW returned an empty host identity");
        }
        return Ok(host);
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("this platform has no supported host identity query");
    }
}

#[cfg(feature = "shellnet")]
fn encode_pool_write_lock_holder(holder: &PoolWriteLockHolder) -> Result<String> {
    serde_json::to_string(holder).context("encode pool lock holder identity")
}

/// Is the process a sentinel recorded still running? `None` when this platform cannot say.
/// SECOND signal, never the first. A PID is reused and it outlives the process that wrote it, so
/// this can never establish on its own that a holder is gone -- [`reclaim_pool_write_lock_if_holder_is_gone`]
/// uses it only to REFUSE, by requiring the advisory lock and this to agree before anything is
/// taken over. What it is here to catch is the one direction the advisory lock alone gets wrong: a
/// sentinel written by a build that did not take the lock carries none, and a live holder of one
/// would otherwise read as gone.
/// This is a local process-table query. A host-aware sentinel reaches it only after its recorded
/// host matches this host; a foreign-host sentinel is refused before either local signal is used.
/// `kill(pid, 0)` is the POSIX existence check -- it performs the permission and existence test and
/// delivers no signal. Its three answers map exactly onto the three this returns, and anything else
/// is `None` rather than a guess.
#[cfg(feature = "shellnet")]
pub(crate) fn recorded_holder_is_running(pid: u32) -> Option<bool> {
    #[cfg(unix)]
    {
        // 0 and negatives are process GROUP selectors to `kill`, not process ids, and a value past
        // `pid_t` cannot name one at all. None of them is a question this can answer.
        if pid == 0 || pid > i32::MAX as u32 {
            return None;
        }
        // SAFETY: `kill` with signal 0 is a pure existence/permission query on a value already
        // checked to be a representable, positive `pid_t`. It writes nothing, delivers nothing, and
        // borrows nothing.
        let answered = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if answered == 0 {
            return Some(true);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            // No process bears this id.
            Some(libc::ESRCH) => Some(false),
            // One does, and it is not ours to signal. Still running.
            Some(libc::EPERM) => Some(true),
            _ => None,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// Take over a pool lock whose holder is PROVABLY gone, and only then.
/// `--resume` is the crash-recovery entry point, and a buyer that was SIGKILLed mid-submit left a
/// sentinel behind: `Drop` never ran, nothing else removes one, and every later attempt -- including
/// the recovery attempt -- was refused for the lifetime of the file. The safety property and the
/// recovery path contradicted each other and the safety property won by accident of implementation.
/// What makes taking it over defensible is that the verdict is LIVENESS, not absence:
/// * a host-aware sentinel must name this host. Advisory locks and process tables are local
/// signals, so neither is consulted for a foreign host; the host-identity refusal names the
/// recorded host, this host, and the two signals it cannot trust. A pid-only legacy sentinel
/// cannot make that check and keeps the pre- two-signal fallback for compatibility.
/// * the first signal is the OS advisory lock every holder takes on the sentinel for as long as
/// it holds it. The kernel releases it when the holding process dies, whatever killed it, so a
/// lock that is still held is a holder that is still running, and a live holder is refused -- in
/// those words, rather than as a bare "already held".
/// * an UNLOCKED sentinel is not, by itself, evidence that the holder is gone. A sentinel written
/// by a build that did not take the lock carries none while its holder is alive and well, so
/// lock-absence alone would report that live holder as gone -- the one direction in which this
/// could fail open, and the only one, since every other branch refuses. So the second signal has
/// to agree: the recorded process must ALSO not be running. The PID is still never sufficient --
/// it is reused, and it is not consulted at all until the lock is already free -- but it is
/// necessary, and two independent signals saying "gone" is what a take-over costs.
/// * anything this cannot establish -- a foreign or unreadable host identity, an unreadable or
/// unparseable sentinel, a lock error that is not contention, a platform that cannot answer the
/// liveness question, an unlocked sentinel whose recorded process IS running, or a read-back
/// that does not find our own claim -- is a refusal. Doubt fails closed, in the words of the
/// doubt.
/// Taking the lock over does NOT mean forgetting what it guarded. The caller reclaims it only in
/// order to run the by-fact reconciliation the buyer money journal exists for, before any second
/// submission is allowed; see `raise_pending_buyer_money_before_fresh_reads`.
/// Returns `Ok(None)` when there is no sentinel at all -- nothing to reclaim, and the caller takes
/// the lock the ordinary way.
#[cfg(feature = "shellnet")]
pub(crate) fn reclaim_pool_write_lock_if_holder_is_gone(
    pool_path: &std::path::Path,
) -> Result<Option<PoolWriteLock>> {
    use std::io::{Read as _, Seek as _};

    let (lock_path, pool_path) = pool_write_lock_paths(pool_path)?;
    match std::fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => bail!("pool lock {} must be a regular file", lock_path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("inspect pool lock {}: {e}", lock_path.display()),
    }
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!(
            "cannot establish whether the holder of pool lock {} is still running: opening it \
             failed with {e}",
            lock_path.display()
        ),
    };
    // The recorded holder. Its host decides whether the two local liveness signals below are
    // meaningful; the raw text is also what refusals name so an operator can inspect the claim.
    let recorded = {
        let mut recorded = String::new();
        match file.read_to_string(&mut recorded) {
            Ok(_) => recorded.trim().to_string(),
            Err(_) => String::new(),
        }
    };
    let recorded_holder = parse_pool_write_lock_holder(&recorded);
    let shown = match &recorded_holder {
        Some(RecordedPoolWriteLockHolder::HostAware(holder)) => {
            format!("pid {} on host {:?}", holder.pid, holder.host)
        }
        Some(RecordedPoolWriteLockHolder::LegacyPid(pid)) => format!("pid {pid}"),
        None if recorded.is_empty() => "nothing".to_string(),
        None => format!("unparseable value {recorded:?}"),
    };
    let host_for_claim = match &recorded_holder {
        Some(RecordedPoolWriteLockHolder::HostAware(holder)) => {
            let this_host = match current_pool_lock_host_identity() {
                Ok(host) => host,
                Err(error) => bail!(
                    concat!(
                        "host identity check for pool lock {} saw recorded host {:?}, but reading ",
                        "this host failed with {:#}; it needed the same host before the ",
                        "advisory-lock and PID liveness signals could be trusted, so nothing was ",
                        "reclaimed"
                    ),
                    lock_path.display(),
                    holder.host,
                    error
                ),
            };
            if holder.host != this_host {
                bail!(
                    concat!(
                        "host identity check for pool lock {} saw recorded host {:?}, but this host ",
                        "is {:?}; it needed the same host before the advisory-lock and PID liveness ",
                        "signals could be trusted, so nothing was reclaimed"
                    ),
                    lock_path.display(),
                    holder.host,
                    this_host
                );
            }
            Some(this_host)
        }
        Some(RecordedPoolWriteLockHolder::LegacyPid(_)) | None => None,
    };
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {}
        Err(e) if pool_lock_is_contended(&e) => bail!(
            "pool lock {} is held by a process that is still running (it recorded {shown}); this is \
             a live holder, not a leftover",
            lock_path.display()
        ),
        Err(e) => bail!(
            "cannot establish whether the holder of pool lock {} is still running: locking it \
             failed with {e}",
            lock_path.display()
        ),
    }
    // The lock is free. That is NOT yet a holder that is gone: a sentinel written by a build that
    // did not take the lock carries none while its holder is alive, so the recorded process has to
    // agree before anything is taken over.
    let recorded_pid = match &recorded_holder {
        Some(RecordedPoolWriteLockHolder::HostAware(holder)) => Some(holder.pid),
        Some(RecordedPoolWriteLockHolder::LegacyPid(pid)) => Some(*pid),
        None => None,
    };
    match recorded_pid.and_then(recorded_holder_is_running) {
        Some(false) => {}
        Some(true) => bail!(
            "pool lock {} carries no lock, but the process it records is running ({shown}); an \
             unlocked sentinel is not evidence its holder is gone, so this is undecidable and \
             nothing was reclaimed",
            lock_path.display()
        ),
        None => bail!(
            "cannot establish whether the holder of pool lock {} is still running: it records \
             {shown}, and this platform cannot answer that for it; nothing was reclaimed",
            lock_path.display()
        ),
    }
    // Both signals say the holder is gone. Claim the sentinel as ours by recording this process,
    // then read it back BY PATH: if the file we just locked had already been unlinked by a reclaim
    // that completed between our open and our lock, the read-back finds a different sentinel -- or
    // none -- and we refuse rather than run beside whoever created it.
    let ours = match host_for_claim {
        Some(host) => encode_pool_write_lock_holder(&PoolWriteLockHolder {
            pid: std::process::id(),
            host,
        })?,
        // A pre- sentinel has no host identity to validate. Preserve its pid-only format while
        // applying the exact advisory-lock plus local-pid fallback it was written for.
        None => std::process::id().to_string(),
    };
    let claim = |file: &mut std::fs::File| -> std::io::Result<()> {
        // Rewind before truncating: the read above left the cursor at the end of the old pid, and
        // writing there would leave that many NUL bytes in front of ours.
        file.rewind()?;
        file.set_len(0)?;
        writeln!(file, "{ours}")?;
        file.flush()
    };
    if let Err(e) = claim(&mut file) {
        bail!(
            "claim pool lock {} after its holder was found gone: {e}",
            lock_path.display()
        );
    }
    match std::fs::read_to_string(&lock_path) {
        Ok(observed) if observed.trim() == ours => {}
        Ok(observed) => bail!(
            "pool lock {} was taken by another process while it was being reclaimed (it now \
             records {}); nothing was reclaimed",
            lock_path.display(),
            observed.trim()
        ),
        Err(e) => bail!(
            "cannot confirm the reclaimed pool lock {} is the one now held: {e}",
            lock_path.display()
        ),
    }
    Ok(Some(PoolWriteLock {
        path: lock_path,
        pool_path,
        file: Some(file),
    }))
}

#[cfg(feature = "shellnet")]
fn acquire_pool_write_lock_inner(pool_path: &std::path::Path, wait: bool) -> Result<PoolWriteLock> {
    let (lock_path, pool_path) = pool_write_lock_paths(pool_path)?;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(POOL_LOCK_TIMEOUT_SECS);
    loop {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&lock_path) {
            Ok(mut lock) => {
                let holder = current_pool_lock_host_identity().and_then(|host| {
                    encode_pool_write_lock_holder(&PoolWriteLockHolder {
                        pid: std::process::id(),
                        host,
                    })
                });
                let holder = match holder {
                    Ok(holder) => holder,
                    Err(error) => {
                        let _ = std::fs::remove_file(&lock_path);
                        return Err(error.context(format!(
                            "record host identity in pool lock {}",
                            lock_path.display()
                        )));
                    }
                };
                if let Err(e) = writeln!(lock, "{holder}") {
                    let _ = std::fs::remove_file(&lock_path);
                    return Err(anyhow::anyhow!(
                        "write pool lock {}: {e}",
                        lock_path.display()
                    ));
                }
                // the sentinel first binds this PID to this host. Hold the OS advisory
                // lock for as long as it exists, so a same-host recovery can tell THIS holder still
                // running from THIS holder having died without releasing. Nobody else can hold it:
                // the file was created a line ago by an atomic `create_new`.
                if let Err(e) = fs2::FileExt::try_lock_exclusive(&lock) {
                    let _ = std::fs::remove_file(&lock_path);
                    return Err(anyhow::anyhow!(
                        "hold pool lock {}: {e}",
                        lock_path.display()
                    ));
                }
                return Ok(PoolWriteLock {
                    path: lock_path,
                    pool_path,
                    file: Some(lock),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match std::fs::symlink_metadata(&lock_path) {
                    Ok(metadata) if metadata.file_type().is_file() => {}
                    Ok(_) => bail!("pool lock {} must be a regular file", lock_path.display()),
                    Err(inspect) if inspect.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(inspect) => {
                        bail!("inspect pool lock {}: {inspect}", lock_path.display())
                    }
                }
                if !wait {
                    bail!("pool lock {} is already held", lock_path.display());
                }
                if std::time::Instant::now() >= deadline {
                    bail!(
                        "timed out after {POOL_LOCK_TIMEOUT_SECS}s waiting for pool lock {}; another pool writer may still be active",
                        lock_path.display()
                    );
                }
                std::thread::sleep(POOL_LOCK_POLL_INTERVAL);
            }
            Err(e) => bail!("create pool lock {}: {e}", lock_path.display()),
        }
    }
}

/// Hold the write lock for one update of a pool-shaped FILE, and let a dead holder's sentinel go.
/// Everything that comes through here is a plain file write -- the pool JSON, the buyer money
/// journal, the buyer subscription state, the pool recovery record, the note-deploy fold -- and every
/// one of them lands atomically(`write_pool_private` -> `write_private_atomic`). So the file a
/// crashed holder leaves behind is whole either way, and its sentinel asserts one thing only:
/// somebody is writing this file RIGHT NOW. It is not the buyer money lock, which asserts that a
/// money submission is awaiting by-fact reconciliation; that one is taken through
/// [`try_acquire_pool_write_lock`] by `BuyerMoneyLock` and stays gated on the recovery entry point,
/// because taking IT over means promising to reconcile first.
/// Here there is nothing to reconcile, so a same-host holder both local signals say is gone is
/// simply not a holder, and no command has to earn the right to say so. That is why this is not
/// gated on `--resume`: a dead mutex wedges every writer, and gating would leave a fresh buy,
/// `note deploy` and `recover` refused forever by a process that no longer exists.
/// It is what still stood in front of `--resume` after the money lock learned to reclaim.
/// `run_buyer_inner`'s FIRST statement is `preflight_buyer_pool_for_money_move`, which arrives here
/// on the pool file ahead of every reclaim seam the money lock has; and `write_buyer_submit_journal`
/// arrives here from inside the money-lock hold, behind them. A buyer SIGKILLed mid-submit holds the
/// money lock and is inside one of those writes, so it leaves both sentinels -- and either one alone
/// refused recovery for the lifetime of the file.
/// The proof is [`reclaim_pool_write_lock_if_holder_is_gone`]'s and it is not weakened to reuse it:
/// a foreign host is refused before local signals are trusted, a held same-host advisory lock is a
/// live holder, an unlocked sentinel whose recorded process is still running is undecidable, and
/// anything that cannot be established is a refusal. A refusal does not fail the update -- it falls
/// through to the ordinary acquire, which waits for a live holder exactly as it did before and names
/// what could not be established if that wait runs out. So doubt always lands on the unchanged
/// behaviour and never on a take-over: the check errs towards leaving the
/// sentinel alone, which costs an operator-visible stall, rather than towards taking it, which would
/// cost two writers on one money-adjacent file.
#[cfg(feature = "shellnet")]
pub(crate) fn with_pool_write_lock<T>(
    pool_path: &std::path::Path,
    update: impl FnOnce(&std::path::Path) -> Result<T>,
) -> Result<T> {
    let lock = match reclaim_pool_write_lock_if_holder_is_gone(pool_path) {
        Ok(Some(reclaimed)) => {
            eprintln!(
                "pool_write_lock_reclaimed {} was left behind by a process that is no longer \
                 running; taken over for this write",
                reclaimed.path.display()
            );
            reclaimed
        }
        // No sentinel: nothing to reclaim, and the ordinary rules apply.
        Ok(None) => acquire_pool_write_lock(pool_path)?,
        // Not proof the holder is gone. Wait for it exactly as before, and if that wait runs out,
        // say what could not be established rather than reporting a live writer.
        Err(undecided) => acquire_pool_write_lock(pool_path)
            .map_err(|waited| waited.context(format!("{undecided:#}")))?,
    };
    update(&lock.pool_path)
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_pool_path(explicit: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    if let Some(root) = crate::cli::data_dir::explicit() {
        return Some(root.join("pn_pool.json"));
    }
    match std::env::var_os("DEXDO_PN_POOL") {
        Some(raw) if !raw.is_empty() => Some(std::path::PathBuf::from(raw)),
        _ => None,
    }
}

/// The explicitly supplied recovery identity, normalized once for both the single-target resolver and
/// the multi-target plan: `(--note-addr, --token-contract/--market)`.
#[cfg(feature = "shellnet")]
fn explicit_recovery_identity(
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let explicit_tc = if market.is_some() || token_contract.is_some() {
        let (tc, _frame, _nonce) = resolve_market_fields(market, token_contract, None)?;
        Some(dexdo_core::normalize_wallet_address(&tc).map_err(|e| anyhow::anyhow!("{e}"))?)
    } else {
        None
    };
    let explicit_note_addr = identity
        .note_addr
        .as_deref()
        .map(dexdo_core::normalize_wallet_address)
        .transpose()
        .map_err(|e| anyhow::anyhow!("--note-addr: {e}"))?;
    Ok((explicit_note_addr, explicit_tc))
}

/// `--note-addr` + `--note-key` + `--token-contract/--market` fully determine one deal; the pool is not
/// read at all in that case. Returns the signing identity of that deal: `(note, owner key, TC)`.
#[cfg(feature = "shellnet")]
fn fully_explicit_recovery_identity(
    identity: &RecoveryIdentityArgs,
    explicit_note_addr: Option<&String>,
    explicit_tc: Option<&String>,
) -> Result<Option<(String, Zeroizing<String>, String)>> {
    let (Some(note_addr), Some(note_key), Some(tc)) = (
        explicit_note_addr,
        identity.note_key.as_deref(),
        explicit_tc,
    ) else {
        return Ok(None);
    };
    Ok(Some((
        note_addr.clone(),
        read_secret_hex(note_key, "--note-key")?.into(),
        tc.clone(),
    )))
}

/// The owner key a recovery signs with: an explicit `--note-key` overrides the key recorded next to the
/// entry. Exactly one copy of the secret is produced, and it is moved, never cloned.
#[cfg(feature = "shellnet")]
fn recovery_note_secret(
    identity: &RecoveryIdentityArgs,
    recorded: String,
) -> Result<Zeroizing<String>> {
    match identity.note_key.as_deref() {
        Some(path) => Ok(read_secret_hex(path, "--note-key")?.into()),
        None => Ok(recorded.into()),
    }
}

/// Every pool note entry that records a `token_contract` and matches the explicitly supplied filters --
/// **every role**, including `seller`. Role selection belongs to the caller: a seller row for the same
/// note and TokenContract as a buyer row is a same-deal contradiction that a buyer-side plan must be able
/// to see, while a seller row for some other deal is simply not part of that plan.
#[cfg(feature = "shellnet")]
fn matching_pool_recovery_records(
    command: &str,
    pool: Option<&std::path::Path>,
    explicit_note_addr: Option<&String>,
    explicit_tc: Option<&String>,
) -> Result<(
    std::path::PathBuf,
    Vec<crate::cli::note::PoolNoteRecoveryRecord>,
)> {
    let Some(pool_path) = note_pool_path(pool) else {
        bail!(
            "{command}: pass --note-addr, --note-key, and --token-contract/--market, or pass --pool / set \
             DEXDO_PN_POOL containing this note entry with token_contract recovery metadata"
        );
    };
    let pool_path = crate::cli::note::resolve_private_file_path(&pool_path, "DEXDO_PN_POOL")?;
    let pool = load_pool_json(&pool_path)?;
    let records = crate::cli::note::pool_note_recovery_records(&pool)?
        .into_iter()
        .filter(|record| {
            explicit_note_addr.is_none_or(|want| *want == record.note_addr)
                && explicit_tc.is_none_or(|want| *want == record.token_contract)
        })
        .collect::<Vec<_>>();
    Ok((pool_path, records))
}

/// the pool records several recoverable deals and `recover`/`dispute` act on exactly one.
/// Returned as a typed error instead of a bare message so the caller can resolve the choice from chain
/// facts and then ask for that one deal **by name**, through the same resolver, rather than opening a
/// second path into the money. It carries addresses only -- the recorded owner keys stay inside the
/// resolver, so nothing that decides *which* deal is acted on has ever seen one.
/// `Display` is the unchanged refusal an operator sees when nothing resolves the choice.
#[cfg(feature = "shellnet")]
#[derive(Debug)]
pub(crate) struct AmbiguousRecoveryDeals {
    message: String,
    /// The pool file these deals were read from, already resolved through any symlink.
    pub(crate) pool: std::path::PathBuf,
    /// Every selectable deal as `(note address, TokenContract address)`, in the plan's recorded order.
    pub(crate) deals: Vec<(String, String)>,
}

#[cfg(feature = "shellnet")]
impl std::fmt::Display for AmbiguousRecoveryDeals {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[cfg(feature = "shellnet")]
impl std::error::Error for AmbiguousRecoveryDeals {}

/// Resolve the one deal `dispute` acts on. `dispute` persists nothing back into the pool.
#[cfg(feature = "shellnet")]
pub(crate) fn resolve_pool_recovery_inputs(
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
) -> Result<PoolRecoveryInputs> {
    resolve_recovery_inputs("dispute", identity, market, token_contract, pool, false, None)
}

/// the same resolution, narrowed to the one recorded deal the caller has proved from the chain is
/// the one this invocation acts on.
#[cfg(feature = "shellnet")]
pub(crate) fn resolve_pool_recovery_inputs_for_deal(
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
    deal: &(String, String),
) -> Result<PoolRecoveryInputs> {
    resolve_recovery_inputs(
        "dispute",
        identity,
        market,
        token_contract,
        pool,
        false,
        Some(deal),
    )
}

/// Resolve the one deal `recover` acts on. `recover` writes the resolved buyer record back into the pool
/// after its STOP and is the only consumer of `PoolRecoveryInputs::pool_record`.
#[cfg(feature = "shellnet")]
pub(crate) fn resolve_persistable_pool_recovery_inputs(
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
) -> Result<PoolRecoveryInputs> {
    resolve_recovery_inputs("recover", identity, market, token_contract, pool, true, None)
}

/// the same resolution, narrowed to the one recorded deal the caller has proved from the chain is
/// the one this invocation acts on. The pool record `recover` writes back is still built only from what
/// the pool itself recorded, exactly as it is for a pool holding a single deal.
#[cfg(feature = "shellnet")]
pub(crate) fn resolve_persistable_pool_recovery_inputs_for_deal(
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
    deal: &(String, String),
) -> Result<PoolRecoveryInputs> {
    resolve_recovery_inputs(
        "recover",
        identity,
        market,
        token_contract,
        pool,
        true,
        Some(deal),
    )
}

/// Resolve the ONE deal `recover`/`dispute` acts on out of everything the pool records.
/// the selection is made from [`pool_recovery_plan`] -- the same primitive `reclaim` drives --
/// rather than from the raw row list, because the raw row count is not the number of deals. Rows that
/// agree on every recorded fact describe ONE deal recorded twice, and the plan collapses them; the
/// row count did not, so a pool holding a duplicated entry refused with `pass --note-addr or
/// --token-contract to disambiguate` while both rows carried the SAME note and the SAME
/// TokenContract. Neither flag can separate values that are equal, so the advice could not be
/// followed and that deal's escrow had no way out short of hand-copying the owner key out of the pool
/// file. Failing closed on a genuine ambiguity is right; refusing where there was none, with no
/// alternative, is money stranded by the client rather than by the chain.
/// What did NOT change is the money decision. One invocation still acts on one deal, and fanning a
/// buyer STOP or a bond-locking dispute across every recorded deal remains a different decision that
/// belongs to whoever asks for it.
/// follow-up: with several deals and `selected == None` this still REFUSES, returning
/// [`AmbiguousRecoveryDeals`] naming each deal so `--token-contract` can select it. `selected` is that
/// same one-deal decision made for the operator, and only where the chain itself proved it: the caller
/// reads every recorded deal and comes back naming the one the chain places in the state the command
/// acts on. It re-enters here rather than driving the plan directly, so the recorded owner key, the
/// contradiction rules and the record `recover` persists all stay in one place. The plan is re-read
/// rather than trusted from the caller's first read: a pool that changed in between, or a choice that
/// is no longer exactly one recorded deal, is refused.
#[cfg(feature = "shellnet")]
fn resolve_recovery_inputs(
    command: &str,
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
    persists_pool_record: bool,
    selected: Option<&(String, String)>,
) -> Result<PoolRecoveryInputs> {
    let mut plan = pool_recovery_plan(command, identity, market, token_contract, pool)?;
    if let Some((want_note, want_tc)) = selected {
        plan.targets
            .retain(|target| &target.note_addr == want_note && &target.token_contract == want_tc);
        if plan.targets.len() != 1 {
            let want_note = dexdo_core::address::display(want_note);
            let want_tc = dexdo_core::address::display_self_dapp(want_tc);
            bail!(
                "{command}: DEXDO_PN_POOL {} no longer records exactly one recoverable deal for note \
                 {want_note} and TokenContract {want_tc} ({} found); nothing was submitted",
                plan.pool_path
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new("-"))
                    .display(),
                plan.targets.len()
            );
        }
    }
    if plan.targets.len() > 1 {
        // Every selectable deal is named, so the operator picks one instead of being told to narrow
        // a set they cannot see. Addresses only: a target also holds the recorded owner key.
        let choices = plan
            .targets
            .iter()
            .map(|target| {
                format!(
                    "\n  --note-addr {} --token-contract {}",
                    dexdo_core::address::display(&target.note_addr),
                    dexdo_core::address::display_self_dapp(&target.token_contract)
                )
            })
            .collect::<String>();
        let pool_path = plan
            .pool_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("-"));
        return Err(anyhow::Error::new(AmbiguousRecoveryDeals {
            message: format!(
                "{command}: DEXDO_PN_POOL {} records {} recoverable deals and {command} acts on one; \
                 pass --note-addr and/or --token-contract to disambiguate, naming exactly one of:{choices}",
                pool_path.display(),
                plan.targets.len()
            ),
            deals: plan
                .targets
                .iter()
                .map(|target| (target.note_addr.clone(), target.token_contract.clone()))
                .collect(),
            pool: pool_path,
        }));
    }
    let Some(target) = plan.targets.pop() else {
        // The plan itself refuses an empty pool, so reaching here means every recorded deal was
        // contradicted. Each contradiction says which entry and why, which is what the operator needs
        // to repair the pool -- a bare count never was.
        bail!(
            "{command}: DEXDO_PN_POOL {} records no recoverable deal; every matching entry was refused:\n  {}",
            plan.pool_path
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("-"))
                .display(),
            plan.refused
                .iter()
                .map(|refusal| refusal.reason.clone())
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    };
    // One deal is selected, but a contradicted sibling is still the operator's money and stays
    // unrecoverable until the pool is fixed. Saying so here is the only report it gets: this command
    // is about to act on a different deal and will otherwise look like a clean success.
    for refusal in &plan.refused {
        eprintln!("{command}: skipped recovery entry: {}", refusal.reason);
    }
    // Built only for the caller that persists it, and only when the whole identity came from the pool:
    // no other path carries a second copy of the recorded owner key.
    let pool_record = (persists_pool_record
        && identity.note_addr.is_none()
        && identity.note_key.is_none()
        && market.is_none()
        && token_contract.is_none())
    .then(|| {
        plan.pool_path.map(|pool_path| PoolRecoveryRecord {
            pool_path,
            note_addr: target.note_addr.clone(),
            note_secret_hex: target.note_secret_hex.clone(),
            token_contract: target.token_contract.clone(),
            role: target.role.clone(),
        })
    })
    .flatten();
    Ok(PoolRecoveryInputs {
        note_addr: target.note_addr,
        note_secret_hex: target.note_secret_hex,
        token_contract: target.token_contract,
        pool_record,
    })
}

/// One deal a pool-only recovery may act on: exactly the facts the driver signs and decides with, and
/// nothing else. A target still carries no `PoolRecoveryRecord` -- the recorded owner key is held once,
/// by the consumer that actually reads it, and a persistence record is built by the one caller that
/// persists rather than handed to every caller that drives.
#[cfg(feature = "shellnet")]
pub(crate) struct PoolRecoveryTarget {
    pub(crate) note_addr: String,
    pub(crate) note_secret_hex: Zeroizing<String>,
    pub(crate) token_contract: String,
    /// The entry's recorded `token_contract_updated_at_unix`, never the reader's clock.
    pub(crate) recorded_at_unix: Option<u64>,
    /// The entry's recorded `token_contract_role` (`buyer` or `unknown`; a coherent `seller` row is
    /// never a buyer-side target). Carried because `recover` must name the row it is writing back to
    /// (`persist_pool_recovery_record_locked` matches on role), and re-reading the pool to recover a
    /// fact this plan already read is how a resolved record and a persisted one drift apart.
    pub(crate) role: String,
}

/// A recorded entry the plan refuses to act on because the pool's own records contradict each other.
#[cfg(feature = "shellnet")]
pub(crate) struct PoolRecoveryRefusal {
    pub(crate) note_addr: String,
    pub(crate) token_contract: String,
    pub(crate) reason: String,
}

/// Every deal a pool-only recovery can drive, in a deterministic order, plus the entries it refuses.
#[cfg(feature = "shellnet")]
pub(crate) struct PoolRecoveryPlan {
    pub(crate) targets: Vec<PoolRecoveryTarget>,
    pub(crate) refused: Vec<PoolRecoveryRefusal>,
    /// The pool file these targets were read from, already resolved through any symlink, or
    /// `None` when the identity was given in full on the command line and no pool was read at all.
    pub(crate) pool_path: Option<std::path::PathBuf>,
}

/// plan a recovery from recorded pool metadata alone. Where
/// [`resolve_pool_recovery_inputs`] resolves exactly one deal and refuses as soon as the pool holds a
/// second recoverable entry, this returns **all** recorded deals so the caller can drive each of them as
/// its own individually idempotent action -- an ordinary pool holds one entry per deal the note took part
/// in, and after a crash the pool file is all the operator has.
/// Money-safety rules enforced here, before any chain contact:
/// * exactly one planned target per recorded deal -- rows for the same note and TokenContract collapse
/// only when **every** recorded fact agrees(owner key, role and recorded time); a row that agrees on
/// the deal but disagrees on any of them -- including one row calling the note the buyer and another
/// calling it the seller -- is a contradiction, not a duplicate, and is refused with it;
/// * a note whose records contradict each other(the same note claiming two different TokenContracts) is
/// refused outright, and so is a TokenContract claimed by more than one note. These are counted over
/// the **complete** buyer-side candidate set, contradicted deals included, so a contradiction refuses
/// every deal it touches instead of quietly clearing the way for its own sibling;
/// * a recorded `seller` deal is not a buyer-side candidate at all: a note that sold one deal and bought
/// another is ordinary, and its seller record neither joins nor blocks the buyer plan;
/// * the order is taken from the recorded `token_contract_updated_at_unix` (entries with a recorded time
/// first, earliest first; entries without one last), tie-broken by the recorded note/TokenContract
/// addresses -- never from the reader's wall clock and never from the entry's position in the file, so
/// permuting the pool file cannot change what runs or in which order.
#[cfg(feature = "shellnet")]
pub(crate) fn resolve_pool_recovery_plan(
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
) -> Result<PoolRecoveryPlan> {
    pool_recovery_plan("reclaim", identity, market, token_contract, pool)
}

/// The plan itself, named by the command whose messages it will appear in.
/// `reclaim` drives every target. `recover` and `dispute` act on ONE -- and this function does not pick
/// it for them: given several targets they REFUSE, and act only if the caller comes back naming the one
/// deal the chain proved is the only one they can act on (`resolve_recovery_inputs`'s `selected`,
/// ). Two live deals, or a chain that cannot answer for one of them, still refuse. Both commands
/// read the pool through this one function, so what counts as a deal, what counts as a contradiction
/// and what order entries come back in cannot diverge between them.
#[cfg(feature = "shellnet")]
fn pool_recovery_plan(
    command: &str,
    identity: &RecoveryIdentityArgs,
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    pool: Option<&std::path::Path>,
) -> Result<PoolRecoveryPlan> {
    let (explicit_note_addr, explicit_tc) =
        explicit_recovery_identity(identity, market, token_contract)?;
    if let Some((note_addr, note_secret_hex, token_contract)) = fully_explicit_recovery_identity(
        identity,
        explicit_note_addr.as_ref(),
        explicit_tc.as_ref(),
    )? {
        return Ok(PoolRecoveryPlan {
            targets: vec![PoolRecoveryTarget {
                note_addr,
                note_secret_hex,
                token_contract,
                recorded_at_unix: None,
                // Nothing was read from a pool, so there is no recorded row to write back to.
                role: String::new(),
            }],
            refused: Vec::new(),
            pool_path: None,
        });
    }
    let (pool_path, records) = matching_pool_recovery_records(
        command,
        pool,
        explicit_note_addr.as_ref(),
        explicit_tc.as_ref(),
    )?;

    // One candidate per recorded deal, in a key order fixed by the recorded addresses. A candidate is
    // either coherent(one agreed row) or contradicted(rows that disagree); both are candidates, so a
    // contradiction is still counted when deciding whether some other deal is ambiguous.
    let mut by_deal: std::collections::BTreeMap<
        (String, String),
        Vec<crate::cli::note::PoolNoteRecoveryRecord>,
    > = std::collections::BTreeMap::new();
    for record in records {
        by_deal
            .entry((record.note_addr.clone(), record.token_contract.clone()))
            .or_default()
            .push(record);
    }
    let mut candidates: Vec<(crate::cli::note::PoolNoteRecoveryRecord, Option<String>)> =
        Vec::new();
    for ((_, token_contract), rows) in by_deal {
        let first = &rows[0];
        let disagreeing = rows
            .iter()
            .filter(|row| {
                row.owner_secret_hex != first.owner_secret_hex
                    || row.role != first.role
                    || row.recorded_at_unix != first.recorded_at_unix
            })
            .count();
        if disagreeing == 0 {
            // A coherent `seller` record is this note's own sold deal, not a buyer recovery entry.
            if first.role == "seller" {
                continue;
            }
            candidates.push((rows.into_iter().next().expect("group is never empty"), None));
            continue;
        }
        // A contradicted deal is a buyer-side concern only if some row claims the buyer side.
        if !rows
            .iter()
            .any(|row| row.role == "buyer" || row.role == "unknown")
        {
            continue;
        }
        let reason = format!(
            "DEXDO_PN_POOL {} holds {} rows for TokenContract {} whose recorded facts \
             disagree (owner key, role or recorded time); refusing to guess which row is the deal -- fix \
             the pool or pass explicit --note-addr/--note-key/--token-contract",
            pool_path.display(),
            rows.len(),
            dexdo_core::address::display_self_dapp(&token_contract),
        );
        candidates.push((
            rows.into_iter().next().expect("group is never empty"),
            Some(reason),
        ));
    }
    if candidates.is_empty() {
        bail!(
            "{command}: DEXDO_PN_POOL {} has no matching note entry with token_contract recovery metadata; \
             run the buyer once with this pool active, or pass explicit --note-addr/--note-key/--token-contract",
            pool_path.display()
        );
    }
    if candidates.len() > 1 && identity.note_key.is_some() {
        bail!(
            "{command}: DEXDO_PN_POOL {} has {} matching recovery entries and --note-key names a single \
             note's owner key; pass --note-addr to select that entry, or drop --note-key so each entry is \
             driven with its own recorded owner key",
            pool_path.display(),
            candidates.len()
        );
    }
    // Counted over the complete candidate set -- contradicted deals included -- and over addresses only,
    // so the recorded owner key is never copied to decide admissibility.
    let mut deals_per_note: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut notes_per_tc: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (record, _) in &candidates {
        *deals_per_note.entry(record.note_addr.clone()).or_default() += 1;
        *notes_per_tc
            .entry(record.token_contract.clone())
            .or_default() += 1;
    }

    let mut refused = Vec::new();
    let mut targets = Vec::new();
    for (record, contradiction) in candidates {
        let deals_for_note = deals_per_note[&record.note_addr];
        let notes_for_tc = notes_per_tc[&record.token_contract];
        if let Some(reason) = contradiction {
            refused.push(PoolRecoveryRefusal {
                reason,
                note_addr: record.note_addr,
                token_contract: record.token_contract,
            });
            continue;
        }
        if deals_for_note > 1 {
            refused.push(PoolRecoveryRefusal {
                reason: format!(
                    "DEXDO_PN_POOL {} holds {deals_for_note} contradictory recovery records for note {}; \
                     refusing to act on any of them -- fix the pool or pass explicit \
                     --note-addr/--note-key/--token-contract for the intended deal",
                    pool_path.display(),
                    dexdo_core::address::display(&record.note_addr)
                ),
                note_addr: record.note_addr,
                token_contract: record.token_contract,
            });
            continue;
        }
        if notes_for_tc > 1 {
            refused.push(PoolRecoveryRefusal {
                reason: format!(
                    "DEXDO_PN_POOL {} has {notes_for_tc} different notes recorded as the buyer of \
                     TokenContract {}; refusing to act on a contradictory record -- fix the pool or pass \
                     explicit --note-addr/--note-key/--token-contract for the intended deal",
                    pool_path.display(),
                    dexdo_core::address::display_self_dapp(&record.token_contract)
                ),
                note_addr: record.note_addr,
                token_contract: record.token_contract,
            });
            continue;
        }
        targets.push(PoolRecoveryTarget {
            note_secret_hex: recovery_note_secret(identity, record.owner_secret_hex)?,
            note_addr: explicit_note_addr.clone().unwrap_or(record.note_addr),
            token_contract: explicit_tc.clone().unwrap_or(record.token_contract),
            recorded_at_unix: record.recorded_at_unix,
            role: record.role,
        });
    }
    targets.sort_by(|left, right| plan_order_key(left).cmp(&plan_order_key(right)));
    refused.sort_by(|left, right| {
        (&left.note_addr, &left.token_contract).cmp(&(&right.note_addr, &right.token_contract))
    });
    Ok(PoolRecoveryPlan {
        targets,
        refused,
        pool_path: Some(pool_path),
    })
}

/// The total order a plan runs in, made of recorded facts only: entries carrying a recorded time come
/// first and earliest first, entries without one come last, and both are tie-broken by the recorded
/// note and TokenContract addresses. Nothing here can vary with the pool file's row order.
#[cfg(feature = "shellnet")]
fn plan_order_key(target: &PoolRecoveryTarget) -> (bool, u64, &String, &String) {
    (
        target.recorded_at_unix.is_none(),
        target.recorded_at_unix.unwrap_or(0),
        &target.note_addr,
        &target.token_contract,
    )
}

#[cfg(feature = "shellnet")]
pub(crate) fn persist_pool_recovery_record(record: &PoolRecoveryRecord) -> Result<()> {
    with_pool_write_lock(&record.pool_path, |_| {
        persist_pool_recovery_record_locked(record)
    })
}

#[cfg(feature = "shellnet")]
fn persist_pool_recovery_record_locked(record: &PoolRecoveryRecord) -> Result<()> {
    let mut pool = load_pool_json(&record.pool_path)?;
    let notes = pool["notes"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("DEXDO_PN_POOL: malformed (\"notes\" is not an array)"))?;
    let mut matched = Vec::new();
    let mut conflicting_buyer_record = false;
    for (index, note) in notes.iter().enumerate() {
        let Some(address) = note["address"].as_str() else {
            continue;
        };
        let address = dexdo_core::normalize_wallet_address(address)
            .unwrap_or_else(|_| address.trim().to_ascii_lowercase());
        if address != record.note_addr {
            continue;
        }
        let role = note["token_contract_role"].as_str().unwrap_or("unknown");
        let secret = note["owner_secret_key_hex"].as_str();
        let tc = note["token_contract"]
            .as_str()
            .and_then(|tc| dexdo_core::normalize_wallet_address(tc).ok());
        if secret == Some(record.note_secret_hex.as_str())
            && tc.as_deref() == Some(record.token_contract.as_str())
            && role == record.role
        {
            matched.push(index);
        } else if role == "buyer" || role == "unknown" {
            conflicting_buyer_record = true;
        }
    }
    if matched.len() != 1 {
        bail!(
            "recover: DEXDO_PN_POOL {} no longer contains exactly one resolved {} recovery record for note {} and TokenContract {}; refusing to persist a wrong-key or changed record",
            record.pool_path.display(),
            record.role,
            dexdo_core::address::display(&record.note_addr),
            dexdo_core::address::display_self_dapp(&record.token_contract)
        );
    }
    if conflicting_buyer_record {
        bail!(
            "recover: DEXDO_PN_POOL {} contains a different buyer recovery record for note {}; refusing to clobber or create an ambiguous record",
            record.pool_path.display(),
            dexdo_core::address::display(&record.note_addr)
        );
    }
    let note = &mut notes[matched[0]];
    note["address"] = json!(record.note_addr);
    note["token_contract"] = json!(record.token_contract);
    note["token_contract_role"] = json!("buyer");
    note["token_contract_updated_at_unix"] = json!(unix_now_secs());
    let bytes = serde_json::to_vec_pretty(&pool)?;
    write_pool_private(&record.pool_path, &bytes)
}

#[cfg(feature = "shellnet")]
pub(crate) fn is_note_deploy_wallet_busy_error(error: &anyhow::Error) -> bool {
    let msg = error.to_string().to_ascii_lowercase();
    let norm = msg.replace(['_', '=', ':', '-'], " ");
    let exit_code_52 = norm.split("exit code").skip(1).any(|suffix| {
        suffix
            .trim_start()
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .and_then(|code| code.parse::<u32>().ok())
            == Some(52)
    });
    // bare `tvm_error` is not a busy signal; matching it masked real
    // deployPrivateNote reverts behind retries that never surfaced the cause.
    !msg.contains("rootpn.deployprivatenote")
        && (norm.contains("replay protection")
            || exit_code_52
            || norm.contains("nonce")
            || norm.contains("seqno"))
}

#[cfg(feature = "shellnet")]
fn is_note_deploy_history_proof_expired_error(error: &anyhow::Error) -> bool {
    crate::cli::note_cmd::note_deploy_has_exact_finalized_rootpn_exit_code(error, 403)
}

/// `dex::ERR_INVALID_ZKPROOF`(137) finalized by RootPN, which is the OPPOSITE of the 403 next to it.
/// 403 is a race against the node's history window and is answered by proving again; 137 says the
/// proof's public inputs disagree with the `value`/`tokenType` RootPN was handed, which no retry can
/// change. Both arrive as "the submit failed", and found them sharing one outcome -- so they are
/// separated here by the exact finalized exit code, never by matching text.
#[cfg(feature = "shellnet")]
fn is_note_deploy_zk_public_input_mismatch_error(error: &anyhow::Error) -> bool {
    crate::cli::note_cmd::note_deploy_has_exact_finalized_rootpn_exit_code(error, 137)
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_error(
    funding_multisig_address: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    let funding_multisig_address =
        dexdo_core::address::display_self_dapp(funding_multisig_address);
    if is_note_deploy_history_proof_expired_error(&error) {
        anyhow::anyhow!(
            "note deploy failed: history proof expired (exit 403). The same paid voucher recovery is preserved; \
             re-run the same `dexdo note deploy` command with its `--recovery` file later \
             (action=resume_same_paid_voucher_later). \
             Do not fund a new voucher. Raw error: deploy PrivateNote from wallet \
             {funding_multisig_address}: {error}"
        )
    } else if is_note_deploy_zk_public_input_mismatch_error(&error) {
        anyhow::anyhow!(
            "note deploy failed: the proof's public inputs do not match what RootPN was given \
             (exit 137, dex::ERR_INVALID_ZKPROOF). This is NOT the 403 history-proof race: proving \
             the same voucher again, on any history layer, reverts identically \
             (action=do_not_retry_this_voucher). Raw error: deploy PrivateNote from wallet \
             {funding_multisig_address}: {error}"
        )
    } else if is_note_deploy_wallet_busy_error(&error) {
        anyhow::anyhow!(
            "note deploy wallet busy/out-of-sync for funding wallet {funding_multisig_address}: a previous \
             wallet transaction is likely still pending or the wallet nonce cache is stale. Retry after the prior \
             `dexdo note deploy` reaches a terminal state; local deploys are serialized by a wallet lock."
        )
    } else {
        anyhow::anyhow!("deploy PrivateNote from wallet {funding_multisig_address}: {error}")
    }
}

pub(crate) fn load_enabled_model_registry_policy(
    role: RegistryRole,
    args: &ModelRegistryValidationArgs,
    contracts: &std::path::Path,
) -> Result<Option<RegistryValidationPolicy>> {
    let policy = RegistryValidationPolicy::load(
        &RegistryValidationInput {
            config_path: args.model_registry_validation.clone(),
            address_override: args.model_registry_address.clone(),
        },
        contracts,
    )?;
    if policy.check_enabled(role) {
        Ok(Some(policy))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "shellnet")]
pub(crate) async fn preload_model_registry_policy(
    role: RegistryRole,
    policy: Option<&RegistryValidationPolicy>,
    contracts: &std::path::Path,
) -> Result<()> {
    preload_model_registry_policy_with_endpoint(role, policy, contracts, None).await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn preload_model_registry_policy_with_endpoint(
    role: RegistryRole,
    policy: Option<&RegistryValidationPolicy>,
    contracts: &std::path::Path,
    endpoint: Option<&str>,
) -> Result<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    ShellnetModelRegistryReader::from_manifest_with_endpoint(
        contracts,
        endpoint,
        policy.required_address(role)?,
    )?
        .read_account_once()
        .await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn preload_default_model_registry(contracts: &std::path::Path) -> Result<()> {
    preload_default_model_registry_with_endpoint(contracts, None).await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn preload_default_model_registry_with_endpoint(
    contracts: &std::path::Path,
    endpoint: Option<&str>,
) -> Result<()> {
    let registry_address = default_model_registry_address(contracts)?;
    ShellnetModelRegistryReader::from_manifest_with_endpoint(
        contracts,
        endpoint,
        &registry_address,
    )?
    .read_account_once()
    .await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn enforce_model_registry_policy(
    role: RegistryRole,
    policy: &RegistryValidationPolicy,
    contracts: &std::path::Path,
    frame_model: &str,
    expected_order_book: &str,
    order_book_active: bool,
    buyer_missing_book_policy: BuyerMissingBookPolicy,
) -> Result<RegistryBookAction> {
    enforce_model_registry_policy_with_endpoint(
        role,
        policy,
        contracts,
        None,
        frame_model,
        expected_order_book,
        order_book_active,
        buyer_missing_book_policy,
    )
    .await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn enforce_model_registry_policy_with_endpoint(
    role: RegistryRole,
    policy: &RegistryValidationPolicy,
    contracts: &std::path::Path,
    endpoint: Option<&str>,
    frame_model: &str,
    expected_order_book: &str,
    order_book_active: bool,
    buyer_missing_book_policy: BuyerMissingBookPolicy,
) -> Result<RegistryBookAction> {
    let registry_address = policy.required_address(role)?;
    let reader = ShellnetModelRegistryReader::from_manifest_with_endpoint(
        contracts,
        endpoint,
        registry_address,
    )?;
    enforce_model_registry_policy_with_reader(
        &reader,
        role,
        policy,
        frame_model,
        expected_order_book,
        order_book_active,
        buyer_missing_book_policy,
    )
    .await
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn enforce_model_registry_policy(
    role: RegistryRole,
    policy: &RegistryValidationPolicy,
    contracts: &std::path::Path,
    frame_model: &str,
    expected_order_book: &str,
    order_book_active: bool,
    buyer_missing_book_policy: BuyerMissingBookPolicy,
) -> Result<RegistryBookAction> {
    let _ = (
        role,
        policy,
        contracts,
        frame_model,
        expected_order_book,
        order_book_active,
        buyer_missing_book_policy,
    );
    bail!("ModelRegistry validation requires a shellnet build")
}

#[cfg(feature = "shellnet")]
async fn resolve_model_registry_target_with_reader(
    reader: &dyn ModelRegistryReader,
    role: RegistryRole,
    policy: &RegistryValidationPolicy,
    requested_model: &str,
    mut target: BookTarget,
) -> Result<BookTarget> {
    let registry_address = policy.required_address(role)?;
    let identity =
        resolve_registered_model_identity(reader, role, registry_address, requested_model).await?;
    if target.order_book.is_some()
        && (target.frame_model != identity.registry_model
            || !target.model_hash.eq_ignore_ascii_case(&identity.model_hash)
            || !target
                .order_book
                .as_deref()
                .is_some_and(|book| book.eq_ignore_ascii_case(&identity.order_book)))
    {
        let registry_address = dexdo_core::address::display(registry_address);
        let identity_order_book = dexdo_core::address::display(&identity.order_book);
        let target_order_book = dexdo_core::address::display_opt(target.order_book.as_deref(), "-");
        bail!(
            "{} model registry check failed: requested model {} resolved to exact ModelRegistry {} \
             identity {} (modelHash {}, orderBook {}), but the selected market target is {} \
             (modelHash {}, orderBook {})",
            role.as_str(),
            requested_model,
            registry_address,
            identity.registry_model,
            identity.model_hash,
            identity_order_book,
            target.frame_model,
            target.model_hash,
            target_order_book
        );
    }
    target.frame_model = identity.registry_model;
    target.model_hash = identity.model_hash;
    Ok(target)
}

#[cfg(feature = "shellnet")]
pub(crate) async fn resolve_model_registry_target(
    role: RegistryRole,
    policy: Option<&RegistryValidationPolicy>,
    contracts: &std::path::Path,
    requested_model: &str,
    target: BookTarget,
) -> Result<BookTarget> {
    resolve_model_registry_target_with_endpoint(
        role,
        policy,
        contracts,
        None,
        requested_model,
        target,
    )
    .await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn resolve_model_registry_target_with_endpoint(
    role: RegistryRole,
    policy: Option<&RegistryValidationPolicy>,
    contracts: &std::path::Path,
    endpoint: Option<&str>,
    requested_model: &str,
    target: BookTarget,
) -> Result<BookTarget> {
    let Some(policy) = policy else {
        return Ok(target);
    };
    let registry_address = policy.required_address(role)?;
    let reader = ShellnetModelRegistryReader::from_manifest_with_endpoint(
        contracts,
        endpoint,
        registry_address,
    )?;
    resolve_model_registry_target_with_reader(&reader, role, policy, requested_model, target).await
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn resolve_model_registry_target(
    role: RegistryRole,
    policy: Option<&RegistryValidationPolicy>,
    contracts: &std::path::Path,
    requested_model: &str,
    target: BookTarget,
) -> Result<BookTarget> {
    if policy.is_none() {
        return Ok(target);
    }
    let _ = (role, contracts, requested_model);
    bail!("ModelRegistry validation requires a shellnet build")
}

/// Resolve a model name against the ModelRegistry the way the BUYER resolves it, and refuse if it
/// does not resolve.
/// The lookup is `resolve_registered_model_identity` against the registry named by the contracts
/// manifest -- the same function, the same candidate order and the same failure text the buyer's
/// content-identity preflight produces. The point is that both sides ask the SAME question: the
/// buyer's version is mandatory, and the seller's used to be reachable only through
/// `resolve_model_registry_target`, which returns its target untouched when no
/// `--model-registry-validation` config is passed. The guard was there; on the default path nothing
/// called it, and a seller could deploy a whole market for a name no buyer could ever resolve.
/// **Answer only.** The resolved registry name is returned but deliberately not substituted for what
/// the operator asked for: renaming the market under the seller would change the derived
/// `model_hash` and the book with it, which is the separate canonicalisation question.
/// This says yes or no, before money moves.
#[cfg(feature = "shellnet")]
pub(crate) async fn resolve_registry_content_identity(
    role: RegistryRole,
    contracts: &std::path::Path,
    endpoint: Option<&str>,
    requested_model: &str,
) -> Result<String> {
    let registry_address = default_model_registry_address(contracts).with_context(|| {
        format!(
            "read default ModelRegistry address from {} for content identity",
            contracts.display()
        )
    })?;
    let reader = ShellnetModelRegistryReader::from_manifest_with_endpoint(
        contracts,
        endpoint,
        &registry_address,
    )?;
    let identity =
        resolve_registered_model_identity(&reader, role, &registry_address, requested_model)
            .await?;
    Ok(identity.registry_model)
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn resolve_registry_content_identity(
    role: RegistryRole,
    contracts: &std::path::Path,
    endpoint: Option<&str>,
    requested_model: &str,
) -> Result<String> {
    let _ = (role, contracts, endpoint, requested_model);
    bail!("content identity ModelRegistry resolution requires a shellnet build")
}

#[cfg(all(test, feature = "shellnet"))]
mod registry_target_tests {
    use super::*;
    use async_trait::async_trait;
    use dexdo::registry::ModelRegistryEntry;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const REGISTRY: &str = "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXACT_BOOK: &str = "0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const LEGACY_BOOK: &str = "0:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const NOTE: &str = "0:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const REQUESTED: &str = "qwen--qwen3--32b";
    const EXACT: &str = "Qwen/Qwen3-32B";

    #[derive(Default)]
    struct FakeReader {
        entries: BTreeMap<String, ModelRegistryEntry>,
        queries: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ModelRegistryReader for FakeReader {
        async fn model(&self, frame_model: &str) -> Result<Option<ModelRegistryEntry>> {
            self.queries
                .lock()
                .expect("query lock")
                .push(frame_model.to_string());
            Ok(self.entries.get(frame_model).cloned())
        }
    }

    fn policy() -> RegistryValidationPolicy {
        RegistryValidationPolicy {
            network: "shellnet".to_string(),
            registry_address: Some(REGISTRY.to_string()),
            seller_check_model_registry: true,
            seller_deploy_missing_order_book: true,
            buyer_check_model_registry: true,
            source: None,
            address_overridden: false,
        }
    }

    fn reader() -> FakeReader {
        FakeReader {
            entries: BTreeMap::from([(
                EXACT.to_string(),
                ModelRegistryEntry {
                    exists: true,
                    model_hash: model_hash_for(EXACT),
                    order_book: EXACT_BOOK.to_string(),
                },
            )]),
            queries: Mutex::new(Vec::new()),
        }
    }

    fn target(frame_model: &str, order_book: Option<&str>) -> BookTarget {
        BookTarget {
            frame_model: frame_model.to_string(),
            model_hash: model_hash_for(frame_model),
            order_book: order_book.map(str::to_string),
            root_model: None,
            note_addr: Some(NOTE.to_string()),
        }
    }

    #[tokio::test]
    async fn resolved_target_rejects_legacy_manifest_before_dispatch() {
        let error = match resolve_model_registry_target_with_reader(
            &reader(),
            RegistryRole::Seller,
            &policy(),
            REQUESTED,
            target(REQUESTED, Some(LEGACY_BOOK)),
        )
        .await
        {
            Ok(_) => panic!("legacy manifest target must fail closed"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains(REQUESTED), "{error}");
        assert!(error.contains(EXACT), "{error}");
        // the refusal names the registry's exact order book canonically; an
        // `InferenceOrderBook` is a contract of the shared dexdo DApp.
        assert!(
            error.contains(&format!(
                "{}::{}",
                dexdo_core::DEXDO_DAPP_ID,
                EXACT_BOOK.strip_prefix("0:").expect("fixture chain form")
            )),
            "{error}"
        );
    }

    #[tokio::test]
    async fn disabled_registry_policy_preserves_legacy_target() {
        let original = target(REQUESTED, Some(LEGACY_BOOK));
        let resolved = resolve_model_registry_target(
            RegistryRole::Buyer,
            None,
            std::path::Path::new("missing-contracts.json"),
            REQUESTED,
            target(REQUESTED, Some(LEGACY_BOOK)),
        )
        .await
        .unwrap();
        assert_eq!(resolved.frame_model, original.frame_model);
        assert_eq!(resolved.model_hash, original.model_hash);
        assert_eq!(resolved.order_book, original.order_book);
    }

    #[test]
    fn explicit_registry_identity_wins_over_colliding_config_key() {
        let dir = tempfile::tempdir().unwrap();
        let models = dir.path().join("models.json");
        std::fs::write(
            &models,
            r#"{
              "models": {
                "Qwen/Qwen3-32B": {
                  "frame_model": "other--model--1",
                  "base_url": "https://provider.example/v1",
                  "served_model": "other/model",
                  "api_key_env": "PROVIDER_API_KEY",
                  "tokenizer_family": "other",
                  "price_per_tick": 1
                }
              }
            }"#,
        )
        .unwrap();

        assert_eq!(registry_requested_model(&models, EXACT).unwrap(), EXACT);
    }

    #[test]
    fn explicit_registry_identity_does_not_require_models_config() {
        let missing = tempfile::tempdir().unwrap().path().join("missing.json");

        assert_eq!(
            registry_requested_model(&missing, REQUESTED).unwrap(),
            REQUESTED
        );
        assert_eq!(registry_requested_model(&missing, EXACT).unwrap(), EXACT);
    }
}

fn role_arg_to_handle(role: DealRoleArg) -> deals::DealHandleRole {
    match role {
        DealRoleArg::Buyer => deals::DealHandleRole::Buyer,
        DealRoleArg::Seller => deals::DealHandleRole::Seller,
    }
}

#[cfg(feature = "shellnet")]
pub(crate) fn load_deal_target(
    input: &str,
    deals_dir: Option<&std::path::Path>,
    raw_role: Option<DealRoleArg>,
    raw_note_addr: Option<String>,
) -> Result<DealTarget> {
    let dir = deals::resolve_deals_dir(deals_dir)?;
    if let Some((_path, handle)) = deals::resolve_deal_ref(
        input,
        &dir,
        raw_role.map(role_arg_to_handle),
        raw_note_addr.as_deref(),
    )? {
        let role = handle.role;
        let token_contract = handle.token_contract.clone();
        let note_addr = Some(handle.note_addr.clone());
        let market = handle.market.clone();
        return Ok(DealTarget {
            handle: Some(handle),
            token_contract,
            role: Some(role),
            note_addr,
            market,
        });
    }
    Ok(DealTarget {
        handle: None,
        token_contract: input.to_string(),
        role: raw_role.map(role_arg_to_handle),
        note_addr: raw_note_addr,
        market: None,
    })
}

#[cfg(feature = "shellnet")]
pub(crate) fn deal_contracts_path(
    explicit: Option<&std::path::Path>,
    target: &DealTarget,
) -> std::path::PathBuf {
    explicit
        .map(std::path::PathBuf::from)
        .or_else(|| {
            target.handle.as_ref().and_then(|h| {
                (!h.contracts.trim().is_empty()).then(|| std::path::PathBuf::from(&h.contracts))
            })
        })
        .unwrap_or_else(|| {
            crate::cli::data_dir::explicit()
                .map(|root| root.join(DEFAULT_CONTRACTS_PATH))
                .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_CONTRACTS_PATH))
        })
}

#[cfg(feature = "shellnet")]
pub(crate) async fn shellnet_doctor_preflight_market(
    contracts: &std::path::Path,
    market: Option<&dexdo_core::MarketManifest>,
) -> Result<()> {
    let contracts = contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = dexdo_core::RealChainBackend::connect(contracts)?;
    let report = chain.doctor(market).await?;
    if !report.is_ok() {
        bail!("{}", render_shellnet_doctor_report(&report));
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
pub(crate) fn save_runtime_deal_handle_for_network(
    input: RuntimeDealHandleInput<'_>,
    network: &str,
    emit_human_output: bool,
) -> Result<deals::DealHandle> {
    let h = persist_runtime_deal_handle(input, network)?;
    if emit_human_output {
        println!("deal_handle={}", h.handle);
    }
    Ok(h)
}

#[cfg(all(test, feature = "shellnet"))]
pub(crate) fn save_runtime_deal_handle(
    input: RuntimeDealHandleInput<'_>,
    emit_human_output: bool,
) -> Result<deals::DealHandle> {
    save_runtime_deal_handle_for_network(
        input,
        dexdo_core::params::DEFAULT_DOCTOR_NETWORK,
        emit_human_output,
    )
}

#[cfg(not(feature = "shellnet"))]
pub(crate) fn save_runtime_deal_handle_for_network(
    _input: RuntimeDealHandleInput<'_>,
    _network: &str,
    _emit_human_output: bool,
) -> Result<deals::DealHandle> {
    bail!("real shellnet deal handles unavailable: build with `--features shellnet`")
}

#[cfg(all(test, not(feature = "shellnet")))]
#[allow(dead_code)]
pub(crate) fn save_runtime_deal_handle(
    _input: RuntimeDealHandleInput<'_>,
    _emit_human_output: bool,
) -> Result<deals::DealHandle> {
    bail!("real shellnet deal handles unavailable: build with `--features shellnet`")
}

const GATEWAY_CHECK_STAGES: [&str; 6] = [
    "dns_resolve",
    "tcp_connect",
    "tls_handshake",
    "http2_handshake",
    "grpc_challenge",
    "challenge_response",
];

fn completed_gateway_check_stages(failed: &str) -> &'static [&'static str] {
    let barrier = match failed {
        "tls_certificate_pin" => "tls_handshake",
        stage => stage,
    };
    let completed = GATEWAY_CHECK_STAGES
        .iter()
        .position(|stage| *stage == barrier)
        .unwrap_or(0);
    &GATEWAY_CHECK_STAGES[..completed]
}

pub(crate) async fn run_gateway_check(args: GatewayCheckArgs) -> Result<()> {
    let timeout = dexdo_core::params::SellerLivenessParams::canonical().health_check_timeout;
    println!("gateway={}", args.endpoint);
    match dexdo::seller::liveness::probe_gateway_with_timeout(
        &args.endpoint,
        &args.tls_fingerprint,
        timeout,
    )
    .await
    {
        Ok(()) => {
            for stage in GATEWAY_CHECK_STAGES {
                println!("PASS stage={stage}");
            }
            Ok(())
        }
        Err(fault) => {
            for stage in completed_gateway_check_stages(fault.stage()) {
                println!("PASS stage={stage}");
            }
            println!(
                "FAIL stage={} wrong_endpoint={} error={}",
                fault.stage(),
                fault.is_wrong_endpoint(),
                fault.cause_detail()
            );
            bail!("gateway reachability check failed at {}", fault.stage())
        }
    }
}

#[cfg(feature = "shellnet")]
async fn shellnet_doctor_report(
    network: &str,
    endpoint: Option<&str>,
    contracts: &std::path::Path,
    market: Option<&std::path::Path>,
) -> Result<dexdo_core::ShellnetDoctorReport> {
    let endpoint = endpoint.or((network != "shellnet").then_some(network));
    let contracts = contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let market = market.map(load_market).transpose()?;
    let chain = dexdo_core::RealChainBackend::connect_with_endpoint(contracts, endpoint)
        .map_err(|error| doctor_contracts_error(std::path::Path::new(contracts), error))?;
    chain.doctor(market.as_ref()).await
}

#[cfg(feature = "shellnet")]
fn doctor_contracts_error(path: &std::path::Path, error: anyhow::Error) -> anyhow::Error {
    let not_found = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    });
    if not_found {
        anyhow::anyhow!(
            "contracts manifest {} not found; run `dexdo doctor` from the repository root or pass \
             `--contracts <path>` to the downloaded deployed.shellnet.json",
            path.display()
        )
    } else {
        error
    }
}

#[cfg(feature = "shellnet")]
fn render_shellnet_doctor_report(report: &dexdo_core::ShellnetDoctorReport) -> String {
    let mut out = String::new();
    let status = if report.is_ok() { "PASS" } else { "FAIL" };
    out.push_str(&format!(
        "dexdo doctor: {status} network={}\n",
        report.network
    ));
    if !report.versions.is_empty() {
        out.push_str("versions:\n");
        for (name, version) in &report.versions {
            out.push_str(&format!("  {name}: {version}\n"));
        }
    }
    out.push_str("checks:\n");
    for c in &report.checks {
        out.push_str(&format!("  {:<4} {}", c.status.as_str(), c.name));
        if let Some(addr) = &c.address {
            out.push_str(&format!(" addr={addr}"));
        }
        if let Some(expected) = &c.expected {
            out.push_str(&format!(" expected={expected}"));
        }
        if let Some(actual) = &c.actual {
            out.push_str(&format!(" actual={actual}"));
        }
        out.push_str(&format!(" - {}\n", c.message));
    }
    out
}

#[cfg(feature = "shellnet")]
pub(crate) async fn shellnet_doctor_preflight(
    contracts: &std::path::Path,
    market: Option<&std::path::Path>,
) -> Result<()> {
    shellnet_doctor_preflight_with_endpoint(contracts, None, market).await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn shellnet_doctor_preflight_with_endpoint(
    contracts: &std::path::Path,
    endpoint: Option<&str>,
    market: Option<&std::path::Path>,
) -> Result<()> {
    let deployed = dexdo_core::Deployed::load(contracts)
        .with_context(|| format!("load --contracts {}", contracts.display()))?;
    let endpoint = manifest_preflight_endpoint(&deployed, endpoint)?;
    let report = shellnet_doctor_report(
        dexdo_core::params::DEFAULT_DOCTOR_NETWORK,
        Some(&endpoint),
        contracts,
        market,
    )
    .await?;
    if !report.is_ok() {
        bail!("{}", render_shellnet_doctor_report(&report));
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn manifest_preflight_endpoint(
    deployed: &dexdo_core::Deployed,
    endpoint: Option<&str>,
) -> Result<String> {
    // `network` selects the SDK profile; it is never a Block Manager host.
    dexdo_core::resolve_endpoint(endpoint, deployed)
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn shellnet_doctor_preflight(
    _contracts: &std::path::Path,
    _market: Option<&std::path::Path>,
) -> Result<()> {
    bail!("shellnet doctor unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_doctor(args: DoctorArgs) -> Result<()> {
    let report = shellnet_doctor_report(
        &args.network,
        args.endpoint.as_deref(),
        &args.contracts,
        args.market.as_deref(),
    )
    .await?;
    print!("{}", render_shellnet_doctor_report(&report));
    println!("{}", policy::doctor_policy_line(args.policy.as_deref())?);
    if !report.is_ok() {
        bail!("doctor failed: {}", report.fail_summary());
    }
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_doctor(_args: DoctorArgs) -> Result<()> {
    bail!("shellnet doctor unavailable: build with `--features shellnet`")
}

pub(crate) struct BookTarget {
    pub(crate) frame_model: String,
    // Filled on every path; only the shellnet book/market views read these three back.
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    pub(crate) model_hash: String,
    pub(crate) order_book: Option<String>,
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    pub(crate) root_model: Option<String>,
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    pub(crate) note_addr: Option<String>,
}

#[cfg(feature = "shellnet")]
pub(crate) fn model_target_from_config(
    models: &std::path::Path,
    model: &str,
    note_addr: Option<String>,
) -> Result<BookTarget> {
    let cfg = dexdo::seller::ModelsConfig::load(models)?;
    let frame_model = cfg.get(model)?.frame_model.clone();
    Ok(BookTarget {
        model_hash: model_hash_for(&frame_model),
        frame_model,
        order_book: None,
        root_model: None,
        note_addr,
    })
}

#[cfg(feature = "shellnet")]
pub(crate) fn registry_requested_model(models: &std::path::Path, model: &str) -> Result<String> {
    if model.contains("--") || model.contains('/') {
        return Ok(model.to_string());
    }
    let cfg = dexdo::seller::ModelsConfig::load(models)?;
    Ok(cfg.get(model)?.frame_model.clone())
}

#[cfg(feature = "shellnet")]
pub(crate) fn target_from_market(path: &std::path::Path) -> Result<BookTarget> {
    let m = load_market(path)?;
    Ok(BookTarget {
        frame_model: m.frame_model,
        model_hash: m.model_hash,
        order_book: Some(m.inference_order_book),
        root_model: Some(m.root_model),
        note_addr: None,
    })
}

#[cfg(feature = "shellnet")]
pub(crate) fn target_from_market_for_model(
    path: &std::path::Path,
    models: &std::path::Path,
    requested_model: &str,
) -> Result<BookTarget> {
    let target = target_from_market(path)?;
    let requested_frame_model = if dexdo_core::validate_canonical_model_id(requested_model).is_ok()
    {
        requested_model.to_string()
    } else {
        dexdo::seller::ModelsConfig::load(models)?
            .get(requested_model)?
            .frame_model
            .clone()
    };
    let requested_hash = model_hash_for(&requested_frame_model);
    if target.frame_model != requested_frame_model || target.model_hash != requested_hash {
        bail!(
            "dexdo market requested model `{requested_model}` -> `{requested_frame_model}`, but --market is for \
             `{}` (model_hash {}): refusing to render the wrong market",
            target.frame_model,
            target.model_hash
        );
    }
    Ok(target)
}

#[cfg(feature = "shellnet")]
pub(crate) async fn read_book_target(
    chain: &dexdo_core::RealChainBackend,
    target: &BookTarget,
) -> Result<OrderBookSnapshot> {
    if let Some(ob) = &target.order_book {
        let ob =
            dexdo_core::Address::parse(ob).map_err(|e| anyhow::anyhow!("order_book {ob}: {e}"))?;
        return chain
            .inference_orderbook_snapshot(&ob, &target.frame_model, &target.model_hash)
            .await;
    }
    let note_addr = target
        .note_addr
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--note-addr is required when --market is not supplied"))?;
    let note = dexdo_core::Address::parse(note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    chain
        .inference_orderbook_snapshot_for_note(
            &note,
            &target.frame_model,
            &target.model_hash,
            dexdo_core::TICK_SIZE,
        )
        .await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn read_executable_book_target(
    chain: &dexdo_core::RealChainBackend,
    target: &BookTarget,
) -> Result<OrderBookSnapshot> {
    let mut snapshot = read_book_target(chain, target).await?;
    snapshot.orders = chain.executable_resting_asks(&snapshot).await?;
    Ok(snapshot)
}

#[cfg(feature = "shellnet")]
pub(crate) async fn resolve_order_book_target(
    chain: &dexdo_core::RealChainBackend,
    target: &BookTarget,
) -> Result<String> {
    if let Some(order_book) = target.order_book.as_deref() {
        return dexdo_core::Address::parse(order_book)
            .map(|address| address.with_workchain())
            .map_err(|error| anyhow::anyhow!("order_book {order_book}: {error}"));
    }
    let note_addr = target
        .note_addr
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--note-addr is required when --market is not supplied"))?;
    let note = dexdo_core::Address::parse(note_addr)
        .map_err(|error| anyhow::anyhow!("--note-addr {note_addr}: {error}"))?;
    chain
        .inference_orderbook_address(&note, &target.model_hash, dexdo_core::TICK_SIZE)
        .await
        .map_err(|error| market_note_getter_error(note_addr, chain.client().endpoint(), error))
        .map(|address| address.with_workchain())
}

#[cfg(feature = "shellnet")]
fn market_note_getter_error(
    note_addr: &str,
    endpoint: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    let note_addr = dexdo_core::address::display(note_addr);
    let message = format!("{error:#}").to_ascii_lowercase();
    let exit_code = message
        .split_once("exit code:")
        .and_then(|(_, suffix)| suffix.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok());
    let getter_exit_60 =
        message.contains("run_tvm getter getinferenceorderbookaddress") && exit_code == Some(60);
    if message == "note is not active" {
        anyhow::anyhow!(
            "note {note_addr} not found or not initialized on {endpoint}; verify `--note-addr` and \
             the shellnet endpoint"
        )
    } else if getter_exit_60 {
        anyhow::anyhow!(
            "market lookup failed for note {note_addr} on {endpoint} \
             (getInferenceOrderBookAddress exit 60) -- verify the note address is a deployed, \
             initialized order-book note"
        )
    } else {
        error
    }
}

#[cfg(feature = "shellnet")]
pub(crate) fn fold_snapshot_from_orders<'a>(
    target: &BookTarget,
    order_book: &str,
    orders: impl IntoIterator<Item = &'a LiveBookOrder>,
) -> OrderBookSnapshot {
    OrderBookSnapshot {
        frame_model: target.frame_model.clone(),
        model_hash: target.model_hash.clone(),
        order_book: order_book.to_string(),
        stats: None,
        orders: orders
            .into_iter()
            .map(|order| OrderBookOrder {
                order_id: order.order_id,
                owner_note: order.note.clone(),
                token_contract: (!order.is_buy).then(|| order.token_contract.clone()),
                is_buy: order.is_buy,
                price_per_tick: order.price,
                ticks: order.ticks_remaining,
                escrow: 0,
                deadline: order.deadline,
                // the placement event declares `flags`, so this is the book's own answer --
                // unlike `escrow` just above, which the event does not carry and which the row
                // therefore renders as `-` rather than as this filler zero.
                flags: order.flags,
                timestamp: 0,
            })
            .collect(),
    }
}

#[cfg(feature = "shellnet")]
pub(crate) fn snapshot_with_executable_orders(
    mut snapshot: OrderBookSnapshot,
    executable_orders: Vec<OrderBookOrder>,
) -> OrderBookSnapshot {
    snapshot.orders = executable_orders;
    snapshot
}

#[cfg(feature = "shellnet")]
fn transient_executable_read(error: &anyhow::Error) -> bool {
    if error.chain().any(|cause| {
        cause.downcast_ref::<reqwest::Error>().is_some_and(|error| {
            error.is_connect()
                || error.is_timeout()
                || error.is_body()
                || error
                    .status()
                    .is_some_and(|status| status.is_server_error() || status.as_u16() == 429)
        })
    }) {
        return true;
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("timed out")
        || message.contains("timeout")
        || message.contains("connection")
        || message.contains("http 429")
        || (500..=599).any(|status| message.contains(&format!("http {status}")))
}

#[cfg(feature = "shellnet")]
pub(crate) async fn retry_executable_read<T, F, Fut>(label: &str, mut read: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    for (attempt, delay) in EXECUTABLE_READ_BACKOFF.iter().enumerate() {
        match read().await {
            Ok(value) => return Ok(value),
            Err(error) if transient_executable_read(&error) => {
                tracing::warn!(
                    read = label,
                    attempt = attempt + 1,
                    backoff_ms = delay.as_millis(),
                    error = %format!("{error:#}"),
                    "transient executable read failed; retrying"
                );
                tokio::time::sleep(*delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    read().await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn expected_order_book_for_note(
    contracts: &std::path::Path,
    note_addr: &str,
    frame_model: &str,
) -> Result<String> {
    let manifest = contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = dexdo_core::RealChainBackend::connect(manifest)?;
    let note = dexdo_core::Address::parse(note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let model_hash = model_hash_for(frame_model);
    let ob = chain
        .inference_orderbook_address(&note, &model_hash, dexdo_core::TICK_SIZE)
        .await?;
    Ok(ob.with_workchain())
}

#[cfg(feature = "shellnet")]
pub(crate) async fn order_book_active(
    chain: &dexdo_core::RealChainBackend,
    expected_order_book: &str,
) -> Result<bool> {
    let ob = dexdo_core::Address::parse(expected_order_book)
        .map_err(|e| anyhow::anyhow!("order_book {expected_order_book}: {e}"))?;
    Ok(chain.inference_orderbook_stats(&ob).await?.is_some())
}

#[cfg(feature = "shellnet")]
pub(crate) async fn order_book_active_from_contracts(
    contracts: &std::path::Path,
    expected_order_book: &str,
) -> Result<bool> {
    let manifest = contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = dexdo_core::RealChainBackend::connect(manifest)?;
    order_book_active(&chain, expected_order_book).await
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn order_book_active_from_contracts(
    contracts: &std::path::Path,
    expected_order_book: &str,
) -> Result<bool> {
    let _ = (contracts, expected_order_book);
    bail!("order-book state reads require a shellnet build")
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn expected_order_book_for_note(
    contracts: &std::path::Path,
    note_addr: &str,
    frame_model: &str,
) -> Result<String> {
    let _ = (contracts, note_addr, frame_model);
    bail!("order-book derivation requires a shellnet build")
}

pub(crate) fn mock_chain_for_machine(
    endpoints_file: Option<std::path::PathBuf>,
) -> Result<MockChainBackend> {
    let endpoints_file = resolve_endpoints_file(endpoints_file)?;
    Ok(MockChainBackend::new(
        endpoints_file,
        ProtocolConsts::canonical(),
        DobParams::canonical(),
    ))
}

pub(crate) fn mock_orders_from_offers(offers: Vec<OfferListing>) -> Vec<OrderBookOrder> {
    offers
        .into_iter()
        .enumerate()
        .map(|(i, offer)| OrderBookOrder {
            order_id: (i as u128).saturating_add(1),
            owner_note: offer.seller_id,
            token_contract: Some(offer.token_contract),
            is_buy: false,
            price_per_tick: u128::from(offer.price_per_tick),
            ticks: u128::from(offer.max_ticks),
            escrow: 0,
            deadline: 0,
            flags: 0,
            timestamp: 0,
        })
        .collect()
}

pub(crate) fn role_arg_str(role: DealRoleArg) -> &'static str {
    match role {
        DealRoleArg::Buyer => "buyer",
        DealRoleArg::Seller => "seller",
    }
}

fn handle_role_to_arg(role: deals::DealHandleRole) -> DealRoleArg {
    match role {
        deals::DealHandleRole::Buyer => DealRoleArg::Buyer,
        deals::DealHandleRole::Seller => DealRoleArg::Seller,
    }
}

pub(crate) struct MockDealTarget {
    pub(crate) handle: Option<deals::DealHandle>,
    pub(crate) token_contract: String,
    pub(crate) role: Option<DealRoleArg>,
    pub(crate) note_addr: Option<String>,
    pub(crate) frame_model: Option<String>,
}

pub(crate) fn resolve_mock_deal_target(
    input: &str,
    deals_dir: Option<&std::path::Path>,
    raw_role: Option<DealRoleArg>,
    raw_note_addr: Option<String>,
) -> Result<MockDealTarget> {
    let dir = deals::resolve_deals_dir(deals_dir)?;
    if let Some((_path, handle)) = deals::resolve_deal_ref(
        input,
        &dir,
        raw_role.map(role_arg_to_handle),
        raw_note_addr.as_deref(),
    )? {
        return Ok(MockDealTarget {
            token_contract: handle.token_contract.clone(),
            role: Some(handle_role_to_arg(handle.role)),
            note_addr: Some(handle.note_addr.clone()),
            frame_model: Some(handle.frame_model.clone()),
            handle: Some(handle),
        });
    }
    Ok(MockDealTarget {
        handle: None,
        token_contract: input.to_string(),
        role: raw_role,
        note_addr: raw_note_addr,
        frame_model: None,
    })
}

/// The inputs `close` needs *below* clap: a role and an actor note. A stored handle carries
/// both; a raw `TokenContract` has neither, so the operator must pass `--role` and `--note-addr`.
/// The handlers resolve identity through this, and the tests that check the `close` lines the CLI
/// prints call it too, so a printed line cannot drift from what its handler demands.
pub(crate) fn require_close_target_identity<R>(
    deal: &str,
    role: Option<R>,
    note_addr: Option<&str>,
) -> Result<(R, String)> {
    let role = role.ok_or_else(|| {
        anyhow::anyhow!(
            "close: `{deal}` is not a local handle; pass --role buyer|seller with a raw TokenContract"
        )
    })?;
    let note_addr = note_addr.ok_or_else(|| {
        anyhow::anyhow!(
            "close: `{deal}` is not a local handle; pass --note-addr with a raw TokenContract"
        )
    })?;
    Ok((role, note_addr.to_string()))
}

/// The `dexdo close` follow-up the CLI hands an operator, built in one place so every message says
/// the same thing.
/// It is guidance, not an argv template, and that is forced by what this site knows. `close` signs,
/// so it demands `--note-key`, and the note owner key is never a value dexdo may render into a
/// printed line; a raw `TokenContract` target additionally demands the `--role`/`--note-addr` that
/// `require_close_target_identity` enforces below clap. Emitting `--note-key <buyer-key>` would not
/// even be a command: a POSIX shell reads `<buyer-key>` as an input redirection and never hands the
/// token to `dexdo`. So the command is named, the deal reference is rendered shell-quoted (a handle
/// id or path containing a space is otherwise split by the operator's shell), and the remaining
/// inputs -- including any non-default `--deals-dir`/`--contracts` this run resolved, which a
/// follow-up would otherwise silently lose -- are stated in prose the shell never sees.
pub(crate) fn close_guidance(
    deal: &str,
    raw_target_role: Option<&str>,
    actor: &str,
    deals_dir: Option<&std::path::Path>,
    contracts: Option<&std::path::Path>,
) -> String {
    let identity = match raw_target_role {
        Some(role) => format!(
            ", passing --role {role} and the {actor} --note-addr because this deal reference is a \
             raw TokenContract and carries neither"
        ),
        None => String::new(),
    };
    format!(
        "run `dexdo close` on {}{identity}, with the {actor} --note-key to sign{}",
        crate::cli::support::shell_arg(deal),
        identity_free_options(deals_dir, contracts)
    )
}

/// The `--deals-dir`/`--contracts` a `close`/`status` follow-up must repeat, stated as prose.
fn identity_free_options(
    deals_dir: Option<&std::path::Path>,
    contracts: Option<&std::path::Path>,
) -> String {
    crate::cli::support::stated_options(&[("--deals-dir", deals_dir), ("--contracts", contracts)])
}

/// The one `close` follow-up that *is* a complete runnable line: `dexdo status` reads, so it needs
/// no key and no role, and everything it takes is known here. The deal reference is shell-quoted
/// and the run's own `--deals-dir`/`--contracts` are carried, so the line resolves the same deal
/// against the same deployment.
/// Its only caller is the shellnet `close` path, so it exists exactly where that does -- the same
/// boundary the settlement builders use -- rather than shipping behind a dead-code suppression.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn status_command(
    deal: &str,
    deals_dir: Option<&std::path::Path>,
    contracts: Option<&std::path::Path>,
) -> String {
    let mut command = format!("dexdo status {}", crate::cli::support::shell_arg(deal));
    for (flag, path) in [("--deals-dir", deals_dir), ("--contracts", contracts)] {
        if let Some(path) = path {
            command.push_str(&format!(
                " {flag} {}",
                crate::cli::support::shell_arg(&path.display().to_string())
            ));
        }
    }
    command
}

/// `deals_dir`/`contracts` are the options the *current* run was given, and they are threaded in
/// rather than re-derived: a handle resolved from a custom `--deals-dir`, or a deal read through an
/// explicit `--contracts` manifest, would otherwise be pointed at the defaults by the follow-up
/// this prints.
#[cfg(feature = "shellnet")]
pub(crate) fn close_hint(
    target: &DealTarget,
    s: &deals::DealStateSummary,
    deals_dir: Option<&std::path::Path>,
    contracts: Option<&std::path::Path>,
) -> String {
    let deal = target
        .handle
        .as_ref()
        .map(|h| h.handle.as_str())
        .unwrap_or(&target.token_contract);
    // A raw TokenContract target has no stored handle, so the guidance must also name the
    // `--role`/`--note-addr` the close handler requires below clap, and it must state the
    // `--deals-dir`/`--contracts` this run resolved rather than let a rerun fall back to defaults.
    let raw_seller = target.handle.is_none().then_some("seller");
    let raw_buyer = target.handle.is_none().then_some("buyer");
    let close_as_seller = close_guidance(deal, raw_seller, "seller", deals_dir, contracts);
    let close_as_buyer = close_guidance(deal, raw_buyer, "buyer", deals_dir, contracts);
    match target.role {
        Some(deals::DealHandleRole::Seller) if s.kind == deals::DealStateKind::Stopped => {
            format!("next=destroy action={close_as_seller}")
        }
        Some(deals::DealHandleRole::Seller) if s.opened && !s.probe_accepted => {
            format!(
                "next=seller_wait_delivery_then_accept_probe action=keep the seller gateway running for {deal} detail=it waits for the first delivered canonical tick, then calls TokenContract.acceptProbe() after PROBE_WINDOW stop_action={close_as_seller} stop_effect=TokenContract.sellerStop() reason=awaiting_delivery_then_probe_window"
            )
        }
        Some(deals::DealHandleRole::Seller) if s.opened => {
            format!(
                "next=seller_claim_finalize_or_settle_week_or_seller_stop action=keep the seller gateway running for {deal} detail=it calls TokenContract.claimTokens(cumulativeTokens) for delivered output and TokenContract.finalize() for mature claims, while the subscription keeper also calls TokenContract.settleWeek() at crossed week boundaries stop_action={close_as_seller} stop_effect=TokenContract.sellerStop(); buyer may STOP when done"
            )
        }
        Some(deals::DealHandleRole::Seller) if s.funded && !s.probe_accepted => {
            format!(
                "next=buyer_cleanup_after_timeout action=the buyer {}",
                close_guidance(
                    &target.token_contract,
                    Some("buyer"),
                    "buyer",
                    deals_dir,
                    contracts
                )
            )
        }
        // what is left here is the UNSOLD deal -- never funded, so never opened and never
        // stopped. "not stopped" was true and useless: there is nothing to stop in a deal that never
        // started, and the destroy it pointed at could never accept this shape. The applicable
        // action is `TokenContract.close()`, which returns the seller bond to the note and
        // self-destructs(`contracts/airegistry/TokenContract.sol:803-821`) -- but only once the ask
        // is off the book, so the ordering is part of the answer.
        Some(deals::DealHandleRole::Seller) => format!(
            "next=close_unsold_deal command=`dexdo close {deal} --note-key '<seller-key>'` reason=deal_never_matched note=cancel_any_resting_ask_first_with_`dexdo orders cancel`"
        ),
        Some(deals::DealHandleRole::Buyer) if s.kind == deals::DealStateKind::Stopped => {
            "next=none reason=deal_already_terminal".to_string()
        }
        Some(deals::DealHandleRole::Buyer) if s.opened => {
            format!("next=stream_stop action={close_as_buyer}")
        }
        Some(deals::DealHandleRole::Buyer) if s.funded && !s.probe_accepted => {
            format!("next=cleanup_unopened_after_timeout action={close_as_buyer}")
        }
        Some(deals::DealHandleRole::Buyer) => {
            "next=cancel_resting_bid_or_wait_match reason=deal_not_funded".to_string()
        }
        None => "next=unknown_role pass_local_handle_or_--role".to_string(),
    }
}

/// One resting ask as the order-book renderer needs it: price per tick, its max ticks, and the full deal
/// `TokenContract` address. Kept minimal so both the buyer's pre-buy view and the read-only `dexdo markets`
/// table view can build it from their own sources(`discover_offers` / `OrderBookSnapshot::resting_asks`).
pub struct BookRow {
    pub price_per_tick: u128,
    pub max_ticks: u128,
    pub token_contract: String,
}

pub(crate) fn declared_model_flags(
    frame_model: &str,
) -> Option<dexdo_core::CanonicalModelFlags> {
    dexdo_core::parse_canonical_model_id(frame_model)
        .ok()
        .map(|parsed| parsed.flags)
        .filter(|flags| !flags.is_empty())
}

pub(crate) fn render_model_flags_field(frame_model: &str) -> String {
    declared_model_flags(frame_model)
        .map(|flags| format!(" model_flags={}", flags.render_human()))
        .unwrap_or_default()
}

/// Render a per-model inference order book to the terminal as a narrow box table (/ UX:
/// "choose a model = choose the market"). Public + read-only: given the resting asks, it prints the
/// `#/price-per-tick/max-ticks/exec` table plus the full `tokenContract` addresses by `#`. `max_price_per_tick`
/// (when `Some`) marks which asks are executable at that ceiling; `your_order_ticks`(when `Some`) appends the
/// buyer's order summary line. The caller sorts nothing -- this sorts by price ascending(best ask first).
pub fn print_book_table(
    frame_model: &str,
    rows: &[BookRow],
    max_price_per_tick: Option<u128>,
    your_order_ticks: Option<u128>,
) {
    use std::io::IsTerminal;
    // ANSI styling only on a real terminal -- piped/headless output stays plain(clean logs, copyable).
    let color = std::io::stdout().is_terminal() && !crate::cli::no_color_requested();
    let paint = |s: &str, code: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    // One tick = a fixed number of delivered model tokens -- print it
    // so price/tick and the tick counts are interpretable in model tokens, not abstract units.
    let tick_size = DobParams::canonical().tick_size as u128;
    let title = format!(
        "inference order book -- {frame_model}{}",
        render_model_flags_field(frame_model)
    );
    let subtitle = format!(
        "1 tick = {tick_size} model tokens * prices are raw ECC[2] (PRICE_STEP 1000000000 = 1 SHELL)"
    );
    if rows.is_empty() {
        println!("{}  ({subtitle})", paint(&title, "1;36"));
        println!(
            "  {} no resting asks yet -- a buy would rest until a seller matches",
            paint("*", "2")
        );
        return;
    }
    let mut sorted: Vec<&BookRow> = rows.iter().collect();
    sorted.sort_by_key(|o| o.price_per_tick);

    // Columns are dynamic: the `exec` verdict only appears when there is a price ceiling to judge against
    // (the buyer's pre-buy view); the read-only `market` discovery view omits it. The full `tokenContract`
    // address is a column IN the table(un-truncated, copy-paste intact) -- the table is as wide as it needs.
    // 0 = center, 1 = right, 2 = left.
    let has_exec = max_price_per_tick.is_some();
    let mut headers: Vec<&str> = vec!["#", "price/tick", "max ticks"];
    let mut aligns: Vec<u8> = vec![0, 1, 1];
    if has_exec {
        headers.push("exec");
        aligns.push(0);
    }
    headers.push("tokenContract");
    aligns.push(2);
    let rows_str: Vec<Vec<String>> = sorted
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let mut cells = vec![
                (i + 1).to_string(),
                o.price_per_tick.to_string(),
                o.max_ticks.to_string(),
            ];
            if let Some(cap) = max_price_per_tick {
                cells.push(if o.price_per_tick <= cap { "yes" } else { "no" }.to_string());
            }
            cells.push(dexdo_core::address::display_self_dapp(&o.token_contract));
            cells
        })
        .collect();
    let n = headers.len();
    let mut w = vec![0usize; n];
    for (i, head) in headers.iter().enumerate() {
        w[i] = head.chars().count();
    }
    for r in &rows_str {
        for i in 0..n {
            w[i] = w[i].max(r[i].chars().count());
        }
    }
    // Box-drawing border for the given junction chars(left, mid, right).
    let border = |l: &str, m: &str, r: &str| {
        let seg: Vec<String> = w.iter().map(|&c| "-".repeat(c + 2)).collect();
        format!("{l}{}{r}", seg.join(m))
    };
    let fit = |s: &str, width: usize, align: u8| {
        let pad = width.saturating_sub(s.chars().count());
        match align {
            1 => format!("{}{}", " ".repeat(pad), s), // right
            2 => format!("{}{}", s, " ".repeat(pad)), // left
            _ => {
                let left = pad / 2;
                format!("{}{}{}", " ".repeat(left), s, " ".repeat(pad - left)) // center
            }
        }
    };
    let bar = paint("-", "2");
    let render_row = |cells: &[String], style: &dyn Fn(&str, usize) -> String| {
        let body: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| style(&fit(c, w[i], aligns[i]), i))
            .collect();
        format!("{bar} {} {bar}", body.join(&format!(" {bar} ")))
    };

    println!("{}  ({subtitle})", paint(&title, "1;36"));
    println!("{}", paint(&border("-", "-", "-"), "2"));
    let head_strings: Vec<String> = headers.iter().map(|s| s.to_string()).collect();
    println!("{}", render_row(&head_strings, &|s, _| paint(s, "1;36")));
    println!("{}", paint(&border("-", "-", "-"), "2"));
    let exec_col = has_exec.then_some(3usize);
    for r in &rows_str {
        println!(
            "{}",
            render_row(r, &|s, i| {
                if Some(i) == exec_col {
                    if s.trim() == "yes" {
                        paint(s, "1;32")
                    } else {
                        paint(s, "2")
                    }
                } else {
                    s.to_string()
                }
            })
        );
    }
    println!("{}", paint(&border("-", "-", "-"), "2"));
    if let (Some(ticks), Some(cap)) = (your_order_ticks, max_price_per_tick) {
        println!(
            "{} {ticks} ticks (= {} model tokens) at up to {} raw ECC[2]/tick \
             (PRICE_STEP 1000000000 = 1 SHELL) -- fills the best ask within the limit",
            paint("your order:", "1"),
            ticks.saturating_mul(tick_size),
            paint(&cap.to_string(), "33"),
        );
    }
}

pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// (review): write the `DEXDO_PN_POOL`(carries note owner secret keys) privately + atomically --
/// an exclusive 0600 temp in the destination directory, then `rename` over the target. A plain `fs::write`
/// inherits the umask, and a predictable non-exclusive temp path can clobber a pre-created file/symlink.
#[cfg(feature = "shellnet")]
pub(crate) fn write_pool_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    crate::cli::note::write_private_atomic(path, bytes)
}

// The only caller is the temp-clobber regression, so the seam exists exactly where it is used.
#[cfg(all(test, feature = "shellnet"))]
pub(crate) fn write_pool_private_via_temp(
    path: &std::path::Path,
    tmp: &std::path::Path,
    bytes: &[u8],
) -> Result<()> {
    crate::cli::note::write_private_atomic_via_temp(path, tmp, bytes)
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_same_file_pool_guard(
    env_pool: Option<&std::ffi::OsStr>,
    pool: &std::path::Path,
) -> Result<()> {
    let Some(env_pool) = env_pool else {
        return Ok(());
    };
    if env_pool.is_empty() {
        return Ok(());
    }
    let env_pool = std::path::Path::new(env_pool);
    let (Ok(env_pool), Ok(pool)) = (std::fs::canonicalize(env_pool), std::fs::canonicalize(pool))
    else {
        return Ok(());
    };
    if env_pool == pool {
        bail!(
            "note deploy refused: DEXDO_PN_POOL and --pool both point to the same existing file {}. \
             This append mode can hide note-key confusion and leave a pool entry whose --note-key later fails \
             owner-signed writes with ERR_INVALID_SENDER 101. Unset DEXDO_PN_POOL while deploying, or deploy \
             into a fresh --pool <new_file> and switch DEXDO_PN_POOL to that file after the command succeeds.",
            pool.display()
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_recovery_pool_guard(
    pool: &std::path::Path,
    recovery: &std::path::Path,
) -> Result<()> {
    if comparable_path(pool)? == comparable_path(recovery)? {
        bail!(
            "note deploy refused: --recovery and --pool both point to {}. The recovery file is an \
             intermediate secret-bearing state file; keep it separate from the final DEXDO_PN_POOL.",
            pool.display()
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn comparable_path(path: &std::path::Path) -> Result<std::path::PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Ok(canonical);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let base = match parent {
        Some(parent) => std::fs::canonicalize(parent).unwrap_or_else(|_| cwd.join(parent)),
        None => cwd,
    };
    let file = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "path {} has no file name for same-file check",
            path.display()
        )
    })?;
    Ok(base.join(file))
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_endpoint_url(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        bail!("--endpoint must not be empty");
    }
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        Ok(endpoint.to_string())
    } else {
        Ok(format!("https://{endpoint}"))
    }
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_multisig_secret_hex(
    args: &NoteDeployArgs,
) -> Result<(&'static str, String)> {
    multisig_secret_hex(&args.multisig_key, &args.multisig_seed_file)
}

/// The `--multisig-key` / `--multisig-seed-file` pair, read once for every command that spends from
/// the funding wallet. Taken as the two option paths rather than one command's args struct so a
/// second such command reuses this reading instead of growing its own: two readings of one operator
/// secret is two places for the "which flag wins" answer to differ.
#[cfg(feature = "shellnet")]
pub(crate) fn multisig_secret_hex(
    multisig_key: &Option<std::path::PathBuf>,
    multisig_seed_file: &Option<std::path::PathBuf>,
) -> Result<(&'static str, String)> {
    match (multisig_key, multisig_seed_file) {
        (Some(_), Some(_)) => bail!("use only one of --multisig-key or --multisig-seed-file"),
        (Some(path), None) => Ok(("--multisig-key", read_secret_hex(path, "--multisig-key")?)),
        (None, Some(path)) => {
            let phrase = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("read --multisig-seed-file {}: {e}", path.display())
            })?;
            if phrase.split_whitespace().next().is_none() {
                bail!("--multisig-seed-file {} is empty", path.display());
            }
            let key = dexdo::wallet_seed::derive_multisig_key_from_seed_phrase(&phrase)
                .map_err(|e| anyhow::anyhow!("--multisig-seed-file {}: {e}", path.display()))?;
            Ok(("--multisig-seed-file", key.secret_hex().to_string()))
        }
        (None, None) => bail!("one of --multisig-key or --multisig-seed-file is required"),
    }
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_secs())
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_fold_state_into_pool(
    pool_path: &std::path::Path,
    state: &crate::cli::note::OnboardPnState,
    funding_multisig_address: &str,
) -> Result<usize> {
    with_pool_write_lock(pool_path, |pool_path| {
        note_deploy_fold_state_into_pool_locked(pool_path, state, funding_multisig_address, || {})
    })
}

#[cfg(feature = "shellnet")]
pub(crate) fn note_deploy_fold_state_into_pool_locked(
    pool_path: &std::path::Path,
    state: &crate::cli::note::OnboardPnState,
    funding_multisig_address: &str,
    after_read: impl FnOnce(),
) -> Result<usize> {
    use crate::cli::note::{pn_state_to_pool_note, pool_with_note_added};

    let note = pn_state_to_pool_note(state)?;
    let existing = match std::fs::read(pool_path) {
        Ok(b) => Some(serde_json::from_slice(&b).map_err(|e| {
            anyhow::anyhow!("--pool {} is not valid JSON: {e}", pool_path.display())
        })?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => bail!("read --pool {}: {e}", pool_path.display()),
    };
    after_read();
    let now = note_deploy_now_unix()?;
    let pool = pool_with_note_added(existing, state, note, now, funding_multisig_address)?;
    let pool_json = serde_json::to_string_pretty(&pool)?;
    write_pool_private(pool_path, pool_json.as_bytes())?;
    Ok(pool["notes"].as_array().map(|a| a.len()).unwrap_or(0))
}

#[cfg(feature = "shellnet")]
pub(crate) fn now_unix_secs() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_secs())
}

#[cfg(all(test, feature = "shellnet"))]
mod actionable_error_tests {
    use super::*;

    #[tokio::test]
    async fn doctor_missing_contracts_manifest_names_path_and_fix() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("contracts/deployed.shellnet.json");

        let error = shellnet_doctor_report("shellnet", None, &missing, None)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains(&missing.display().to_string()));
        assert!(error.contains("run `dexdo doctor` from the repository root"));
        assert!(error.contains("`--contracts <path>`"));
        assert!(!error.starts_with("No such file or directory"));
    }

    #[test]
    fn market_missing_note_getter_is_actionable_but_other_errors_pass_through() {
        let note = "0:0000000000000000000000000000000000000000000000000000000000000001";
        let mapped = market_note_getter_error(
            note,
            "https://shellnet.example",
            anyhow::anyhow!("note is not active"),
        )
        .to_string();
        // the actionable error names the note canonically; a PrivateNote is a contract of the
        // shared dexdo DApp, so its DApp half is `DEXDO_DAPP_ID`.
        let note_rendered = format!(
            "{}::{}",
            dexdo_core::DEXDO_DAPP_ID,
            note.strip_prefix("0:").expect("fixture is the chain form")
        );
        let expected = format!(
            "note {note_rendered} not found or not initialized on https://shellnet.example; verify \
             `--note-addr` and the shellnet endpoint"
        );
        assert_eq!(mapped, expected);

        let exit_60_expected = format!(
            "market lookup failed for note {note_rendered} on https://shellnet.example \
             (getInferenceOrderBookAddress exit 60) -- verify the note address is a deployed, \
             initialized order-book note"
        );
        let exit_60 = anyhow::anyhow!(
            "run_tvm getter getInferenceOrderBookAddress: Contract execution was terminated with \
             error: Unknown error, exit code: 60 (Contract has no fallback function but function ID \
             is wrong)"
        );
        assert_eq!(
            market_note_getter_error(note, "https://shellnet.example", exit_60).to_string(),
            exit_60_expected
        );

        let exit_600_message = "run_tvm getter getInferenceOrderBookAddress: Contract execution was \
            terminated with error: Unknown error, exit code: 600 (Contract has no fallback function \
            but function ID is wrong)";
        assert_eq!(
            market_note_getter_error(
                note,
                "https://shellnet.example",
                anyhow::anyhow!(exit_600_message)
            )
            .to_string(),
            exit_600_message
        );

        let exit_601_message = "run_tvm getter getInferenceOrderBookAddress: Contract execution was \
            terminated with error: Unknown error, exit code: 601 (Contract has no fallback function \
            but function ID is wrong)";
        assert_eq!(
            market_note_getter_error(
                note,
                "https://shellnet.example",
                anyhow::anyhow!(exit_601_message)
            )
            .to_string(),
            exit_601_message
        );

        let exit_160_message = "run_tvm getter getInferenceOrderBookAddress: Contract execution was \
            terminated with error: Unknown error, exit code: 160 (Contract has no fallback function \
            but function ID is wrong)";
        assert_eq!(
            market_note_getter_error(
                note,
                "https://shellnet.example",
                anyhow::anyhow!(exit_160_message)
            )
            .to_string(),
            exit_160_message
        );

        let different = anyhow::anyhow!(
            "run_tvm getter getInferenceOrderBookAddress: transport connection refused"
        );
        assert_eq!(
            market_note_getter_error(note, "https://shellnet.example", different).to_string(),
            "run_tvm getter getInferenceOrderBookAddress: transport connection refused"
        );
    }
}

/// checks that must run in the default build too: the remote PR gate does not compile
/// the `shellnet` feature, and these are about what the CLI prints, not about the chain.
#[cfg(test)]
mod printed_command_tests {
    use super::*;
    use clap::Parser as _;

    #[cfg(feature = "shellnet")]
    #[test]
    fn provision_mainnet_profile_keeps_manifest_endpoint() {
        let manifest: dexdo_core::Deployed = serde_json::from_value(serde_json::json!({
            "network": "mainnet",
            "endpoint": "https://dd-mainnet.ackinacki.org",
            "superroot": format!("0:{}", "0".repeat(64)),
            "dapp_config": "",
            "dapp_id": "0".repeat(64)
        }))
        .expect("mainnet manifest fixture");

        assert_eq!(
            manifest_preflight_endpoint(&manifest, None).expect("resolve provision endpoint"),
            "https://dd-mainnet.ackinacki.org"
        );
        assert_eq!(
            manifest_preflight_endpoint(
                &manifest,
                Some("https://explicit-mainnet.example/graphql")
            )
            .expect("resolve explicit provision endpoint"),
            "https://explicit-mainnet.example"
        );
    }

    /// `close` guidance must be guidance and nothing more. `close` signs, so its handler
    /// demands a `--note-key` this site does not have; an argv template filling that gap with
    /// `<buyer-key>` is not even argv, because the shell consumes `<buyer-key>` as a redirection.
    /// So every command span here has to be a bare command path, and every input the handler
    /// enforces below clap -- including the `--role`/`--note-addr` a raw `TokenContract` target
    /// lacks, named through the handler's own `require_close_target_identity` -- has to be stated
    /// in the prose around it. Both target modes are driven, with a deal reference a shell would
    /// otherwise split.
    #[test]
    fn close_guidance_names_the_command_and_states_every_input_its_handler_demands() {
        use crate::cli::support::printed_commands::assert_emitted_commands_name_only;
        let deals_dir = std::path::Path::new("/tmp/my deals");
        let contracts = std::path::Path::new("/tmp/my deploy/deployed.json");
        for (raw_role, deal, actor) in [
            (None, "seller-0:33 with space", "seller"),
            (Some("seller"), "0:33", "seller"),
            (Some("buyer"), "0:33", "buyer"),
        ] {
            let guidance = close_guidance(deal, raw_role, actor, Some(deals_dir), Some(contracts));
            // `close` signs, so the key must be stated; and the options this run was given must
            // survive into the follow-up, or it silently resolves a different handle directory and
            // a different deployment. Stating them through the helper is what makes the guarantee
            // structural rather than something this call site remembered to check.
            assert_emitted_commands_name_only(
                &guidance,
                &format!("close guidance (raw_role={raw_role:?})"),
                &[
                    &format!("{actor} --note-key"),
                    "--deals-dir '/tmp/my deals'",
                    "--contracts '/tmp/my deploy/deployed.json'",
                ],
            );
            assert!(
                guidance.contains(&crate::cli::support::shell_arg(deal)),
                "the deal reference must be quoted so a shell keeps it whole: {guidance}"
            );
            // Exactly what `load_deal_target` carries for a raw TokenContract: without a stored
            // handle the role and note come from flags, and the handler rejects their absence.
            // The two rejections are read from the handler's own function, one input at a time,
            // so this states what `close` demands rather than restating it.
            let missing_role =
                require_close_target_identity::<deals::DealHandleRole>(deal, None, None)
                    .expect_err("the handler must demand a role for a raw TokenContract")
                    .to_string();
            let missing_note =
                require_close_target_identity(deal, Some(deals::DealHandleRole::Buyer), None)
                    .expect_err("the handler must demand a note for a raw TokenContract")
                    .to_string();
            if raw_role.is_some() {
                for demanded in [missing_role.as_str(), missing_note.as_str()] {
                    let flag = if demanded.contains("--role") {
                        "--role"
                    } else {
                        "--note-addr"
                    };
                    assert!(
                        guidance.contains(flag),
                        "the handler demands {flag} but the guidance omits it: {guidance}"
                    );
                }
            } else {
                assert!(
                    !guidance.contains("--role"),
                    "a stored handle carries the role; guidance must not ask for it: {guidance}"
                );
            }
        }
    }

    /// `dexdo status` is the one close follow-up that *is* a complete line -- it reads, so it
    /// needs neither a key nor a role -- and it must survive the operator's shell with the deal
    /// reference intact and the run's own manifest/handle directory attached.
    #[test]
    fn printed_status_line_survives_a_shell_and_keeps_this_run_s_options() {
        use crate::cli::support::printed_commands::assert_emitted_commands_parse;
        let line = status_command(
            "seller-0:33 with space",
            Some(std::path::Path::new("/tmp/my deals")),
            Some(std::path::Path::new("/tmp/my deploy/deployed.json")),
        );
        assert_emitted_commands_parse(
            &format!("inspect with `{line}`"),
            "close status hint",
            false,
        );
        let parsed = crate::Cli::try_parse_from(
            crate::cli::support::printed_commands::shell_split(&line)
                .expect("the printed status line is one a shell accepts"),
        )
        .unwrap_or_else(|e| panic!("the printed line must parse: {line}\n{e}"));
        let crate::Command::Status(args) = parsed.command else {
            panic!("status command");
        };
        assert_eq!(args.deal, "seller-0:33 with space");
        assert_eq!(
            args.deals_dir.as_deref(),
            Some(std::path::Path::new("/tmp/my deals"))
        );
        assert_eq!(
            args.contracts.as_deref(),
            Some(std::path::Path::new("/tmp/my deploy/deployed.json"))
        );
    }

    /// the two settlement follow-ups name commands whose handlers demand a seller note and
    /// owner key *after* clap accepts the line. Neither is known where they are printed, so both
    /// must be prose naming the command -- and both must still carry the manifest this run used,
    /// or the operator settles against the default deployment.
    #[test]
    fn settlement_guidance_names_its_command_and_keeps_the_authoritative_manifest() {
        use crate::cli::support::{
            destroy_guidance, printed_commands::assert_emitted_commands_name_only,
            release_dispute_guidance,
        };
        let contracts = std::path::Path::new("/tmp/my deploy/deployed.json");
        for guidance in [
            release_dispute_guidance("0:33", Some(contracts)),
            destroy_guidance("0:33", Some(contracts)),
        ] {
            assert_emitted_commands_name_only(
                &guidance,
                "settlement guidance",
                &[
                    "--token-contract",
                    "--note-addr",
                    "--note-key",
                    "--contracts '/tmp/my deploy/deployed.json'",
                ],
            );
        }
    }
}
