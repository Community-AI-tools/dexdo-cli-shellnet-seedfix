//! The durable half of `dexdo wallet`: where a binding lives on disk, and the one atomic
//! point at which it becomes the active one.
//! Layout under the effective `--data-dir`:
//! ```text
//! wallet/active/<network>.json the active binding ON THAT NETWORK
//! wallet/bindings/<binding-id>/ that binding's owner-only secrets
//! wallet/archive/<unix-secs>-<binding-id>.json every binding it replaced
//! ```
//! Three properties this file exists to hold. A rebind never overwrites the previous binding's
//! secrets, because the `binding-id` is minted before any key is generated and each binding owns
//! its own directory. A replaced binding is copied into `archive/` before the active file is
//! replaced, never deleted, because the old Hot can still hold funds.
//! And the active record is keyed by NETWORK. There used to be one global
//! `wallet/binding.json`, which meant a Hot bound on shellnet was the wallet a mainnet money
//! command resolved and spent from -- real funds, from a wallet the operator bound for a test
//! chain. The network is now part of the PATH, so the read cannot reach across chains: a command
//! running on mainnet names `active/mainnet.json` and nothing else can answer it.
//! The write is keyed the same way, from [`WalletBinding::network`] rather than from a parameter,
//! so no caller can place a record in the other network's slot even by mistake.

use anyhow::{Context as _, Result};
use rand::RngCore as _;
use std::path::{Path, PathBuf};

use super::{WalletBinding, WalletNetwork, BINDING_VERSION};

/// Mint a binding id. Called before any key exists, so the per-binding secret directory is already
/// distinct by the time the first secret is written.
pub(crate) fn new_binding_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// How many characters [`new_binding_id`] produces: 16 random bytes, hex-encoded.
const BINDING_ID_LEN: usize = 32;

/// Is this the id shape the store MINTS, rather than merely a non-empty string?
/// The shape is the whole check: an id is used as a path component twice -- to resolve
/// `bindings/<id>/`, and to name the archive file -- so anything that is not this alphabet cannot be
/// one of ours and must never reach a path. `hex::encode` emits lowercase, so uppercase is not the
/// same id and is not accepted either; there is no case in which the store wrote one.
fn is_minted_binding_id(id: &str) -> bool {
    id.len() == BINDING_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One onboarding attempt's reserved identity and secrets directory.
pub(crate) struct BindingDraft {
    id: String,
    dir: PathBuf,
}

impl BindingDraft {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Remove the reserved directory when the attempt wrote nothing into it.
    /// An empty draft directory is worth nothing to a retry, while a directory holding a generated
    /// key or a resumable onboarding draft is exactly the state a retry resumes from -- so the
    /// emptiness test, not the failure, decides. Best effort by design: failing to tidy up must not
    /// replace the error the operator actually needs to read.
    pub(crate) fn discard_if_empty(&self) {
        let empty = std::fs::read_dir(&self.dir).is_ok_and(|mut entries| entries.next().is_none());
        if empty {
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}

/// The `<data-dir>/wallet` tree.
pub(crate) struct WalletStore {
    root: PathBuf,
}

impl WalletStore {
    /// The store under the effective instance data directory. `--data-dir` already redirects it;
    /// the operator never has to know the platform path.
    pub(crate) fn open() -> Result<Self> {
        Ok(Self::at(crate::cli::data_dir::automatic("wallet")?))
    }

    pub(crate) fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The active binding ON `network`. The network is part of the path, not a field the reader
    /// checks afterwards, so a command running on one chain cannot name the other chain's record.
    pub(crate) fn binding_path(&self, network: WalletNetwork) -> PathBuf {
        self.active_dir().join(format!("{}.json", network.as_str()))
    }

    fn active_dir(&self) -> PathBuf {
        self.root.join("active")
    }

    /// Create `wallet/active/`, hardening the wallet root on the way.
    /// Both levels, not just the leaf: `create_dir_all` would make the root with whatever the
    /// umask allows, and the root is what holds `bindings/` and `archive/`. The write this
    /// precedes used to harden the root directly, so creating only the leaf would quietly relax a
    /// directory that guards key material.
    fn create_active_dir(&self) -> Result<()> {
        create_owner_only_dir(&self.root)?;
        create_owner_only_dir(&self.active_dir())
    }

    /// Where the shipped code kept the ONE global binding, before it was keyed by network.
    /// Read only by [`Self::migrate_legacy`], and only ever into the slot the record's own
    /// `network` field names.
    fn legacy_binding_path(&self) -> PathBuf {
        self.root.join("binding.json")
    }

    pub(crate) fn bindings_dir(&self) -> PathBuf {
        self.root.join("bindings")
    }

    pub(crate) fn archive_dir(&self) -> PathBuf {
        self.root.join("archive")
    }

    /// The active record as it is ON DISK: read, parsed and version-checked, with its id NOT
    /// validated.
    /// Two callers need this and only these two. `commit_active` archives whatever it replaces, and
    /// a record that fails validation is exactly the one that most needs archiving -- it may name a
    /// Hot that holds funds. And `onboard`/`rebind` ask "is there a record here at all", which a
    /// broken record answers yes to: refusing it would put the operator's only way out of a corrupt
    /// binding behind the corrupt binding.
    /// A file that exists but does not parse is an error, not a `None`: silently treating a
    /// corrupt or newer binding as "no wallet" would send the next command into onboarding while a
    /// real Hot, possibly holding funds, is already bound.
    pub(crate) fn read_active_record(&self, network: WalletNetwork) -> Result<Option<WalletBinding>> {
        self.migrate_legacy()?;
        self.read_record_at(&self.binding_path(network))
    }

    /// Parse one active-record file. The version gate lives here so it guards the legacy file too:
    /// a record this build cannot read must not be relocated as if it were understood.
    fn read_record_at(&self, path: &Path) -> Result<Option<WalletBinding>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "read wallet binding {}: {error}",
                    path.display()
                ))
            }
        };
        let binding: WalletBinding = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse wallet binding {}", path.display()))?;
        if binding.version != BINDING_VERSION {
            anyhow::bail!(
                "wallet binding {} is version {}, and this build reads version {BINDING_VERSION}; \
                 it is refused rather than read with fields this build would silently ignore",
                path.display(),
                binding.version
            );
        }
        Ok(Some(binding))
    }

    /// Move a `wallet/binding.json` written by the shipped global-binding code into the slot its
    /// OWN `network` field names, once, before any read answers a question with it.
    /// The destination is computed from the record and never from the network being asked about.
    /// That is the entire point: treating a legacy file as belonging to whichever chain happens to
    /// be asking is the money-safety defect this change exists to remove, and doing it one
    /// directory deeper would be the same bug with a longer path. A shellnet record migrates to
    /// `active/shellnet.json` even when the command that triggered the migration is a mainnet one --
    /// and that mainnet command then finds no binding of its own, which is the correct answer.
    /// Idempotent, and safe to interrupt. The destination is written atomically before the legacy
    /// file is removed, so a crash between the two leaves both; the next run finds a destination
    /// holding the same record and finishes the move. Two files that DISAGREE are never merged and
    /// never ranked -- the operator is told about both and nothing is read, because picking one
    /// would be a guess about which Hot their money should come from.
    fn migrate_legacy(&self) -> Result<()> {
        let legacy_path = self.legacy_binding_path();
        let Some(legacy) = self.read_record_at(&legacy_path)? else {
            return Ok(());
        };
        let destination = self.binding_path(legacy.network);
        match self.read_record_at(&destination)? {
            Some(existing) if existing != legacy => anyhow::bail!(
                "wallet binding {} is from a build that kept one binding for every network, and \
                 {} already holds a DIFFERENT binding for {}: the first names Hot {} (binding {}, \
                 provider `{}`) and the second names Hot {} (binding {}, provider `{}`). Neither \
                 was read and nothing was changed, because choosing between them would be a guess \
                 about which wallet your money comes from. Keep the one you mean to spend from, \
                 delete or move the other, and run the command again",
                legacy_path.display(),
                destination.display(),
                legacy.network,
                legacy.hot_address,
                legacy.id,
                legacy.provider,
                existing.hot_address,
                existing.id,
                existing.provider,
            ),
            // Already migrated, or a previous run was interrupted after the write and before the
            // removal. Same record either way, so finishing the move loses nothing.
            Some(_) => {}
            None => {
                let mut json = serde_json::to_vec_pretty(&legacy)
                    .context("serialize the wallet binding being migrated")?;
                json.push(b'\n');
                self.create_active_dir()?;
                crate::cli::note::write_private_atomic(&destination, &json)?;
            }
        }
        std::fs::remove_file(&legacy_path).map_err(|error| {
            anyhow::anyhow!(
                "wallet binding {} was migrated to {} but could not be removed: {error}. It is \
                 left in place rather than ignored: two records of a Hot that can hold funds must \
                 not diverge silently",
                legacy_path.display(),
                destination.display(),
            )
        })
    }

    /// The active binding, or `None` when this instance has never bound a wallet -- validated, and
    /// therefore safe to resolve as the funding wallet.
    /// # Why the READ validates and not only the write
    /// The commit path already refuses a binding whose id is not the one this attempt reserved. That
    /// guards records written from now on and does nothing for the records already on disk: a
    /// `binding.json` whose id is empty, or is not the shape the store mints, or names a
    /// `bindings/<id>/` directory that is not there, used to deserialize cleanly and resolve as the
    /// funding wallet. The corrupt binding a live `wallet onboard manual` produced is
    /// exactly that record, and it still loaded after the write was guarded.
    /// It is not a cosmetic mismatch. The id is the ONLY route from the active record to that
    /// binding's secrets, so an id naming nothing is a Hot whose key this instance cannot reach --
    /// and for `gosh-ai`, whose recovery phrase is generated INTO `bindings/<id>/`, it is the phrase
    /// itself that is stranded, and with it the funds.
    pub(crate) fn load_active(&self, network: WalletNetwork) -> Result<Option<WalletBinding>> {
        let Some(binding) = self.read_active_record(network)? else {
            return Ok(None);
        };
        self.validate_binding_id(&binding)?;
        self.validate_network(&binding, network)?;
        Ok(Some(binding))
    }

    /// The record found under `network` must SAY `network`.
    /// Keying the file by network is what stops a command reaching across chains; this is what
    /// stops a file that was copied, hand-edited or restored from a backup into the wrong slot
    /// from being spent anyway. It is deliberately a refusal and not a fallback to the network the
    /// record claims: the operator asked to spend on one chain, the only record available belongs
    /// to another, and quietly obeying the file instead of the command is how a shellnet Hot ends
    /// up funding a mainnet spend.
    fn validate_network(&self, binding: &WalletBinding, network: WalletNetwork) -> Result<()> {
        if binding.network == network {
            return Ok(());
        }
        anyhow::bail!(
            "wallet binding {} is bound to {} but this command is running on {}. Nothing was read \
             from it and no wallet was resolved: a Hot bound on one network must never fund a \
             spend on another. Run this command against {} contracts, or bind a {} wallet with \
             `dexdo wallet onboard` -- bindings are kept per network, so binding one does not \
             replace the other",
            self.binding_path(network).display(),
            binding.network,
            network,
            binding.network,
            network,
        )
    }

    /// The three ways an id fails, in the only order that is safe.
    /// Emptiness and shape are answered BEFORE the id is joined onto a path, because joining is the
    /// thing being protected: `bindings_dir().join("../..")` escapes the wallet tree, and the same
    /// id reaches the archive filename. By the time the directory is resolved the id is known to be
    /// 32 hex characters, which cannot traverse.
    /// Each refusal names the file and ends at the same remediation, because there is only one:
    /// `rebind` mints a fresh id, writes a binding that resolves, and ARCHIVES this record rather
    /// than deleting it -- the old Hot may still hold funds.
    fn validate_binding_id(&self, binding: &WalletBinding) -> Result<()> {
        let path = self.binding_path(binding.network);
        if binding.id.is_empty() {
            anyhow::bail!(
                "wallet binding {} records an empty binding id, so it names no secrets directory \
                 and this instance cannot reach the Hot {} it points at. Nothing was read from it. \
                 Run `dexdo wallet rebind` with this binding's provider (`{}`) to bind a wallet \
                 again -- this record is archived, not deleted, because funds can still sit in that \
                 Hot",
                path.display(),
                binding.hot_address,
                binding.provider,
            );
        }
        if !is_minted_binding_id(&binding.id) {
            anyhow::bail!(
                "wallet binding {} records binding id {:?}, which is not an id this store mints \
                 ({BINDING_ID_LEN} lowercase hex characters). It is used as a directory name and as \
                 an archive filename, so it is refused rather than resolved, and nothing was read \
                 from it. Run `dexdo wallet rebind` with this binding's provider (`{}`) to bind a \
                 wallet again -- this record is archived, not deleted, because funds can still sit \
                 in Hot {}",
                path.display(),
                binding.id,
                binding.provider,
                binding.hot_address,
            );
        }
        let dir = self.bindings_dir().join(&binding.id);
        if !dir.is_dir() {
            anyhow::bail!(
                "wallet binding {} records binding id {}, whose secrets directory {} does not \
                 exist. The id is the only route from this record to that binding's secrets, so \
                 the Hot {} it names cannot be signed for by this instance; it is refused rather \
                 than resolved as the funding wallet. Run `dexdo wallet rebind` with this \
                 binding's provider (`{}`) to bind a wallet again -- this record is archived, not \
                 deleted, because funds can still sit in that Hot",
                path.display(),
                binding.id,
                dir.display(),
                binding.hot_address,
                binding.provider,
            );
        }
        Ok(())
    }

    /// The active binding, or the fail-fast every wallet-dependent command raises BEFORE any chain
    /// write when there is none.
    pub(crate) fn require_active(&self, network: WalletNetwork) -> Result<WalletBinding> {
        match self.load_active(network)? {
            Some(binding) => Ok(binding),
            None => Err(self.not_configured(network)),
        }
    }

    /// There IS an active record here, whatever state it is in -- the question `rebind` asks.
    /// Deliberately not [`Self::require_active`]. `rebind` exists to replace the record, and a
    /// record that fails validation is the one an operator most needs to replace; answering that
    /// question with the validation refusal would leave the only documented way out of a corrupt
    /// binding reachable only from a binding that is not corrupt.
    pub(crate) fn require_active_record(&self, network: WalletNetwork) -> Result<WalletBinding> {
        match self.read_active_record(network)? {
            Some(binding) => Ok(binding),
            None => Err(self.not_configured(network)),
        }
    }

    fn not_configured(&self, network: WalletNetwork) -> anyhow::Error {
        dexdo_core::DexdoError::new(
            dexdo_core::error_codes::E_WALLET_NOT_CONFIGURED,
            format!(
                "no active wallet binding for {network} at {}",
                self.binding_path(network).display()
            ),
        )
        .with_hint(dexdo_core::error_codes::E_WALLET_NOT_CONFIGURED.fix())
        .into()
    }

    /// Reserve one onboarding attempt's id and owner-only secrets directory.
    pub(crate) fn open_draft(&self) -> Result<BindingDraft> {
        let id = new_binding_id();
        let dir = self.bindings_dir().join(&id);
        create_owner_only_dir(&dir)?;
        Ok(BindingDraft { id, dir })
    }

    /// The `<data-dir>/wallet` tree itself, for a provider flow that has to look at what a previous
    /// attempt of its own left behind.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Continue an attempt that already reserved an id, instead of minting a second one.
    /// This is what makes a resumed onboarding commit at all. `commit_onboarded` refuses a binding
    /// whose id is not the one this attempt reserved, so a flow that resumed a stored draft under a
    /// freshly minted id would prove its Hot on chain and then be refused at the last step, with
    /// the phrase it just used sitting in a directory the active binding does not name.
    /// The id is validated before it is joined onto a path, for the reason
    /// [`Self::validate_binding_id`] gives: an id is a path component, and the only ids that reach
    /// here come from reading a file. The directory must already exist -- this reserves nothing and
    /// creates nothing, it adopts what a previous attempt reserved.
    pub(crate) fn adopt_draft(&self, id: &str) -> Result<BindingDraft> {
        if !is_minted_binding_id(id) {
            anyhow::bail!(
                "cannot resume onboarding under binding id {id:?}: it is not an id this store \
                 mints ({BINDING_ID_LEN} lowercase hex characters), and it would be used as a \
                 directory name"
            );
        }
        let dir = self.bindings_dir().join(id);
        if !dir.is_dir() {
            anyhow::bail!(
                "cannot resume onboarding under binding id {id}: its secrets directory {} does \
                 not exist",
                dir.display()
            );
        }
        Ok(BindingDraft {
            id: id.to_string(),
            dir,
        })
    }

    /// Make `binding` the active one ON ITS OWN NETWORK, archiving whatever it replaces there.
    /// Returns the archive path when a previous binding was replaced.
    /// The destination comes from `binding.network` and there is no parameter that could say
    /// otherwise, so a shellnet record cannot be written into the mainnet slot even by a caller
    /// that means to. It also means committing a binding for one network never touches, replaces
    /// or archives the other network's binding: the operator keeps both, which is the point of
    /// keying them separately.
    /// The archive copy is written FIRST. Interrupted after it, the tree holds a harmless duplicate
    /// record; interrupted the other way round, the only record of a Hot that may still hold funds
    /// would be gone. The active file itself is replaced by one atomic rename, so a reader sees the
    /// old binding or the new one and never a half-written file.
    pub(crate) fn commit_active(&self, binding: &WalletBinding) -> Result<Option<PathBuf>> {
        self.create_active_dir()?;
        // The record as it is on disk, NOT the validated one: a binding that fails validation is
        // still a record of a Hot that may hold funds, and archiving it is the whole remediation
        // this store offers. Validating here would make a corrupt binding unreplaceable.
        let archived = match self.read_active_record(binding.network)? {
            Some(previous) => Some(self.archive(&previous)?),
            None => None,
        };
        let mut json =
            serde_json::to_vec_pretty(binding).context("serialize the wallet binding")?;
        json.push(b'\n');
        crate::cli::note::write_private_atomic(&self.binding_path(binding.network), &json)?;
        Ok(archived)
    }

    fn archive(&self, previous: &WalletBinding) -> Result<PathBuf> {
        let dir = self.archive_dir();
        create_owner_only_dir(&dir)?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| anyhow::anyhow!("system clock before epoch: {error}"))?
            .as_secs();
        let path = dir.join(archive_file_name(stamp, &previous.id));
        let mut json = serde_json::to_vec_pretty(previous)
            .context("serialize the wallet binding being archived")?;
        json.push(b'\n');
        crate::cli::note::write_private_atomic(&path, &json)?;
        Ok(path)
    }
}

/// The archive filename for a record being replaced, built so that the id it carries can never
/// steer where the file lands.
/// `archive` is the one place that must accept a record its own reader refuses -- that is how a
/// corrupt binding gets out -- so the id reaching it is untrusted by construction. An id holding `/`
/// or `..` in a hand-edited `binding.json` would otherwise write outside `archive/`.
/// The id is used only when it is the shape this store mints. Otherwise it is dropped from the
/// NAME, not from the record: the archived JSON still carries the id verbatim, so nothing about the
/// broken binding is lost, and a freshly minted token keeps two such archives written in the same
/// second from landing on each other.
fn archive_file_name(stamp: u64, id: &str) -> String {
    if is_minted_binding_id(id) {
        format!("{stamp}-{id}.json")
    } else {
        format!("{stamp}-invalid-id-{}.json", new_binding_id())
    }
}

/// Create a directory the CLI owns alone. The wallet tree holds key files and resumable onboarding
/// drafts, so the directory permissions are part of protecting them, not a detail.
fn create_owner_only_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|error| anyhow::anyhow!("create wallet directory {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                anyhow::anyhow!(
                    "set owner-only permissions on wallet directory {}: {error}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}
