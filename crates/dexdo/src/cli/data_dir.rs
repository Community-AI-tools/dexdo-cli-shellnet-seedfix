use anyhow::{bail, Result};
use std::io::{Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static EXPLICIT_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Configure the one per-process instance root before command dispatch.
pub(crate) fn configure(explicit: Option<PathBuf>) -> Result<()> {
    let Some(path) = explicit else {
        return Ok(());
    };
    std::fs::create_dir_all(&path)
        .map_err(|error| anyhow::anyhow!("create --data-dir {}: {error}", path.display()))?;
    let path = std::fs::canonicalize(&path)
        .map_err(|error| anyhow::anyhow!("resolve --data-dir {}: {error}", path.display()))?;
    if !path.is_dir() {
        bail!("--data-dir {} is not a directory", path.display());
    }
    EXPLICIT_DATA_DIR
        .set(path)
        .map_err(|_| anyhow::anyhow!("--data-dir was configured more than once"))
}

pub(crate) fn explicit() -> Option<&'static Path> {
    EXPLICIT_DATA_DIR.get().map(PathBuf::as_path)
}

fn platform_data_dir() -> Result<PathBuf> {
    directories::ProjectDirs::from("ai", "gosh", "dexdo")
        .map(|project| project.data_dir().to_path_buf())
        .ok_or_else(|| {
            anyhow::anyhow!("could not determine the platform data directory; pass --data-dir")
        })
}

pub(crate) fn effective() -> Result<PathBuf> {
    explicit()
        .map(Path::to_path_buf)
        .map_or_else(platform_data_dir, Ok)
}

pub(crate) fn automatic(relative: impl AsRef<Path>) -> Result<PathBuf> {
    Ok(effective()?.join(relative))
}

/// Resolve an automatic private-file path and ensure its instance root exists owner-only.
/// This is deliberately separate from [`automatic`]: only a path the CLI selected may create its
/// parent. An explicit file flag remains an exact path and gets no implicit directory creation.
pub(crate) fn automatic_private_file(relative: impl AsRef<Path>) -> Result<PathBuf> {
    let root = effective()?;
    std::fs::create_dir_all(&root).map_err(|error| {
        anyhow::anyhow!(
            "create private instance data directory {}: {error}",
            root.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                anyhow::anyhow!(
                    "set owner-only permissions on instance data directory {}: {error}",
                    root.display()
                )
            },
        )?;
    }
    Ok(root.join(relative))
}

/// Rebase a clap-provided canonical default only when the operator selected `--data-dir`.
/// Custom path flags remain exact overrides.
pub(crate) fn rebase_default(path: &mut PathBuf, canonical_default: &str) {
    if path == Path::new(canonical_default) {
        if let Some(root) = explicit() {
            *path = root.join(canonical_default);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum InstanceRole {
    Seller,
    Buyer,
}

impl InstanceRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Seller => "seller",
            Self::Buyer => "buyer",
        }
    }
}

pub(crate) struct InstanceLock {
    file: std::fs::File,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// Refuse two processes of the same runtime role on one effective instance root.
/// Seller and buyer deliberately use different lock files: the two roles are expected to share one
/// instance root and its handover. Legacy runs that explicitly override every mutable mock path keep
/// their existing behavior; an explicit `--data-dir` always takes the lock.
pub(crate) fn acquire_instance_lock(
    role: InstanceRole,
    legacy_uses_shared_defaults: bool,
) -> Result<Option<InstanceLock>> {
    if explicit().is_none() && !legacy_uses_shared_defaults {
        return Ok(None);
    }
    let root = effective()?;
    std::fs::create_dir_all(&root).map_err(|error| {
        anyhow::anyhow!("create instance data directory {}: {error}", root.display())
    })?;
    let path = root.join(format!(".dexdo-{}.instance.lock", role.as_str()));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| anyhow::anyhow!("open instance lock {}: {error}", path.display()))?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {}
        Err(error)
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
                || error.kind() == std::io::ErrorKind::WouldBlock =>
        {
            bail!(
                "another {} instance is already using data directory {}; choose a different \
                 --data-dir for the second instance (lock {} is held)",
                role.as_str(),
                root.display(),
                path.display()
            )
        }
        Err(error) => bail!("lock instance state {}: {error}", path.display()),
    }
    file.rewind()
        .and_then(|_| file.set_len(0))
        .and_then(|_| writeln!(file, "{}", std::process::id()))
        .and_then(|_| file.flush())
        .map_err(|error| anyhow::anyhow!("record instance lock {}: {error}", path.display()))?;
    Ok(Some(InstanceLock { file }))
}
