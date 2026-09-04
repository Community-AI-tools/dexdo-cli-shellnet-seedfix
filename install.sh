#!/bin/sh
# dexdo installer for Linux and macOS.
#
#   curl -fsSL https://github.com/gosh-sh/dexdo-cli/releases/latest/download/install.sh | sh
#
# Detects your OS and CPU, downloads the matching release archive, verifies its
# checksum, and installs `dexdo` into ~/.local/bin (override with DEXDO_BIN_DIR).
#
# It then adds that directory to your PATH in your shell config, so `dexdo`
# works in new terminals. To skip that step:
#
#   curl -fsSL .../install.sh | DEXDO_NO_MODIFY_PATH=1 sh
#   sh install.sh --no-modify-path
#   curl -fsSL .../install.sh | sh -s -- --no-modify-path
set -eu

REPO="gosh-sh/dexdo-cli"
BINDIR="${DEXDO_BIN_DIR:-$HOME/.local/bin}"

# PATH setup is on by default; DEXDO_NO_MODIFY_PATH is the opt-out that survives
# `curl | sh` (where there is no argv), and --no-modify-path covers a downloaded
# script or `sh -s --`.
modify_path=1
case "${DEXDO_NO_MODIFY_PATH:-}" in
  ''|0|false|no) ;;
  *) modify_path=0 ;;
esac
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-modify-path) modify_path=0; shift ;;
    -h|--help)
      echo "usage: install.sh [--no-modify-path]"
      echo "  --no-modify-path   do not touch your shell config (same as DEXDO_NO_MODIFY_PATH=1)"
      exit 0
      ;;
    *) echo "dexdo: unknown argument: $1" >&2; exit 2 ;;
  esac
done

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  osname="linux" ;;
  Darwin) osname="macos" ;;
  *) echo "dexdo: unsupported operating system: $os" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64)   archname="x86_64" ;;
  aarch64|arm64)  archname="aarch64" ;;
  *) echo "dexdo: unsupported architecture: $arch" >&2; exit 1 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "dexdo: '$1' is required" >&2; exit 1; }; }
need curl
need tar

# Resolve the latest release tag.
ver="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
[ -n "$ver" ] || { echo "dexdo: could not resolve the latest release" >&2; exit 1; }
vern="${ver#v}"

asset="dexdo-${vern}-${archname}-${osname}.tar.gz"
base="https://github.com/${REPO}/releases/download/${ver}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "dexdo: downloading ${asset} (${ver})"
curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"

# Verify the archive checksum against SHA256SUMS. Fail closed: a missing
# SHA256SUMS or a missing entry for this asset aborts the install.
curl -fsSL "${base}/SHA256SUMS" -o "${tmp}/SHA256SUMS" || { echo "dexdo: could not fetch SHA256SUMS" >&2; exit 1; }
expected="$(grep " ${asset}\$" "${tmp}/SHA256SUMS" | awk '{print $1}' | head -n1)"
[ -n "$expected" ] || { echo "dexdo: ${asset} not found in SHA256SUMS" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || { echo "dexdo: checksum mismatch" >&2; exit 1; }
echo "dexdo: checksum verified"

tar -C "$tmp" -xzf "${tmp}/${asset}"
mkdir -p "$BINDIR"
[ ! -e "${BINDIR}/dexdo" ] || echo "dexdo: warning: replacing existing ${BINDIR}/dexdo" >&2
install -m 0755 "${tmp}/dexdo-${vern}-${archname}-${osname}/dexdo" "${BINDIR}/dexdo"
echo "dexdo: installed ${ver} to ${BINDIR}/dexdo"

# ---------------------------------------------------------------------------
# The deployment manifest, at the client's sole per-user default. Without the
# variable set, this is the ONLY place dexdo looks for one -- not the working
# directory, the binary directory, or XDG. It is a release artifact, not user
# data, so every install replaces it together with the binary.
#
# Verified rather than assumed: an `install` that silently did nothing leaves
# exactly the broken install this is here to prevent.
# ---------------------------------------------------------------------------
manifest_path="${HOME}/.dexdo/manifest.json"
mkdir -p "$(dirname "$manifest_path")"
[ ! -d "$manifest_path" ] || {
  echo "dexdo: install failed: ${manifest_path} is a directory; expected a file" >&2
  exit 1
}
[ ! -e "$manifest_path" ] || echo "dexdo: warning: replacing existing ${manifest_path}" >&2
install -m 0644 \
  "${tmp}/dexdo-${vern}-${archname}-${osname}/manifest/mainnet.manifest.json" \
  "$manifest_path"
[ -s "$manifest_path" ] || {
  echo "dexdo: install failed: ${manifest_path} was not written" >&2
  exit 1
}
echo "dexdo: installed the mainnet manifest to ${manifest_path}"

# ---------------------------------------------------------------------------
# PATH setup. A binary the shell cannot find is a failed install, so this runs
# by default. The shell is taken from $SHELL (the user's login shell) and NOT
# from the interpreter running this script: `curl | sh` always runs under sh
# while the user lives in zsh/bash/fish.
#
# Only $HOME is ever touched, never /etc; no sudo; no `sed -i` (GNU/BSD differ).
# ---------------------------------------------------------------------------
marker="# added by dexdo installer"

# Config file + the exact line for the user's login shell. Leaves both empty
# when the shell is unknown or $SHELL is unset, which means "print the manual
# instruction and write nothing".
shell_name="${SHELL:-}"
shell_name="${shell_name##*/}"
config=""
path_line=""
case "$shell_name" in
  zsh)
    config="$HOME/.zshrc"
    path_line="export PATH=\"${BINDIR}:\$PATH\""
    ;;
  bash)
    # macOS Terminal starts bash as a login shell, which reads ~/.bash_profile
    # and not ~/.bashrc; on Linux the interactive shell reads ~/.bashrc.
    if [ "$osname" = "macos" ]; then
      config="$HOME/.bash_profile"
    else
      config="$HOME/.bashrc"
    fi
    path_line="export PATH=\"${BINDIR}:\$PATH\""
    ;;
  fish)
    config="$HOME/.config/fish/config.fish"
    path_line="fish_add_path \"${BINDIR}\""
    ;;
  *) ;;
esac

# The line to paste by hand: the one for the detected shell when we know it,
# otherwise the portable POSIX form.
manual_hint() {
  echo "dexdo: add ${BINDIR} to your PATH to run 'dexdo', e.g."
  if [ -n "$path_line" ]; then
    echo "dexdo:     ${path_line}"
  else
    echo "dexdo:     export PATH=\"${BINDIR}:\$PATH\""
  fi
}

if [ "$modify_path" -eq 0 ]; then
  echo "dexdo: PATH setup skipped (--no-modify-path / DEXDO_NO_MODIFY_PATH); no file was modified"
  manual_hint
elif [ -z "$config" ]; then
  if [ -n "$shell_name" ]; then
    echo "dexdo: unrecognized shell '${shell_name}'; no file was modified"
  else
    echo "dexdo: could not detect your shell (\$SHELL is not set); no file was modified"
  fi
  manual_hint
else
  if [ -f "$config" ] && grep -F -x "$path_line" "$config" >/dev/null 2>&1; then
    echo "dexdo: ${BINDIR} is already in ${config}; no file was modified"
  else
    mkdir -p "$(dirname "$config")"
    # Leading blank line so the entry cannot glue itself onto a last line that
    # has no trailing newline.
    printf '\n%s\n%s\n' "$marker" "$path_line" >> "$config"
    echo "dexdo: updated ${config}"
    echo "dexdo: added line: ${path_line}"
    echo "dexdo: run 'source \"${config}\"' or open a new terminal to use dexdo now"
  fi
fi
