#!/usr/bin/env bash
set -euo pipefail

BIN="${1:?usage: check-dexdo-version.sh <binary> <version>}"
VERSION="${2:?usage: check-dexdo-version.sh <binary> <version>}"
EXPECTED="dexdo $VERSION"

set +e
ACTUAL="$("$BIN" --version 2>&1)"
STATUS=$?
set -e

printf 'expected: %s\n' "$EXPECTED"
printf 'actual:   %s\n' "$ACTUAL"

# The build stamps git provenance into `--version`, e.g.
# `dexdo 0.0.22 (3f2a1c9, 2026-08-27T13:00:00+00:00)`. Accept the exact
# release version, or that version immediately followed by ` (` build metadata.
# The `X.Y.Z` must still match the release tag exactly, so a stale or malformed
# binary is still rejected.
if [[ "$STATUS" -ne 0 || ( "$ACTUAL" != "$EXPECTED" && "$ACTUAL" != "$EXPECTED ("* ) ]]; then
  echo "dexdo version does not match the release tag" >&2
  exit 1
fi
