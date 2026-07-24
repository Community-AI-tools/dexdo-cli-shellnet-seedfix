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

if [[ "$STATUS" -ne 0 || "$ACTUAL" != "$EXPECTED" ]]; then
  echo "dexdo version does not match the release tag" >&2
  exit 1
fi
