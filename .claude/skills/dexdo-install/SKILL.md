---
name: dexdo-install
description: Install and verify the dexdo CLI so an agent (or a fresh machine) is ready to sell or buy model inference on the dexdo market (real Acki Nacki shellnet). Covers the one-line installer (or a source build), putting `dexdo` on PATH, fetching the deployed-contracts manifest, verifying with `dexdo --version` / `dexdo doctor`, creating and funding the supported shellnet multisig wallet, and the remaining prerequisites needed before running the seller or buyer. Load this to get `dexdo` installed and green from scratch; then use the `dexdo-sell-model` skill to sell or `dexdo-buy-model` to buy.
---

# dexdo -- install and verify the CLI

Goal: end this skill with a working `dexdo` binary on PATH, the deployed-contracts manifest in place,
`dexdo doctor` green (binary, manifest, and network verified), a supported funded shellnet wallet,
and a clear list of what the operator must still provide before real trading (model key and a
completed failure policy).
Run each step, show its output, and do not advance until the step succeeds. Secrets (wallet seed/key,
note owner secret, provider API keys) are never printed, logged, or committed.

---

## Phase 1. Install the binary

One-line installer (primary):

```sh
# Linux / macOS
curl -fsSL https://get.dex.do/install.sh | sh
# Windows (PowerShell)
# irm https://get.dex.do/install.ps1 | iex
```

The installer downloads the latest release, verifies its SHA256 against the published `SHA256SUMS`,
unpacks it, and installs `dexdo` into `~/.local/bin` (Linux/macOS) or `%LOCALAPPDATA%\dexdo\bin`
(Windows). The Linux binaries are static musl and run on any distro (Ubuntu 20.04+, Debian, RHEL,
Alpine) with no glibc version requirement.

It then puts that directory on PATH by default. On Linux/macOS it appends one line, marked
`# added by dexdo installer`, to the config of the shell named in `$SHELL` -- `~/.zshrc` (zsh),
`~/.bashrc` (bash on Linux), `~/.bash_profile` (bash on macOS), or a `fish_add_path` line in
`~/.config/fish/config.fish` (fish); on Windows it appends to the user `Path` variable. It prints the
file it changed and the line it added, only ever writes inside `$HOME`, needs no `sudo`, and a repeat
run does not duplicate the entry. An unrecognized shell is left untouched with a copy-paste
instruction. The already-running shell keeps its old PATH, so `source` the printed file or open a new
terminal before the next step. To skip the PATH edit, set `DEXDO_NO_MODIFY_PATH=1` (works with
`curl | sh`) or pass `--no-modify-path` (`... | sh -s -- --no-modify-path`).

Build from source (alternative, needs Rust):

```sh
git clone https://github.com/gosh-sh/dexdo-cli && cd dexdo-cli
cargo build --release -p dexdo --features shellnet   # binary: target/release/dexdo
```

The `shellnet` feature is required for any on-chain command; a build without it fails closed with
`unavailable: build with --features shellnet`. The released binary already includes it.

## Phase 2. Verify the binary

```sh
dexdo --version   # prints the installed release, e.g. "dexdo <version>"
dexdo --help      # lists the commands: note, provision, market, seller, buyer, quote, status, ...
```

Both must succeed (exit 0) before continuing.

## Phase 3. Fetch the deployed-contracts manifest

Every on-chain command needs `contracts/deployed.shellnet.json` in the working directory (it pins the
deployed contract addresses and the shellnet version). If you installed the binary (did not build from
source), download it once:

```sh
mkdir -p contracts
curl -fsSL https://raw.githubusercontent.com/gosh-sh/dexdo-cli/main/contracts/deployed.shellnet.json \
  -o contracts/deployed.shellnet.json
```

A source checkout already ships this file.

## Phase 4. Health check

```sh
dexdo doctor --contracts contracts/deployed.shellnet.json
```

`dexdo doctor` reports the reachable shellnet version and whether your manifest is fresh (matches the
deployed contracts). A green doctor here means the binary, manifest, and network are ready. The failure
policy is a separate gate -- you set it up in Phase 5, and `dexdo seller` / `dexdo buyer` enforce a
complete policy when they start (once a policy exists, doctor also flags an incomplete one). If doctor
flags manifest drift, re-download the manifest (Phase 3). If it flags shellnet unreachable, check
network access to `shellnet.ackinacki.org`.

## Phase 5. Prerequisites for real trading (before seller / buyer)

The binary is ready, but real trading needs these from the operator -- gather them now so the sell/buy
flow does not stall:

### Create and fund a supported wallet (shellnet only)

This is the testnet onboarding path for real `shellnet.ackinacki.org`. It is not a mainnet giver
path. The System-dApp giver is used only to create and initially fund this wallet; production
`dexdo note deploy` below has no giver. This path creates
`UpdateCustodianMultisigWallet_v2` v2.2.0 with code hash
`09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded`, one matching pubkey
custodian, and 1-of-1 confirmations. The generic cabinet wallet hash `3a7a5324...` is unsupported.
Each native funding leg is one flag-16 send; the active wallet's spendable ECC[2] budget is a
separate flag-1 send. No flag-2 balance is required by this wallet-to-note path.

This manual `tvm-cli` walkthrough deploys the v2.2.0 wallet, which remains fully usable because
`dexdo` spending accepts both v2.2.0 and v2.4.0 through its exact allowlist; `dexdo` itself is pinned
to deploy the v2.4.0 artifact vendored in the binary, while this walkthrough cannot deploy v2.4.0
until that artifact is reachable at a public URL.

The commands require Rust/Cargo, Git, `curl`, and `jq`. Run the whole block in one POSIX shell on
Linux or macOS. Never enable `set -x`; `tvm-cli genaddr --genkey` includes key material in its
output, so that output is captured in a temporary `0600` file and removed. Native PowerShell wallet
onboarding is not validated or supported. On Windows, use WSL and keep `WALLET_HOME` under the WSL
Linux home, not `/mnt/c`, so `0600` permissions are enforced.

```sh
set -eu
umask 077

TVM_NETWORK=shellnet
DEXDO_ENDPOINT=shellnet.ackinacki.org
[ "$TVM_NETWORK" = shellnet ] || {
  printf '%s\n' 'wallet onboarding is shellnet-only' >&2
  exit 1
}

WALLET_HOME="${WALLET_HOME:-"$HOME/.dexdo/shellnet-wallet"}"
mkdir -p "$WALLET_HOME/contracts"
chmod 700 "$WALLET_HOME" "$WALLET_HOME/contracts"

# How much ECC[2] SHELL the wallet must hold before `dexdo note deploy` will spend anything.
# Derived from the contract's own constants, never from a remembered total -- change the nominal
# below and every figure in this block follows it.
#
#   deposit leg  = NOMINAL_RAW + ROOT_PN_GAS_DEPOSIT_RAW
#     Since 4.0.33 `RootPN.generateVoucher(skUCommit, isFee=false)` subtracts GAS_DEPOSIT from the
#     attachment and matches only the REMAINDER against ALLOWED_NOMINALS, so the wallet must attach
#     the nominal plus the gas deposit or the deposit is refused (ERR_BELOW_GAS_DEPOSIT / 408,
#     ERR_NOT_ALLOWED / 141) after the wallet has already spent.
#   gas voucher leg = ECC_SHELL_DEPOSIT_RAW
#     A separate `isFee=true` voucher, deducted nothing, that gives the new note its own SHELL gas.
#
# `dexdo note deploy` checks the SUM before it submits anything, so an underfunded wallet is
# refused with `missing=<raw>` and no wallet POST is made.
NOMINAL=N100
NOMINAL_RAW=100000000000
ROOT_PN_GAS_DEPOSIT_RAW=250000000000  # contracts/dex/modifiers/modifiers.sol: GAS_DEPOSIT
ECC_SHELL_DEPOSIT_RAW=100000000000    # the SHELL gas voucher leg
WALLET_ECC_MIN=$((NOMINAL_RAW + ROOT_PN_GAS_DEPOSIT_RAW + ECC_SHELL_DEPOSIT_RAW))

TVM_SDK_REV=88d50d3883c5bef619e29db8534002eb5e65eb4b
TVM_SDK_DIR="$WALLET_HOME/tvm-sdk"
TVM_TARGET_DIR="$WALLET_HOME/tvm-sdk-target"

if [ -z "${TVM_CLI:-}" ]; then
  TVM_CLI=$(command -v tvm-cli || true)
fi
if [ -z "$TVM_CLI" ] ||
   ! "$TVM_CLI" --help 2>&1 | grep -Fq "COMMIT_ID: $TVM_SDK_REV"; then
  if [ ! -d "$TVM_SDK_DIR/.git" ]; then
    git init "$TVM_SDK_DIR"
    git -C "$TVM_SDK_DIR" remote add origin https://github.com/Futurizt/tvm-sdk.git
  fi
  git -C "$TVM_SDK_DIR" fetch --depth 1 origin "$TVM_SDK_REV"
  git -C "$TVM_SDK_DIR" checkout --detach FETCH_HEAD
  [ "$(git -C "$TVM_SDK_DIR" rev-parse HEAD)" = "$TVM_SDK_REV" ]
  cargo build --release --locked \
    --manifest-path "$TVM_SDK_DIR/tvm_cli/Cargo.toml" \
    --target-dir "$TVM_TARGET_DIR"
  TVM_CLI="$TVM_TARGET_DIR/release/tvm-cli"
fi
"$TVM_CLI" --help 2>&1 | grep -Fq "COMMIT_ID: $TVM_SDK_REV"

ABI="$WALLET_HOME/contracts/UpdateCustodianMultisigWallet_v2.abi.json"
TVC="$WALLET_HOME/contracts/UpdateCustodianMultisigWallet_v2.tvc"
GIVER_ABI="$WALLET_HOME/contracts/GiverV3.abi.json"

curl -fsSL \
  https://raw.githubusercontent.com/gosh-sh/dexdo-cli/v0.0.17/crates/core/contracts/msig/UpdateCustodianMultisigWallet_v2.abi.json \
  -o "$ABI"
curl -fsSL \
  https://raw.githubusercontent.com/gosh-sh/dexdo-cli/v0.0.17/crates/core/contracts/msig/UpdateCustodianMultisigWallet_v2.tvc \
  -o "$TVC"
curl -fsSL \
  https://raw.githubusercontent.com/gosh-dot-ai/gosh.ackinacki/47c0341ba79651de8d6693a2cc5a79c1b107292f/contracts/giver/GiverV3.abi.json \
  -o "$GIVER_ABI"
chmod 600 "$ABI" "$TVC" "$GIVER_ABI"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
check_sha256() {
  actual_sha256=$(sha256_file "$1")
  [ "$actual_sha256" = "$2" ] || {
    printf 'checksum mismatch: %s\n' "$1" >&2
    exit 1
  }
}

check_sha256 "$ABI" \
  28312c9773b1231623998a2d09d6285a8afc272e10af6b595bfabcddb320e45e
check_sha256 "$TVC" \
  535e180e85ee019c23631c6046449fa2a5536d88f55b26d64e026d671e82d520
check_sha256 "$GIVER_ABI" \
  45738980bfbe5bbb9517aca6ca4e1a0265a5b3881b393fa6a28d8bf51fc716c1

CANONICAL_CODE_HASH=09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded
"$TVM_CLI" -j decode stateinit --tvc "$TVC" > "$WALLET_HOME/artifact-stateinit.json"
[ "$(jq -er '.code_hash' "$WALLET_HOME/artifact-stateinit.json")" = \
  "$CANONICAL_CODE_HASH" ]

KEYS="$WALLET_HOME/wallet.keys.json"
if [ ! -s "$KEYS" ]; then
  GENADDR_TRANSCRIPT="$WALLET_HOME/.genaddr-transcript.$$"
  : > "$GENADDR_TRANSCRIPT"
  chmod 600 "$GENADDR_TRANSCRIPT"
  trap 'rm -f "$GENADDR_TRANSCRIPT"' EXIT
  "$TVM_CLI" -j genaddr --abi "$ABI" --genkey "$KEYS" "$TVC" \
    > "$GENADDR_TRANSCRIPT" 2>&1
  rm -f "$GENADDR_TRANSCRIPT"
fi
chmod 600 "$KEYS"
jq -e '.public | test("^[0-9a-fA-F]{64}$")' "$KEYS" >/dev/null
jq -e '.secret | test("^[0-9a-fA-F]{64}$")' "$KEYS" >/dev/null

"$TVM_CLI" -j genaddr --abi "$ABI" --setkey "$KEYS" "$TVC" \
  > "$WALLET_HOME/derived-1.json"
"$TVM_CLI" -j genaddr --abi "$ABI" --setkey "$KEYS" "$TVC" \
  > "$WALLET_HOME/derived-2.json"
WALLET_ADDR=$(jq -er '.raw_address' "$WALLET_HOME/derived-1.json")
WALLET_ROUTE=$(jq -er '.dapp_account' "$WALLET_HOME/derived-1.json")
[ "$WALLET_ADDR" = \
  "$(jq -er '.raw_address' "$WALLET_HOME/derived-2.json")" ]
[ "$WALLET_ROUTE" = \
  "$(jq -er '.dapp_account' "$WALLET_HOME/derived-2.json")" ]
printf '%s\n' "$WALLET_ADDR" | grep -Eq '^0:[0-9a-fA-F]{64}$'

WORK_TVC="$WALLET_HOME/wallet.tvc"
cp "$TVC" "$WORK_TVC"
"$TVM_CLI" -j genaddr --abi "$ABI" --setkey "$KEYS" --save "$WORK_TVC" \
  > "$WALLET_HOME/derived-saved.json"
[ "$WALLET_ADDR" = \
  "$(jq -er '.raw_address' "$WALLET_HOME/derived-saved.json")" ]
"$TVM_CLI" -j decode stateinit --tvc "$WORK_TVC" \
  > "$WALLET_HOME/wallet-stateinit.json"
[ "$(jq -er '.code_hash' "$WALLET_HOME/wallet-stateinit.json")" = \
  "$CANONICAL_CODE_HASH" ]

account_read() {
  : > "$2"
  : > "$2.err"
  chmod 600 "$2" "$2.err"
  if "$TVM_CLI" -j -u "$TVM_NETWORK" account "$1" > "$2" 2> "$2.err"; then
    return 0
  fi
  jq -e '.Error | type == "string"' "$2" >/dev/null
}

ACCOUNT="$WALLET_HOME/wallet-account.json"
account_read "$WALLET_ROUTE" "$ACCOUNT"
ACCOUNT_ERROR=$(jq -r '.Error // empty' "$ACCOUNT")
case "$ACCOUNT_ERROR" in
  "")
    ACCOUNT_STATE=$(jq -r '.acc_type // "Missing"' "$ACCOUNT")
    ;;
  *"Not found: Resource not found"*)
    ACCOUNT_STATE=Missing
    ;;
  *)
    printf '%s\n' 'shellnet wallet account query failed' >&2
    exit 1
    ;;
esac

if [ "$ACCOUNT_STATE" = Active ]; then
  if ! jq -e --arg code "$CANONICAL_CODE_HASH" \
    '.acc_type == "Active" and .code_hash == $code' "$ACCOUNT" >/dev/null; then
    printf '%s\n' 'unsupported wallet code hash; refusing before funding/deploy' >&2
    exit 1
  fi
else
  [ "$ACCOUNT_STATE" = Missing ] || [ "$ACCOUNT_STATE" = Uninit ] || {
    printf 'unexpected wallet state: %s\n' "$ACCOUNT_STATE" >&2
    exit 1
  }

  GIVER_ROUTE=0000000000000000000000000000000000000000000000000000000000000000::1111111111111111111111111111111111111111111111111111111111111111
  GIVER_ACCOUNT="$WALLET_HOME/giver-account.json"
  account_read "$GIVER_ROUTE" "$GIVER_ACCOUNT"
  if ! jq -e \
    '.acc_type == "Active" and (.code_hash | type == "string" and length == 64)' \
    "$GIVER_ACCOUNT" >/dev/null; then
    printf '%s\n' \
      'shellnet System-dApp giver unavailable or empty; refusing before wallet funding' >&2
    exit 1
  fi

  giver_send() {
    GIVER_AMOUNT=$1
    GIVER_FLAG=$2
    GIVER_RECEIPT=$3
    GIVER_PARAMS=$(jq -cn \
      --arg dest "$WALLET_ADDR" \
      --arg amount "$GIVER_AMOUNT" \
      --argjson flag "$GIVER_FLAG" \
      '{dest:$dest,value:$amount,ecc:{"2":$amount},flag:$flag}')
    "$TVM_CLI" -j -u "$TVM_NETWORK" callx \
      --addr "$GIVER_ROUTE" \
      --abi "$GIVER_ABI" \
      --method sendCurrencyWithFlag \
      "$GIVER_PARAMS" > "$GIVER_RECEIPT" 2> "$GIVER_RECEIPT.err"
    chmod 600 "$GIVER_RECEIPT" "$GIVER_RECEIPT.err"
    jq -e '.aborted == false and .exit_code == 0' "$GIVER_RECEIPT" >/dev/null
  }

  giver_send 200000000000 16 "$WALLET_HOME/giver-predeploy-flag16.json"

  poll_account_state() {
    POLL_EXPECTED=$1
    POLL_INDEX=1
    while [ "$POLL_INDEX" -le 30 ]; do
      account_read "$WALLET_ROUTE" "$ACCOUNT"
      if jq -e --arg state "$POLL_EXPECTED" \
        '.Error == null and .acc_type == $state' "$ACCOUNT" >/dev/null; then
        return 0
      fi
      POLL_INDEX=$((POLL_INDEX + 1))
      sleep 5
    done
    printf 'timeout waiting for wallet state %s\n' "$POLL_EXPECTED" >&2
    return 1
  }

  poll_account_state Uninit
  jq -e '(.balance | tonumber) >= 200000000000' "$ACCOUNT" >/dev/null

  PUBLIC_KEY=$(jq -er '.public' "$KEYS")
  CONSTRUCTOR_JSON=$(jq -cn --arg pubkey "0x$PUBLIC_KEY" \
    '{owners_pubkey:[$pubkey],owners_address:[],reqConfirms:1,reqConfirmsData:1,value:"0"}')
  "$TVM_CLI" -j -u "$TVM_NETWORK" deploy \
    --abi "$ABI" \
    --keys "$KEYS" \
    --dst-dapp-id "${WALLET_ROUTE%%::*}" \
    "$WORK_TVC" "$CONSTRUCTOR_JSON" \
    > "$WALLET_HOME/wallet-deploy.json" \
    2> "$WALLET_HOME/wallet-deploy.err"
  chmod 600 "$WALLET_HOME/wallet-deploy.json" "$WALLET_HOME/wallet-deploy.err"
  jq -e '.aborted == false and .exit_code == 0' \
    "$WALLET_HOME/wallet-deploy.json" >/dev/null

  poll_account_state Active
  jq -e --arg code "$CANONICAL_CODE_HASH" \
    '.code_hash == $code' "$ACCOUNT" >/dev/null

  giver_send "$WALLET_ECC_MIN" 1 "$WALLET_HOME/giver-postdeploy-flag1.json"
  giver_send 200000000000 16 "$WALLET_HOME/giver-postdeploy-flag16.json"

  BALANCE_POLL_INDEX=1
  while [ "$BALANCE_POLL_INDEX" -le 30 ]; do
    account_read "$WALLET_ROUTE" "$ACCOUNT"
    if jq -e --arg code "$CANONICAL_CODE_HASH" \
      --argjson ecc_min "$WALLET_ECC_MIN" \
      '.acc_type == "Active"
       and .code_hash == $code
       and (.balance | tonumber) >= 200000000000
       and (.ecc_balance["2"] | tonumber) >= $ecc_min' \
      "$ACCOUNT" >/dev/null; then
      break
    fi
    BALANCE_POLL_INDEX=$((BALANCE_POLL_INDEX + 1))
    sleep 5
  done
  [ "$BALANCE_POLL_INDEX" -le 30 ] || {
    printf '%s\n' 'timeout waiting for sufficient wallet balances' >&2
    exit 1
  }
fi

account_read "$WALLET_ROUTE" "$ACCOUNT"
jq -e --arg code "$CANONICAL_CODE_HASH" \
  '.acc_type == "Active" and .code_hash == $code' "$ACCOUNT" >/dev/null

"$TVM_CLI" -j -u "$TVM_NETWORK" runx \
  --addr "$WALLET_ROUTE" --abi "$ABI" --method getVersion '{}' \
  > "$WALLET_HOME/getVersion.json" 2> "$WALLET_HOME/getVersion.err"
"$TVM_CLI" -j -u "$TVM_NETWORK" runx \
  --addr "$WALLET_ROUTE" --abi "$ABI" --method getCustodians '{}' \
  > "$WALLET_HOME/getCustodians.json" 2> "$WALLET_HOME/getCustodians.err"
"$TVM_CLI" -j -u "$TVM_NETWORK" runx \
  --addr "$WALLET_ROUTE" --abi "$ABI" --method getParameters '{}' \
  > "$WALLET_HOME/getParameters.json" 2> "$WALLET_HOME/getParameters.err"
chmod 600 "$WALLET_HOME"/getVersion.* \
  "$WALLET_HOME"/getCustodians.* "$WALLET_HOME"/getParameters.*

jq -e \
  '.value0 == "2.2.0" and .value1 == "UpdateCustodianMultisigWallet_v2"' \
  "$WALLET_HOME/getVersion.json" >/dev/null
EXPECTED_PUBKEY="0x$(jq -er '.public' "$KEYS")"
jq -e --arg pubkey "$EXPECTED_PUBKEY" \
  '(.custodians | length) == 1
   and (.custodians[0].owner_pubkey | ascii_downcase) == ($pubkey | ascii_downcase)
   and .custodians[0].owner_address == null' \
  "$WALLET_HOME/getCustodians.json" >/dev/null
jq -e \
  '(.requiredTxnConfirms | tostring) == "1"
   and (.requiredDataConfirms | tostring) == "1"' \
  "$WALLET_HOME/getParameters.json" >/dev/null

NATIVE_BALANCE=$(jq -er '.balance' "$ACCOUNT")
ECC2_BALANCE=$(jq -r '.ecc_balance["2"] // "0"' "$ACCOUNT")
[ "$NATIVE_BALANCE" -ge 200000000000 ] || {
  printf '%s\n' 'wallet native balance is below the onboarding minimum' >&2
  exit 1
}
[ "$ECC2_BALANCE" -ge "$WALLET_ECC_MIN" ] || {
  printf 'wallet ECC[2] balance %s is below the %s the %s deposit needs\n' \
    "$ECC2_BALANCE" "$WALLET_ECC_MIN" "$NOMINAL" >&2
  exit 1
}
printf 'supported shellnet wallet ready: %s\n' "$WALLET_ADDR"
```

An immediate rerun reaches the `Active` branch, re-verifies code hash, version, sole matching
custodian, confirmation parameters, and balances, and submits no giver or deploy transaction. If an
existing wallet is underfunded, the block fails closed; it does not use the onboarding giver as a
general-purpose top-up.

Create a production note from that wallet. This command is the no-giver path:

```sh
WALLET_SECRET="$WALLET_HOME/wallet.secret.hex"
jq -er '.secret | select(test("^[0-9a-fA-F]{64}$"))' "$KEYS" > "$WALLET_SECRET"
chmod 600 "$WALLET_SECRET"

PN_POOL="${DEXDO_PN_POOL:-"$WALLET_HOME/pn_pool.json"}"
dexdo note deploy --json \
  --multisig-address "$WALLET_ADDR" \
  --multisig-key "$WALLET_SECRET" \
  --nominal "$NOMINAL" \
  --token-type shell \
  --endpoint "$DEXDO_ENDPOINT" \
  --pool "$PN_POOL" > "$WALLET_HOME/note-deploy.json"
jq -e '.status == "deployed" and .error == null' \
  "$WALLET_HOME/note-deploy.json" >/dev/null
chmod 600 "$PN_POOL" "$WALLET_HOME/note-deploy.json"
[ ! -f "$PN_POOL.recovery.json" ] || chmod 600 "$PN_POOL.recovery.json"
export DEXDO_PN_POOL="$PN_POOL"

NOTE_ADDR=$(jq -er '.notes[-1].address' "$PN_POOL")

# `dexdo note balance` refuses any note that is not the CURRENT PrivateNote generation and exits
# non-zero, so reaching the line after it is itself the generation proof. Do not re-assert the code
# hash from the manifest file here: the CLI checks against the hash it verified against the live
# chain, and a manifest copy can be older than the chain (`dexdo doctor` prints both).
dexdo note balance \
  --note-addr "$NOTE_ADDR" \
  --contracts contracts/deployed.shellnet.json \
  --endpoint "$DEXDO_ENDPOINT" > "$WALLET_HOME/note-balance.txt"
chmod 600 "$WALLET_HOME/note-balance.txt"
grep -Fq 'status: Active' "$WALLET_HOME/note-balance.txt"

# The tradeable money is the note's RECORD (`PrivateNote.getDetails().balance`), not the account's
# ECC[2] coin pocket -- two different balances, printed under two different headings. The nominal
# lands in the record; the pocket holds deployment gas and is NOT the nominal.
sed -n '/^PrivateNote.getDetails spendable token balance (trading money):$/,/^[^ ]/p' \
  "$WALLET_HOME/note-balance.txt" | grep -Fq "(raw $NOMINAL_RAW)"
```

The pool and recovery file contain note owner secrets. Never print or commit them. The block above is
the check to run before using the note: `Active`, the current generation (enforced by `dexdo note
balance` itself), and the selected nominal present as the `getDetails` spendable record. Do not
expect the account's own ECC[2] to equal the nominal -- since 4.0.33 a note is born holding
`RootPN.GAS_DEPOSIT` in that pocket, and a fully funded note can read `0` there while its record
holds the whole balance.

### Other prerequisites

1. A **model access key** for the seller only (for example `GROQ_API_KEY`), exported in the
   environment (`export GROQ_API_KEY=...`), never written to logs or files that get committed.
2. A completed **failure policy**. Scaffold and fill it now:

   ```sh
   dexdo policy init --role seller    # or --role buyer
   dexdo policy show
   ```

   The real `dexdo seller`/`dexdo buyer` refuse to start until every field is set (no `UNSET`). For a
   seller, `seller.max_open_deals` must be exactly `1`. Use the allowed values listed under
   `_legend.allowed` in the scaffold.
3. A **private note** (wallet-funded, no giver). The wallet block above already deploys one; these
   are the rules it obeys. Notes are funded in SHELL only, so `--token-type shell` is the only
   accepted currency, and `--nominal` is required with no default (`N100`, `N1000`, or `N10000` --
   a larger `N...` = more SHELL, and the `WALLET_ECC_MIN` above follows whichever you pick).
   `dexdo note deploy` is the user note-creation path. It creates or appends the pool file, which
   holds the note owner secret. Keep it private, never commit it, and point later seller or buyer
   commands at it -- the block above exports `DEXDO_PN_POOL` for you, or set it by hand:

   ```sh
   export DEXDO_PN_POOL="$PWD/pn_pool.json"
   ```

## Phase 6. Run it -- work end to end

After Phase 5 (wallet, key, policy, note), pull the note address and owner secret out of the pool (the
secret goes to a `0600` file, never the screen):

```sh
NOTE_ADDR=$(jq -r '.notes[-1].address' "$DEXDO_PN_POOL")
jq -r '.notes[-1].owner_secret_key_hex' "$DEXDO_PN_POOL" > note.secret.hex
chmod 600 note.secret.hex
```

### Sell (seller side)

Needs a `models.json` mapping your model (frame id, upstream base_url, served_model, `api_key_env`).
Read the current price, provision one per-deal market, then run the gateway:

```sh
dexdo market qwen--qwen3--32b --note-addr "$NOTE_ADDR" --contracts contracts/deployed.shellnet.json
dexdo provision --note-addr "$NOTE_ADDR" --note-key note.secret.hex --frame-model qwen--qwen3--32b \
  --nonce 1 --price-per-tick 1000000000 --max-ticks 1024 --deposit-shells 20 --output market.json \
  --contracts contracts/deployed.shellnet.json
export GROQ_API_KEY=<your-key>
dexdo seller --market market.json --model qwen --models models.json \
  --note-addr "$NOTE_ADDR" --note-key note.secret.hex --gateway-listen 0.0.0.0:8443 \
  --gateway-advertise <public-host>:8443 \
  --contracts contracts/deployed.shellnet.json
```

`--gateway-advertise` is the address a REMOTE buyer dials; it must be publicly reachable.
Startup rejects a bind-all/loopback/private/link-local/CGNAT advertise -- and any reserved range
that is never routed (documentation, benchmarking, `240.0.0.0/4`, `0.0.0.0/8`, multicast) -- with
`error[E_ADVERTISE_NOT_PUBLIC]` before posting the offer. For same-host or LAN testing only,
add `--allow-private-advertise`.

Hand the buyer the deal address (`token_contract` in `market.json`) and the frame model
`qwen--qwen3--32b`. Check revenue: `dexdo status 0:<TC> --contracts contracts/deployed.shellnet.json`
or `dexdo monitor --market market.json --contracts contracts/deployed.shellnet.json`.

### Buy (buyer side)

Read an executable quote, place the buy, then send OpenAI-style requests to the local listener:

```sh
dexdo quote --market market.json --ticks 8 --contracts contracts/deployed.shellnet.json
dexdo buyer --market market.json --note-addr "$NOTE_ADDR" --note-key note.secret.hex \
  --ticks 8 --max-price-per-tick 1000000000 --local-listen 127.0.0.1:8080 \
  --contracts contracts/deployed.shellnet.json
# in another shell, send OpenAI-style requests to the buyer's local endpoint:
curl http://127.0.0.1:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"qwen--qwen3--32b","messages":[{"role":"user","content":"hi"}]}'
```

`--max-price-per-tick` must be `>=` the ask or the order never crosses. Check the deal with
`dexdo status 0:<TC> --contracts contracts/deployed.shellnet.json`.

## Next (full flows + recovery)

- To SELL model access: load the `dexdo-sell-model` skill -- models.json, pricing, provision, the
  gateway, status/monitor accounting, and wrap-up.
- To BUY model access: load the `dexdo-buy-model` skill -- quote depth, price ceilings, continuity
  modes, using the model, and recovery/resume.

## Hard rules

- Never print, log, or commit the wallet seed/key, the note owner secret (`owner_secret_key_hex`), the
  pool file, or any provider API key.
- Every on-chain command takes the same `contracts/deployed.shellnet.json`; a mismatch between two
  sides is diagnosed by `dexdo doctor`.

## Common install errors

- `dexdo: command not found` right after install -- the installer edits the shell config, but a shell
  that is already running keeps its old PATH; `source` the file the installer printed, or open a new
  terminal. If the installer reported an unrecognized shell (or ran with `DEXDO_NO_MODIFY_PATH=1` /
  `--no-modify-path`), add the printed line to your shell config by hand (Linux/macOS: `~/.local/bin`).
- `unavailable: build with --features shellnet` -- a source build compiled without the feature; rebuild
  with `--features shellnet` (Phase 1). The released binary already includes it.
- `dexdo doctor` reports manifest drift -- re-download `contracts/deployed.shellnet.json` (Phase 3).
- On an older Linux the released binary still runs (static musl); if a self-built glibc binary fails
  with `GLIBC_... not found`, use the released musl binary instead of a local glibc build.
