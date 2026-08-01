---
name: dexdo-sell-model
description: Guides a SELLER end-to-end through selling model inference on the dexdo market (real shellnet) -- install the client, deploy a wallet-funded private note, configure the model access key and models.json, read the current price with `dexdo market`, fill and validate the required seller policy, provision a per-deal market (`dexdo provision` -> market.json), run the `dexdo seller` gateway (posts the offer, forces the model, proxies the real upstream, streams tick by tick), hand the deal address to the buyer, and check by-fact accounting (`dexdo status`/`dexdo monitor`) -- how many ticks were delivered and how much SHELL was received. Load this when the user wants to SELL access to their model, stand up a seller gateway, serve buyers, or check revenue and delivered tokens. For the buyer side, use the `dexdo-buy-model` skill.
---

# dexdo -- selling model access (seller side)

Walk the seller through the real shellnet flow: install -> note -> price -> policy -> validate ->
provision -> gateway -> status. After each command, show the output and do not advance until the step is green.
Secrets (wallet seed/key, note owner secret, the pool file, `GROQ_API_KEY`) are never printed or
committed.

If any command fails, run `dexdo doctor` first -- it reports the shellnet version, manifest
freshness, and whether your `policy.json` is complete.

**Prerequisites:** a deployed and funded `UpdateCustodianMultisigWallet_v2` v2.2.0 wallet holding
test tokens plus its seed phrase (or key file), and a model access key (for example
`GROQ_API_KEY`). The wallet must have exactly one custodian whose public key matches the supplied
funding key. Other wallet contract types are not supported, and the CLI does not create or fund the
multisig.

---

## Phase 1. Install the client

One-line installer (primary):

```sh
# Linux / macOS
curl -fsSL https://github.com/gosh-sh/dexdo-cli/releases/latest/download/install.sh | sh
# Windows (PowerShell)
# irm https://github.com/gosh-sh/dexdo-cli/releases/latest/download/install.ps1 | iex
```

Build from source (alternative):

```sh
git clone https://github.com/gosh-sh/dexdo-cli && cd dexdo-cli
cargo build --release -p dexdo --features shellnet   # binary: target/release/dexdo
```

Verify with `dexdo --help`. Every command defaults to the deployed-contracts manifest at
`contracts/deployed.shellnet.json` in the working directory; if you installed the binary (did not
build from source), download it once:

```sh
mkdir -p contracts
curl -fsSL https://raw.githubusercontent.com/gosh-sh/dexdo-cli/main/contracts/deployed.shellnet.json \
  -o contracts/deployed.shellnet.json
```

## Phase 2. Deploy a private note

`dexdo note deploy` funds a fresh private note from your multisig wallet (no giver) and folds it
into a pool file. The note's SHELL funds the per-deal market deploys, gas, and runtime, so pick a
nominal with enough SHELL (a larger `N...` = more SHELL).

```sh
dexdo note deploy \
  --multisig-address 0:<WALLET-ADDRESS> \
  --multisig-seed-file /path/to/wallet.seed \
  --nominal N10000 \
  --token-type nackl \
  --endpoint shellnet.ackinacki.org \
  --pool pn_pool.json
```

Use `--multisig-key /path/to/wallet.key` (a file with the 32-byte hex secret) instead of
`--multisig-seed-file` if you hold the raw key. `pn_pool.json` holds the note owner secret -- keep it
private, never commit it. `dexdo note deploy` is the user note-creation path. Point later seller
commands at the pool it creates:

```sh
export DEXDO_PN_POOL="$PWD/pn_pool.json"
```

## Phase 3. Note key, balance check, models.json, and the upstream key

Pull the note address and owner secret out of the pool with `jq` (the secret goes straight to a
`0600` file, never to the screen). `--note-addr` = `$NOTE_ADDR`; `--note-key` = `note.secret.hex`.

```sh
NOTE_ADDR=$(jq -r '.notes[-1].address' pn_pool.json)
jq -r '.notes[-1].owner_secret_key_hex' pn_pool.json > note.secret.hex
chmod 600 note.secret.hex
```

Confirm the note actually holds SHELL before you spend it (read-only, no key):

```sh
dexdo note balance --note-addr "$NOTE_ADDR" --contracts contracts/deployed.shellnet.json
```

**Sizing:** the note's on-chain SHELL (its ECC currency-2 balance) must cover `--deposit-shells` for
the deal deploys (Phase 5, whole SHELL) plus runtime gas. If it is short, deploy a larger `--nominal`
(or another note). Provision fails closed if `--deposit-shells` exceeds this balance.

`models.json` in the working directory maps a model key to its canonical id, upstream, and metadata.
`frame_model` is the on-chain canonical id (the market name); `served_model` is sent upstream;
`api_key_env` names the env var holding the key. Add another model as a new entry.

```json
{
  "models": {
    "qwen": {
      "frame_model": "qwen--qwen3--32b",
      "base_url": "https://api.groq.com/openai/v1",
      "served_model": "qwen/qwen3-32b",
      "api_key_env": "GROQ_API_KEY",
      "tokenizer_family": "qwen",
      "price_per_tick": 1000000000,
      "capabilities": { "logprobs": true, "top_logprobs": 5, "max_output_tokens": 40960 }
    }
  }
}
```

`capabilities.max_output_tokens` is the model's own maximum completion length at that provider (Groq
answers `400` above `40960` for `qwen/qwen3-32b`). The seller clamps every outbound request to it, so the
field is REQUIRED: a model entry without it is refused before the provider is contacted rather than served
with an unbounded limit. Take the number from your provider's model card.

The `price_per_tick` here is decorative metadata -- it does NOT set the live deal price. The price
buyers pay is whatever you set at `dexdo provision --price-per-tick` (Phase 5); editing this field
changes nothing on-chain.

Export the upstream key (not written to logs): `export GROQ_API_KEY=<your-key>`

### Selling Claude through the native Anthropic upstream

Dexdo selects `seller/upstream/anthropic.rs` when the model entry points to `api.anthropic.com`. The seller
calls the Anthropic Messages API directly; do not put a LiteLLM/OpenAI-compatible proxy between them. Keep the
real key in the environment named by `api_key_env`, never in `models.json`. Anthropic does not return token ids
or OpenAI logprobs, so keep `logprobs` off and omit `top_logprobs`:

```json
{
  "models": {
    "claude-sonnet": {
      "frame_model": "anthropic--claude-sonnet--4",
      "served_model": "claude-sonnet-4-20250514",
      "base_url": "https://api.anthropic.com",
      "api_key_env": "ANTHROPIC_API_KEY",
      "tokenizer_family": "claude",
      "price_per_tick": 1000000000,
      "capabilities": { "logprobs": false, "max_output_tokens": 64000 }
    }
  }
}
```

Set `ANTHROPIC_API_KEY`, then run the seller with `--model claude-sonnet --models models.json`. The adapter
streams text immediately and reconciles billing to Anthropic's cumulative `usage.output_tokens`, not SSE
content-delta count.

## Phase 4. Read the price, then fill the failure policy

First look at the model's shared order book (read-only, writes nothing) so you can price your offer
against the market:

```sh
dexdo market qwen--qwen3--32b --note-addr "$NOTE_ADDR" \
  --contracts contracts/deployed.shellnet.json
```

It prints the resting asks (price per tick, max ticks) and their deal addresses. `dexdo markets
--models models.json --note-addr "$NOTE_ADDR" --contracts contracts/deployed.shellnet.json` lists
every configured book. To be taken by a best-price buyer, price at or below the current best ask.

The real `dexdo provision` and `dexdo seller` commands use the same complete seller policy. Keep one
explicit path for both commands:

```sh
POLICY="${XDG_CONFIG_HOME:-$HOME/.config}/dexdo/policy.json"
dexdo policy init --role seller --path "$POLICY"
dexdo policy edit --path "$POLICY"
```

This writes each required field as `UNSET`. Edit the file (or `dexdo policy edit`) and replace every
`UNSET` with a valid choice:

```json
{
  "version": 1,
  "seller": {
    "on": {
      "buyer_no_show": "retire_gateway",
      "after_deal_done": "retire",
      "dispute_against_me": "release_if_clean"
    },
    "max_open_deals": 1
  }
}
```

Allowed values (the scaffold also lists these under `_legend.allowed`):

- `seller.on.buyer_no_show`: `retire_gateway`.
- `seller.on.after_deal_done`: `retire`.
- `seller.on.dispute_against_me`: `release_if_clean | hold`.
- `seller.max_open_deals`: **exactly `1`** -- the gateway owns one deal per
  process and refuses to start with any other value.

The republish and cleanup action families are not seller runtime capabilities. Validation rejects
them locally; it never substitutes a supported action.

`policy.json` is the shared recovery control point. Manage it with `dexdo policy init`,
`dexdo policy show`, `dexdo policy edit`, and `dexdo policy validate`. The seller section chooses
the supported terminal action after buyer no-show or deal completion and whether to release or hold
a dispute.

## Phase 5. Validate the policy, then provision the deal

Validate immediately before provisioning. `provision` repeats the same pure-local validation before
it reads the note key, connects to shellnet, prompts for a deposit, writes a manifest, or submits a
transaction:

```sh
dexdo policy validate --role seller --path "$POLICY"
dexdo provision \
  --policy "$POLICY" \
  --note-addr "$NOTE_ADDR" \
  --note-key note.secret.hex \
  --frame-model qwen--qwen3--32b \
  --nonce 1 \
  --price-per-tick 1000000000 \
  --max-ticks 1024 \
  --deposit-shells 20 \
  --output market.json \
  --contracts contracts/deployed.shellnet.json
```

Provision the per-deal `TokenContract` once per deal. `--nonce` is required and must be unique per
deal (it derives the deal address). `--price-per-tick` is the live raw ECC[2] tick price and must
be a positive whole `PRICE_STEP` multiple (`1000000000` raw = 1 SHELL);
`--max-ticks` is a tick count and bounds the deal.
`--deposit-shells` (whole SHELL) funds the two deploys (RootModel + TokenContract, split ~half each),
defaults to ~20, and must fit the note balance from Phase 3 -- do not set it to the whole note (the
remainder burns at `destroy`, and the note still needs runtime SHELL). The result `market.json`
carries the deal address (`token_contract`), the model, and the nonce.

## Phase 6. Run the seller gateway

```sh
dexdo seller \
  --policy "$POLICY" \
  --market market.json \
  --model qwen \
  --models models.json \
  --note-addr "$NOTE_ADDR" \
  --note-key note.secret.hex \
  --gateway-listen 0.0.0.0:8443 \
  --contracts contracts/deployed.shellnet.json
```

The offer price and volume come from the provisioned deal in `market.json` (set in Phase 5). The
seller's own `--price-per-tick` flag is **ignored on the `--market` path** -- to re-price, run a new
`dexdo provision` with a fresh `--nonce` and serve that manifest. `--gateway-listen` must be
reachable by the buyer; if the buyer is on another host, also pass `--gateway-advertise
<public-host>:8443` (the public address written into the handover -- never `127.0.0.1`). With
`--market`, do not also pass `--token-contract`/`--nonce` (they come from the file). On start the
gateway posts the offer, then daemonizes: it polls for a match, opens the stream, and streams tick by
tick. The wait for a buyer is open-ended -- the resting offer is not torn down.

## Phase 7. Hand the deal address to the buyer

Give the buyer either the `market.json` file OR the `token_contract` string (`0:...`) from it. If you
hand over the bare `token_contract` (not the file), you **must also give the buyer the canonical
frame model** `qwen--qwen3--32b` -- the buyer needs it as `--frame-model` alongside
`--token-contract`. The buyer places the buy; the gateway opens the stream automatically and forces
the configured model.

## Phase 8. Check status (by-fact accounting)

Authoritative deal state (reads the chain, moves nothing) -- pass the deal `token_contract` from
`market.json`:

```sh
dexdo status 0:<TOKEN-CONTRACT> --contracts contracts/deployed.shellnet.json
```

It prints the lifecycle `state=` (`placed`/`funded-but-never-opened`/`probe`/`streaming`/`stopped`/
`disputed`), the boolean flags (`funded`/`opened`/`probe_accepted`/`disputed`), and accounting
(`finalized_owed`, `buyer_locked`, `deposit`, ...). For a revenue roll-up across one or more markets:

```sh
dexdo monitor --market market.json --contracts contracts/deployed.shellnet.json
```

Read-only: ticks delivered, SHELL received, per-deal collateral held or burned, and whether the deal is closed.
Repeat `--market` for several markets; run it in a separate terminal.

## Phase 9. Anti-abuse and recovery

Each deal keeps its own exact `2P` seller bond and contested buyer amount in that TokenContract.
A dispute freezes only those per-deal funds; it does not lock the seller's or buyer's whole
PrivateNote, so other independent deals remain possible.

Use the recovery action that matches the failure:

```text
+----------------------------------------+-------------------------------------+-------------------------------------------------------------------+
| Situation                              | Command                             | What it gives you                                                 |
+----------------------------------------+-------------------------------------+-------------------------------------------------------------------+
| Concede a dispute                      | dexdo release-dispute               | Returns this TC's contested amount and seller bond.                |
| Collect finalized closed-deal earnings | dexdo withdraw-shell                | Moves finalized SHELL owed by the deal to the recipient.          |
| Cancel one stale resting offer         | dexdo orders cancel <ID>            | Removes that order from the model book.                           |
| Cancel all stale resting offers        | dexdo orders cancel-all             | Removes all of this note's orders from the model book.            |
+----------------------------------------+-------------------------------------+-------------------------------------------------------------------+
```

`dexdo release-dispute` and `dexdo withdraw-shell` take `--note-addr` and `--note-key`, plus either
`--token-contract 0:<TC>` or `--market market.json`. For resting offers, put the shared note and
market flags before the subcommand:

```sh
dexdo orders --note-addr "$NOTE_ADDR" --note-key note.secret.hex --market market.json cancel <ID>
dexdo orders --note-addr "$NOTE_ADDR" --note-key note.secret.hex --market market.json cancel-all
```

Resolve a disputed TC with `release-dispute` or arbitration. There is no whole-note stream lock or
force-clear step in the 4.0.28 economics model.

## Wrap-up

After the buyer closes (stops) the deal, close the deal contract to release resources (any leftover
deal gas burns cross-dapp):

```sh
dexdo destroy --market market.json --note-addr "$NOTE_ADDR" --note-key note.secret.hex \
  --contracts contracts/deployed.shellnet.json
```

Move the note's remaining token balance back to a wallet:

```sh
dexdo note withdraw --note-addr "$NOTE_ADDR" --note-key note.secret.hex \
  --to 0:<WALLET-ADDRESS> --contracts contracts/deployed.shellnet.json
```

---

## Common errors

- `policy (...) is missing or unreadable ... Run dexdo policy init` (or `... is incomplete`) -- the seller
  policy is absent or still has `UNSET`/invalid fields. Run `dexdo policy init --role seller`, fill
  every field (Phase 4), run `dexdo policy validate --role seller`, and remember
  `seller.max_open_deals` must be `1`.
- `--note-addr ... is required` / `--note-key ... is required` -- pass the note address and key (Phase 3).
- `--nonce <n> is required and must be UNIQUE per deal` -- set a new unique `--nonce` each deal.
- provision fails for lack of SHELL -- the note's ECC currency-2 balance is below `--deposit-shells`;
  deploy a larger `--nominal` or lower `--deposit-shells` (check `dexdo note balance`).
- `unavailable: build with --features shellnet` -- only a source build compiled WITHOUT the feature.
  The released binary already includes shellnet; rebuild with `--features shellnet` (Phase 1).
- buyer cannot connect -- check `--gateway-listen`/`--gateway-advertise` reachability and that both
  sides use the same `contracts/deployed.shellnet.json`. `dexdo doctor` diagnoses manifest drift.

## Hard rules

- Never print, log, or commit the wallet seed/key, the note owner secret (`owner_secret_key_hex`),
  the pool file, or `GROQ_API_KEY`.
- Do not trust the buyer request's `model` field -- the market forces the model from `--model`.
- `dexdo destroy` is destructive: run it only on a closed (stopped) deal.
