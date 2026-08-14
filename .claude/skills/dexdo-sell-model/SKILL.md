---
name: dexdo-sell-model
description: Guides a SELLER end-to-end through selling model inference on the dexdo market (real shellnet) -- install the client, derive and fund the operational wallet, mint a wallet-funded private note, configure the model access key and models.json, read the current price with `dexdo market`, fill and validate the required seller policy, provision a per-deal market (`dexdo provision` -> market.json), run the `dexdo seller` gateway (posts the offer, forces the model, proxies the real upstream, streams tick by tick), hand the deal address to the buyer, and check by-fact accounting (`dexdo status`/`dexdo monitor`) -- how many ticks were delivered and how much SHELL was received. Load this when the user wants to SELL access to their model, stand up a seller gateway, serve buyers, or check revenue and delivered tokens. For the buyer side, use the `dexdo-buy-model` skill.
---

# dexdo -- selling model access (seller side)

Walk the seller through the real shellnet flow: install -> wallet -> note -> price -> policy -> validate ->
provision -> gateway -> status. After each command, show the output and do not advance until the step is green.
Secrets (wallet seed/key, note owner secret, the pool file, `GROQ_API_KEY`) are never printed or
committed.

If any command fails, run `dexdo doctor` first -- it reports the shellnet version, manifest
freshness, and whether your `policy.json` is complete.

**Prerequisites:** the user's own `--note-key` seed, access to SHELL for the planned trading and
deployment costs, and a model access key (for example `GROQ_API_KEY`). An existing deployed and
funded `UpdateCustodianMultisigWallet_v2` v2.2.0 or v2.4.0 wallet can be reused if it has exactly
one custodian whose public key matches the supplied funding key. Other wallet contract types are
not supported. `dexdo note deploy` itself does not create or fund the multisig.

---

## Choose order semantics before posting an offer

Use the mapping below before offering a command. `N` is the requested number of ticks; one tick is
1,000,000 tokens. `L` is the buyer's limit price per tick, and `A` is the seller's actual ask at a
fill, with `A <= L`. For any price `p`, `fee(p) = floor(p * 250 / 10000)`,
`E_p = N * (p + fee(p))` is the fee-inclusive service deposit, and `T_p = E_p + 2p` adds the buyer
bond.

### "I want to offer ongoing access, not a one-off purchase"

**Support:** Supported only as a fixed four-week subscription.

**Flags:** The seller uses `seller --model A --subscription`. The buyer counterpart must place with
`subscription --model A place --max-price-per-tick L --ticks N`, then use the matched deal with
`buyer --resume --frame-model A` and optional `--local-listen ADDR`. For an explicit due-week
booking, the buyer adds `--settle` to `subscription ... status ID`; plain status is read-only. Both
orders carry `AON|SUBSCRIPTION`.

**Money and time:** Posting the resting SELL holds no escrow. The offered product is exactly four
weeks. On the buyer side, `T_L` leaves the note at placement; cancelling while unfilled returns all
of it. At match, `T_A` enters the deal and the limit-price spread returns. Each week allows `N/4`
ticks, and unused allowance expires at that week's boundary instead of rolling forward. The
take-or-pay clock starts when the probe is accepted, not when the order is placed or matched.
Before probe acceptance, no week is charged, but buyer STOP burns one probe price. After
acceptance, buyer STOP bills every elapsed week and the current week in full whether or not its
allowance was used. Future unstarted weeks return on a clean close, as does the `2A` buyer bond. A
dispute or penalty can instead burn stake `D` between `A` and `2A`. Buyer resume reuses the same
match, places no new BUY, and preserves the subscription when the process exits.

**Refuse nearby:** There is no custom term, custom week length, rollover, subscription MARKET
order, or split across sellers. There is no buyer-side `--subscription` flag; placement must use
the `subscription` subcommand. Do not tell a buyer to resume an order that is still resting.

### "Cancel my sell offer if it is unfilled in an hour"

**Support:** A user-selected seller TTL is not supported. The shipped seller uses a fixed one-hour
deadline and its liveness path submits expiry for its own stale ask.

**Flags:** There is no TTL flag. Use `seller --model A` for an ordinary offer or add
`--subscription` for a subscription offer; the backend supplies 3600 seconds. Before the deadline,
use `orders ... cancel ID`. After it, `orders ... expire ID` is the explicit removal action.

**Money and time:** At the fixed deadline, 3600 seconds after placement, the offer becomes
non-fillable, but time alone sends no transaction. The seller liveness path reaps its stale ask; a
permissionless expiry can also remove it. A resting SELL holds no escrow, its deal latch is released
on removal, and no fill means no book trading fee.

**Refuse nearby:** There is no selectable seller TTL or CLI GTC. Do not promise a removal
transaction at exactly 3600 seconds or a keeper reward. BUY expiry is different: the buyer process
does not automatically sweep it, and BUY funds remain recorded until a removal transaction lands.

### "Sell only to subscribers"

**Support:** Supported with exact symmetric separation between subscription and ordinary orders.

**Flags:** Use `seller --model A --subscription`. The buyer counterpart must use
`subscription --model A place`. Both orders carry `AON|SUBSCRIPTION`.

**Money and time:** Compatibility is checked before pricing or settlement. A subscription ask can
match only a subscription BUY, and an ordinary ask can match only an ordinary BUY. The resting SELL
holds no escrow. If the subscription matches, its fixed four-week shape and the buyer's deposit,
bond, billing, refund, and burn commitments are exactly those stated in the first mapping above.

**Refuse nearby:** There is no single ask that accepts both products, subscriber preference with
ordinary fallback, or buyer-side `--subscription` flag. A live resting ask cannot change shape;
remove it before reposting with different flags.

## Addresses

dexdo prints and stores addresses in the canonical Acki Nacki form
`<dapp_id>::<account_id>` (two 64-hex halves). Paste that form back into later
commands; every address example below uses `<DAPP-ID>::<ACCOUNT-ID>`. For a fresh
operational wallet, `dexdo note wallet` prints `<ACCOUNT-ID>::<ACCOUNT-ID>` because
the wallet's dapp id is its own account id.

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

## Phase 2. Prepare and fund the operational wallet

The operational multisig is the user's source of funds for minting notes. Its address is
deterministic: derive it from the user's own `--note-key` seed and show it to the user before
anything is deployed. The same seed controls the note and the operational wallet, so there is no
separate `--wallet-addr` identity and no independently chosen wallet address.

Run the onboarding command with the nominal of the note you intend to mint:

```sh
dexdo note wallet \
  --note-key /path/to/note.key \
  --nominal N1000 \
  --contracts contracts/deployed.shellnet.json
```

On a fresh seed, this command derives and prints the canonical address without submitting a chain
write. While funding is absent it reports that the wallet is waiting and exits without deploying.
It uses no faucet or giver. Mainnet has no giver, and this path does not need one.

The chain forces this order:

1. Send the stage-one amount the command printed to the derived address with the non-bounceable
   ECC[2] flag-`16` form. The destination becomes `Uninit` with that amount as native balance and
   ECC[2] still zero. This leg buys deploy gas and nothing else, so it is a small flat figure that
   does not depend on the nominal: SHELL that lands as native can never be spent as currency again.
2. Rerun `dexdo note wallet`. It deploys the wallet once the native balance is present, and the
   account becomes `Active`.
3. Send the stage-two amount the command printed to the now-`Active` wallet as ECC[2] with the
   active-account flag-`1` form, then rerun `dexdo note wallet` to confirm the funding. This is the
   larger of the two and the one the nominal belongs to.

The non-bounceable predeploy leg leaves the money at the deterministic address. There is no
automatic refund if the operator stops; it becomes reachable by deploying the matching derived
wallet.

ECC[2] cannot be delivered to an account that does not exist, so the ECC[2] leg cannot precede the
deploy. A live shellnet proof completed both funding legs from an ordinary canonical v2.4 multisig.
That funding wallet needs native for the outbound message and its fees as well as ECC[2] for the
note. ECC[2]-only provisioning fails in the transaction's action phase: no outbound message is
emitted, no ECC[2] moves, and the balances appear unchanged. The observed failure was
`result_code=37` with `no_funds=true`.

In the shellnet proof, deploying from a 1,250 SHELL predeploy balance consumed `156 222 000` raw
native, about 0.156 SHELL, in fee and gas. That is a shellnet measurement, not a mainnet cost
promise. The remaining balance stayed in the user's wallet for spending or withdrawal.

## Phase 3. Mint a private note

A private note is the funded trading account used by the seller commands below. One note can fund
trading up to its nominal, so choose the nominal for the amount that note needs to trade against.

The contract allows `N100`, `N1000`, `N10000`, `N100000`, and `N1000000`. The pinned SDK parser used
by the CLI accepts only `N100`, `N1000`, and `N10000` today. `N100000` and `N1000000` are
contract-legal but CLI-impossible. Therefore `N10000` is the largest note this tool can mint today.
To trade against more, mint several notes.

For the deposit voucher, the wallet attaches the chosen nominal plus the contract's
`GAS_DEPOSIT` of 250 SHELL:

```text
+-------------+----------------+
| Wanted note | Attach (SHELL) |
+-------------+----------------+
| N100        | 350            |
| N1000       | 1,250          |
| N10000      | 10,250         |
+-------------+----------------+
```

The attachment is not the price of a note: 350 SHELL is only the `N100` case, and wallet deploy
and transaction gas are separate. Do not attach the bare nominal. Attaching exactly 10,000 SHELL
leaves 9,750 after `GAS_DEPOSIT`, which is not an allowed nominal and fails with
`ERR_NOT_ALLOWED` (141). Attaching exactly 100 SHELL is below `GAS_DEPOSIT` and fails with
`ERR_BELOW_GAS_DEPOSIT` (408).

`dexdo note deploy` funds a fresh private note from your multisig wallet (no giver) and folds it
into a pool file. Notes are funded in SHELL only -- SHELL is what pays the per-deal market deploys,
gas, and runtime -- so `--token-type shell` is the only accepted currency. `--nominal` is required
and has no default: pick one of the three CLI-supported values above.

```sh
dexdo note deploy \
  --multisig-address <ACCOUNT-ID>::<ACCOUNT-ID> \
  --multisig-seed-file /path/to/wallet.seed \
  --nominal N10000 \
  --token-type shell \
  --endpoint shellnet.ackinacki.org \
  --pool pn_pool.json
```

Use `--multisig-key /path/to/wallet.key` (a file with the 32-byte hex secret) instead of
`--multisig-seed-file` if you hold the raw key. `pn_pool.json` holds the note owner secret -- keep it
private, never commit it. `dexdo note deploy` is the user note-creation path. Point later seller
commands at the pool it creates. Success is the line `note deployed -> PrivateNote <address> ...;
folded into --pool pn_pool.json ...`; do not advance on an earlier progress line.

Point later seller commands at the pool it creates:

```sh
export DEXDO_PN_POOL="$PWD/pn_pool.json"
```

## Phase 4. Note key, balance check, models.json, and the upstream key

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
the deal deploys (Phase 6, whole SHELL) plus runtime gas. If it is short, deploy a larger `--nominal`
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
      "capabilities": { "max_output_tokens": 40960 }
    }
  }
}
```

`capabilities.max_output_tokens` is the model's own maximum completion length at that provider (Groq
answers `400` above `40960` for `qwen/qwen3-32b`). The seller clamps every outbound request to it, so the
field is REQUIRED: a model entry without it is refused before the provider is contacted rather than served
with an unbounded limit. Take the number from your provider's model card.

`capabilities.logprobs` and `capabilities.top_logprobs` are RETIRED. The client no longer requests, parses or
verifies log probabilities anywhere, so setting either key changes nothing about what the seller sends or how
it is paid. An existing `models.json` that still carries them keeps working: the keys are **ignored, not
rejected** -- deliberately, so an upgrade does not take a live seller off the market. Do not add them to a new
config; `max_output_tokens` is the only capability the seller reads.

The `price_per_tick` here is decorative metadata -- it does NOT set the live deal price. The price
buyers pay is whatever you set at `dexdo provision --price-per-tick` (Phase 6); editing this field
changes nothing on-chain.

Export the upstream key (not written to logs): `export GROQ_API_KEY=<your-key>`

### Selling Claude through the native Anthropic upstream

Dexdo selects `seller/upstream/anthropic.rs` when the model entry points to `api.anthropic.com`. The seller
calls the Anthropic Messages API directly; do not put a LiteLLM/OpenAI-compatible proxy between them. Keep the
real key in the environment named by `api_key_env`, never in `models.json`. Its `capabilities` need only the
model's own output limit:

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
      "capabilities": { "max_output_tokens": 64000 }
    }
  }
}
```

Set `ANTHROPIC_API_KEY`, then run the seller with `--model claude-sonnet --models models.json`. The adapter
streams text immediately and reconciles billing to Anthropic's cumulative `usage.output_tokens`, not SSE
content-delta count.

## Phase 5. Read the price, then fill the failure policy

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

## Phase 6. Validate the policy, then provision the deal

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
defaults to ~20, and must fit the note balance from Phase 4 -- do not set it to the whole note (the
remainder burns at `destroy`, and the note still needs runtime SHELL). The result `market.json`
carries the deal address (`token_contract`), the model, and the nonce.

## Phase 7. Run the seller gateway

```sh
dexdo seller \
  --policy "$POLICY" \
  --market market.json \
  --model qwen \
  --models models.json \
  --note-addr "$NOTE_ADDR" \
  --note-key note.secret.hex \
  --gateway-listen 0.0.0.0:8443 \
  --gateway-advertise <public-host>:8443 \
  --contracts contracts/deployed.shellnet.json
```

The offer price and volume come from the provisioned deal in `market.json` (set in Phase 6). The
seller's own `--price-per-tick` flag is **ignored on the `--market` path** -- to re-price, run a new
`dexdo provision` with a fresh `--nonce` and serve that manifest. `--gateway-listen` is the local
bind address; `--gateway-advertise` is the address a REMOTE buyer dials (the public address written
into the handover -- never `127.0.0.1`). It must be publicly reachable: startup rejects a bind-all
(`0.0.0.0`/`::`), loopback, RFC1918, link-local or CGNAT advertise -- and equally a reserved range
that is never routed (documentation `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`, `3fff::/20`; benchmarking `198.18.0.0/15`; `240.0.0.0/4`; `0.0.0.0/8`; multicast)
-- with `error[E_ADVERTISE_NOT_PUBLIC] (config)` BEFORE the offer is posted, so no resting ask ever
points at an unreachable gateway. For same-host/LAN testing only, add `--allow-private-advertise`. With
`--market`, do not also pass `--token-contract`/`--nonce` (they come from the file). On start the
gateway posts the offer, then daemonizes: it polls for a match, opens the stream, and streams tick by
tick. The wait for a buyer is open-ended -- the resting offer is not torn down.

## Phase 8. Hand the deal address to the buyer

Give the buyer either the `market.json` file OR the `token_contract` string
(`<DAPP-ID>::<ACCOUNT-ID>`) from it. If you hand over the bare `token_contract` (not the file), you
**must also give the buyer the canonical
frame model** `qwen--qwen3--32b` -- the buyer needs it as `--frame-model` alongside
`--token-contract`. The buyer places the buy; the gateway opens the stream automatically and forces
the configured model.

## Phase 9. Check status (by-fact accounting)

Authoritative deal state (reads the chain, moves nothing) -- pass the deal `token_contract` from
`market.json`:

```sh
dexdo status <DAPP-ID>::<ACCOUNT-ID> --contracts contracts/deployed.shellnet.json
```

It prints the lifecycle `state=` (`placed`/`funded-but-never-opened`/`probe`/`streaming`/`stopped`/
`disputed`), the boolean flags (`funded`/`opened`/`probe_accepted`/`disputed`), and accounting
(`finalized_owed`, `buyer_locked`, `deposit`, ...). For a revenue roll-up across one or more markets:

```sh
dexdo monitor --market market.json --contracts contracts/deployed.shellnet.json
```

Read-only: ticks delivered, SHELL received, per-deal collateral held or burned, and whether the deal is closed.
Repeat `--market` for several markets; run it in a separate terminal.

## Phase 10. Anti-abuse and recovery

Each deal keeps its own exact `2P` seller bond and contested buyer amount in that TokenContract.
A dispute freezes only those per-deal funds; it does not lock the seller's or buyer's whole
PrivateNote, so other independent deals remain possible.

Use the recovery action that matches the failure:

```text
+----------------------------------------+-------------------------------------+-------------------------------------------------------------------+
| Situation                              | Command                             | What it gives you                                                 |
+----------------------------------------+-------------------------------------+-------------------------------------------------------------------+
| Concede a dispute                      | dexdo release-dispute               | Returns this TC's contested amount and seller bond.                |
| Collect finalized closed-deal earnings | dexdo withdraw-shell                | Pays finalized SHELL to the seller note the deal stored.          |
| Cancel one stale resting offer         | dexdo orders cancel <ID>            | Removes that order from the model book.                           |
| Cancel all stale resting offers        | dexdo orders cancel-all             | Removes all of this note's orders from the model book.            |
+----------------------------------------+-------------------------------------+-------------------------------------------------------------------+
```

`dexdo release-dispute` and `dexdo withdraw-shell` take `--note-addr` and `--note-key`, plus either
`--token-contract <DAPP-ID>::<ACCOUNT-ID>` or `--market market.json`. For resting offers, put the shared note and
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
  --to <DAPP-ID>::<ACCOUNT-ID> --contracts contracts/deployed.shellnet.json
```

---

## Common errors

- `policy (...) is missing or unreadable ... Run dexdo policy init` (or `... is incomplete`) -- the seller
  policy is absent or still has `UNSET`/invalid fields. Run `dexdo policy init --role seller`, fill
  every field (Phase 5), run `dexdo policy validate --role seller`, and remember
  `seller.max_open_deals` must be `1`.
- `--note-addr ... is required` / `--note-key ... is required` -- pass the note address and key (Phase 4).
- `--nonce <n> is required and must be UNIQUE per deal` -- set a new unique `--nonce` each deal.
- provision fails for lack of SHELL -- the note's ECC currency-2 balance is below `--deposit-shells`;
  deploy a larger `--nominal` or lower `--deposit-shells` (check `dexdo note balance`).
- `unavailable: build with --features shellnet` -- only a source build compiled WITHOUT the feature.
  The released binary already includes shellnet; rebuild with `--features shellnet` (Phase 1).
- buyer cannot connect -- check `--gateway-listen`/`--gateway-advertise` reachability and that both
  sides use the same `contracts/deployed.shellnet.json`. `dexdo doctor` diagnoses manifest drift.
- `error[E_ADVERTISE_NOT_PUBLIC] (config)` -- `--gateway-advertise` (or the `--gateway-listen` it
  defaulted to) is not an address a remote buyer can dial. Pass a public `host:port`, or
  `--allow-private-advertise` for local/LAN testing only.
- `advertised_gateway ... status="fail"` with `error[E_ADVERTISE_UNREACHABLE] (network)` -- the
  startup self-probe to the advertised address failed at the transport level. This is fatal and no
  offer is posted. Behind NAT/a VPN/an SSH reverse tunnel the probe can hairpin back into
  this same process and fail while a remote buyer connects fine -- but the seller cannot tell that
  apart from an address no buyer can reach, so it refuses to publish. Verify from outside
  (`curl -k https://<advertise>/`) and fix the path the probe took.
- `error[E_ADVERTISE_WRONG_GATEWAY] (tls)` -- something answered on the advertised address but it is
  not this gateway (certificate-pin mismatch). This is always fatal; fix the address or the tunnel
  target, never bypass it.

## Hard rules

- Never print, log, or commit the wallet seed/key, the note owner secret (`owner_secret_key_hex`),
  the pool file, or `GROQ_API_KEY`.
- Do not trust the buyer request's `model` field -- the market forces the model from `--model`.
- `dexdo destroy` is destructive: run it only on a closed (stopped) deal.
