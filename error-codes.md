# dexdo error codes

Every user-facing failure the CLI reports through the structured error type carries a stable,
greppable code. This file is the authoritative table: **code -> meaning -> likely fix**. A code with
no row here is a defect -- `dexdo-core`'s `code_table_matches_the_documented_table` test fails the
build if `codes::TABLE` and this table disagree in either direction, and
`every_rendered_code_literal_is_a_table_code` fails if any source file renders an `error[CODE]` that
is not in the table.

Source of truth for the codes themselves: [`crates/core/src/error.rs`](crates/core/src/error.rs).

## Rendered shape

```text
error[E_ADVERTISE_UNREACHABLE] (network): advertised gateway 94.156.178.14:8443 did not complete the pinned-TLS (h2) self-probe (stage: tls_handshake)
  cause: transport error
  cause: io: connection reset by peer
  secondary (pool owner-fill audit): error[E_POOL_UNKNOWN_OWNER_FILL] (pool): ...
  hint: the advertised address must be reachable AND serve this gateway's cert from THIS host
```

- `error[CODE] (kind): message` -- the code is stable across releases; `kind` is the coarse category;
  the message names the concrete subject (address, TokenContract, file, order id).
- `(stage: ...)` -- which step of a multi-step operation failed, when the operation has steps.
- `cause:` -- the preserved `std::error::Error` source chain, deepest last. It is walked at render
  time, never flattened into a string at the boundary.
- `secondary (label):` -- a failure that is a **consequence** of the headline, attached so it cannot
  masquerade as the root cause. Fix the headline first.
- `hint:` -- the actionable fix.

## Kinds

`config` * `network` * `tls` * `pool`

Kinds are for grouping and `grep`: `config` is operator input, `network` is transport/reachability,
`tls` is endpoint identity, and `pool` is the seller's local deal-pool state.

## Codes

| code | kind | meaning | likely fix |
|---|---|---|---|
| `E_ADVERTISE_NOT_PUBLIC` | config | `--gateway-advertise` names an address no remote buyer can dial: bind-all `0.0.0.0`/`::`, loopback, RFC1918/ULA, link-local, CGNAT, a reserved local name such as `*.local`, or a reserved-but-unroutable range -- documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`), benchmarking (`198.18.0.0/15`), `240.0.0.0/4`, `0.0.0.0/8`, multicast -- including their IPv4-mapped IPv6 forms. The message names the class it matched. The offer would rest in the book backed by an address nobody can reach. | Pass a public `host:port` reachable from the internet, or run the gateway on a public host. For local/LAN testing only, opt in with `--allow-private-advertise`. |
| `E_ADVERTISE_UNREACHABLE` | network | The pinned-TLS (h2) self-probe of the advertised gateway failed at the transport level. The `(stage: ...)` suffix says how far it got (`tcp_connect`, `tls_handshake`, `http2_handshake`, `grpc_challenge`, `handshake_timeout`) and the `cause:` lines carry the underlying `io`/TLS error. | Check that the advertised address is reachable from this host and forwards back to this gateway. A NAT/VPN/reverse-tunnel hairpin can fail the in-process self-probe while a remote buyer connects fine -- verify externally, e.g. `curl -k https://<advertise>/`. |
| `E_ADVERTISE_WRONG_GATEWAY` | tls | Something answered on the advertised address, but it is provably **not** this gateway: the pinned certificate fingerprint did not match, or the port is served by a foreign service. Never a tunnel artifact. | Point `--gateway-advertise` at this gateway's own address, or free the port from the other service. Do not relax the certificate pin. |
| `E_GATEWAY_UNREACHABLE` | network | The buyer's pinned-TLS (h2) dial of the seller gateway failed at the transport level. The headline names the `host:port` that was dialled, the `(stage: ...)` suffix says how far it got (`tcp_connect`, `tls_handshake`, `http2_handshake`) and the `cause:` lines carry the underlying `io`/TLS error. Before this the whole failure printed as `transport error` with no address at all, at any log level. | Check that the address on the headline answers from this host (`curl -k https://<host:port>/`). `tcp_connect` means the host or port is not reachable (down, firewalled, or the seller advertised an address that does not route to it); `tls_handshake`/`http2_handshake` mean something answered but did not complete the pinned h2 handshake. |
| `E_GATEWAY_WRONG_ENDPOINT` | tls | The address in the handover answered the buyer's dial, but the certificate it presented does not match the fingerprint the handover pinned -- it is provably not that seller's gateway (a foreign service on the port, or a stale handover). The pin is never relaxed, so the connection is torn down before any stream is received. | Get a fresh handover from the seller, or have the seller advertise its own address instead of one served by another service. Do not relax the certificate pin. |
| `E_POOL_UNKNOWN_OWNER_FILL` | pool | The seller note was matched on an order (an "owner fill") whose `TokenContract` has no deal handle or `market.json` in this pool, so the delivered capacity cannot be accounted. The pool refuses to silently discard it. | Run the seller from the directory that holds that deal's handle/`market.json`, or close the orphaned deal (`dexdo deals`, then `destroy`/`recover`). When this appears as a `secondary` note under another error it is a **consequence** -- fix that primary error first and re-run. |
| `E_SELLER_POOL_FAILED` | pool | The seller deal pool failed and had consequence findings attached. The headline is the primary (root) failure; the `secondary` lines are its consequences, not independent problems. | Fix the primary failure on the headline and its `cause:` lines, re-run, and only then look at the secondary notes. |
| `E_WALLET_NOT_CONFIGURED` | config | The command needs the funding (Hot) wallet, and this instance has no active wallet binding at `<data-dir>/wallet/binding.json`. The CLI refuses **before any chain write** rather than starting onboarding by itself or picking a provider: the provider is recorded when the wallet is bound and cannot be recovered from an address, a code hash or an on-chain parameter afterwards, because all three providers can hand over the same canonical multisig. | Bind a wallet once with `dexdo wallet onboard` followed by one of `ackinacki-wallet`, `gosh-ai` or `manual`. On a headless host with no TTY, no browser and no camera, use `dexdo wallet onboard manual`: its whole input is a plain printed address, so it needs no QR and no interactive prompt. Commands that were given `--multisig-address` with `--multisig-key`/`--multisig-seed-file` supply their own wallet and never raise this. |

## Data-source annotations (not errors)

`dexdo orders list` and `dexdo market` read the same order book through different paths, so they can
legitimately show different rows. Both print a provenance line first, so a divergence reads as
staleness rather than contradiction:

```text
orders source=chain:order-book-events as_of=1754006400 last_update_id=... scope=owner-resting-orders owner=0:a5c4...
market source=indexer as_of=1754006400 lastUpdateId=...
```

- `source=indexer` -- the Dodex indexer, which lags the chain by design.
- `source=chain:order-book-events` -- the chain event fold (authoritative, slower).
- `source=chain:getters` -- the legacy contract-getter fallback, used when the event fold is
  unavailable.
- `as_of` -- Unix seconds at which the snapshot was read.
- `scope` -- which subset of the book the command shows: `owner-resting-orders` (only your note's
  resting orders) versus `executable-asks` (asks a buy could actually match). Different scopes are
  the second reason the two views differ.
