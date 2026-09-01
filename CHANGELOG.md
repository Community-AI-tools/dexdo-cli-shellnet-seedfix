## v0.2.0

### Breaking Changes

- CLI amounts and prices are now entered and printed in SHELL instead of raw ECC[2] units. Update scripts and configuration values using 1 SHELL = 1,000,000,000 raw units; prices remain whole SHELL.
- Real-chain selection now comes from the file named by `DEXDO_MANIFEST`. The `--contracts`, `--endpoint`, and `--network` selectors and the shellnet/test-giver Cargo features no longer select a deployment, so set `DEXDO_MANIFEST` for every real-chain command.
- The client now targets contract generation 4.0.36. A seller note deploys each deal and funds its ECC[2] reserve using `0.300 + 0.015 * max_ticks` SHELL. Notes from earlier generations cannot deploy new deals; mint a current note and provision new market handles before trading.
- Market identity is now the exact name held by the on-chain ModelRegistry. Update `frame_model` values in local model configuration to registered names; local aliases and provider slugs no longer choose an order book.
- Deployment manifests no longer contain `contract_hashes`. Contract generation comes from the manifest, while expected code hashes come from the client build; remove the old field from custom manifests.

### New / Improvements

- Interactive commands now ask only for decisions that are not already supplied, can select client-managed notes and keys, discover nearby `models.json` and market handles, and create policy files through a guided interview. The corresponding explicit inputs remain available for non-interactive use.
- `dexdo model-registry --output <path>` exports the on-chain model catalog as deterministic JSON. Use `--json` to write the same `dexdo.model_registry.v1` object to stdout.
- `dexdo markets address --model <name>` resolves a registered model and prints its canonical order-book address without requiring a live note. Use `--json` for the `dexdo.markets_address.v1` object.
- `dexdo note sweep [--note-addr <note>] [--note-key <key>] --to <address>` moves physical ECC[2] that reaches a note after its trading balance was withdrawn. Client-managed note details can come from the pool. The destination receives SHELL, not native vmshell.
- `dexdo oracle forfeit-stake ... --abandon-the-stake` releases a note from a stake that cannot pass `oracle cancel-stake`. The explicit flag is required because the stake is abandoned.
- `dexdo settlement-receipt <token-contract> --json --require-conserved` exits successfully only when the receipt proves conservation. Without `--require-conserved`, all receipt verdicts keep the previous zero exit status.
- Commands now accept the canonical `<dapp_id>::<account_id>` address form that dexdo itself prints.
- `dexdo note deploy` no longer creates a redundant second gas voucher. A new note uses the gas deposit it receives at creation, reducing wallet cost and deployment time.
- The chain client applies the manifest's `requests_per_second` ceiling across shared reads, and keeps outbound-message polling within the same limit.
- Public buyer and seller guides are now separated into human-run and agent-run workflows; install and seller-operations guides are published alongside them.

### Fixes

- Wallet onboarding reads its endpoint from `DEXDO_MANIFEST`. Gosh.ai onboarding is offered only when the manifest provides `goshai_onboarding_url`, and otherwise refuses before printing or storing invitation material.
- Wallet deployment and top-up payment codes name the target network. Deployment codes also request conversion with wallet flag 16 so transferred SHELL arrives as native vmshell.
- Seller startup skips stale local deal handles instead of refusing the entire deal list, and seller shutdown bounds its chain drain instead of waiting indefinitely.
- Model aliases can no longer redirect collateral to a different order book. Buyer admission accepts both registered identity spellings encountered during the 4.0.36 transition without weakening exact money-path comparison.
- Settlement receipts distinguish proven, unbalanced, incomplete, and unverified conservation instead of treating a one-sided reconstruction as proof.
- Chain and funding refusals retain the failing endpoint and actionable recovery text, and wallet read failures are no longer reported as insufficient balance.
- The public tree carries the mainnet manifest at `manifest/mainnet.manifest.json`; it no longer stages the shellnet manifest under `contracts/`.
- Withdrawn-note guidance points to executable recovery commands, including `note outstanding` and `note sweep`, rather than suggesting unavailable state or flags.

## v0.0.23

- fix(release): the release regression must carry every path the allow-list requires
- fix(release): two files that change the published binary were not being published
- fix(test): the last two platform rows -- a bound sized for the fast runner, and a stop Windows cannot make
- merge PR1435: an executed Vault transfer is credited by identity, not by a grown balance
- fix(windows): the shipped binary overflows the 1 MiB main-thread stack
- fix(test): isolate the data directory with the flag, not a Linux-only env var
- fix(test): the probe budget must outlast the platform refusal it waits for
- fix(ci): the Linux leg was killing the linker, not failing a test
- fix(ci): the campaign harness must run on the mac runner too
- fix(ci): the Windows leg, all three causes, measured on the runner
- merge PR1411: drop --contracts from the wallet commands, one endpoint seam, dd-shellnet
- chore(ci): throwaway windows loopback probe (delete after reading)
- fix(test): the gateway-check row holds its dead port the portable way too
- fix(test): the dead-address primitive must refuse on BSD too, not only on Linux
- fix(ci): the pinned-schema seam must not need the shellnet feature
- dev 92a2de8a. , :
- Promotes 717 commits of dev work. main held no unique non-merge commits -- its
- release: merge dev into main for v0.0.19
- Shellnet 4.0.29 client alignment, canonical multisig v2, recovered-buyer price safety, seller policy preflight, probe guidance, and release hardening.

## v0.0.22

- Fix wallet invitation output in terminals
- docs: report verification
- fix: switch to direct mainnet endpoint
- The live acceptance campaign passed 24/24 on 2ae2fff6 with set88. dev moved to
- test(live): bind settlement terminal by type
- test(campaign): run the two live onboarding proofs as campaign steps
- test: anchor lifecycle assertions at probe
- fix: preserve explicit onboarding paths
- fix: isolate Acki Nacki defaults per binding
- fix: keep PR1329 scoped to audit items 5 and 6
- fix: publish item 7's remediation where it is documented, and prove item 6 by what it produces
- fix: gosh-ai resumes, the menu has defaults, and the refusal keeps its contract
- 13f: PR1332 + PR1345 set85
- fix: chain liveness HTTP-
- integration 2026-08-14a: PR
- integration 2026-08-13d: five accepted PRs, live 22/22 on set84
- integration 2026-08-13c: four accepted PRs, live 22/22 on set82
- integration 2026-08-13b: the provider-answer fix, one address identity for the pool tools, and a verifier that refuses nothing
- integration 2026-08-13a: the wallet stack, the funding-wallet lock and the markdown scrub, proven live 22/22
- cut 12i: five fixes proven by a green live campaign (26/26 on set76)
- fix(ci): operator key material is structurally uncommittable
- fix(note wallet): stage one is measured deploy gas, not a nominal-sized burn
- test: wait for the gateway outcome, not for a wall-clock budget
- fix(note wallet): print the funding recipe note deploy actually requires
- test: the upstream stream shapes UPS-B3..UPS-B12, in mocks

## v0.0.21

- fix(test): let the live acceptance suite finish a full run
- fix: admission reserves the identity verification a fresh deal owes
- fix: preserve seller probe source chain
- fix: close seller liveness edge regressions
- fix(test): remove the shared-resource races that make CI non-deterministic (, )
- fix: use canonical advertise structured error
- fix: make installer PATH persistence rc-backed
- fix(ci): assert terminal 3/4/4 accounting
- fix(test): keep seller child output line-safe under libtest
- fix: refresh the subscription weekly allowance across boundaries
- fix(seller): reserve relay capacity before exposure
- fix: resolve an inherited :0 advertise to the bound gateway address
- fix: read canonical addresses in the release gate and live tests
- fix: let the real buyer book his own subscription week boundary
- fix: drive pool-only reclaim from recorded metadata alone
- fix: stop onboarding docs instructing a rejected --token-type
- merge: land structured CLI errors on top of /
- fix: urgent v0.0.21 pack -- installer PATH, canonical addresses, release version guard (, , )
- fix: validate public gateway advertise and tolerate tunneled self-probe (, )

## v0.0.20

- fix(tests): keep the models-fixture guard compiling without test-giver
- fix: do not count the probe seed as an unbacked delivery advance
- fix: declare model output caps in live fixtures ( follow-up)
- fix: clamp upstream max_tokens to the model output cap
- fix: emit seller_offer_outcome RESTED on every resting path
- fix: integrate complete v0.0.20 client for contracts 4.0.32
- contracts: integrate live shellnet 4.0.31 from PR713

## v0.0.19

- fix(release): omit internal agent docs from notes
- fix: require SHELL across dexdo market paths
- fix(seller): emit factual terminal and upstream events
- test: bootstrap SHELL-only no-giver release funding
- fix(buyer): show exact preflight and local handoff
- feat(seller): supervise partial-fill residual pool
- fix(note): re-prove the same paid voucher after exact 403
- docs: make lead own executor lifecycle
- docs: unblock exact bee wallet dependency for
- [v0.0.19][CI] Two-runner Windows seller Linux buyer shellnet E2E
- docs: replace onboarding with bee session v1
- fix: cancel unavailable seller offers
- fix: reject stale note deploy before wallet spend
- fix: resume interrupted Hermez SRS downloads
- fix: generate notes from current release baseline

## v0.0.18

- Shellnet 4.0.29 client alignment, canonical multisig v2, recovered-buyer price safety, seller policy preflight, probe guidance, and release hardening.

## v0.0.17

- Shellnet 4.0.29 client alignment, canonical multisig v2, recovered-buyer price safety, seller policy preflight, probe guidance, and release hardening.

