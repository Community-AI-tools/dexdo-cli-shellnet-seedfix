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

