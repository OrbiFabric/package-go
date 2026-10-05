# S04 stage evidence

Protocol authority: `7ff166365dc83cee783e4e6715225968c81ef7b9`.
Source baseline / prerequisite S03 merge: `110a55da17c9714d51585cfeea9bc8be55f84177`.
Stage Issue: [#7](https://github.com/OrbiFabric/package-go/issues/7).
Prior pushed subset: `1e5459c4a38828786612414cf22978eaed4caf26`. Final implementation head/PR/merge/main read-back are recorded in the Stage Issue after merge.

Allowed changes: SDK history/object/materialization/commit code, model/resource safety, focused tests and SDK docs. Frozen machine assets and top-level LICENSE/NOTICE unchanged. Sole writable implementation repository is package-go; no consumer, protocol authority, product/DB/Provider/cloud source mutation or V1 compatibility/migration.

Executed on Go 1.26.0 linux/amd64:

- `GOPROXY=off GOSUMDB=off go test -race -count=1 ./...`: final PASS, exit 0. Validates all eight shared stage history/object subsets, actual parent-chain enumeration/all-Version coverage, object dedup/hash/size/extra checks, no HEAD/working-byte substitution, both historical payloads after working overwrite, empty bytes/folders, unsigned root/child commits, old document immutability, identity continuity/new copies, unknown optional preservation, whole prospective tree/JSON/entity budgets, maximum ordinal and transaction failures/stability/publication acknowledgement.
- `GOPROXY=off GOSUMDB=off go test -race -run '^TestConcurrentWritersRejectStaleHEADWithoutFork$' -count=25`: PASS, exit 0. In each run exactly one of two same-HEAD writers commits, the other receives STALE_HEAD, and actual stored history remains one two-Version chain.
- `GOPROXY=off GOSUMDB=off go vet ./...`: PASS, exit 0.
- `python3 scripts/check-foundation.py --spec-dir <local-spec-clone>`: PASS, exit 0; all 51 frozen assets exact, 112 dependency packages all standard library or SDK, no SDK network/database dependency.
- `git diff --check` and staged exact SDK/test/doc allowlist/public-content review: PASS. Remote exact head/path verification and clean merged-main read-back recorded after merge.

Shared asset checks consume frozen expected applicable integrity/negative-completeness/reason fields; they do not regenerate expected values from SDK output:

| Fixture | Exercised actual behavior | Result |
|---|---|---|
| complete-history | two actual parent-linked Versions, two verified distinct objects, both restored offline | PASS for history/object/restoration scope |
| missing-object | UNAVAILABLE / NOT_FULL / MISSING_OBJECT; working copy retained but never borrowed | PASS |
| object-hash-mismatch | INVALID / INVALID / OBJECT_HASH_MISMATCH | PASS |
| cycle | NON_LINEAR_HISTORY | PASS |
| missing-parent | MISSING_PARENT | PASS |
| multiple-roots | NON_LINEAR_HISTORY | PASS |
| detached-version | NON_LINEAR_HISTORY | PASS |
| multiple-parents | INVALID_SCHEMA | PASS |

Positive complete-history profile FULL is NOT_RUN/NOT_CHECKED at S04 because portable-memory/embedded evidence semantics belong to following required stages. No seven-level SDK conformance or product/external integration is inferred from the above scoped tests. Signatures/identity/evidence/online dimensions remain separate.

Failure injection verifies object-stage/close, Version-stage/no-overwrite and pre-publication failures discard pending proposals without changing committed bytes/HEAD. A detected payload change or second-read hash drift blocks publication. Final expected-HEAD recheck catches a late change. A false publication acknowledgement is rejected by actual HEAD read-back. Uncertain post-publication/transaction-close failures return an error without cleanup deleting the already-published complete chain. Host transaction contracts and actual SDK serialization are tested; native production durability/authorization/journal/restart integration is NOT_RUN at S04.

Initial new commit test run failed because its pending-Version assertion mistakenly counted the existing versions/ container as a proposal. Corrected the test path filter to check only child Version paths; no SDK acceptance or frozen expected asset was weakened. Follow-up review added full prospective budgets, preserved-field merging and bounded optional shared-value expansion; final race/stress/vet passed.

Maximum ordinal is tested at the arithmetic boundary: max-1 succeeds, max returns a stop error, no wrap. Building a literal max-ordinal chain would require 9,007,199,254,740,991 Versions and is not represented as executed. Remote CI, native Windows/macOS runtime, real Provider/official signer and full Complete/crypto/codec/product acceptance are NOT_RUN here.
