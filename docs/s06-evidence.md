# S06 evidence — canonical JSON, VersionSubject and strict signatures

Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`; dependency: S05 merge `25069f7b71ec1dbe49142f9010e055302adeda1d`. Public Issue #11. Earlier tested checkpoint: `2a013ab8e0c78e91f4a220cc40acef6c552b3f2c`. Only Apache-2.0 SDK/tests/docs change; no frozen schema/vector/expected bytes, license/notice, consumer mutation or V1 compatibility/migration.

Frozen checks and final behavior:

- Every canonical golden byte/digest and invalid JSON vector; every C0 escape, scalar UTF-8 versus UTF-16 ordering, no NFC transformation, direct HTML/slash/U+2028/U+2029/non-BMP bytes, exact canonical policy boundaries, safe integer types and rejected float/-0/exponent/unsafe integers/surrogates/duplicate keys/invalid UTF-8/custom Go values.
- Exact full manifest/subject canonical bytes and all digests; explicit null/scalar parent; content-set dedup/copy/empty manifest/file; full optional/label/sealed facts bind digests; mutable title/Working bytes/later delivery/evidence do not. Whole optional/manifest/aggregate/shadow/shared-expansion/cycle/depth/member guards precede serialization.
- Exact frozen signing-input bytes and fixed signature regenerated with the published TEST ONLY seed; strict verification passes. `valid-signature` and `bad-signature` compare actual signature/identity/reason codes against frozen expected values; committed integrity separately matches VALID. Positive full Complete/FULL comparison is NOT_RUN here.
- Canonical A/R/y/x-sign/base64url/S/fingerprint, wrong lengths/points/message/labels/time/identity/digest, local-versus-official conditional/closed facts, ID/path/Version/capability checks, including a mathematically valid signature reusing a historical entry ID. All eight canonical small-order points rejected as A and R. A constructed canonical non-small-order fixture satisfying only `[8]` equality is rejected; RFC8032 TEST 1 and 32 independently signed ordinary positive samples pass. Field operations handle public verification only.
- Every actual signature item remains visible; invalid beside valid remains aggregate INVALID; absent remains ABSENT/UNKNOWN; no pins yields UNTRUSTED; official self-claims do not grant trust; Host purpose/key/environment/profile matching can grant TRUSTED after valid math only. A well-formed bad signature retains UNTRUSTED claimed identity per the frozen fixture. Trust/I/O/resource/cancellation interruptions never advertise overall success.
- One selected Signer under one snapshot: unsigned capability-declaring historical Version is signed without changing any tree/HEAD/Version bytes. Pins, fresh IDs, owned messages/response, stability/check/close ownership, begin-with-error cleanup, no fallback/retry, profile/sign failure, changed key/type/environment/profile, malformed/weak key before Host effects, mutated input, corrupt response, late source failure, cancellation and close failures tested. Unit official tests are fake local TEST ONLY signing, not an external official service.

Executed offline on Linux amd64, Go 1.26.0:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test -run '^$' -fuzz '^FuzzCanonicalRestrictedDomain$' -fuzztime=15s -parallel=2
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test -run '^$' -fuzz '^FuzzSignatureEnvelopeRestrictedDomain$' -fuzztime=15s -parallel=2
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test ./internal/strict25519 -run '^$' -fuzz '^FuzzStrictPublicInputs$' -fuzztime=15s -parallel=2
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
git diff --check
```

Final race suite/vet PASS; canonical checkpoint fuzz 304,599 executions PASS; envelope fuzz 618,196 executions PASS, with 83,607 final executions PASS after strict field-type/schema-alphabet refinements; strict public-input fuzz 513,620 executions PASS. Go 1.23/current primitive source and RFC8032 consulted read-only; runtime does not fetch them. All 51 embedded machine assets match exact frozen git-tree bytes. Production graph: 120 packages; no external/network/database runtime imports. Exact local/remote diff/head/public-content review and merged-main read-back are recorded in the Issue/PR handoff after execution.

Original failures retained: the initial canonical subset had an unresolved helper; signature build had a shared-helper name collision, both corrected without frozen changes. The first frozen bad-signature test exposed UNKNOWN versus required UNTRUSTED identity; implementation corrected without changing expected values. Initial selected-signer tests incorrectly used `core-minimal`, which declares no signing capability; the implementation correctly rejected before Signer effects. Tests switched to existing unsigned `complete-history` (both capability declarations present), with a separate missing-capability rejection test retained. After weak-key rejection moved before Host effects, its obsolete sign/close-count assertion failed and was corrected to expect zero effects; final race/vet include the regression. Final review also distinguishes closed text/alphabet/length schema failures from well-shaped cryptographic failures; final envelope fuzz was repeated after that refinement. No failed check is reported as PASS before revalidation.

NOT_RUN: full seven-level/positive Complete verification and producer freeze; independent delivery/evidence semantics (S07); native Windows/macOS runtime and production no-follow/crash/publication/authorization/trust adapters; Directory/ZIP round trips; consumer/product/external integration; real Provider/official signing, production key use, online checks and remote CI (no configured checks observed). Signature addition/publication is a following codec/Host responsibility. No overall conformance or external-identity PASS is claimed.
