# S06 partial checkpoint — canonical JSON and VersionSubject

Status: IN_PROGRESS, not whole-stage acceptance. Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`; dependency: S05 merge `25069f7b71ec1dbe49142f9010e055302adeda1d`. Issue #11. Only Apache-2.0 SDK/tests/development evidence changed; no spec/license/consumer mutation or V1 compatibility/migration.

Implemented subset:

- Independent `CanonicalJSON`/`ReadCanonicalJSON`: exact restricted-domain integer handling, UTF-8 scalar-byte object ordering, retained array order, exact short/lowercase C0 escapes, direct HTML/slash/U+2028/U+2029/non-BMP scalars, no arbitrary NFC conversion/BOM/LF/whitespace. Floats/custom marshalers/invalid Go representations/UTF-8 and unsafe number lexical forms are rejected. Cycles/depth/member/single/aggregate bytes are bounded; key/string budgets precede sorting/expansion. No canonical ordering/escaping delegates to encoding/json or JCS.
- Distinct content-set commitment, deduplicated and ordered ContentIDs/sizes, including empty manifest/file and copies; paths/labels/ordinals are not content identities.
- `DeriveVersionSubject`/`DeriveSubjectAt`: validate and own immutable document models, derive all schema fields and full Package/Version/manifest/sealed metadata digests plus content commitment and domain-separated subject digest. Scalar/null parent; known invalid root/self-parent relationships reject. Unknown immutable fields and label bind digests. Mutable metadata, Working Tree, later delivery/evidence and representation bytes do not enter this subject.
- Caller optional-value/UTF-8/shadow/whole-manifest/shared-expansion/aggregate guards run before model serialization. Subject canonical serialization validates claimed field shape but cannot certify claimed digests; verification must derive a fresh subject from actual history.

Executed offline on Linux amd64, Go 1.26.0:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test -run '^$' -fuzz '^FuzzCanonicalRestrictedDomain$' -fuzztime=15s -parallel=2
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
git diff --check
```

PASS for this subset: every frozen canonical vector byte/digest and invalid JSON case, exact frozen manifest/subject canonical bytes/digests, all C0 escapes, UTF-8 versus UTF-16 ordering, decomposed text preservation, exact byte boundary without HTML overestimation, scalar child parent, optional facts/dedup/empty content, mutable/delivery/evidence-independent subject invariance, caller invalid domains/identity/ordinal and resource guards. Canonical fuzz PASS: 304,599 executions; accepted canonical output reparses identically. Race/vet and all 51 frozen assets/113 production dependency checks passed. The first subset build caught an unresolved helper reference; replaced with existing schema-shape validation without changing frozen expected assets; behavioral vector tests passed on first execution. Final checks repeat after the added aggregate-policy regression test.

NOT_RUN/remaining: fixed frozen signing-input and signature comparison; signature envelope parser/verification; strict canonical point/scalar and small-order Ed25519 tests; Signer error/no-fallback and Host trust/per-signature reports; valid-signature/bad-signature behavior; S06 PR/merge/main read-back. Full seven-level/Complete conformance, native production Host/adapters, codecs and consumer/external integration remain required later. This checkpoint does not claim signature, identity or Complete verification. No whole-stage PASS or producer freeze.
