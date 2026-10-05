# S10 evidence — import/export plans and explicit hydration

Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`, PKG-CONTRACT-010/017/018/019; S09 dependency `500887413bbac371ea80cc57b5b63c15fe2e4fb4`. Public Issue #19. Only Apache-2.0 SDK/tests/docs change; no spec/assets/expected/consumer/license changes or V1 recognition/layout/compatibility/migration.

Executed behavior:

- Frozen `complete-history`, `missing-object`, `object-hash-mismatch` and `unknown-optional-extension` compare actual offline integrity and coupled plan completeness subsets. Missing input retains NOT_FULL/UNAVAILABLE and needs an explicit Resolver; no output transaction begins offline. Wrong source hashes reject without repair/fallback. Complete and opaque-extension sources preserve every raw file byte.
- A two-Version tree is made entirely remote-only, including its historical removed content, with two HEAD files sharing one ContentID. Planning invokes no Resolver. Each distinct all-history object is fetched once, SHA-256/size verified, stream closed and selected revision checked after close. Every historical Version restores offline from the actual output. Input bytes and original NOT_FULL observation remain unchanged; output is proved FULL from its actual tree. Caller summary/revision-map mutation cannot change execution, and transient revisions never appear in portable bytes.
- Resolver wrong hash/short/long stream, wrong revision, absent revision check, late revision change, partial-response error, read/close failure and cancellation produce no success/output and close returned streams exactly once. Host fact selection is mandatory, rechecked at execution and receives owned copies; attempted approval-view edits do not affect plans. Working/optional JSON/extension/memory/object/HEAD drift, revoked approval and source stability/close failures cannot publish. Missing Complete memory/embedded evidence and unknown content selections reject.
- Import and export Directory transactions cover begin/mkdir/create/write/close/seal/publication/cleanup faults. ZIP artifact transactions cover begin/write/close/seal/publication/cleanup faults. Every failure yields an empty result; uncertain post-move outcomes retain installed bytes. Temporary ZIP trees are never published and are cleaned before artifact commit.
- Native Linux Directory and ZIP workflows hydrate all historical objects directly into staging and preserve original source files. Persisted native ZIP artifacts are reopened through the native no-follow random-access source and imported to actual Directory output without any Resolver, with FULL proved from actual bytes. All historical Versions restore offline.
- Native artifact targets already containing file/empty directory/link, a concurrent winner, pending tampering before/after sealing, lost move reply, cancellation and eight concurrent publishers are exercised. Exactly one concurrent winner publishes and no loser pending leaks remain. Native source file/parent links, non-regular input, byte policy, cancelled ReadAt and same-size edit with restored mtime reject. A subprocess exits with code 86 before artifact close/seal/publication, leaving only external unfinished pending output and no destination.
- Existing S01–S09 tests, including crypto/signature/evidence independence, Directory/ZIP safety, S04 expected-HEAD/HEAD-last transactions and frozen vectors remain passing. A standalone transfer proof is not the final producer conformance certificate.

Verification:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
<verified-local-Go-1.23.12> test -race -count=1 ./...
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
GOOS=windows GOARCH=amd64 go test -c -o <temporary-test-binary> .
GOOS=darwin GOARCH=arm64 go test -c -o <temporary-test-binary> .
git diff --check
```

Original failures retained: first generic behavior run had two raw-map equality assertions treating nil and empty zero-byte slices as different despite equal file bytes; comparisons now require exact keys/count and `bytes.Equal` for each value, without changing any frozen expected bytes. First native test build had an unused import; removing it fixes compilation. Subsequent behavior runs PASS. Initial spec lookup guessed nonexistent chapter filenames; the frozen tree's actual content/Complete chapter and numbered contracts were read instead, with no authority mutation. Review captures native metadata-close errors and guards artifact size overflow. Final race/vet/minimum-Go/platform builds and exact diff/remote-head/merge/main read-back are recorded after execution. All 51 frozen machine assets match exact authority bytes; production dependency graph has 125 packages and no external/network/database runtime imports.

NOT_RUN: full seven-level verifier/producer freeze, native Windows/macOS/runtime adapters/recovery, physical power loss/storage-controller faults, production Provider/official signer/credential/fact-selection integrations and consumer/product E2E. Test policies/Resolvers are Host contract evidence, not production privacy/remote-service claims. No unrun gate is promoted to PASS.
