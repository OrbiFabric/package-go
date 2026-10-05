# S03 tree/HEAD/Working Tree evidence

Frozen authority: `7ff166365dc83cee783e4e6715225968c81ef7b9`.
Source baseline / prerequisite merged S02: `3a2c4287adb70676925a8100888218dbd26eab21`.
Stage Issue: [#5](https://github.com/OrbiFabric/package-go/issues/5).
The prior pushed HEAD subset `ccbc03d7bfef39e49ef9f15fe5ba51c453811331` is part of this stage branch. Final head/PR/merge/read-back SHA are recorded in the Stage Issue.

Allowed changes: SDK paths/Root/HEAD/scan/diff, model safety and resource policy, implementation tests, exact Unicode16 folding data/generation/tests and SDK docs. No frozen specification machine asset or top-level LICENSE/NOTICE changed. Sole writable implementation repository remains this SDK.

Executed on Go 1.26.0 linux/amd64:

- `GOPROXY=off GOSUMDB=off go test -race -count=1 ./...`: final PASS, exit 0. Includes exact HEAD and expected-HEAD cancellation/stale/close failures, full path/Unicode/Windows-reserved-name/UTF16/special-kind preflight, control allowlist and capability short-circuit, manifest derived paths, ID-aware diff, real folder external edit and detected scan race, mtime independence, actual local symlink rejection, empty folders, ambiguous equal bytes, copy/rename proof, pending observation failure and no partial scan success. Unicode16 normalization/folding data tests pass.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=2 go test -run '^$' -fuzz '^FuzzPortableTreePaths$' -fuzztime=3s -parallel=2`: PASS, exit 0, 16,739 executions after 67 cached seeds; earlier five-second run completed 29,935 executions. No failing corpus found.
- `GOPROXY=off GOSUMDB=off go vet ./...`: PASS, exit 0.
- `python3 scripts/check-foundation.py --spec-dir <local-spec-clone>`: PASS, exit 0; all 51 frozen assets remain byte-exact, 112 production dependency packages all standard library or this module, no SDK network/database imports.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o <temporary-test-binary>`: build PASS, exit 0. Native Windows runtime/junction creation checks NOT_RUN.
- `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go test -c -o <temporary-test-binary>`: build PASS, exit 0. Native macOS runtime NOT_RUN.
- `git diff --check` and exact staged diff/public-content review: PASS. Remote exact head/changed-path verification and clean merged-main read-back recorded after merge.

Stage fixture behavior reads input and expected recognition/working/reason fields directly from frozen shared assets:

| Fixture | Actual scoped result | Result |
|---|---|---|
| unborn | RECOGNIZED, UNBORN, no Root/scan error | PASS |
| invalid-head-crlf | RECOGNIZED, INVALID_HEAD; proposed scan discarded | PASS |
| dirty-working-tree | RECOGNIZED, DIRTY; HEAD unchanged and committed HEAD object independently hash/size verified | PASS |
| path-traversal | RECOGNIZED, UNREADABLE, PATH_TRAVERSAL; no unsafe/history/payload stream opened | PASS |
| case-conflict | RECOGNIZED, UNREADABLE, CASE_CONFLICT; no history/payload stream opened | PASS |
| unicode-normalization-conflict | RECOGNIZED, UNREADABLE, UNICODE_NORMALIZATION_CONFLICT; no history/payload stream opened | PASS |

These checks prove stage behavior; complete fixture history/integrity/signature/evidence dimensions and seven-level conformance certification are NOT_RUN at S03. Fixture dimensions marked NOT_CHECKED in frozen expected results do not become PASS. No syntax-only asset checker is represented as SDK conformance. No product/Provider/official signer/remote CI is run.

Retained initial failure: moved-file unexpectedly reported DIRTY because filesystem kind directory did not match manifest kind folder, so a stable folder looked Added/Removed. Corrected the representation mapping; unchanged moved-file now scans CLEAN. Frozen expected data was not changed. Initial five-second fuzz and subsequent fixed-head race/vet/fuzz verification are recorded above.

The scan-race filesystem helper is a test Host adapter; it proves SDK error handling for actual detected concurrent edits, not production adapter authorization/no-follow guarantees. Later Host/codec integration must supply and verify that boundary. Snapshot and expected-HEAD tests do not certify durable publication, full linear history or Complete recovery; those remain mandatory subsequent stages.
