# S02 core model evidence

Protocol authority: `7ff166365dc83cee783e4e6715225968c81ef7b9`.
Source baseline / prerequisite S01 merged main: `3846fec82be2ebf2c49179605e50baec681c7c09`.
Stage Issue: [#3](https://github.com/OrbiFabric/package-go/issues/3).
Implementation head / PR / merge/main read-back SHA are recorded in the Stage Issue after merge.

Allowed paths: SDK identity/model/tree proposal code/tests, typed foundation ContentID boundary adjustments, exact Unicode16 normalization data/tests/generator and SDK docs. Frozen machine assets and top-level LICENSE/NOTICE unchanged. No product/Provider/Wails/database/cloud runtime dependency, V1 encoding, old-data migration or fallback was added.

Commands executed on Go 1.26.0 linux/amd64:

- `GOPROXY=off GOSUMDB=off go test -race -count=1 ./...`: final PASS, exit 0. Exercises ID/date boundaries, secure/concurrent/collision-limited generation, zero generator errors, Package creation facts, required-field/schema negatives, optional JSON preservation, logical topology, explicit empty folders, cross-Version kind continuity, model operation identity and deep proposal isolation.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=2 go test -run '^$' -fuzz '^FuzzProtocolModels$' -fuzztime=3s -parallel=2`: final PASS, exit 0. Execution count is recorded in the Stage Issue/PR; Package/Version/manifest strict parsing and accepted-model serialization exercised.
- `GOPROXY=off GOSUMDB=off go vet ./...`: PASS, exit 0.
- `python3 scripts/check-foundation.py --spec-dir <local-spec-clone>`: PASS, exit 0; all 51 frozen specification JSON inputs unchanged/exact, 112 dependency packages all standard library or SDK; no SDK network/database imports.
- `python3 scripts/generate-unicode16.py <pinned-local-ucd-dir>`: PASS, exit 0, deterministic regeneration from pinned source digests; 934 nonzero canonical combining classes, 2,081 canonical decompositions and 961 composition pairs. Complete 19,965-row Unicode 16 NFC test passes under the race suite. Runtime/validation has no hidden network requirement; explicit development acquisition of public Unicode16 inputs occurred before offline tests.
- `git diff --check` / staged diff review: PASS; exact remote head/changed paths and clean merged-main read-back required before close-out.

Shared fixture model scope:

| Case | Actual model behavior | Result |
|---|---|---|
| core-minimal | Package/Version/manifest parse; file content/identity facts preserved | PASS |
| renamed-file | both snapshots parse; stable FileID, changed name | PASS |
| moved-file | both snapshots parse; stable FileID, explicit folder/parent relationship | PASS |
| modified-file | both snapshots parse; stable FileID, changed ContentID/size | PASS |

Fixture inputs are decoded directly from frozen assets; checks exercise SDK parsers/identity/topology rather than a fixture syntax checker. All other fixture dimensions and full Reader/Writer/Complete/Verifier/Directory/ZIP levels are NOT_RUN here.

Retained initial failure: the first S02 test compilation exited 1 because a test took the address of a typed FolderID constant. Replaced it with a local typed variable pointer; all final race/vet/fuzz checks passed. No implementation or frozen expected result was weakened to pass tests.

Product workflows, external Provider, official signer, complete crypto/history/codec conformance and remote CI remain NOT_RUN at S02. No external integration PASS is claimed. See model.md for exact scope and remaining gates.
