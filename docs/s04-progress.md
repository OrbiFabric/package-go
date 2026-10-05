# S04 earlier partial checkpoint (historical evidence)

This file records the earlier pushed partial checkpoint. Current stage evidence is [s04-evidence.md](s04-evidence.md); it does not replace the original command scope below.

Frozen protocol authority: `7ff166365dc83cee783e4e6715225968c81ef7b9`.
Source baseline / merged S03: `110a55da17c9714d51585cfeea9bc8be55f84177`.
Stage Issue: [#7](https://github.com/OrbiFabric/package-go/issues/7).

Implemented and tested subset: actual HEAD-to-null chain enumeration covering all Version directories, single-parent/ordinal/Package/path/manifest validation, historical kind continuity and all-Version ContentID/size union. Objects are read once per ContentID, including HEAD's committed copy; Working Tree bytes are never substituted. Extra object names/hashes are checked too. Missing committed objects yield UNAVAILABLE/NOT_FULL; incorrect referenced objects yield INVALID/INVALID. A corrupt unreferenced extra object blocks history completeness while leaving otherwise correct referenced committed integrity independent. Valid object coverage alone leaves history_completeness NOT_CHECKED because portable memory/embedded evidence has not been checked.

Historical materialization planning and payload-only reconstruction use manifest-derived paths and committed object streams, preserving empty bytes/empty folders and keeping HEAD unchanged. Output is caller-isolated pending data; no container publication, DB, network resolver or signing occurs. All-history recovery tests overwrite the working file before restoring both committed Versions. Aggregate control JSON (64 MiB default) and historical entity-count budgets bound retained history data before further allocation.

Executed on Go 1.26.0 linux/amd64:

- `GOPROXY=off GOSUMDB=off go test -race -count=1 ./...`: PASS, exit 0 for the implemented subset. The tests consume the eight S04 frozen fixtures, compare applicable integrity/negative completeness/reason fields, and separately assert valid object coverage remains NOT_CHECKED for full completeness. Positive FULL profile expectations are explicitly NOT_RUN until remaining dimensions are implemented.
- `GOPROXY=off GOSUMDB=off go vet ./...`: PASS, exit 0.
- `python3 scripts/check-foundation.py --spec-dir <local-spec-clone>`: PASS, exit 0; 51 unchanged exact frozen assets and 112 standard-library/SDK dependency packages, no SDK network/database dependency.
- `git diff --check` and staged SDK-only allowlist/public-content review: PASS.

S04 remains IN_PROGRESS. Required remaining work: unsigned commit/proposal creation, expected-HEAD isolation spanning stable source/object/Version writes and HEAD-last publication, concurrent stale-writer and maximum-ordinal tests, publication interruption/no-overwrite behavior, complete S04 review/PR/merge/main read-back. Positive full Complete/portable-memory/evidence/crypto/codec conformance, producer freeze and all product/external integration are NOT_RUN. This partial report is not S04 PASS or seven-level conformance certification.
