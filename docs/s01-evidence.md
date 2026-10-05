# S01 foundation evidence

Public authority: `OrbiFabric/package-spec@7ff166365dc83cee783e4e6715225968c81ef7b9`.
Source baseline: `68721587d6029e49ee8b175ea7365bd6c2fd1cbb`.
Stage Issue: [#1](https://github.com/OrbiFabric/package-go/issues/1).
Implementation head / PR / final merge SHA are recorded in the Stage Issue after merge to avoid a self-referential future SHA.

Allowed changes: SDK module/model/public boundaries, implementation tests, offline conformance adapters/assets and development docs only. LICENSE/NOTICE are preserved. Machine JSON assets are verbatim public authority, with their Apache-2.0 attribution. No external implementation was copied.

Executed on Go 1.26.0 linux/amd64:

- `GOPROXY=off GOSUMDB=off go test -race -count=1 ./...`: PASS, exit 0. Covers shared format contracts, schema/capability negatives, strict restricted JSON, bounded reads, cancellation before/during read/after final write, pending write failure, content SHA-256/size negatives and empty content, result separation and offline asset inventory.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=2 go test -run '^$' -fuzz FuzzProtocolJSONAndFormat -fuzztime=3s -parallel=2`: PASS, exit 0; 140,745 executions, six initial seeds, 54 newly interesting inputs; no failure found. This short foundation fuzz run does not substitute for later path/archive/race testing.
- `GOPROXY=off GOSUMDB=off go vet ./...`: PASS, exit 0.
- `python3 scripts/check-foundation.py --spec-dir <local-spec-clone>`: PASS, exit 0; all 51 machine JSON assets compared byte-for-byte to frozen git tree; complete machine input inventory checked; 105 production dependency packages, all standard library or this module, no SDK network/database imports.
- `git diff --check`: PASS, exit 0. Staged diff and remote head equality checked again before merge; main read-back recorded in the Issue.

Shared fixture case results at this stage:

| Case | Exercised behavior | Actual | Expected | Result |
|---|---|---|---|---|
| core-minimal | format discriminator/schema/required capability recognition | RECOGNIZED, no format error | RECOGNIZED | PASS |
| unknown-required-capability | format required capability short circuit | UNSUPPORTED, UNKNOWN_REQUIRED_CAPABILITY | UNSUPPORTED, UNKNOWN_REQUIRED_CAPABILITY | PASS |

The tests read bytes/expected values directly from the frozen fixture snapshot without materializing untrusted paths. Only these foundation behaviors are exercised; other dimensions of both fixtures are NOT_RUN. No Reader/Writer/Complete/Verifier/Directory/ZIP conformance level is claimed. Public tests make this scope explicit.

Resource policy is documented in foundation.md: JSON bytes/depth/collection count enforced by parsing; content single/total byte policy enforced before stream copy. Other codec/multi-object budgets belong to later stages. Context cancellation and Host I/O errors are reported separately from protocol failures. The SDK never publishes the pending output stream by itself.

Initial compilation before tests existed was successful and explicitly reported `[no test files]`; it is not test evidence. Product, Provider, official signer, full crypto/codec/history/shared conformance and remote CI are NOT_RUN at S01. No external integration PASS is claimed.
