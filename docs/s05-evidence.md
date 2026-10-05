# S05 evidence — portable metadata, history and provenance

Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`; dependency: S04 merge `72876bd7bd3c66b2f9532822f5c23107a698ce87`. Public tracking: Issue #9. Apache-2.0 SDK/test/doc scope only; no spec asset/expected value, license, consumer code or database change. No V1 compatibility/migration.

Behavior checks:

- `cloud-origin-provenance`: all five memory paths present; schema/PackageID/ContentID history relationships checked, Google Drive opaque source facts retained, no Provider access or Working bytes read.
- `unknown-optional-extension`: five memory documents valid; unknown declared binary bytes including NUL/invalid text bytes copied exactly; opaque `.json` and empty extension directory preserved; open optional/nested metadata/event facts survive the SDK read/write plan. Full Directory/ZIP round trips NOT_RUN here.
- `complete-history`: memory references validated against both actual Versions. Deleted historical FileID targets stay valid; later event references are resolved by inventory without chronology sorting/replay. Restoration still uses the committed manifest/object bytes. Full FULL/Complete/signature/evidence result comparison NOT_RUN; these are stage-scoped memory checks against frozen input, not a seven-level conformance claim.
- Notes: first revision/gap/duplicate/order/target drift/tombstone/body/restore/current projection; closed-field rejection.
- Tags: contiguous global revisions, duplicate add/absent remove, exact case sensitivity, surrounding Unicode whitespace, decomposed NFC text, current projection.
- Events: known labels and unknown namespaced explanations, nullable/opaque actor, nested allowed data, preserved file order with reversed timestamps, zero bytes; missing LF/blank/CRLF/BOM/duplicate ID/multiple values/closed-field/schema rejection. Line boundary and multi-buffer lines, aggregate bytes, ten records with count policy nine, cancellation and read interruption tested.
- Provenance: sorted unique records, source vocabulary, Gregorian times, original-name schema, content/file/package history references; another-Package relationship with optional Version retained without opening it; same-Package relationship rejected. Unknown fields and schema errors tested.
- Combined memory: Package agreement, non-existent/wrong-kind targets, cross-domain UUID reuse and tombstoned ID retention, including validated control-envelope path IDs without a crypto PASS. UUID-shaped payload filenames do not invent control identities. Ordinary Commit reserves memory IDs; explicit tracking reuse and invalid memory block publication.
- Write planning: no prior note/tag/event/provenance rewrite/removal/reorder, sorted insertion of a new Note, mutable display facts independent of sealed facts/HEAD, optional/nested loss rejection and explicit optional removal intent. Mandatory Host policy with safe selected fields rejects unselected secret/runtime categories; policy receives an owned copy and cannot mutate planned output.
- Resource/ownership: invalid caller UTF-8/floats/shadow/cycles, shared-value expansion, line/depth/entry/aggregate/prospective tree budgets; 10,000-note proposal rejected under small byte policy before expanded model allocation/Host approval. Advertised aggregate limits block all control opens; actual event byte count is checked even when a listed empty stream exactly exhausts the JSON budget. Extension extra bytes and read interruptions fail without publication.

Executed locally on Linux amd64, Go 1.26.0, offline runtime/module policy:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test -run '^$' -fuzz '^FuzzPortableNDJSON$' -fuzztime=15s -parallel=2
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
git diff --check
```

Race suite and vet PASS. NDJSON fuzz PASS: 1,069,630 executions; accepted records preserve all facts over serialize/read or explicitly fail expanded byte policy. The final resource refactor affects the memory writer, not this unchanged event reader; writer-specific/full race checks were repeated after it. All 51 embedded frozen machine assets match exact git-tree bytes; production graph has 113 packages with no external/network/database runtime imports. Diff/public-content review and exact remote head/path equality are required before merge; merged-main read-back is recorded in Issue/PR handoff after execution.

Original development failures retained: the first build caught an unused import; the first new test build caught a helper name collision with an existing test helper. Both were fixed without changing frozen input/expected assets; all new behavioral tests passed on first execution. Review subsequently tightened empty-stream inspection, BOM-in-string handling, historical cross-domain identity checks, true event-count coverage, append-only provenance and collection byte checks before expanded allocation and control-path versus payload-name ID reservation; final checks above include these changes. No behavioral failure was hidden as PASS.

NOT_RUN: full seven-level and Complete positive verification; canonical/crypto/evidence stages; native Windows/macOS runtime, production no-follow/junction/crash/authorization adapters and transaction publication; Directory/ZIP codec round trips; consumer/product/external integration; remote CI (no configured checks observed). Host fact selection is a tested port contract, not a claimed production privacy policy. Evidence/signature integration and full offline profile verification remain required before producer freeze.
