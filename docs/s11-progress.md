# S11 development progress — verifier checkpoint

S11 remains IN_PROGRESS; SDK producer NOT_YET_FROZEN. Dependency: S10 merged main `63faf6deff74d386b0764bdf78891d943ea79dbc`. Authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`. Public Issue #21 records the exact reviewed development commit; this checkpoint is not an S11 merge, final conformance certificate or consumer pin.

Executed behavior:

- Every one of the 30 frozen manifest fixtures runs through the actual single-observation SDK verifier, including direct wrapped/unwrapped ZIP input and dangerous archive rejection. [Per-case actual results](s11-verifier-progress.json) link each independent frozen expected source/digest. Mandatory dimensions match and all expected reason codes occur. Expected NOT_CHECKED permits additional safe checks, as the frozen runner contract specifies. Passing a rejection case never means its INVALID/NOT_FULL dimensions succeeded.
- Missing/invalid Complete memory, incorrect extra object bytes, bad evidence mathematics and missing embedded evidence exercise coupled completeness with separate content/signature/identity/evidence outcomes. When the final actual envelope is absent, evidence is ABSENT while its broken embedded-presence obligation still makes history NOT_FULL. Unsupported optional memory/signature semantics are not read; absence of evidence skips unrelated signature reads.
- Owning observation closes exactly once; stability/close/cancellation revoke positive proof. Trust callback failure stays NOT_CHECKED, rather than ABSENT. Resource policy, including implicitly expanded parent entry budgets, prevents further discriminator reads or semantic success. ZIP recognition diagnostics reject duplicate/multiple Root markers, bad marker CRC and unstable observation; corrupt unsafe payload is never interpreted to decide recognition.
- Full existing S01–S10 Linux behavioral/race tests continue to pass, including crypto vectors, Directory/ZIP/history restoration, sealed hydration and transactional safety. This does not substitute for the remaining explicit level adapters and writer operations.

Verification on the reviewed checkpoint:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
<verified-local-Go-1.23.12> test -race -count=1 ./...
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec>
GOOS=windows GOARCH=amd64 go test -c -o <temporary-test-binary> .
GOOS=darwin GOARCH=arm64 go test -c -o <temporary-test-binary> .
GOMAXPROCS=2 go test -run '^$' -fuzz '^FuzzProtocolJSONAndFormat$' -fuzztime=20s -fuzzminimizetime=1s -parallel=2 .
GOMAXPROCS=2 go test -run '^$' -fuzz '^FuzzPortableTreePaths$' -fuzztime=20s -fuzzminimizetime=1s -parallel=2 .
GOMAXPROCS=2 go test -run '^$' -fuzz '^FuzzZIPWholeTreePreflight$' -fuzztime=20s -fuzzminimizetime=1s -parallel=2 .
git diff --check
```

PASS: full Go 1.26.0/minimum Go 1.23.12 race suites, vet, Windows amd64/macOS arm64 compilation, exact 51 assets and 125 production dependency packages without external/network/database runtime imports. Fuzz executes JSON 569,069; paths 690,347; ZIP initial 83,827 and final 179,052 after resource-diagnostic review. Native Windows/macOS runtime remains NOT_RUN.

Original failures retained: first behavioral run exposed missing recognition on two unsafe ZIP fixtures and an unsupported signature read via the empty-evidence path; SDK diagnostic and semantic gating fixed both, without changing expected assets. One added test initially referenced an evidence ID at the envelope rather than its subject, causing a build error. Two implementation-only test assumptions were corrected to normative behavior: no actual envelope is ABSENT despite a missing embedded obligation, and duplicate-marker archive rejection can precede a simultaneous traversal error. Each original log is retained in the execution handoff; final targeted/full reruns PASS. Review additionally corrects trust-error reporting and halts diagnostic reads after resource failure. Spec chapter lookup failures were resolved by the actual frozen file inventory, without authority mutation.

PENDING: explicit seven-level operation matrix (Core Reader/Writer 1 fixture each, Complete Reader/Writer/Verifier/Directory Codec 26 each, ZIP Codec 30), actual stale-head zero publication and linear commit operations in that runner, final per-level crypto/invariance/writer-rejection evidence, public final diff/PR merge/main read-back and exact module-version producer freeze. Existing earlier stage coverage is supporting evidence, not a substitute for this formal gate. Production Provider/official signer, consumer/product E2E and platform recovery integrations remain NOT_RUN. No frozen assets, expected authority, specification, licenses or consumer code change.
