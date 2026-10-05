# S11 shared conformance and producer handoff

Authority: [package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`](https://github.com/OrbiFabric/package-spec/tree/7ff166365dc83cee783e4e6715225968c81ef7b9). Dependency: S10 merge `63faf6deff74d386b0764bdf78891d943ea79dbc`. The [public stage Issue #21](https://github.com/OrbiFabric/package-go/issues/21) records the final reviewed head, PR, merge, clean main read-back, exact producer SHA and resolved module version. Use that exact completed pin; a development branch or floating main is not the producer handoff.

All seven levels pass the actual Linux operation matrix:

| Level | Applicable fixture cases | Actual behavior |
| --- | ---: | --- |
| Core Reader | 1 | Native selected-root inspection; Core dimensions |
| Core Writer | 1 | Sealed plan, actual native Directory publication/read-back |
| Complete Reader | 26 | Native safe input or virtual unsafe preflight; full all-history offline proof |
| Complete Writer | 26 | Actual isolated Directory publication or negative rejection |
| Verifier | 26 | Independent nine dimensions, crypto vectors, no embedded trust/network |
| Directory Codec | 26 | Safe actual source materialization and native `PublishDirectory` round-trip/rejection |
| ZIP Codec | 30 | Direct frozen ZIP inputs; native DEFLATE artifact publication/read-back and STORE writing/decoding |

[Per-case results](s11-level-results.json) include independent frozen expected and actual dimensions, output results, authority fixture digest, actual transaction/publication counts, restoration counts and comparisons. PASS means the expected behavior, including a rejection; INVALID, NOT_FULL and NOT_CHECKED never mean semantic success. The report identifies its pre-merge working-tree observation. Issue #21's clean merged-main reports provide the final implementation revision. Expected fields originate in the pinned CC BY 4.0 protocol assets; implementation/tests are Apache-2.0. Assets/expected/license authority is unchanged.

The 136 applicable cases execute 53 offline reads, 42 lossless published round-trips and 41 pre-publication rejections. Positive outputs preserve all raw control/payload/extension bytes, implicit and explicit empty folders, Package/Version/File/Folder identities, all historical manifests and Version subjects. Every historical Version restores from output objects into real independent regular files, with correct digest/size and link count one: 69 restorations across Directory and both ZIP methods. Actual native artifact read-back uses the bounded SDK ZIP codec. ZIP staging never becomes a published Package.

All writers now share known-invalid attestation rejection: Directory publication, bare ZIP writer and import/export plans fail before output begins on invalid signature/evidence input, preserving the original bytes. The verifier still proves bad-signature input's correct committed history FULL and reports signature INVALID independently. Valid untrusted signatures are preserved without identity promotion. Missing offline objects cannot borrow Working Tree bytes or silently call a Resolver. Uninterpreted evidence obligations cannot create FULL transfer output. Portable schema/reference validation precedes object reads.

The manifest's two writer operations run at both Writer levels through the SDK compare-and-commit implementation and an explicit transaction contract Host. Stale HEAD leaves all original raw authority unchanged, stages/publishes zero Versions and reports STALE_HEAD. Linear commit writes actual SDK object/version/manifest bytes, keeps the prior authority, produces the expected single parent and ordinal 2, publishes HEAD last and verifies the new history FULL/CLEAN. These contract Hosts are not native product journal/authorization adapters.

The Verifier gate consumes all crypto vector sections: five exact canonical byte/digest cases, eight invalid JSON inputs, package/version/manifest and exact VersionSubject/digest, fixed seed/public key/fingerprint/signing-input/signature mathematics, untrusted identity and bad-signature fixture. The actual before/after invariant binds the frozen Version ID and subject digest and preserves raw signatures and receipt-bound Delivery digests. Rename/move/modified fixture pairs preserve FileID with the required separate path/content changes. Existing strict Ed25519 canonical A/R/S, all small-order/cofactor-only negative cases and independent evidence/trust/online tests remain passing.

Run the declared gate with an explicit development report destination:

```sh
GOPROXY=off GOSUMDB=off PACKAGE_GO_CONFORMANCE_REPORT=<temporary-report-path> \
  go test -count=1 -run '^TestS11' -v .
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
<verified-local-Go-1.23.12> test -race -count=1 ./...
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec>
```

The runner records the actual Git revision and dirty/clean state, declared levels, independent expected/actual values and explicit Host policy: 10,000 entries, 16 MiB file, 64 MiB total, 1 MiB JSON/NDJSON line, 64 MiB aggregate JSON, depth 64, path bytes 4,096, tree depth 256 and ratio 1,000. No network or embedded-key trust is used. Full Go 1.26.0 and minimum Go 1.23.12 race suites and vet PASS; all 51 frozen assets match exact authority and 125 production dependency packages contain no external/network/database runtime imports. Windows amd64/macOS arm64/Linux arm64 test binaries compile PASS; their native runtime is NOT_RUN. Final parse/path/archive fuzz runs execute 770,069 / 814,582 / 157,008 cases respectively and PASS. Earlier verifier checkpoint fuzz evidence is retained separately.

Original failures and final revalidation are retained: the first matrix test build used the wrong existing byte-map helper name; the next run exposed a test adapter opening sealed native restoration streams before List, which correctly rejected. The adapter now lists/compares the whole restored tree before opening streams. Full writer-contract review also exposed two early-stage implementation tests expecting bad signatures to be copied. The SDK and those implementation-only expectations now enforce the frozen negative writer rule; no frozen expected asset changed. The prior verifier checkpoint's ZIP recognition, optional semantic gating, evidence-subject test field, independent absence/embedded-presence assumptions and resource/trust fixes remain recorded in [historical progress](s11-progress.md). Final focused and complete reruns PASS.

Only SDK implementation/tests/conformance adapters/English development reports change. One shared protocol implementation remains; codec and writer tests invoke the same production primitives, not a second parser. No V1 recognition/dispatch/layout/compatibility/migration or consumer changes are introduced. Production Provider/official signer/credential/fact-selection integrations, consumer/product E2E, native non-Linux recovery and physical power-loss/storage-controller faults remain NOT_RUN. This producer acceptance does not certify those subsequent integrations or an independent final audit.

S11 supplemental coupled-proof correction: after provisional PR #22 merge `ac795a52c8f4ac8fd5ecf60cc28eb1873e06d76f`, six executed PKG-CONTRACT-001/018/020/021 tests exposed incorrect FULL on missing actual Root/referenced-Version signature/evidence capability declarations and invalid known closed attestation schemas. Issue #21 was reopened and producer freeze deferred. The corrected shared declaration preflight runs before object reads in the coupled verifier, Directory/ZIP writers and import/export plans; unsupported optional evidence bodies stay uninterpreted. Known schema failure yields structural/history INVALID, while correct committed object integrity and independently observed signature/evidence dimensions remain separate. Mathematical bad signatures still have FULL history when all schemas/declarations are legal. Original failures are retained in the Issue handoff; all six supplemental tests, all 136 level cases, complete Go 1.26/minimum Go 1.23 race suites, vet, exact 51 assets/125 dependencies and the three compile-only platform checks PASS after correction. The final correction PR/merge/main read-back and module resolution in Issue #21 determine the frozen pin; PR #22 alone is not that pin.
