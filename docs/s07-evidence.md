# S07 evidence — Delivery and independent evidence

Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`; dependency: S06 merge `ea01a4f9a47737d7bd782bd2bd4aa1ac992f8b90`. Public Issue #13. Only Apache-2.0 SDK/tests/docs change; no spec/assets/expected bytes/license/consumer mutation or V1 compatibility/migration.

Executed behavior:

- `multi-delivery`: both actual descriptors reference the existing valid selected-Version signature and actual derived subject; evidence ABSENT and online NOT_REQUESTED compare frozen expected. Independent signature/content results also match expected.
- `later-evidence-append`: both descriptors remain verified; supplied frozen cloud anchor cryptography/identity/path/Version digest verified, evidence VALID and online NOT_REQUESTED compare expected. The first Delivery digest equals its pre-append digest and Version subject/original signature remain unchanged. Positive full FULL/Complete result comparison NOT_RUN here; inventory alone is not promoted to FULL.
- `bad-signature`: evidence remains ABSENT while signature INVALID and committed integrity VALID match frozen expected, proving no evidence requirement/fallback or contamination.
- All four subject variants verified with actual receipt Delivery digest and lifecycle full event digest, common facts and separate key-purpose trust inputs. A Host rule for cloud-anchor purpose does not trust the other three kinds or reuse Version signer official facts.
- Invalid/missing/wrong-Version/unsorted signature references, duplicate evidence IDs, wrong ref kind, path/Package/Version/subject/fingerprint/signature/schema/unknown field and inappropriate variant facts reject. Actual receipt/event digest/ID failures are tested with otherwise valid mathematical signatures, not a coincidental crypto failure.
- Delivery append preserves immutable prefix and receipt-bound facts, refuses recipient/old reference edits/removal/duplicates; evidence envelope/observed fact rewrite rejects. Empty arrays/conditional schema and UUID/time rules follow frozen readers.
- Missing embedded file is explicitly inventoried; switching a reference to external removes the embedded requirement without opening nonexistent bytes or calling a network. Supplying evidence still verifies it. SDK reports no FULL on positive coverage alone.
- CreateDelivery selects every valid existing signature, derives fresh identity/subject, owns selected facts and approved bytes, leaves all actual source/HEAD/Version data unchanged, and rejects missing/bad references, Host fact-policy rejection, late snapshot mutation and close failure without success artifacts.
- Offline/online separation: offline verification never invokes status Host; an explicit revoked status query leaves all old bytes/digests and mathematical evidence valid, with subsequent offline status still NOT_REQUESTED. Host failures propagate as UNAVAILABLE without historical mutation.
- Resource/cancellation/stream/trust failures cannot advertise PASS; advertised aggregate JSON budget blocks any source opens and 10,000-reference proposal fails a small byte policy before expanded model allocation.

Executed on Linux amd64, Go 1.26.0, offline module/runtime policy:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test -run '^$' -fuzz '^FuzzEvidenceEnvelopeRestrictedDomain$' -fuzztime=15s -parallel=2
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
git diff --check
```

Final race suite/vet PASS. Evidence fuzz PASS: 431,900 executions; accepted envelope facts survive SDK serialize/read and preserve subject digest or explicitly fail expanded resource policy. All 51 machine assets match exact frozen git-tree bytes; 120 production dependency packages with no external/network/database runtime imports. Exact diff/public-content/head review and merged-main read-back are recorded in Issue/PR after execution.

Original failure retained: first new test build had two imports reserved for subsequent failure/ownership tests but not yet used; later tests use them. All behavior tests passed on first execution after the test file compiled; no frozen expected values changed. Final review added reference allocation and selected-count policy checks and explicit cancellation/trust-error handling; final race/vet include these changes.

NOT_RUN: full seven-level/positive Complete verification, SDK producer freeze, native Windows/macOS/runtime no-follow/publication/restart adapters, Directory/ZIP round trips, real issuer/official signer/Provider/network service, production key use and consumer/product E2E. Remote CI has no configured checks observed. Status/issuer/fact selection ports are tested contracts, not claimed production integrations. Required following gates remain open.
