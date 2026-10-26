# Portable 2.0 UTC microsecond cutover

Authority: package-spec main `181f9c2048b7cad346044a6fa4a15096166e83d4`, ordinary merges [#4](https://github.com/OrbiFabric/package-spec/pull/4) and [#6](https://github.com/OrbiFabric/package-spec/pull/6). This is the Founder-authorized unreleased-development Clean Break, tracked by [Cloud Goal #690](https://github.com/OrbiFabric/orbifabric-cloud/issues/690), not a published backward-compatible minor update. Earlier stage reports remain historical evidence at their original pins.

All SDK-produced portable timestamps now use UTC RFC3339 with exactly six fractional digits and literal `+00:00`. `Timestamp` first converts explicit Host time to UTC and renders microseconds; `ParseTimestamp` rejects old Z, other offsets, missing/variable precision, invalid Gregorian dates/years, leap seconds and trailing whitespace, and returns a UTC time. The shared parser reaches Package, Version, Subject, Signature, Delivery, Notes, Tags, Provenance, Events and all four Evidence subjects. No automatic signed-byte normalization, legacy fallback or signature-domain change is introduced. Existing valid UUIDv7 allocation remains unchanged.

The SDK embeds all 66 machine assets verbatim from the exact merged upstream tree, with a SHA-256 lock and matching public spec constants. Tests consume the new independent Python-generated subject/hash/Ed25519 vectors and all 19 timestamp samples. The Linux seven-level matrix grows from 136 to 241 applicable cases across 45 fixtures; it retains the original expected results and adds 15 timestamp rejections at every level. A rejection passes only when its actual dimensions/reasons match; it is not successful Package validation.

## Verification and original failures

Initial adoption exposed an upstream fixture defect: Complete inputs were assigned to Core levels, which correctly stopped at unsupported portable-memory rather than the intended timestamp error. The original failing SDK experiment was withdrawn to a clean checkout before the sole Writer returned to package-spec. Upstream #6 corrects the input template to Core and verifies that only package.created_at differs; expectations and SDK capability checks were not relaxed. The first run also identified two fixed fixture-inventory counts and an old positive max-year timestamp literal in SDK tests; these are updated to the new authority.

Actual first corrected run: Go 1.26.8 Linux amd64, `GOPROXY=off GOSUMDB=off go test -count=1 ./...` PASS. `python3 scripts/check-foundation.py --spec-dir /home/ketao/projects/package-spec` PASS: exact 66 upstream assets and 125 production dependency packages with no external/network/database runtime imports. `git diff --check` PASS. Fixed-source race/vet, independent review and ordinary merge/main read-back are recorded in the adoption PR after execution.

The original local failure log remains `/tmp/packtell-package-go-utc-first.log`; the corrected run is `/tmp/packtell-package-go-utc-second.log`. These local files contain synthetic test results, not product/Provider credentials. Cloud/Packtell consumer pins and real official Provider/native integration remain **NOT_RUN here** and belong to the following Goal stages. No Production or public release authorization.

## Fixed-source exit evidence

Tested and independently reviewed SDK implementation: `a21ee79363537f5a310bc8ebc1e486051be1b327`. Subsequent report-only commits do not change the reviewed implementation, tests or embedded assets. Actual commands on this clean source:

```sh
GOPROXY=off GOSUMDB=off PACKAGE_GO_CONFORMANCE_REPORT=/tmp/packtell-package-go-utc-conformance.json go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
python3 scripts/check-foundation.py --spec-dir /home/ketao/projects/package-spec
git diff --check
```

All PASS on Go 1.26.8 Linux amd64. The generated report binds spec `181f9c2048b7cad346044a6fa4a15096166e83d4`, implementation `a21ee79363537f5a310bc8ebc1e486051be1b327` and `working_tree_clean=true`. It records **241/241 comparison passes**: Core Reader 16, Core Writer 16, Complete Reader 41, Complete Writer 41, Verifier 41, Directory Codec 41 and ZIP Codec 45. The original cases account for 136 and the new time negatives for 105; rejection does not mean semantic validation success. Full race output is retained at `/tmp/packtell-package-go-utc-race.log`.

Independent reviewer: separate read-only agent `/root/protocol_review`, same implementation SHA. The reviewer executed timestamp, Subject, strict signature, Evidence/append invariants and the complete seven-level matrix, verified all 66 embedded assets and the dependency boundary, and found no blocker. It confirmed there is no UUIDv7/domain/purpose/capability change or legacy time fallback. Ordinary PR Merge Commit and main SHA read-back are recorded in the adoption PR; Cloud/Packtell must pin that merged SDK source rather than a floating development branch.
