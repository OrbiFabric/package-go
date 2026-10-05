# S08 evidence — Directory tree and safe publication

Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`, PKG-CONTRACT-002/016/017/018; dependency S07 merge `c81a555be26422cbf38e3be270b1e7dbad65b1f8`. Public Issue #15. Only Apache-2.0 SDK implementation/tests/docs change. Frozen assets, schemas, expected values, spec, consumers and license remain unchanged. No V1 compatibility or migration.

Executed on Linux amd64, Go 1.26.0:

The full race suite also executes on the supported minimum Go 1.23.12 toolchain. Native Windows amd64, macOS arm64 and Linux arm64 test-binary builds pass; runtime claims remain Linux amd64 only.

- All five required shared cases (`minimal-valid`, `complete-history`, `dirty-working-tree`, `moved-file`, `unknown-optional-extension`) are written into actual directories, exported through native external staging/no-overwrite publication, and read through the descriptor-anchored native reader. Every path, kind, size and raw byte matches before/after, including supplemented explicit empty nested folders. Actual history/object/memory readers check exported output; every Version's derived subject matches its original. Unmodified fixture Working results compare frozen expected states. The supplemented empty folders intentionally make payload dirty without changing history.
- Every historical Version in every case restores offline from the exported object's bytes into real independent files and directories; contents match its manifest-selected objects, with inode checks rejecting hard-link dependence. No Resolver or network is supplied. A hard-linked source payload/object becomes two independent exported files.
- Fourteen injected phases cover partial Begin, mkdir/create/write/writer-close, Seal before/after (including a returned observation with error), pending list/open/stability/close, publication before/after and cleanup error. Every error yields an empty publication. Errors before publication leave the destination absent; uncertain post-move/cleanup errors retain the installed complete bytes. Source snapshot close/stability errors also prevent publication.
- Missing object, wrong object bytes, missing parent, cyclic/multiple-root history, CRLF HEAD, case and NFC collisions, missing Complete portable file, malformed memory and a tiny entry budget fail without success output. A declared missing embedded evidence file prevents publication. Valid appended evidence and an invalid frozen Version signature are retained raw, with bad signature remaining INVALID independently.
- Existing empty directory/file/symlink and a destination created immediately before commit remain untouched. Same-size dirty payload alteration in pending output is detected by raw-byte read-back; alteration after validation is detected by native pre-rename recheck. A Host move with a lost reply proves Abort does not delete a tree no longer named pending.
- Root/file/parent symlinks, a parent changed into a symlink after staging, FIFO, traversal stream request, replaced Root, added entry, same-size payload edit with restored mtime, mid-copy source change, stream cancellation and entry budget are tested on actual Linux filesystem. No unsafe stream or successful output is returned.
- Cancellation before start/during writing/before sealing/before publication returns no success and removes owned pending output. Twelve actual native publishers synchronize at the final commit: exactly one succeeds, all others receive destination-exists errors, installed bytes are intact and all loser staging directories are removed.
- A subprocess exits with code 86 after creating a pending `.packtell/HEAD`, before Seal/Publish/Abort. The target is absent and only the external private pending sibling remains, requiring Host recovery. This is real process interruption evidence, not a fake successful retry or physical power-loss proof.
- The existing S04 transaction suite remains passing, including expected-HEAD comparison, stable payload, object/Version completion, HEAD-last acknowledgement, stale concurrent writers and uncertain-publication handling. Directory export is isolated publication; native in-place Commit/Host recovery integration is separate work.

Verification commands:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
go test -run 'S08|Directory' -v ./...
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
GOOS=windows GOARCH=amd64 go test -c -o <temporary-test-binary> .
GOOS=darwin GOARCH=arm64 go test -c -o <temporary-test-binary> .
GOOS=linux GOARCH=arm64 go test -c -o <temporary-test-binary> .
git diff --check
```

First behavior run PASS. First vet reported a test-only context cancellation cleanup omission; adding deferred cancellation fixes it. An initial patch application was rejected for duplicate target operations; no partial edit occurred. Review before the first behavior run corrected pending-only abort to establish the named anchor before deleting any child; the later uncertain-move test proves this property. Final review added Host write-policy enforcement, retained sealed digest/stamp recheck, metadata-only O_PATH enumeration (no special-file I/O), stream byte-policy checks, post-publication cancellation/cleanup uncertainty and comparator self-equality. The first minimum-toolchain invocation with GOSUMDB=off was refused by toolchain checksum verification; invoking the already verified local Go 1.23.12 executable directly runs the offline race suite successfully. Final race suite and vet PASS. Cross-platform test binaries compile; their native runtime behavior is NOT_RUN. Exact frozen asset check: 51 assets PASS; production dependency graph: 121 packages, no external/network/database runtime imports PASS. Exact head/diff review and merged main read-back are recorded in GitHub after execution.

NOT_RUN: full seven-level/positive Complete verdict comparison (S11), SDK producer freeze, Windows/macOS/arm64 native runtime, non-atomic platform Host isolation/recovery, physical power loss, storage-controller failure, production startup recovery, native in-place Host Commit integration, ZIP, real Provider/official signer/services and consumer/product E2E. Native built-ins explicitly reject unsupported platforms; compilation is not their runtime proof. All subsequent gates remain required.
