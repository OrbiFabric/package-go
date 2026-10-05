# S09 evidence — ZIP v1 and archive safety

Frozen authority: package-spec `7ff166365dc83cee783e4e6715225968c81ef7b9`, PKG-CONTRACT-016/017; S08 dependency `cb693ca0f7df8d6a809307de3b7cba9f24ae6b34`. Public Issue #17. Only Apache-2.0 SDK implementation/tests/docs change; no asset/spec/schema/expected-value/consumer/license mutation, V1 layout, compatibility or migration.

Executed behavior:

- Frozen `zip-wrapped` and `zip-unwrapped` produce the exact same entries and bytes. Actual Root recognition/history, committed object integrity, portable file presence/references, signature/identity/evidence/online and Working dimensions compare their frozen expected subsets. Full positive FULL/Complete verdict comparison remains NOT_RUN until the coupled producer verifier.
- Frozen `zip-traversal` and `zip-duplicate` fail with required PATH_TRAVERSAL/UNSAFE_ARCHIVE before exposing a tree or starting any output transaction. Frozen `case-conflict` and NFC conflict reject through shared Unicode preflight; Directory and ZIP writer paths agree. Unsafe tree/history/object inputs write no ZIP bytes.
- Five original tree fixtures (minimal, complete-history, dirty, moved and optional extension), plus frozen appended evidence and bad signature, pass STORE/DEFLATE/compression-level/wrapper variants, raw JSON/extension/dirty-byte and explicit empty-folder round trips. Every historical Version subject equals its original; actual signature/identity/evidence states and item inventories remain unchanged, including mathematically bad signatures and valid independent evidence. Artifact SHA-256/byte count independently match actual ZIP bytes and differ across tested presentations. A wrapper named `.PACKTELL` does not become logical control authority. An independent standard writer's reversed entry order, mtime/permission and unwrapped variants preserve the same tree.
- Actual Linux Directory -> written/persisted ZIP artifact -> native no-overwrite Directory publication preserves every path/kind/size/raw file byte and empty folder for all five cases under both STORE and DEFLATE. Archive bytes are supplied by a test Host observation; native random-access artifact Host integration is not claimed.
- Central/local name/method/flags/size/CRC mismatches, encryption/strong encryption/reserved flags, unsupported method, symlink/FIFO/reparse mode, disk fields/count/range/offset overlap, malformed UTF-8/absent non-ASCII UTF-8 flag, truncated end, limits/ratio, data descriptor CRC/size mismatches, traversal/absolute/drive/backslash, duplicate/file-parent/file-directory conflicts, multiple roots and extra siblings reject. An unsafe Unicode-name extra override is ignored while the safe raw name remains authoritative.
- Wrong actual CRC, corrupt DEFLATE, actual output exceeding declared size, trailing compressed junk and directory CRC failure reject. Directory extraction leaves no published destination even if a Working payload CRC fails after isolated staging begins. A committed object CRC failure propagates UNSAFE_ARCHIVE before output, rather than being downgraded to an ordinary missing object. Six explicit object open/read/close cases preserve UNSAFE_ARCHIVE/RESOURCE_LIMIT as errors with integrity NOT_CHECKED.
- A real SDK writer tree with 65,536 explicit empty payload folders triggers Zip64 end/locator/count encoding; the reader processes it and smaller count policy blocks it before collection expansion. Independently assembled small Zip64 size fields and 64-bit data descriptors preserve bytes and are also accepted by the independent Go standard reader. Zip64 disk/count/offset/size/record-length/missing-extra failures reject. Bounded variable-length Zip64 end data and unsigned ordinary descriptors are exercised. No physical >4 GiB payload is claimed.
- Host begin/read/stability/close faults and read cancellation expose no usable tree; observation cleanup is checked. Pending writer/source stability/source close/cancel/display/method/ratio failures return no artifact. Existing S08 no-overwrite/interruption/uncertain-cleanup and S04 expected-HEAD transaction suites remain passing.

Verification:

```sh
GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOPROXY=off GOSUMDB=off go vet ./...
<verified-local-Go-1.23.12> test -race -count=1 ./...
GOMAXPROCS=2 GOPROXY=off GOSUMDB=off go test -run '^$' -fuzz '^FuzzZIPWholeTreePreflight$' -fuzztime=20s -fuzzminimizetime=1s -parallel=2
python3 scripts/check-foundation.py --spec-dir <read-only-frozen-spec-checkout>
GOOS=windows GOARCH=amd64 go test -c -o <temporary-test-binary> .
GOOS=darwin GOARCH=arm64 go test -c -o <temporary-test-binary> .
git diff --check
```

First build, first behavior run and first race/vet run PASS; no frozen expectations were altered. Initial 15-second fuzz run PASS with only 184 recorded executions; adding small ordinary/Zip64 seeds and limiting minimization yields 256,306 executions in the subsequent 20-second run, PASS. Review added correct wrapper/control namespace separation, variable Zip64 end bounds, byte-exact compressed consumption, writer output ratio/owned-close/per-writer compression, and propagation of codec/resource errors from committed streams. Final verification includes those changes. Linux amd64 behavior is executed; other platform compilation is not runtime proof. Exact frozen machine assets: 51 PASS; production dependency graph: 125 packages, no external/network/database runtime imports. Exact public diff/remote head/merge/main read-back is recorded in Issue/PR following execution.

NOT_RUN: complete seven-level/positive FULL verifier and producer freeze, physical >4 GiB streams, native Windows/macOS/runtime filesystem/ZIP interaction, native artifact Host authorization/random-access/durability/recovery, staged artifact publication through the import/export planner, real Provider/official signer/services and consumer/product E2E. The standalone ZIP writer returns pending proposals and is not claimed as a production publishing integration. Subsequent gates remain required.
