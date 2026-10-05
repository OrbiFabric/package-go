# package-go

> **Official Go Reference Implementation / SDK for OrbiFabric Package Protocol 2.0**  
> 中文: [README.md](README.md)

Module path: `github.com/orbifabric/package-go`

Specification: [github.com/OrbiFabric/package-spec](https://github.com/OrbiFabric/package-spec)

## Role

`package-go` is the official Go reference implementation of Package 2.0. **It is not the normative authority.** Packtell is intended to be its first production consumer: Package detection, open, scan, diff, version/history, verification, import, export, and Directory/ZIP codec behavior should flow through this SDK rather than a second Packtell-specific protocol implementation.

Authority: Package Specification → Schemas → Canonical/Crypto Rules → Conformance Vectors → Go Reference Implementation.

## Planned capabilities

```text
package-go
├── protocol/model
├── tree
├── version/history
├── content/object
├── metadata/provenance
├── verify/signing ports
├── diff
├── import/export planning
├── codec/directory
├── codec/zip
└── conformance support
```

Initial API direction:

- `Detect` / `Open` / `Inspect`
- `Scan` / `Diff`
- `ReadVersion` / `ReadHistory` / `MaterializeVersion`
- `Validate` / `VerifyVersion`
- `PlanExport` / `Export`
- `ReadImport` / `PlanImport`
- Directory / ZIP codec
- shared conformance-runner helpers

## Host ports

The SDK must remain provider-neutral. Third-party storage, signing services, and product databases connect through Host ports, for example:

```go
// conceptual only; exact API will be frozen during implementation.
type ContentResolver interface {
    Resolve(ctx context.Context, contentID ContentID) (ReadableContent, error)
}

type Signer interface {
    Profile(ctx context.Context) (SigningProfile, error)
    Sign(ctx context.Context, subject SignedSubject) (SignatureEnvelope, error)
}
```

Packtell may implement Local / Google Drive / OneDrive / Dropbox resolvers and local-device / OrbiFabric-official signers at the Host layer. `package-go` itself must not import Wails, Packtell SQLite, Provider OAuth SDKs, or the OrbiFabric Cloud client.

## 1.x clean break

Package 1.x is an unreleased development protocol. `package-go` **does not implement a 1.x reader, writer, migration path, or legacy fallback**. Mature SHA-256, Merkle, Ed25519, canonical JSON, safe-archive, and signer/trust design can be migrated, but the public API begins at 2.0.

## CLI / MCP / Web

A future `orbipkg` CLI and optional MCP adapter should reuse `package-go` directly. The browser verifier should be an independent JavaScript implementation that consumes the same `package-spec` schemas/vectors rather than treating Go behavior as the standard.

## Status

**Foundation, core model, tree inspection, linear Version lifecycle, portable memory, signatures/evidence and Directory/ZIP codecs implemented; APIs provisional.** The module provides strict bounded JSON parsing, format/capability recognition, independent result dimensions, explicit cancellable Host ports, and content stream hash/size verification. Protocol authority is pinned to `7ff166365dc83cee783e4e6715225968c81ef7b9`; verbatim machine assets are embedded for offline conformance development. Offline coupled verification is implemented; the seven-level conformance and producer-freeze gate remains incomplete. Core IDs and Package/Version/manifest models, explicit empty folders, identity-preserving working proposals and exact Unicode 16 NFC are implemented. See [foundation contract](docs/foundation.md), [core model](docs/model.md), and [tree/Working Tree contract](docs/tree.md). Root safety, exact HEAD, snapshot scanning, identity-aware diff, unsigned isolated commits and all-history object verification/reconstruction are implemented. See [history/commit contract](docs/history.md). The single-observation offline verifier reports independent dimensions and couples actual Complete proof; see [verification](docs/verification.md) and [S11 verifier progress](docs/s11-progress.md). Portable metadata, notes/tags projections, bounded event NDJSON, provenance relationships, optional fact/extension preservation and Host fact-selection plans are implemented; see [portable memory](docs/portable-memory.md). Independent canonical JSON, VersionSubject derivation, strict signature verification and selected Signer/trust reports are implemented; see [canonical/signature contract](docs/signatures.md). Delivery references/digests, four independent evidence subjects, offline verification, purpose-bound issuer trust and explicit transient status queries are implemented; see [delivery/evidence](docs/delivery-evidence.md).

Directory tree copying, pending validation/raw-byte read-back and Host no-overwrite publication are implemented. Native Linux uses descriptor-anchored no-follow reading, private external staging, durability checks and atomic no-replacement rename; unsupported platforms explicitly require another Host implementation. See [Directory contract and recovery](docs/directory.md) and [S08 evidence](docs/s08-evidence.md). Wrapped ZIP writing and wrapped/unwrapped ZIP reading share the same tree, with bounded central/local preflight, STORE/DEFLATE/Zip64, CRC/size checks and staged Directory extraction; see [ZIP contract](docs/zip.md) and [S09 evidence](docs/s09-evidence.md). Sealed import/export plans, explicit all-history verified hydration and staged Directory/ZIP artifact transactions are implemented; see [transfer contract](docs/transfer.md) and [S10 evidence](docs/s10-evidence.md).

## License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Future Go source files may use the concise SPDX identifier: `SPDX-License-Identifier: Apache-2.0`.
