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

**Bootstrap / implementation pending.** The repository currently freezes responsibilities and dependency boundaries; concrete APIs will be implemented alongside frozen Package 2.0 normative fields and conformance fixtures.

## License

The license will be frozen with the open-source policy before the first stable implementation.
