# package-go

> **OrbiFabric Package Protocol 2.0 官方 Go Reference Implementation / SDK**  
> English: [README.en.md](README.en.md)

Module path：`github.com/orbifabric/package-go`

规范仓库：[github.com/OrbiFabric/package-spec](https://github.com/OrbiFabric/package-spec)

## 定位

`package-go` 是 Package 2.0 的官方 Go 参考实现。**它不是规范权威本身。** Packtell 将成为它的第一个生产级消费者：Package detection、open、scan、diff、version/history、verify、import、export、Directory/ZIP codec 等能力都应通过本 SDK，而不是在 Packtell 内再维护第二套协议实现。

Authority：Package Specification → Schemas → Canonical/Crypto Rules → Conformance Vectors → Go Reference Implementation。

## 计划能力

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

第一阶段计划 API 方向：

- `Detect` / `Open` / `Inspect`
- `Scan` / `Diff`
- `ReadVersion` / `ReadHistory` / `MaterializeVersion`
- `Validate` / `VerifyVersion`
- `PlanExport` / `Export`
- `ReadImport` / `PlanImport`
- Directory / ZIP codec
- Shared conformance runner helpers

## Host Ports

SDK 必须保持 Provider-neutral。第三方存储、签名服务与产品数据库通过 Host ports 接入，例如：

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

Packtell 可以在 Host 层实现 Local / Google Drive / OneDrive / Dropbox resolver，以及 local-device / OrbiFabric-official signer。`package-go` 本身不得 import Wails、Packtell SQLite、Provider OAuth SDK 或 OrbiFabric Cloud client。

## 1.x Clean Break

Package 1.x 是未发布开发协议。`package-go` **不实现 1.x reader、writer、migration 或 legacy fallback**。成熟的 SHA-256、Merkle、Ed25519、canonical JSON、safe archive 与 signer/trust 思想可以迁移，但公开 API 从 2.0 开始。

## CLI / MCP / Web

后续 `orbipkg` CLI 与可选 MCP adapter 应直接复用 `package-go`。浏览器验证器应由独立 JavaScript 实现消费同一 `package-spec` schemas/vectors，而不是把 Go 行为当作标准。

## Status

**SDK foundation 已实现；API 暂未冻结。** 模块提供受限 JSON 输入、format/capability 识别、独立结果维度、显式可取消 Host ports 及内容流 hash/size 校验。规范锁定 `7ff166365dc83cee783e4e6715225968c81ef7b9`；机器资产原样嵌入供离线一致性开发使用。完整 tree/history/signing/codec 和七级 conformance 尚未实现或认证。参见 [foundation contract](docs/foundation.md)。

## License

本项目采用 **Apache License 2.0**。详情见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

后续 Go 源码可以使用简短 SPDX 标识：`SPDX-License-Identifier: Apache-2.0`。
