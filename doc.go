// SPDX-License-Identifier: Apache-2.0

// Package packagego implements Package Protocol 2.0 against the frozen public
// specification. Protocol data is independent of product databases, containers,
// Provider credentials and network state. All I/O is supplied explicitly by a
// caller; Host ports must honor context cancellation. APIs are provisional until
// the producer conformance gate and consumer integration have completed.
package packagego

const (
	SpecCommit                 = "181f9c2048b7cad346044a6fa4a15096166e83d4"
	Protocol                   = "orbifabric.package"
	ProtocolVersion            = "2.0"
	TreeProfile                = "orbifabric.package-tree.v1"
	CapabilityLinearHistory    = "orbifabric.package.capability.linear-history.v1"
	CapabilityContentSHA256    = "orbifabric.package.capability.content-sha256.v1"
	CapabilityPortableMemory   = "orbifabric.package.capability.portable-memory.v1"
	CapabilityVersionSignature = "orbifabric.package.capability.version-signature.v1"
	CapabilityDeliveryEvidence = "orbifabric.package.capability.delivery-evidence.v1"
	ProfileComplete            = "orbifabric.package.profile.complete.v1"
)
