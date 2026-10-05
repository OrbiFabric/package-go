// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"strings"
)

// Coupled proof checks actual capability declarations before object reads.
// This is Core relationship legality, independent from signature mathematics.
// An unsupported optional evidence body is preserved without interpretation.
func validateAttestationDeclarations(ctx context.Context, source TreeReader, h History, l Limits, support CapabilitySupport) error {
	versions := map[VersionID]Version{}
	for _, record := range h.Versions {
		versions[record.Version.VersionID] = record.Version
	}
	nodes := map[string]TreeEntry{}
	for _, entry := range h.Root.Entries {
		nodes[entry.Path] = entry
	}
	for _, entry := range h.Root.Entries {
		if entry.Kind != "file" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.HasPrefix(entry.Path, ".packtell/verification/versions/") {
			if !declaredVersionSigning(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) {
				return schemaError("actual signatures require a Root capability declaration")
			}
			id := VersionID(strings.Split(entry.Path, "/")[3])
			version, exists := versions[id]
			if !exists || !declaredVersionSigning(version.RequiredCapabilities, version.OptionalCapabilities) {
				return schemaError("actual signature path requires its Version and capability declaration")
			}
		}
		if !strings.HasPrefix(entry.Path, ".packtell/evidence/") {
			continue
		}
		if !declaredEvidence(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) {
			return schemaError("actual evidence requires a Root capability declaration")
		}
		if !containsText(support.Capabilities, CapabilityDeliveryEvidence) {
			continue
		}
		b, err := readRootBytes(ctx, source, nodes, entry.Path, l.MaxJSONBytes)
		if err != nil {
			return err
		}
		value, err := ReadProtocolJSON(ctx, bytes.NewReader(b), l)
		if err != nil {
			return err
		}
		document, ok := value.(map[string]any)
		if !ok {
			continue
		} // Full envelope schema is checked by the evidence dimension.
		if strings.HasPrefix(entry.Path, ".packtell/evidence/objects/") {
			subject, ok := document["subject"].(map[string]any)
			if !ok {
				continue
			}
			document = subject
		}
		id, ok := document["package_version_id"].(string)
		if !ok {
			continue
		}
		if version, exists := versions[VersionID(id)]; exists && !declaredEvidence(version.RequiredCapabilities, version.OptionalCapabilities) {
			return schemaError("actual evidence requires its referenced Version capability declaration")
		}
	}
	return nil
}
