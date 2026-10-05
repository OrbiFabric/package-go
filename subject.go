// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
)

const VersionSubjectDomain = "orbifabric.package.version-subject.v2"
const ContentSetDomain = "orbifabric.package.content-set.v1"

type VersionSubject struct {
	Schema               string     `json:"schema"`
	Domain               string     `json:"domain"`
	PackageID            PackageID  `json:"package_id"`
	VersionID            VersionID  `json:"package_version_id"`
	ParentVersionID      *VersionID `json:"parent_version_id"`
	Ordinal              int64      `json:"ordinal"`
	CreatedAt            string     `json:"created_at"`
	Protocol             string     `json:"protocol"`
	ProtocolVersion      string     `json:"protocol_version"`
	TreeProfile          string     `json:"tree_profile"`
	Profiles             []string   `json:"profiles"`
	RequiredCapabilities []string   `json:"required_capabilities"`
	OptionalCapabilities []string   `json:"optional_capabilities"`
	PackageDigest        ContentID  `json:"package_digest"`
	VersionDigest        ContentID  `json:"version_digest"`
	ManifestDigest       ContentID  `json:"manifest_digest"`
	ContentCommitment    ContentID  `json:"content_commitment"`
	SealedMetadataDigest ContentID  `json:"sealed_metadata_digest"`
}

func domainDigest(domain string, canonical []byte) ContentID {
	return ContentIDForBytes(append(append([]byte(domain), '\n'), canonical...))
}

// ContentCommitment covers distinct whole-byte ContentIDs/sizes, never paths,
// ordinal/Merkle rules or representation bytes. It does not verify object bytes.
func ContentCommitment(ctx context.Context, m Manifest, l Limits) (ContentID, error) {
	if err := validateManifestSubjectFacts(ctx, m, l); err != nil {
		return "", err
	}
	sizes := map[ContentID]int64{}
	for _, e := range m.Entries {
		if e.Kind == "file" {
			sizes[e.ContentID] = e.Size
		}
	}
	if int64(len(sizes)) > l.MaxJSONBytes/71 {
		return "", protocolError(ReasonResourceLimit, "content commitment byte policy")
	}
	ids := make([]ContentID, 0, len(sizes))
	for id := range sizes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	set := make([]any, 0, len(ids))
	for _, id := range ids {
		set = append(set, map[string]any{"content_id": string(id), "size": sizes[id]})
	}
	b, err := CanonicalJSON(ctx, set, l)
	if err != nil {
		return "", err
	}
	return domainDigest(ContentSetDomain, b), nil
}

// DeriveVersionSubject validates/owns the exact input models and derives every
// field, including digests of full optional immutable facts. Callers cannot
// supply claimed digest fields or substitute mutable metadata/online/container
// data. This pure derivation certifies neither object coverage nor a signature.
func DeriveVersionSubject(ctx context.Context, p Package, v Version, m Manifest, l Limits, support CapabilitySupport) (VersionSubject, ContentID, error) {
	if err := l.Validate(); err != nil {
		return VersionSubject{}, "", err
	}
	if err := p.Validate(); err != nil {
		return VersionSubject{}, "", err
	}
	pb, err := json.Marshal(p)
	if err != nil {
		return VersionSubject{}, "", err
	}
	sourceLimits := l
	sourceLimits.MaxTotalJSONBytes -= int64(len(pb))
	if sourceLimits.MaxTotalJSONBytes <= 0 {
		return VersionSubject{}, "", protocolError(ReasonResourceLimit, "aggregate immutable JSON byte policy")
	}
	if err := validateSubjectFacts(ctx, v, m, sourceLimits); err != nil {
		return VersionSubject{}, "", err
	}
	if err := v.Validate(ctx, l, support); err != nil {
		return VersionSubject{}, "", err
	}
	if err := m.Validate(ctx, l); err != nil {
		return VersionSubject{}, "", err
	}
	if (v.ParentVersionID == nil && v.Ordinal != 1) || (v.ParentVersionID != nil && (v.Ordinal <= 1 || *v.ParentVersionID == v.VersionID)) {
		return VersionSubject{}, "", protocolError(ReasonNonLinearHistory, "invalid subject root/parent ordinal relationship")
	}
	if p.PackageID != v.PackageID || p.PackageID != m.PackageID || v.VersionID != m.VersionID {
		return VersionSubject{}, "", schemaError("subject document identities disagree")
	}
	// Serializer output is strictly parsed; canonical output never delegates its
	// ordering/string escaping to encoding/json or trusts a model's MarshalJSON.
	pc, err := ReadCanonicalJSON(ctx, bytes.NewReader(pb), l)
	if err != nil {
		return VersionSubject{}, "", err
	}
	vb, err := json.Marshal(v)
	if err != nil {
		return VersionSubject{}, "", err
	}
	version, err := ReadVersion(ctx, bytes.NewReader(vb), l, support)
	if err != nil {
		return VersionSubject{}, "", err
	}
	vc, err := ReadCanonicalJSON(ctx, bytes.NewReader(vb), l)
	if err != nil {
		return VersionSubject{}, "", err
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return VersionSubject{}, "", err
	}
	mc, err := ReadCanonicalJSON(ctx, bytes.NewReader(mb), l)
	if err != nil {
		return VersionSubject{}, "", err
	}
	sb, err := json.Marshal(version.SealedMetadata)
	if err != nil {
		return VersionSubject{}, "", err
	}
	sc, err := ReadCanonicalJSON(ctx, bytes.NewReader(sb), l)
	if err != nil {
		return VersionSubject{}, "", err
	}
	commitment, err := ContentCommitment(ctx, m, l)
	if err != nil {
		return VersionSubject{}, "", err
	}
	subject := VersionSubject{VersionSubjectDomain, VersionSubjectDomain, p.PackageID, version.VersionID, version.ParentVersionID, version.Ordinal, version.CreatedAt, version.Protocol, version.ProtocolVersion, version.TreeProfile, version.Profiles, version.RequiredCapabilities, version.OptionalCapabilities, ContentIDForBytes(pc), ContentIDForBytes(vc), ContentIDForBytes(mc), commitment, ContentIDForBytes(sc)}
	b, err := subject.Canonical(ctx, l)
	if err != nil {
		return VersionSubject{}, "", err
	}
	return subject, domainDigest(VersionSubjectDomain, b), nil
}
func (s VersionSubject) Canonical(ctx context.Context, l Limits) ([]byte, error) {
	// This serializer method does not turn caller-claimed digests into authority.
	// Verification always derives a fresh subject from Package/Version/manifest.
	if s.Profiles == nil || s.RequiredCapabilities == nil || s.OptionalCapabilities == nil {
		return nil, schemaError("subject capability arrays must not be null")
	}
	if s.Schema != VersionSubjectDomain || s.Domain != VersionSubjectDomain {
		return nil, schemaError("invalid subject constants")
	}
	if err := validateSubjectCapabilities(s.Profiles, s.RequiredCapabilities, s.OptionalCapabilities, l); err != nil {
		return nil, err
	}
	for _, id := range []UUID{UUID(s.PackageID), UUID(s.VersionID)} {
		if err := id.Validate(); err != nil {
			return nil, err
		}
	}
	if s.ParentVersionID != nil {
		if err := UUID(*s.ParentVersionID).Validate(); err != nil {
			return nil, err
		}
	}
	if s.Ordinal < 1 || s.Ordinal > MaxProtocolInteger {
		return nil, schemaError("invalid subject ordinal")
	}
	if _, err := ParseTimestamp(s.CreatedAt); err != nil {
		return nil, err
	}
	if s.Protocol != "orbifabric.package" || s.ProtocolVersion != "2.0" || s.TreeProfile != "orbifabric.package-tree.v1" {
		return nil, schemaError("invalid subject protocol")
	}
	for _, digest := range []ContentID{s.PackageDigest, s.VersionDigest, s.ManifestDigest, s.ContentCommitment, s.SealedMetadataDigest} {
		if err := digest.Validate(); err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return ReadCanonicalJSON(ctx, bytes.NewReader(b), l)
}
func validateSubjectCapabilities(profiles, required, optional []string, l Limits) error {
	convert := func(a []string) ([]any, error) {
		if len(a) > l.MaxEntries {
			return nil, protocolError(ReasonResourceLimit, "subject capability count")
		}
		v := make([]any, 0, len(a))
		for _, s := range a {
			v = append(v, s)
		}
		return v, nil
	}
	p, err := convert(profiles)
	if err != nil {
		return err
	}
	r, err := convert(required)
	if err != nil {
		return err
	}
	o, err := convert(optional)
	if err != nil {
		return err
	}
	_, err = parseFormat(map[string]any{"schema": "orbifabric.package.format.v2", "protocol": Protocol, "protocol_version": ProtocolVersion, "tree_profile": TreeProfile, "profiles": p, "required_capabilities": r, "optional_capabilities": o, "extensions": []any{}})
	return err
}
func guardedExtras(known, extra map[string]any, l Limits, reserved ...string) (map[string]any, error) {
	if len(known) > l.MaxEntries-len(extra) {
		return nil, protocolError(ReasonResourceLimit, "immutable model field count")
	}
	for k, v := range extra {
		if _, ok := known[k]; ok || containsText(reserved, k) {
			return nil, schemaError("optional immutable field shadows authority")
		}
		known[k] = v
	}
	return known, nil
}
func validateSubjectFacts(ctx context.Context, v Version, m Manifest, l Limits) error {
	if err := m.Validate(ctx, l); err != nil {
		return err
	}
	convert := func(a []string) ([]any, error) {
		if len(a) > l.MaxEntries {
			return nil, protocolError(ReasonResourceLimit, "immutable capability count")
		}
		out := make([]any, 0, len(a))
		for _, s := range a {
			out = append(out, s)
		}
		return out, nil
	}
	profiles, err := convert(v.Profiles)
	if err != nil {
		return err
	}
	required, err := convert(v.RequiredCapabilities)
	if err != nil {
		return err
	}
	optional, err := convert(v.OptionalCapabilities)
	if err != nil {
		return err
	}
	sealed := map[string]any{"title": v.SealedMetadata.Title}
	if v.SealedMetadata.Description != nil {
		sealed["description"] = *v.SealedMetadata.Description
	}
	if v.SealedMetadata.Extensions != nil {
		sealed["extensions"] = v.SealedMetadata.Extensions
	}
	sealed, err = guardedExtras(sealed, v.SealedMetadata.Extra, l, "title", "description", "extensions")
	if err != nil {
		return err
	}
	var parent any
	if v.ParentVersionID != nil {
		parent = string(*v.ParentVersionID)
	}
	version := map[string]any{"schema": v.Schema, "package_id": string(v.PackageID), "package_version_id": string(v.VersionID), "parent_version_id": parent, "ordinal": v.Ordinal, "created_at": v.CreatedAt, "protocol": v.Protocol, "protocol_version": v.ProtocolVersion, "tree_profile": v.TreeProfile, "profiles": profiles, "required_capabilities": required, "optional_capabilities": optional, "sealed_metadata": sealed}
	if v.Label != nil {
		version["label"] = *v.Label
	}
	version, err = guardedExtras(version, v.Extra, l, "label")
	if err != nil {
		return err
	}
	versionBudget := min(l.MaxJSONBytes, l.MaxTotalJSONBytes)
	startBudget := versionBudget
	if err = walkOptional(ctx, version, l, 0, &versionBudget); err != nil {
		return err
	}
	manifestLimits := l
	manifestLimits.MaxTotalJSONBytes -= startBudget - versionBudget
	return validateManifestSubjectFacts(ctx, m, manifestLimits)
}
func validateManifestSubjectFacts(ctx context.Context, m Manifest, l Limits) error {
	if err := m.Validate(ctx, l); err != nil {
		return err
	}
	manifest, err := guardedExtras(map[string]any{"schema": m.Schema, "package_id": string(m.PackageID), "package_version_id": string(m.VersionID), "entries": []any{}}, m.Extra, l)
	if err != nil {
		return err
	}
	budget := min(l.MaxJSONBytes, l.MaxTotalJSONBytes)
	if err = walkOptional(ctx, manifest, l, 0, &budget); err != nil {
		return err
	}
	for i, e := range m.Entries {
		if i > 0 {
			if err = consumeJSON(1, &budget); err != nil {
				return err
			}
		}
		var parent any
		if e.ParentFolderID != nil {
			parent = string(*e.ParentFolderID)
		}
		entry := map[string]any{"kind": e.Kind, "parent_folder_id": parent, "name": e.Name}
		if e.Kind == "file" {
			entry["file_id"] = string(e.FileID)
			entry["content_id"] = string(e.ContentID)
			entry["size"] = e.Size
		} else {
			entry["folder_id"] = string(e.FolderID)
		}
		entry, err = guardedExtras(entry, e.Extra, l, "file_id", "folder_id", "content_id", "size")
		if err != nil {
			return err
		}
		if err = walkOptional(ctx, entry, l, 2, &budget); err != nil {
			return err
		}
	}
	return nil
}

// DeriveSubjectAt reads only the selected actual committed Version from a
// validated actual history. Subsequent memory/containers/evidence are excluded.
func DeriveSubjectAt(ctx context.Context, source TreeReader, id VersionID, l Limits, support CapabilitySupport) (VersionSubject, ContentID, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return VersionSubject{}, "", err
	}
	for _, record := range h.Versions {
		if record.Version.VersionID == id {
			return DeriveVersionSubject(ctx, h.Root.Package, record.Version, record.Manifest, l, support)
		}
	}
	return VersionSubject{}, "", schemaError("subject Version absent from history")
}
