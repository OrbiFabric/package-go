// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/orbifabric/package-go/internal/unicode16"
)

// Package contains immutable identity/creation facts, never a product DB dump.
type Package struct {
	Schema    string    `json:"schema"`
	PackageID PackageID `json:"package_id"`
	CreatedAt string    `json:"created_at"`
}

func (p Package) Validate() error {
	if p.Schema != "orbifabric.package.package.v2" {
		return protocolError(ReasonInvalidSchema, "invalid Package schema")
	}
	if err := UUID(p.PackageID).Validate(); err != nil {
		return err
	}
	_, err := ParseTimestamp(p.CreatedAt)
	return err
}
func NewPackage(ctx context.Context, g *IDGenerator, at time.Time) (Package, error) {
	s, err := Timestamp(at)
	if err != nil {
		return Package{}, err
	}
	id, err := g.Generate(ctx, at)
	if err != nil {
		return Package{}, err
	}
	return Package{"orbifabric.package.package.v2", PackageID(id), s}, nil
}
func ReadPackage(ctx context.Context, r io.Reader, l Limits) (Package, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return Package{}, err
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 3 {
		return Package{}, protocolError(ReasonInvalidSchema, "invalid closed Package document")
	}
	p := Package{Schema: asString(m["schema"]), PackageID: PackageID(asString(m["package_id"])), CreatedAt: asString(m["created_at"])}
	return p, p.Validate()
}

type SealedMetadata struct {
	Title       string
	Description *string
	Extensions  map[string]any
	Extra       map[string]any
}
type Version struct {
	Schema               string
	PackageID            PackageID
	VersionID            VersionID
	ParentVersionID      *VersionID
	Ordinal              int64
	CreatedAt            string
	Protocol             string
	ProtocolVersion      string
	TreeProfile          string
	Profiles             []string
	RequiredCapabilities []string
	OptionalCapabilities []string
	SealedMetadata       SealedMetadata
	Label                *string
	Extra                map[string]any
}

// Entry is the discriminated union of file and folder schema branches. Root is
// implicit: no Root ID/name/entry exists; nil parent identifies a Root child.
type Entry struct {
	Kind           string
	FileID         FileID
	FolderID       FolderID
	ParentFolderID *FolderID
	Name           string
	ContentID      ContentID
	Size           int64
	Extra          map[string]any
}

func (e Entry) ID() UUID {
	if e.Kind == "file" {
		return UUID(e.FileID)
	}
	return UUID(e.FolderID)
}

type Manifest struct {
	Schema    string
	PackageID PackageID
	VersionID VersionID
	Entries   []Entry
	Extra     map[string]any
}

func asString(v any) string { s, _ := v.(string); return s }
func extras(m map[string]any, known ...string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if !slices.Contains(known, k) {
			out[k] = v
		}
	}
	return out
}
func nullableUUID(m map[string]any, key string) (*UUID, error) {
	v, ok := m[key]
	if !ok {
		return nil, protocolError(ReasonInvalidSchema, "missing nullable ID")
	}
	if v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, protocolError(ReasonInvalidSchema, "invalid nullable ID")
	}
	id := UUID(s)
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return &id, nil
}
func schemaError(detail string) error { return protocolError(ReasonInvalidSchema, detail) }
func optionalText(m map[string]any, key string) (*string, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, schemaError("invalid optional text")
	}
	return &s, nil
}
func parseSealed(m map[string]any) (SealedMetadata, error) {
	s := SealedMetadata{}
	var ok bool
	s.Title, ok = m["title"].(string)
	if !ok {
		return s, schemaError("missing sealed title")
	}
	var err error
	s.Description, err = optionalText(m, "description")
	if err != nil {
		return s, err
	}
	if v, present := m["extensions"]; present {
		s.Extensions, ok = v.(map[string]any)
		if !ok {
			return s, schemaError("invalid metadata extensions")
		}
		for key := range s.Extensions {
			if !namespacePattern.MatchString(key) {
				return s, schemaError("invalid metadata extension namespace")
			}
		}
	}
	s.Extra = extras(m, "title", "description", "extensions")
	return s, nil
}
func parseVersion(m map[string]any, support CapabilitySupport) (Version, error) {
	v := Version{}
	for _, key := range []string{"schema", "package_id", "package_version_id", "parent_version_id", "ordinal", "created_at", "protocol", "protocol_version", "tree_profile", "profiles", "required_capabilities", "optional_capabilities", "sealed_metadata"} {
		if _, present := m[key]; !present {
			return v, schemaError("missing required Version field")
		}
	}
	if m["schema"] != "orbifabric.package.version.v2" {
		return v, schemaError("invalid Version schema")
	}
	v.Schema = "orbifabric.package.version.v2"
	v.PackageID = PackageID(asString(m["package_id"]))
	v.VersionID = VersionID(asString(m["package_version_id"]))
	for _, id := range []UUID{UUID(v.PackageID), UUID(v.VersionID)} {
		if err := id.Validate(); err != nil {
			return v, err
		}
	}
	parent, err := nullableUUID(m, "parent_version_id")
	if err != nil {
		return v, err
	}
	if parent != nil {
		id := VersionID(*parent)
		v.ParentVersionID = &id
	}
	n, ok := m["ordinal"].(int64)
	if !ok || n < 1 || n > MaxProtocolInteger {
		return v, schemaError("invalid ordinal")
	}
	v.Ordinal = n
	v.CreatedAt = asString(m["created_at"])
	if _, err := ParseTimestamp(v.CreatedAt); err != nil {
		return v, err
	}
	fm := map[string]any{"schema": "orbifabric.package.format.v2", "protocol": m["protocol"], "protocol_version": m["protocol_version"], "tree_profile": m["tree_profile"], "profiles": m["profiles"], "required_capabilities": m["required_capabilities"], "optional_capabilities": m["optional_capabilities"], "extensions": []any{}}
	if fm["protocol"] != Protocol || fm["protocol_version"] != ProtocolVersion || fm["tree_profile"] != TreeProfile {
		return v, protocolError(ReasonUnsupportedProtocol, "unsupported historical Version protocol")
	}
	f, err := parseFormat(fm)
	if err != nil {
		return v, err
	}
	for _, capability := range f.RequiredCapabilities {
		if !slices.Contains(support.Capabilities, capability) {
			return v, protocolError(ReasonUnknownRequiredCapability, "unsupported historical required capability")
		}
	}
	for _, profile := range f.Profiles {
		if !slices.Contains(support.Profiles, profile) {
			return v, protocolError(ReasonUnsupportedProtocol, "unsupported historical profile")
		}
	}
	v.Protocol = f.Protocol
	v.ProtocolVersion = f.ProtocolVersion
	v.TreeProfile = f.TreeProfile
	v.Profiles = f.Profiles
	v.RequiredCapabilities = f.RequiredCapabilities
	v.OptionalCapabilities = f.OptionalCapabilities
	sealed, ok := m["sealed_metadata"].(map[string]any)
	if !ok {
		return v, schemaError("invalid sealed metadata")
	}
	v.SealedMetadata, err = parseSealed(sealed)
	if err != nil {
		return v, err
	}
	v.Label, err = optionalText(m, "label")
	if err != nil {
		return v, err
	}
	v.Extra = extras(m, "schema", "package_id", "package_version_id", "parent_version_id", "ordinal", "created_at", "protocol", "protocol_version", "tree_profile", "profiles", "required_capabilities", "optional_capabilities", "sealed_metadata", "label")
	return v, nil
}
func ReadVersion(ctx context.Context, r io.Reader, l Limits, support CapabilitySupport) (Version, error) {
	value, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return Version{}, err
	}
	m, ok := value.(map[string]any)
	if !ok {
		return Version{}, schemaError("Version must be an object")
	}
	v, err := parseVersion(m, support)
	if err != nil {
		return Version{}, err
	}
	if err = ctx.Err(); err != nil {
		return Version{}, err
	}
	return v, nil
}

func (e Entry) Validate() error {
	if err := e.ID().Validate(); err != nil {
		return err
	}
	if e.ParentFolderID != nil {
		if err := UUID(*e.ParentFolderID).Validate(); err != nil {
			return err
		}
	}
	if e.Name == "" || !utf8.ValidString(e.Name) || utf8.RuneCountInString(e.Name) > 255 || strings.ContainsAny(e.Name, "/\\") {
		return schemaError("invalid entry component schema")
	}
	if unicode16.NFC(e.Name) != e.Name {
		return protocolError(ReasonInvalidPath, "authority name is not Unicode 16 NFC")
	}
	for _, r := range e.Name {
		if r < 32 || r == 127 {
			return schemaError("invalid entry component schema")
		}
	}
	switch e.Kind {
	case "file":
		if e.FolderID != "" || e.Size < 0 || e.Size > MaxProtocolInteger {
			return schemaError("invalid file entry")
		}
		if err := e.ContentID.Validate(); err != nil {
			return err
		}
	case "folder":
		if e.FileID != "" || e.ContentID != "" || e.Size != 0 {
			return schemaError("invalid folder entry")
		}
	default:
		return schemaError("unknown entry kind")
	}
	return ValidateComponent(e.Name)
}
func parseEntry(m map[string]any) (Entry, error) {
	e := Entry{Kind: asString(m["kind"]), Name: asString(m["name"])}
	parent, err := nullableUUID(m, "parent_folder_id")
	if err != nil {
		return e, err
	}
	if parent != nil {
		id := FolderID(*parent)
		e.ParentFolderID = &id
	}
	switch e.Kind {
	case "file":
		if _, ok := m["folder_id"]; ok {
			return e, schemaError("file has folder identity")
		}
		e.FileID = FileID(asString(m["file_id"]))
		e.ContentID = ContentID(asString(m["content_id"]))
		var ok bool
		e.Size, ok = m["size"].(int64)
		if !ok {
			return e, schemaError("missing or invalid file size")
		}
		e.Extra = extras(m, "kind", "file_id", "parent_folder_id", "name", "content_id", "size")
	case "folder":
		for _, key := range []string{"file_id", "content_id", "size"} {
			if _, ok := m[key]; ok {
				return e, schemaError("folder carries file fields")
			}
		}
		e.FolderID = FolderID(asString(m["folder_id"]))
		e.Extra = extras(m, "kind", "folder_id", "parent_folder_id", "name")
	default:
		return e, schemaError("unknown entry kind")
	}
	return e, e.Validate()
}
func ReadManifest(ctx context.Context, r io.Reader, l Limits) (Manifest, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return Manifest{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Manifest{}, schemaError("manifest must be an object")
	}
	out := Manifest{Schema: asString(m["schema"]), PackageID: PackageID(asString(m["package_id"])), VersionID: VersionID(asString(m["package_version_id"])), Entries: []Entry{}}
	a, ok := m["entries"].([]any)
	if !ok {
		return out, schemaError("manifest missing entries")
	}
	for _, v := range a {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		item, ok := v.(map[string]any)
		if !ok {
			return out, schemaError("invalid manifest entry")
		}
		e, err := parseEntry(item)
		if err != nil {
			return out, err
		}
		out.Entries = append(out.Entries, e)
	}
	out.Extra = extras(m, "schema", "package_id", "package_version_id", "entries")
	return out, out.Validate(ctx, l)
}

// Validate enforces schema, logical parent topology and exact sibling names.
// Unicode-16 materialization safety/collision preflight is a separate tree stage.
func (m Manifest) Validate(ctx context.Context, l Limits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.Schema != "orbifabric.package.manifest.v2" || m.Entries == nil {
		return schemaError("invalid manifest schema")
	}
	for _, id := range []UUID{UUID(m.PackageID), UUID(m.VersionID)} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if len(m.Entries) > l.MaxEntries {
		return protocolError(ReasonResourceLimit, "manifest entry limit")
	}
	byID := map[UUID]Entry{}
	siblings := map[string]bool{}
	foldedSiblings := map[string]string{}
	sizes := map[ContentID]int64{}
	prior := UUID("")
	for _, e := range m.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.Validate(); err != nil {
			return err
		}
		if e.ID() <= prior {
			return schemaError("entry IDs must be unique and sorted")
		}
		prior = e.ID()
		byID[e.ID()] = e
		parent := ""
		if e.ParentFolderID != nil {
			parent = string(*e.ParentFolderID)
		}
		key := parent + "/" + e.Name
		if siblings[key] {
			return schemaError("duplicate sibling name")
		}
		siblings[key] = true
		if e.ParentFolderID == nil && PathCollisionKey(e.Name) == ".packtell" {
			return protocolError(ReasonInvalidPath, "manifest contains reserved Root control namespace")
		}
		foldedKey := parent + "/" + PathCollisionKey(e.Name)
		if name, ok := foldedSiblings[foldedKey]; ok && name != e.Name {
			return protocolError(ReasonCaseConflict, "manifest sibling full-fold collision")
		}
		foldedSiblings[foldedKey] = e.Name
		if e.Kind == "file" {
			if size, ok := sizes[e.ContentID]; ok && size != e.Size {
				return schemaError("same ContentID has unequal sizes")
			}
			sizes[e.ContentID] = e.Size
		}
	}
	for _, e := range m.Entries {
		if e.ParentFolderID != nil {
			p, ok := byID[UUID(*e.ParentFolderID)]
			if !ok || p.Kind != "folder" {
				return schemaError("entry has missing or non-folder parent")
			}
		}
	}
	// Iterative color walk avoids stack growth for adversarially deep trees.
	color := map[UUID]uint8{}
	for _, e := range m.Entries {
		id := e.ID()
		chain := []UUID{}
		for id != "" && color[id] != 2 {
			if err := ctx.Err(); err != nil {
				return err
			}
			if color[id] == 1 {
				return schemaError("logical folder cycle")
			}
			color[id] = 1
			chain = append(chain, id)
			p := byID[id].ParentFolderID
			id = ""
			if p != nil {
				id = UUID(*p)
			}
		}
		for _, id := range chain {
			color[id] = 2
		}
	}
	return nil
}

// MarshalJSON preserves optional fields and forbids extras shadowing known
// authority. It serializes JSON only; it does not claim canonical byte output.
func withExtras(known map[string]any, extra map[string]any, reserved ...string) ([]byte, error) {
	for k, v := range extra {
		if _, present := known[k]; present || slices.Contains(reserved, k) {
			return nil, schemaError("optional field shadows authority")
		}
		known[k] = v
	}
	return json.Marshal(known)
}
func (s SealedMetadata) MarshalJSON() ([]byte, error) {
	m := map[string]any{"title": s.Title}
	if s.Description != nil {
		m["description"] = *s.Description
	}
	if s.Extensions != nil {
		m["extensions"] = s.Extensions
	}
	return withExtras(m, s.Extra, "title", "description", "extensions")
}
func (v Version) MarshalJSON() ([]byte, error) {
	m := map[string]any{"schema": v.Schema, "package_id": v.PackageID, "package_version_id": v.VersionID, "parent_version_id": v.ParentVersionID, "ordinal": v.Ordinal, "created_at": v.CreatedAt, "protocol": v.Protocol, "protocol_version": v.ProtocolVersion, "tree_profile": v.TreeProfile, "profiles": v.Profiles, "required_capabilities": v.RequiredCapabilities, "optional_capabilities": v.OptionalCapabilities, "sealed_metadata": v.SealedMetadata}
	if v.Label != nil {
		m["label"] = *v.Label
	}
	return withExtras(m, v.Extra, "label")
}
func (e Entry) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	m := map[string]any{"kind": e.Kind, "parent_folder_id": e.ParentFolderID, "name": e.Name}
	if e.Kind == "file" {
		m["file_id"] = e.FileID
		m["content_id"] = e.ContentID
		m["size"] = e.Size
	} else {
		m["folder_id"] = e.FolderID
	}
	return withExtras(m, e.Extra, "file_id", "folder_id", "content_id", "size")
}
func (m Manifest) MarshalJSON() ([]byte, error) {
	return withExtras(map[string]any{"schema": m.Schema, "package_id": m.PackageID, "package_version_id": m.VersionID, "entries": m.Entries}, m.Extra)
}

// Validate checks caller-constructed Version data against the same parser and
// semantic capability contracts as a portable document. It does not commit or
// validate relationships to other Versions; those belong to history validation.
func (v Version) Validate(ctx context.Context, l Limits, support CapabilitySupport) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = ReadVersion(ctx, strings.NewReader(string(b)), l, support)
	return err
}
