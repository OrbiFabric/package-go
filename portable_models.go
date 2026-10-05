// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/orbifabric/package-go/internal/unicode16"
)

type NoteID UUID
type EventID UUID
type ProvenanceID UUID

// Metadata is mutable display state, independent of Version.SealedMetadata.
type Metadata struct {
	Schema      string
	PackageID   PackageID
	Title       string
	Description *string
	Extensions  map[string]any
	Extra       map[string]any
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	v := map[string]any{"schema": m.Schema, "package_id": m.PackageID, "title": m.Title}
	if m.Description != nil {
		v["description"] = *m.Description
	}
	if m.Extensions != nil {
		v["extensions"] = m.Extensions
	}
	return withExtras(v, m.Extra, "description", "extensions")
}

type MemoryTarget struct {
	Kind string `json:"kind"`
	ID   UUID   `json:"id"`
}
type NoteRevision struct {
	NoteID    NoteID       `json:"note_id"`
	Revision  int64        `json:"revision"`
	Target    MemoryTarget `json:"target"`
	UpdatedAt string       `json:"updated_at"`
	Deleted   bool         `json:"deleted"`
	Body      string       `json:"body"`
}
type Notes struct {
	Schema    string         `json:"schema"`
	PackageID PackageID      `json:"package_id"`
	Revisions []NoteRevision `json:"revisions"`
}
type TagRevision struct {
	Revision   int64  `json:"revision"`
	Tag        string `json:"tag"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
}
type Tags struct {
	Schema    string        `json:"schema"`
	PackageID PackageID     `json:"package_id"`
	Revisions []TagRevision `json:"revisions"`
}
type EventActor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Event struct {
	Schema        string         `json:"schema"`
	EventID       EventID        `json:"event_id"`
	PackageID     PackageID      `json:"package_id"`
	Type          string         `json:"type"`
	SchemaVersion int64          `json:"schema_version"`
	OccurredAt    string         `json:"occurred_at"`
	Actor         *EventActor    `json:"actor"`
	Subject       MemoryTarget   `json:"subject"`
	Data          map[string]any `json:"data"`
}
type ProvenanceTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type ProvenanceRelationship struct {
	Kind      string     `json:"kind"`
	PackageID PackageID  `json:"package_id"`
	VersionID *VersionID `json:"package_version_id"`
}
type ProvenanceRecord struct {
	ProvenanceID    ProvenanceID            `json:"provenance_id"`
	Target          ProvenanceTarget        `json:"target"`
	SourceKind      string                  `json:"source_kind"`
	SourceID        *string                 `json:"source_id,omitempty"`
	SourceRevision  *string                 `json:"source_revision,omitempty"`
	OriginalName    *string                 `json:"original_name,omitempty"`
	FirstObservedAt string                  `json:"first_observed_at"`
	Relationship    *ProvenanceRelationship `json:"relationship,omitempty"`
}
type Provenance struct {
	Schema    string             `json:"schema"`
	PackageID PackageID          `json:"package_id"`
	Records   []ProvenanceRecord `json:"records"`
}

func closedObject(v any, fields ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, schemaError("expected closed object")
	}
	if len(m) != len(fields) {
		return nil, schemaError("unknown or missing closed field")
	}
	for _, k := range fields {
		if _, ok = m[k]; !ok {
			return nil, schemaError("missing closed field")
		}
	}
	return m, nil
}
func requiredObject(v any, required []string, optional ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, schemaError("expected object")
	}
	for _, k := range required {
		if _, ok = m[k]; !ok {
			return nil, schemaError("missing required field")
		}
	}
	for k := range m {
		if !containsText(required, k) && !containsText(optional, k) {
			return nil, schemaError("unknown closed field")
		}
	}
	return m, nil
}
func containsText(a []string, s string) bool {
	for _, v := range a {
		if s == v {
			return true
		}
	}
	return false
}
func textField(m map[string]any, k string) (string, error) {
	s, ok := m[k].(string)
	if !ok {
		return "", schemaError("invalid text field")
	}
	return s, nil
}
func document(ctx context.Context, r io.Reader, l Limits, schema string, collection string) (map[string]any, []any, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return nil, nil, err
	}
	m, err := closedObject(v, "schema", "package_id", collection)
	if err != nil {
		return nil, nil, err
	}
	if m["schema"] != schema {
		return nil, nil, schemaError("invalid portable schema")
	}
	if err = UUID(asString(m["package_id"])).Validate(); err != nil {
		return nil, nil, err
	}
	a, ok := m[collection].([]any)
	if !ok {
		return nil, nil, schemaError("invalid portable collection")
	}
	return m, a, nil
}
func parseMemoryTarget(v any) (MemoryTarget, error) {
	m, err := closedObject(v, "kind", "id")
	if err != nil {
		return MemoryTarget{}, err
	}
	t := MemoryTarget{asString(m["kind"]), UUID(asString(m["id"]))}
	if !containsText([]string{"package", "file", "folder", "version", "event"}, t.Kind) {
		return t, schemaError("invalid portable target kind")
	}
	return t, t.ID.Validate()
}
func ReadMetadata(ctx context.Context, r io.Reader, l Limits) (Metadata, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return Metadata{}, err
	}
	m, ok := v.(map[string]any)
	if !ok || m["schema"] != "orbifabric.package.metadata.v1" {
		return Metadata{}, schemaError("invalid mutable metadata schema")
	}
	s, err := parseSealed(m)
	if err != nil {
		return Metadata{}, err
	}
	id := PackageID(asString(m["package_id"]))
	if err = UUID(id).Validate(); err != nil {
		return Metadata{}, err
	}
	return Metadata{"orbifabric.package.metadata.v1", id, s.Title, s.Description, s.Extensions, extras(m, "schema", "package_id", "title", "description", "extensions")}, nil
}
func ReadNotes(ctx context.Context, r io.Reader, l Limits) (Notes, error) {
	m, a, err := document(ctx, r, l, "orbifabric.package.notes.v1", "revisions")
	if err != nil {
		return Notes{}, err
	}
	out := Notes{"orbifabric.package.notes.v1", PackageID(asString(m["package_id"])), []NoteRevision{}}
	for _, v := range a {
		if err = ctx.Err(); err != nil {
			return Notes{}, err
		}
		m, err := closedObject(v, "note_id", "revision", "target", "updated_at", "deleted", "body")
		if err != nil {
			return Notes{}, err
		}
		n := NoteRevision{NoteID: NoteID(asString(m["note_id"])), UpdatedAt: asString(m["updated_at"])}
		if err = UUID(n.NoteID).Validate(); err != nil {
			return Notes{}, err
		}
		var ok bool
		n.Revision, ok = m["revision"].(int64)
		if !ok || n.Revision < 1 {
			return Notes{}, schemaError("invalid note revision")
		}
		n.Target, err = parseMemoryTarget(m["target"])
		if err != nil {
			return Notes{}, err
		}
		if _, err = ParseTimestamp(n.UpdatedAt); err != nil {
			return Notes{}, err
		}
		n.Deleted, ok = m["deleted"].(bool)
		if !ok {
			return Notes{}, schemaError("invalid note tombstone")
		}
		n.Body, err = textField(m, "body")
		if err != nil {
			return Notes{}, err
		}
		if n.Deleted && n.Body != "" {
			return Notes{}, protocolError(ReasonInvalidMetadata, "tombstone has nonempty body")
		}
		if len(out.Revisions) == 0 || out.Revisions[len(out.Revisions)-1].NoteID != n.NoteID {
			if n.Revision != 1 || len(out.Revisions) > 0 && out.Revisions[len(out.Revisions)-1].NoteID >= n.NoteID {
				return Notes{}, protocolError(ReasonInvalidMetadata, "note ordering or first revision")
			}
		} else {
			p := out.Revisions[len(out.Revisions)-1]
			if p.Revision == MaxProtocolInteger || n.Revision != p.Revision+1 || n.Target != p.Target {
				return Notes{}, protocolError(ReasonInvalidMetadata, "note gap or target drift")
			}
		}
		out.Revisions = append(out.Revisions, n)
	}
	return out, nil
}

// Current includes tombstones so identity/history are retained. Display callers
// may filter Deleted without treating a later restore as a new Note identity.
func (n Notes) Current() map[NoteID]NoteRevision {
	out := map[NoteID]NoteRevision{}
	for _, r := range n.Revisions {
		out[r.NoteID] = r
	}
	return out
}
func ReadTags(ctx context.Context, r io.Reader, l Limits) (Tags, error) {
	m, a, err := document(ctx, r, l, "orbifabric.package.tags.v1", "revisions")
	if err != nil {
		return Tags{}, err
	}
	out := Tags{"orbifabric.package.tags.v1", PackageID(asString(m["package_id"])), []TagRevision{}}
	active := map[string]bool{}
	for i, v := range a {
		if err = ctx.Err(); err != nil {
			return Tags{}, err
		}
		m, err := closedObject(v, "revision", "tag", "action", "occurred_at")
		if err != nil {
			return Tags{}, err
		}
		rev, ok := m["revision"].(int64)
		if !ok || rev < 1 {
			return Tags{}, schemaError("invalid tag revision")
		}
		tag, err := textField(m, "tag")
		if err != nil {
			return Tags{}, err
		}
		t := TagRevision{rev, tag, asString(m["action"]), asString(m["occurred_at"])}
		if t.Action != "add" && t.Action != "remove" {
			return Tags{}, schemaError("invalid tag action")
		}
		if _, err = ParseTimestamp(t.OccurredAt); err != nil {
			return Tags{}, err
		}
		// Protocol whitespace uses Unicode White_Space, stable for Unicode 16.
		if t.Tag == "" || strings.TrimFunc(t.Tag, unicode.IsSpace) != t.Tag || unicode16.NFC(t.Tag) != t.Tag || t.Revision != int64(i)+1 {
			return Tags{}, protocolError(ReasonInvalidMetadata, "invalid tag text or sequence")
		}
		if t.Action == "add" {
			if active[t.Tag] {
				return Tags{}, protocolError(ReasonInvalidMetadata, "duplicate tag add")
			}
			active[t.Tag] = true
		} else {
			if !active[t.Tag] {
				return Tags{}, protocolError(ReasonInvalidMetadata, "remove absent tag")
			}
			delete(active, t.Tag)
		}
		out.Revisions = append(out.Revisions, t)
	}
	return out, nil
}
func (t Tags) Current() []string {
	active := map[string]bool{}
	for _, r := range t.Revisions {
		if r.Action == "add" {
			active[r.Tag] = true
		} else {
			delete(active, r.Tag)
		}
	}
	out := []string{}
	for tag := range active {
		out = append(out, tag)
	}
	sortText(out)
	return out
}
func sortText(a []string) { slices.Sort(a) }

func ReadProvenance(ctx context.Context, r io.Reader, l Limits) (Provenance, error) {
	m, a, err := document(ctx, r, l, "orbifabric.package.provenance.v1", "records")
	if err != nil {
		return Provenance{}, err
	}
	out := Provenance{"orbifabric.package.provenance.v1", PackageID(asString(m["package_id"])), []ProvenanceRecord{}}
	for _, v := range a {
		if err = ctx.Err(); err != nil {
			return Provenance{}, err
		}
		m, err := requiredObject(v, []string{"provenance_id", "target", "source_kind", "first_observed_at"}, "source_id", "source_revision", "original_name", "relationship")
		if err != nil {
			return Provenance{}, err
		}
		p := ProvenanceRecord{ProvenanceID: ProvenanceID(asString(m["provenance_id"])), SourceKind: asString(m["source_kind"]), FirstObservedAt: asString(m["first_observed_at"])}
		if err = UUID(p.ProvenanceID).Validate(); err != nil {
			return Provenance{}, err
		}
		if len(out.Records) > 0 && out.Records[len(out.Records)-1].ProvenanceID >= p.ProvenanceID {
			return Provenance{}, protocolError(ReasonInvalidMetadata, "provenance order/duplicate")
		}
		if !containsText([]string{"local_import", "package_import", "google_drive", "onedrive", "dropbox", "external_api", "generated", "other"}, p.SourceKind) {
			return Provenance{}, schemaError("invalid provenance source kind")
		}
		if _, err = ParseTimestamp(p.FirstObservedAt); err != nil {
			return Provenance{}, err
		}
		target, err := closedObject(m["target"], "kind", "id")
		if err != nil {
			return Provenance{}, err
		}
		p.Target = ProvenanceTarget{asString(target["kind"]), asString(target["id"])}
		switch p.Target.Kind {
		case "package", "file":
			err = UUID(p.Target.ID).Validate()
		case "content":
			err = ContentID(p.Target.ID).Validate()
		default:
			err = schemaError("invalid provenance target")
		}
		if err != nil {
			return Provenance{}, err
		}
		p.SourceID, err = optionalText(m, "source_id")
		if err != nil {
			return Provenance{}, err
		}
		p.SourceRevision, err = optionalText(m, "source_revision")
		if err != nil {
			return Provenance{}, err
		}
		p.OriginalName, err = optionalText(m, "original_name")
		if err != nil {
			return Provenance{}, err
		}
		if p.OriginalName != nil {
			s := *p.OriginalName
			if utf8.RuneCountInString(s) < 1 || utf8.RuneCountInString(s) > 255 || strings.ContainsAny(s, "/\\") {
				return Provenance{}, schemaError("invalid provenance original name")
			}
			for _, r := range s {
				if r < 32 || r == 127 {
					return Provenance{}, schemaError("invalid provenance original name")
				}
			}
		}
		if rel, present := m["relationship"]; present {
			rm, err := closedObject(rel, "kind", "package_id", "package_version_id")
			if err != nil {
				return Provenance{}, err
			}
			rr := ProvenanceRelationship{Kind: asString(rm["kind"]), PackageID: PackageID(asString(rm["package_id"]))}
			if !containsText([]string{"derived_from", "copied_from", "supersedes", "reuses"}, rr.Kind) {
				return Provenance{}, schemaError("invalid relationship kind")
			}
			if err = UUID(rr.PackageID).Validate(); err != nil {
				return Provenance{}, err
			}
			id, err := nullableUUID(rm, "package_version_id")
			if err != nil {
				return Provenance{}, err
			}
			if id != nil {
				vid := VersionID(*id)
				rr.VersionID = &vid
			}
			p.Relationship = &rr
		}
		out.Records = append(out.Records, p)
	}
	return out, nil
}
