// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
)

// PortableFactPolicy is an explicit Host selection contract. Approval must
// enforce privacy-safe portable facts with a domain allowlist, not a DB dump or
// URL/secret blacklist. Schema validation is not redaction. The SDK passes an
// owned copy of exact proposed bytes; approval cannot mutate the output plan.
// Nil policy rejects a write. This port does not fetch or authorize Providers.
type PortableFactPolicy interface {
	ApprovePortableFacts(ctx context.Context, documents map[string][]byte) error
}

type PortableMemoryPlan struct {
	Documents map[string][]byte
	// Existing extension bytes must also be preserved by the representation
	// writer. This inventory is a requirement, not permission for lossy output.
	Extensions []TreeEntry
}
type MemoryWriteIntent struct { // Explicit user removal intent for open optional JSON facts.
	AllowOptionalFactRemoval bool
}

// PlanPortableMemoryUpdate validates actual source history/memory, monotonic
// revisions and preserved optional facts before producing reviewable bytes.
// The caller holds one stable Host view and publishes all documents atomically;
// this method does not write files, alter HEAD or create a Version. Future codec
// operations must preserve all extension inventory in the same isolated output.
func PlanPortableMemoryUpdate(ctx context.Context, source TreeReader, proposal PortableMemory, l Limits, support CapabilitySupport, policy PortableFactPolicy, intent MemoryWriteIntent) (PortableMemoryPlan, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return PortableMemoryPlan{}, err
	}
	current, err := readPortableMemory(ctx, source, h, l)
	if err != nil {
		return PortableMemoryPlan{}, err
	}
	documents, err := encodeMemory(ctx, proposal, l)
	if err != nil {
		return PortableMemoryPlan{}, err
	}
	// Parse SDK output through the same closed/relational readers to own values
	// and check every caller-created schema field before requesting Host approval.
	normalized, err := memoryFromDocuments(ctx, documents, l)
	if err != nil {
		return PortableMemoryPlan{}, err
	}
	if err = validateMemoryReferences(ctx, normalized, h, l); err != nil {
		return PortableMemoryPlan{}, err
	}
	if err = validateMemoryAppend(current, normalized, intent); err != nil {
		return PortableMemoryPlan{}, err
	}
	prospective := []TreeEntry{}
	extensions := []TreeEntry{}
	for _, e := range h.Root.Entries {
		if !containsText(portablePaths, e.Path) {
			prospective = append(prospective, e)
		}
		if strings.HasPrefix(e.Path, ".packtell/extensions/") {
			extensions = append(extensions, e)
		}
	}
	for p, b := range documents {
		prospective = append(prospective, TreeEntry{p, "file", int64(len(b))})
	}
	if _, err = PreflightTree(ctx, prospective, l); err != nil {
		return PortableMemoryPlan{}, err
	}
	if err = validateControlJSONBudget(prospective, l); err != nil {
		return PortableMemoryPlan{}, err
	}
	if policy == nil {
		return PortableMemoryPlan{}, protocolError(ReasonInvalidMetadata, "portable fact selection requires Host policy")
	}
	approval := map[string][]byte{}
	for p, b := range documents {
		approval[p] = bytes.Clone(b)
	}
	if err = policy.ApprovePortableFacts(ctx, approval); err != nil {
		return PortableMemoryPlan{}, err
	}
	if err = ctx.Err(); err != nil {
		return PortableMemoryPlan{}, err
	}
	return PortableMemoryPlan{documents, extensions}, nil
}
func memoryFromDocuments(ctx context.Context, d map[string][]byte, l Limits) (PortableMemory, error) {
	m := PortableMemory{}
	var err error
	m.Metadata, err = ReadMetadata(ctx, bytes.NewReader(d[portablePaths[0]]), l)
	if err != nil {
		return m, err
	}
	m.Notes, err = ReadNotes(ctx, bytes.NewReader(d[portablePaths[1]]), l)
	if err != nil {
		return m, err
	}
	m.Tags, err = ReadTags(ctx, bytes.NewReader(d[portablePaths[2]]), l)
	if err != nil {
		return m, err
	}
	m.Provenance, err = ReadProvenance(ctx, bytes.NewReader(d[portablePaths[3]]), l)
	if err != nil {
		return m, err
	}
	m.Events, err = ReadEvents(ctx, bytes.NewReader(d[portablePaths[4]]), l)
	return m, err
}
func validateMemoryAppend(old, next PortableMemory, intent MemoryWriteIntent) error {
	// Note documents sort by ID/revision, so a new note or revision may insert
	// between prior records. All old revisions must still be present unchanged.
	type noteKey struct {
		id       NoteID
		revision int64
	}
	notes := map[noteKey]NoteRevision{}
	for _, r := range next.Notes.Revisions {
		notes[noteKey{r.NoteID, r.Revision}] = r
	}
	for _, r := range old.Notes.Revisions {
		if nr, ok := notes[noteKey{r.NoteID, r.Revision}]; !ok || nr != r {
			return protocolError(ReasonInvalidMetadata, "existing note revision rewritten/removed")
		}
	}
	if len(next.Tags.Revisions) < len(old.Tags.Revisions) || !reflect.DeepEqual(old.Tags.Revisions, next.Tags.Revisions[:len(old.Tags.Revisions)]) {
		return protocolError(ReasonInvalidMetadata, "existing tag revision rewritten/removed")
	}
	if len(next.Events) < len(old.Events) || !reflect.DeepEqual(old.Events, next.Events[:len(old.Events)]) {
		return protocolError(ReasonInvalidMetadata, "existing event rewritten/removed")
	}
	if len(next.Provenance.Records) < len(old.Provenance.Records) || !reflect.DeepEqual(old.Provenance.Records, next.Provenance.Records[:len(old.Provenance.Records)]) {
		return protocolError(ReasonInvalidMetadata, "existing provenance reordered/rewritten/removed")
	}
	if !intent.AllowOptionalFactRemoval {
		if !preservedOptional(old.Metadata.Extra, next.Metadata.Extra) || !preservedOptional(old.Metadata.Extensions, next.Metadata.Extensions) {
			return protocolError(ReasonInvalidMetadata, "lossy optional metadata write requires explicit removal intent")
		}
	}
	return nil
}
func preservedOptional(old, next map[string]any) bool {
	for k, v := range old {
		nv, ok := next[k]
		if !ok || !preservedJSON(v, nv) {
			return false
		}
	}
	return true
}
func preservedJSON(old, next any) bool {
	if m, ok := old.(map[string]any); ok {
		nm, ok := next.(map[string]any)
		return ok && preservedOptional(m, nm)
	}
	return reflect.DeepEqual(old, next)
}
func targetValue(t MemoryTarget) map[string]any {
	return map[string]any{"kind": t.Kind, "id": string(t.ID)}
}
func eventValue(e Event) map[string]any {
	var actor any
	if e.Actor != nil {
		actor = map[string]any{"kind": e.Actor.Kind, "id": e.Actor.ID}
	}
	return map[string]any{"schema": e.Schema, "event_id": string(e.EventID), "package_id": string(e.PackageID), "type": e.Type, "schema_version": e.SchemaVersion, "occurred_at": e.OccurredAt, "actor": actor, "subject": targetValue(e.Subject), "data": e.Data}
}
func encodeMemory(ctx context.Context, m PortableMemory, l Limits) (map[string][]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if len(m.Metadata.Extra) > l.MaxEntries || len(m.Notes.Revisions) > l.MaxEntries || len(m.Tags.Revisions) > l.MaxEntries || len(m.Provenance.Records) > l.MaxEntries || len(m.Events) > l.MaxEntries {
		return nil, protocolError(ReasonResourceLimit, "portable collection policy")
	}
	display := map[string]any{"schema": m.Metadata.Schema, "package_id": string(m.Metadata.PackageID), "title": m.Metadata.Title}
	if m.Metadata.Description != nil {
		display["description"] = *m.Metadata.Description
	}
	if m.Metadata.Extensions != nil {
		display["extensions"] = m.Metadata.Extensions
	}
	for k, v := range m.Metadata.Extra {
		if containsText([]string{"schema", "package_id", "title", "description", "extensions"}, k) {
			return nil, schemaError("metadata optional shadow")
		}
		display[k] = v
	}
	remaining := l.MaxTotalJSONBytes
	out := map[string][]byte{}
	// Walk each value before encoding to bound shared expansion/cycles/UTF-8 and
	// total bytes. json.Marshal is an ordinary serializer, never canonical J(x).
	encode := func(v any, max int64) ([]byte, error) {
		budget := min(max, remaining)
		if err := walkOptional(ctx, v, l, 0, &budget); err != nil {
			return nil, err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		remaining -= int64(len(b))
		return b, nil
	}
	b, err := encode(display, l.MaxJSONBytes)
	if err != nil {
		return nil, err
	}
	out[portablePaths[0]] = b
	// Check each record against one document budget before allocating an expanded
	// []any/map collection. A tiny byte policy can reject a huge caller-owned
	// slice after a few bounded records rather than allocate the entire proposal.
	collection := func(schema string, id PackageID, field string, n int, value func(int) any) ([]byte, error) {
		doc := map[string]any{"schema": schema, "package_id": string(id), field: []any{}}
		budget := min(l.MaxJSONBytes, remaining)
		if err := walkOptional(ctx, doc, l, 0, &budget); err != nil {
			return nil, err
		}
		for i := 0; i < n; i++ {
			if i > 0 {
				if err := consumeJSON(1, &budget); err != nil {
					return nil, err
				}
			}
			if err := walkOptional(ctx, value(i), l, 2, &budget); err != nil {
				return nil, err
			}
		}
		values := make([]any, 0, n)
		for i := 0; i < n; i++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			values = append(values, value(i))
		}
		doc[field] = values
		b, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		remaining -= int64(len(b))
		return b, nil
	}
	b, err = collection(m.Notes.Schema, m.Notes.PackageID, "revisions", len(m.Notes.Revisions), func(i int) any { return noteValue(m.Notes.Revisions[i]) })
	if err != nil {
		return nil, err
	}
	out[portablePaths[1]] = b
	b, err = collection(m.Tags.Schema, m.Tags.PackageID, "revisions", len(m.Tags.Revisions), func(i int) any { return tagValue(m.Tags.Revisions[i]) })
	if err != nil {
		return nil, err
	}
	out[portablePaths[2]] = b
	b, err = collection(m.Provenance.Schema, m.Provenance.PackageID, "records", len(m.Provenance.Records), func(i int) any { return provenanceValue(m.Provenance.Records[i]) })
	if err != nil {
		return nil, err
	}
	out[portablePaths[3]] = b
	var events bytes.Buffer
	for _, e := range m.Events {
		if remaining <= 0 {
			return nil, protocolError(ReasonResourceLimit, "aggregate portable JSON policy")
		}
		remaining--
		b, err := encode(eventValue(e), min(l.MaxJSONBytes, l.MaxNDJSONLineBytes-1))
		if err != nil {
			return nil, err
		}
		if int64(events.Len())+int64(len(b))+1 > min(l.MaxFileBytes, l.MaxTotalBytes) {
			return nil, protocolError(ReasonResourceLimit, "event file policy")
		}
		events.Write(b)
		events.WriteByte('\n')
	}
	out[portablePaths[4]] = events.Bytes()
	return out, nil
}

func noteValue(n NoteRevision) map[string]any {
	return map[string]any{"note_id": string(n.NoteID), "revision": n.Revision, "target": targetValue(n.Target), "updated_at": n.UpdatedAt, "deleted": n.Deleted, "body": n.Body}
}
func tagValue(t TagRevision) map[string]any {
	return map[string]any{"revision": t.Revision, "tag": t.Tag, "action": t.Action, "occurred_at": t.OccurredAt}
}
func provenanceValue(p ProvenanceRecord) map[string]any {
	v := map[string]any{"provenance_id": string(p.ProvenanceID), "target": map[string]any{"kind": p.Target.Kind, "id": p.Target.ID}, "source_kind": p.SourceKind, "first_observed_at": p.FirstObservedAt}
	if p.SourceID != nil {
		v["source_id"] = *p.SourceID
	}
	if p.SourceRevision != nil {
		v["source_revision"] = *p.SourceRevision
	}
	if p.OriginalName != nil {
		v["original_name"] = *p.OriginalName
	}
	if p.Relationship != nil {
		var id any
		if p.Relationship.VersionID != nil {
			id = string(*p.Relationship.VersionID)
		}
		v["relationship"] = map[string]any{"kind": p.Relationship.Kind, "package_id": string(p.Relationship.PackageID), "package_version_id": id}
	}
	return v
}
