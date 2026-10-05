// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
)

var portablePaths = []string{".packtell/metadata/package.json", ".packtell/metadata/notes.json", ".packtell/metadata/tags.json", ".packtell/metadata/provenance.json", ".packtell/history/events.ndjson"}

// PortableMemory contains observations, not an event-sourced Version program.
// Missing Core documents receive empty defaults; MissingPaths retains absence
// for Complete verification. Readers do not certify facts as privacy-safe.
type PortableMemory struct {
	Metadata     Metadata
	Notes        Notes
	Tags         Tags
	Provenance   Provenance
	Events       []Event
	MissingPaths []string
}

func EmptyPortableMemory(id PackageID) PortableMemory {
	return PortableMemory{Metadata: Metadata{Schema: "orbifabric.package.metadata.v1", PackageID: id}, Notes: Notes{"orbifabric.package.notes.v1", id, []NoteRevision{}}, Tags: Tags{"orbifabric.package.tags.v1", id, []TagRevision{}}, Provenance: Provenance{"orbifabric.package.provenance.v1", id, []ProvenanceRecord{}}, Events: []Event{}}
}
func ReadPortableMemory(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport) (PortableMemory, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return PortableMemory{}, err
	}
	return readPortableMemory(ctx, source, h, l)
}
func readPortableMemory(ctx context.Context, source TreeReader, h History, l Limits) (PortableMemory, error) {
	out := EmptyPortableMemory(h.Root.Package.PackageID)
	nodes := map[string]TreeEntry{}
	for _, e := range h.Root.Entries {
		nodes[e.Path] = e
	}
	for _, p := range portablePaths {
		node, exists := nodes[p]
		if !exists {
			out.MissingPaths = append(out.MissingPaths, p)
			continue
		}
		if err := ctx.Err(); err != nil {
			return PortableMemory{}, err
		}
		if p == ".packtell/history/events.ndjson" {
			// Root preflight checks advertised aggregate JSON/NDJSON bytes before open.
			other := int64(0)
			for _, e := range h.Root.Entries {
				if controlJSONPath(e.Path) {
					other += e.Size
				}
			}
			eventLimits := l
			eventLimits.MaxTotalJSONBytes = l.MaxTotalJSONBytes - other
			if eventLimits.MaxTotalJSONBytes <= 0 && node.Size == 0 {
				eventLimits.MaxTotalJSONBytes = 1
			}
			if eventLimits.MaxTotalJSONBytes <= 0 {
				return PortableMemory{}, protocolError(ReasonResourceLimit, "aggregate portable JSON bytes")
			}
			r, err := source.Open(ctx, p)
			if err != nil {
				if r != nil {
					_ = r.Close()
				}
				return PortableMemory{}, err
			}
			if r == nil {
				return PortableMemory{}, schemaError("missing event reader")
			}
			counter := &countMemoryReader{r: r}
			out.Events, err = ReadEvents(ctx, counter, eventLimits)
			err = errors.Join(err, r.Close())
			if err != nil {
				return PortableMemory{}, err
			}
			if counter.n != node.Size {
				return PortableMemory{}, ErrUnstableWorkingTree
			}
		} else {
			b, err := readRootBytes(ctx, source, nodes, p, l.MaxJSONBytes)
			if err != nil {
				return PortableMemory{}, err
			}
			switch p {
			case portablePaths[0]:
				out.Metadata, err = ReadMetadata(ctx, bytes.NewReader(b), l)
			case portablePaths[1]:
				out.Notes, err = ReadNotes(ctx, bytes.NewReader(b), l)
			case portablePaths[2]:
				out.Tags, err = ReadTags(ctx, bytes.NewReader(b), l)
			case portablePaths[3]:
				out.Provenance, err = ReadProvenance(ctx, bytes.NewReader(b), l)
			}
			if err != nil {
				return PortableMemory{}, err
			}
		}
	}
	if err := validateMemoryReferences(ctx, out, h, l); err != nil {
		return PortableMemory{}, err
	}
	return out, nil
}
func (m PortableMemory) KnownIDs() []UUID {
	ids := map[UUID]bool{}
	for _, r := range m.Notes.Revisions {
		ids[UUID(r.NoteID)] = true
	}
	for _, e := range m.Events {
		ids[UUID(e.EventID)] = true
	}
	for _, p := range m.Provenance.Records {
		ids[UUID(p.ProvenanceID)] = true
	}
	out := make([]UUID, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
func validateMemoryReferences(ctx context.Context, m PortableMemory, h History, l Limits) error {
	id := h.Root.Package.PackageID
	for _, actual := range []PackageID{m.Metadata.PackageID, m.Notes.PackageID, m.Tags.PackageID, m.Provenance.PackageID} {
		if actual != id {
			return protocolError(ReasonInvalidMetadata, "portable Package IDs disagree")
		}
	}
	entities := map[UUID]string{UUID(id): "package"}
	content := map[ContentID]bool{}
	addHistorical := func(id UUID, kind string, repeat bool) error {
		if old, ok := entities[id]; ok {
			if old == kind && repeat {
				return nil
			}
			return schemaError("historical identity reused across entity domains")
		}
		if len(entities) >= l.MaxEntries {
			return protocolError(ReasonResourceLimit, "portable identity inventory")
		}
		entities[id] = kind
		return nil
	}
	for _, v := range h.Versions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := addHistorical(UUID(v.Version.VersionID), "version", false); err != nil {
			return err
		}
		for _, e := range v.Manifest.Entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := addHistorical(e.ID(), e.Kind, true); err != nil {
				return err
			}
			if e.Kind == "file" {
				content[e.ContentID] = true
			}
		}
	}
	reserve := func(id UUID, kind string, repeat bool) error {
		if previous, exists := entities[id]; exists {
			if previous == kind && repeat {
				return nil
			}
			return protocolError(ReasonInvalidMetadata, "portable identity reused across entities")
		}
		if len(entities) >= l.MaxEntries {
			return protocolError(ReasonResourceLimit, "portable identity inventory")
		}
		entities[id] = kind
		return nil
	}
	// Core envelope/delivery IDs are present in validated control paths even
	// before their optional signature/evidence semantics are verified. Reserving
	// these identities is not a cryptographic or embedded-evidence PASS.
	for _, entry := range h.Root.Entries {
		parts := strings.Split(entry.Path, "/")
		var identity UUID
		var kind string
		if entry.Kind == "file" && len(parts) == 5 && parts[1] == "verification" {
			identity = UUID(strings.TrimSuffix(parts[4], ".json"))
			kind = "signature"
		}
		if entry.Kind == "file" && len(parts) == 4 && parts[1] == "evidence" && parts[2] == "objects" {
			identity = UUID(strings.TrimSuffix(parts[3], ".json"))
			kind = "evidence"
		}
		if entry.Kind == "directory" && len(parts) == 4 && parts[1] == "evidence" && parts[2] == "deliveries" {
			identity = UUID(parts[3])
			kind = "delivery"
		}
		if identity != "" {
			if err := reserve(identity, kind, false); err != nil {
				return err
			}
		}
	}
	for _, e := range m.Events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.PackageID != id {
			return protocolError(ReasonInvalidMetadata, "event Package ID disagrees")
		}
		if err := reserve(UUID(e.EventID), "event", false); err != nil {
			return err
		}
	}
	for _, n := range m.Notes.Revisions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := reserve(UUID(n.NoteID), "note", true); err != nil {
			return err
		}
	}
	for _, p := range m.Provenance.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := reserve(UUID(p.ProvenanceID), "provenance", false); err != nil {
			return err
		}
	}
	target := func(t MemoryTarget) error {
		if entities[t.ID] != t.Kind {
			return protocolError(ReasonInvalidMetadata, "portable target is absent or wrong kind")
		}
		if t.Kind == "package" && t.ID != UUID(id) {
			return protocolError(ReasonInvalidMetadata, "package target disagrees")
		}
		return nil
	}
	for _, n := range m.Notes.Revisions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := target(n.Target); err != nil {
			return err
		}
	}
	for _, e := range m.Events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := target(e.Subject); err != nil {
			return err
		}
	}
	for _, p := range m.Provenance.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.Target.Kind == "content" {
			if !content[ContentID(p.Target.ID)] {
				return protocolError(ReasonInvalidMetadata, "provenance content absent from history")
			}
		} else {
			if err := target(MemoryTarget{p.Target.Kind, UUID(p.Target.ID)}); err != nil {
				return err
			}
		}
		if p.Relationship != nil && p.Relationship.PackageID == id {
			return protocolError(ReasonInvalidMetadata, "relationship must reference another Package")
		}
	}
	return nil
}

type countMemoryReader struct {
	r io.Reader
	n int64
}

func (r *countMemoryReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}
