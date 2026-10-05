// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

const memoryTime = "2026-10-05T00:00:00.000000Z"

func memoryID(n int) pkg.UUID { return pkg.UUID(fmt.Sprintf("019a0000-0000-7000-8000-%012x", n)) }
func portableEvent(n int, typ string) pkg.Event {
	return pkg.Event{Schema: "orbifabric.package.event.v1", EventID: pkg.EventID(memoryID(n)), PackageID: pkg.PackageID(memoryID(1)), Type: typ, SchemaVersion: 1, OccurredAt: memoryTime, Subject: pkg.MemoryTarget{Kind: "package", ID: memoryID(1)}, Data: map[string]any{}}
}
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func eventBytes(t *testing.T, e pkg.Event) []byte { return append(jsonBytes(t, e), '\n') }
func noteDocument(r ...pkg.NoteRevision) pkg.Notes {
	return pkg.Notes{Schema: "orbifabric.package.notes.v1", PackageID: pkg.PackageID(memoryID(1)), Revisions: r}
}
func tagDocument(r ...pkg.TagRevision) pkg.Tags {
	return pkg.Tags{Schema: "orbifabric.package.tags.v1", PackageID: pkg.PackageID(memoryID(1)), Revisions: r}
}
func baseNote() pkg.NoteRevision {
	return pkg.NoteRevision{NoteID: pkg.NoteID(memoryID(30)), Revision: 1, Target: pkg.MemoryTarget{Kind: "file", ID: memoryID(3)}, UpdatedAt: memoryTime, Body: "portable note"}
}

func TestS05SharedPortableMemory(t *testing.T) {
	for _, name := range []string{"cloud-origin-provenance", "unknown-optional-extension", "complete-history"} {
		t.Run(name, func(t *testing.T) {
			source := treeFixture(t, name)
			m, err := pkg.ReadPortableMemory(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
			if err != nil {
				t.Fatal(err)
			}
			if len(m.MissingPaths) != 0 || m.Metadata.PackageID != pkg.PackageID(memoryID(1)) || m.Metadata.Title != "Fixture" {
				t.Fatal(m)
			}
			if name == "cloud-origin-provenance" {
				if len(m.Provenance.Records) != 1 || m.Provenance.Records[0].SourceKind != "google_drive" || *m.Provenance.Records[0].SourceID != "opaque-example" {
					t.Fatal(m)
				}
			}
			for _, opened := range source.opens {
				if !strings.HasPrefix(opened, ".packtell/") {
					t.Fatal("memory borrowed Working bytes", opened)
				}
			}
			// These are memory schema/relationship subsets only, not full Complete or
			// signature/evidence dimensions. No replacement of frozen expected files.
		})
	}
}
func TestNotesRevisionProjectionAndTombstoneRestore(t *testing.T) {
	first := baseNote()
	deleted := first
	deleted.Revision = 2
	deleted.Deleted = true
	deleted.Body = ""
	restore := first
	restore.Revision = 3
	restore.Body = "restored"
	n, err := pkg.ReadNotes(context.Background(), bytes.NewReader(jsonBytes(t, noteDocument(first, deleted, restore))), pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Current()[first.NoteID]; got != restore {
		t.Fatal(got)
	}
	n, err = pkg.ReadNotes(context.Background(), bytes.NewReader(jsonBytes(t, noteDocument(first, deleted))), pkg.DefaultLimits())
	if err != nil || !n.Current()[first.NoteID].Deleted {
		t.Fatal(n, err)
	}
	for _, name := range []string{"start-two", "gap", "duplicate", "target-drift", "nonempty-tombstone", "unsorted-ID"} {
		t.Run(name, func(t *testing.T) {
			a, b := first, deleted
			switch name {
			case "start-two":
				a.Revision = 2
			case "gap":
				b.Revision = 3
			case "duplicate":
				b.Revision = 1
			case "target-drift":
				b.Target = pkg.MemoryTarget{Kind: "package", ID: memoryID(1)}
			case "nonempty-tombstone":
				b.Body = "lost"
			case "unsorted-ID":
				a.NoteID = pkg.NoteID(memoryID(31))
			}
			_, err := pkg.ReadNotes(context.Background(), bytes.NewReader(jsonBytes(t, noteDocument(a, b))), pkg.DefaultLimits())
			requireCode(t, err, pkg.ReasonInvalidMetadata)
		})
	}
	bad := strings.Replace(string(jsonBytes(t, noteDocument(first))), `"body":`, `"unknown":1,"body":`, 1)
	_, err = pkg.ReadNotes(context.Background(), strings.NewReader(bad), pkg.DefaultLimits())
	requireCode(t, err, pkg.ReasonInvalidSchema)
}
func TestTagsGlobalReplayAndUnicodeText(t *testing.T) {
	rev := func(n int64, tag, action string) pkg.TagRevision {
		return pkg.TagRevision{Revision: n, Tag: tag, Action: action, OccurredAt: memoryTime}
	}
	tags, err := pkg.ReadTags(context.Background(), bytes.NewReader(jsonBytes(t, tagDocument(rev(1, "A", "add"), rev(2, "a", "add"), rev(3, "A", "remove"), rev(4, "é", "add")))), pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tags.Current(), []string{"a", "é"}) {
		t.Fatal(tags.Current())
	}
	for _, r := range [][]pkg.TagRevision{{rev(1, "A", "remove")}, {rev(1, "A", "add"), rev(2, "A", "add")}, {rev(2, "A", "add")}, {rev(1, "A", "add"), rev(3, "A", "remove")}, {rev(1, " A", "add")}, {rev(1, "A\u00a0", "add")}, {rev(1, "e\u0301", "add")}, {rev(1, "", "add")}} {
		_, err := pkg.ReadTags(context.Background(), bytes.NewReader(jsonBytes(t, tagDocument(r...))), pkg.DefaultLimits())
		requireCode(t, err, pkg.ReasonInvalidMetadata)
	}
}
func TestEventsRecordOrderUnknownFactsAndNDJSON(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	first := portableEvent(40, "PACKAGE_CREATED")
	first.OccurredAt = "2026-10-06T00:00:00.000000Z"
	second := portableEvent(41, "org.example.future")
	second.Actor = &pkg.EventActor{Kind: "application", ID: "opaque"}
	second.Data = map[string]any{"uninterpreted": []any{int64(7), true, "\r\ufeff"}}
	data := append(eventBytes(t, first), eventBytes(t, second)...)
	got, err := pkg.ReadEvents(ctx, bytes.NewReader(data), l)
	if err != nil || len(got) != 2 || !reflect.DeepEqual(got, []pkg.Event{first, second}) {
		t.Fatal(got, err)
	}
	if empty, err := pkg.ReadEvents(ctx, strings.NewReader(""), l); err != nil || len(empty) != 0 {
		t.Fatal(empty, err)
	}
	for _, data := range [][]byte{eventBytes(t, first)[:len(eventBytes(t, first))-1], []byte("\n"), append([]byte{0xef, 0xbb, 0xbf}, eventBytes(t, first)...), append(eventBytes(t, first), '\n'), []byte(strings.ReplaceAll(string(eventBytes(t, first)), "\n", "\r\n")), append(eventBytes(t, first), eventBytes(t, first)...)} {
		_, err := pkg.ReadEvents(ctx, bytes.NewReader(data), l)
		requireCode(t, err, pkg.ReasonInvalidMetadata)
	}
	bad := portableEvent(42, "UNDECLARED_NAME")
	_, err = pkg.ReadEvents(ctx, bytes.NewReader(eventBytes(t, bad)), l)
	requireCode(t, err, pkg.ReasonInvalidSchema)
	// Physical LF inside a string, second JSON values and closed unknown fields
	// remain strict JSON/schema errors, never state-transition interpretation.
	for _, bad := range []string{`{"bad":1}` + "\n", strings.TrimSuffix(string(eventBytes(t, first)), "\n") + " {}\n", strings.Replace(string(eventBytes(t, first)), `"data":`, `"extra":1,"data":`, 1)} {
		_, err := pkg.ReadEvents(ctx, strings.NewReader(bad), l)
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
}
func TestEventLimitsAndCancellationBeforeExpansion(t *testing.T) {
	ctx := context.Background()
	data := eventBytes(t, portableEvent(40, "PACKAGE_CREATED"))
	l := pkg.DefaultLimits()
	l.MaxNDJSONLineBytes = int64(len(data))
	if _, err := pkg.ReadEvents(ctx, bytes.NewReader(data), l); err != nil {
		t.Fatal(err)
	}
	l.MaxNDJSONLineBytes--
	_, err := pkg.ReadEvents(ctx, bytes.NewReader(data), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	l = pkg.DefaultLimits()
	l.MaxTotalJSONBytes = int64(len(data))
	second := eventBytes(t, portableEvent(41, "PACKAGE_CREATED"))
	_, err = pkg.ReadEvents(ctx, bytes.NewReader(append(data, second...)), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	l = pkg.DefaultLimits()
	l.MaxEntries = 9
	var countBytes bytes.Buffer
	for i := 0; i < 10; i++ {
		countBytes.Write(eventBytes(t, portableEvent(40+i, "PACKAGE_CREATED")))
	}
	_, err = pkg.ReadEvents(ctx, bytes.NewReader(countBytes.Bytes()), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	big := portableEvent(42, "org.example.future")
	big.Data = map[string]any{"text": strings.Repeat("x", 12000)}
	b := eventBytes(t, big)
	l = pkg.DefaultLimits()
	l.MaxNDJSONLineBytes = int64(len(b))
	if _, err = pkg.ReadEvents(ctx, bytes.NewReader(b), l); err != nil {
		t.Fatal(err)
	}
	l.MaxNDJSONLineBytes--
	_, err = pkg.ReadEvents(ctx, bytes.NewReader(b), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = pkg.ReadEvents(canceled, bytes.NewReader(data), pkg.DefaultLimits())
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	injected := errors.New("read interrupted")
	_, err = pkg.ReadEvents(ctx, io.MultiReader(bytes.NewReader(data), portableErrorReader{injected}), pkg.DefaultLimits())
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
}

type portableErrorReader struct{ err error }

func (r portableErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestMemoryReferencesHistoricalDeletedAndFutureEvent(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	source := treeFixture(t, "complete-history")
	// Remove the File from the latest manifest. References to its older committed
	// identity remain valid; the latest events do not reconstruct payload state.
	h, err := pkg.ReadHistory(ctx, source, l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	latest := h.Versions[1].Manifest
	latest.Entries = []pkg.Entry{}
	source.setFile(".packtell/versions/"+string(latest.VersionID)+"/manifest.json", jsonBytes(t, latest))
	n := baseNote()
	n.Target = pkg.MemoryTarget{Kind: "event", ID: memoryID(41)}
	fileNote := baseNote()
	fileNote.NoteID = pkg.NoteID(memoryID(31))
	source.setFile(".packtell/metadata/notes.json", jsonBytes(t, noteDocument(n, fileNote)))
	first := portableEvent(40, "FILE_REMOVED")
	first.Subject = pkg.MemoryTarget{Kind: "file", ID: memoryID(3)}
	second := portableEvent(41, "org.example.future")
	second.Subject = pkg.MemoryTarget{Kind: "event", ID: memoryID(40)}
	source.setFile(".packtell/history/events.ndjson", append(eventBytes(t, first), eventBytes(t, second)...))
	if _, err = pkg.ReadPortableMemory(ctx, source, l, supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []pkg.MemoryTarget{{Kind: "file", ID: memoryID(99)}, {Kind: "folder", ID: memoryID(3)}, {Kind: "package", ID: memoryID(99)}, {Kind: "event", ID: memoryID(99)}} {
		first.Subject = bad
		source.setFile(".packtell/history/events.ndjson", append(eventBytes(t, first), eventBytes(t, second)...))
		_, err = pkg.ReadPortableMemory(ctx, source, l, supportAllVocabulary())
		requireCode(t, err, pkg.ReasonInvalidMetadata)
	}
}
func TestPortableDocumentAgreementAndIdentityReuse(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"package-ID", "note-event-ID", "historical-entry-ID", "provenance-ID", "note-reference"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "cloud-origin-provenance")
			n := baseNote()
			e := portableEvent(40, "PACKAGE_CREATED")
			switch name {
			case "package-ID":
				e.PackageID = pkg.PackageID(memoryID(99))
			case "note-event-ID":
				n.NoteID = pkg.NoteID(e.EventID)
			case "historical-entry-ID":
				e.EventID = pkg.EventID(memoryID(3))
			case "provenance-ID":
				e.EventID = pkg.EventID(memoryID(25))
			case "note-reference":
				n.Target.ID = memoryID(99)
			}
			s.setFile(".packtell/metadata/notes.json", jsonBytes(t, noteDocument(n)))
			s.setFile(".packtell/history/events.ndjson", eventBytes(t, e))
			_, err := pkg.ReadPortableMemory(ctx, s, pkg.DefaultLimits(), supportAllVocabulary())
			requireCode(t, err, pkg.ReasonInvalidMetadata)
		})
	}
}
func TestProvenanceRelationshipsAndClosedSchemas(t *testing.T) {
	ctx := context.Background()
	s := treeFixture(t, "cloud-origin-provenance")
	m, err := pkg.ReadPortableMemory(ctx, s, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	relVersion := pkg.VersionID(memoryID(90))
	r := m.Provenance.Records[0]
	r.Relationship = &pkg.ProvenanceRelationship{Kind: "copied_from", PackageID: pkg.PackageID(memoryID(91)), VersionID: &relVersion}
	m.Provenance.Records[0] = r
	s.setFile(".packtell/metadata/provenance.json", jsonBytes(t, m.Provenance))
	if _, err = pkg.ReadPortableMemory(ctx, s, pkg.DefaultLimits(), supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"self-package", "missing-content", "missing-file", "duplicate-record", "unsorted", "source-kind", "unknown-field", "bad-time", "bad-original-name"} {
		t.Run(name, func(t *testing.T) {
			p := m.Provenance
			p.Records = append([]pkg.ProvenanceRecord{}, m.Provenance.Records...)
			r := p.Records[0]
			code := pkg.ReasonInvalidMetadata
			switch name {
			case "self-package":
				r.Relationship = &pkg.ProvenanceRelationship{Kind: "reuses", PackageID: p.PackageID}
			case "missing-content":
				r.Target.ID = string(pkg.ContentIDForBytes([]byte("absent")))
			case "missing-file":
				r.Target = pkg.ProvenanceTarget{Kind: "file", ID: string(memoryID(99))}
			case "duplicate-record":
				p.Records = append(p.Records, r)
			case "unsorted":
				r.ProvenanceID = pkg.ProvenanceID(memoryID(24))
				p.Records = append(p.Records, r)
				r = p.Records[0]
			case "source-kind":
				r.SourceKind = "runtime_provider"
				code = pkg.ReasonInvalidSchema
			case "bad-time":
				r.FirstObservedAt = "2026-10-05T00:00:00Z"
				code = pkg.ReasonInvalidSchema
			case "bad-original-name":
				bad := "folder/file"
				r.OriginalName = &bad
				code = pkg.ReasonInvalidSchema
			case "unknown-field":
				code = pkg.ReasonInvalidSchema
			}
			p.Records[0] = r
			data := jsonBytes(t, p)
			if name == "unknown-field" {
				data = []byte(strings.Replace(string(data), `"source_kind":`, `"runtime":true,"source_kind":`, 1))
			}
			s.setFile(".packtell/metadata/provenance.json", data)
			_, err := pkg.ReadPortableMemory(ctx, s, pkg.DefaultLimits(), supportAllVocabulary())
			requireCode(t, err, code)
		})
	}
}

func TestNDJSONAdvertisedBudgetPrecedesOpenAndActualSize(t *testing.T) {
	s := treeFixture(t, "complete-history")
	l := pkg.DefaultLimits()
	var oldTotal int64
	for _, e := range s.entries {
		if strings.HasSuffix(e.Path, ".json") {
			oldTotal += e.Size
		}
	}
	s.setFile(".packtell/history/events.ndjson", eventBytes(t, portableEvent(40, "PACKAGE_CREATED")))
	l.MaxTotalJSONBytes = oldTotal
	_, err := pkg.ReadPortableMemory(context.Background(), s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonResourceLimit)
	if len(s.opens) != 0 {
		t.Fatal("oversized aggregate opened control streams", s.opens)
	}
	l = pkg.DefaultLimits()
	s.openOverride = func(path string, b []byte) io.ReadCloser {
		if path == ".packtell/history/events.ndjson" {
			return io.NopCloser(bytes.NewReader(append(bytes.Clone(b), eventBytes(t, portableEvent(41, "PACKAGE_CREATED"))...)))
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	_, err = pkg.ReadPortableMemory(context.Background(), s, l, supportAllVocabulary())
	if !errors.Is(err, pkg.ErrUnstableWorkingTree) {
		t.Fatal(err)
	}
	// Aggregate budget exactly exhausted by JSON permits a genuinely empty event
	// stream, but must still inspect advertised zero-byte data rather than skip it.
	s = treeFixture(t, "complete-history")
	l.MaxTotalJSONBytes = oldTotal
	if _, err = pkg.ReadPortableMemory(context.Background(), s, l, supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	s.openOverride = func(path string, b []byte) io.ReadCloser {
		if path == ".packtell/history/events.ndjson" {
			return io.NopCloser(strings.NewReader("\n"))
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	_, err = pkg.ReadPortableMemory(context.Background(), s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidMetadata)
}
func FuzzPortableNDJSON(f *testing.F) {
	seed := portableEvent(40, "org.example.future")
	b, _ := json.Marshal(seed)
	f.Add(append(b, '\n'))
	f.Add([]byte{})
	f.Add([]byte("\n"))
	f.Add([]byte{0xef, 0xbb, 0xbf, '\n'})
	f.Fuzz(func(t *testing.T, data []byte) {
		l := pkg.DefaultLimits()
		l.MaxJSONBytes = 64 << 10
		l.MaxTotalJSONBytes = 128 << 10
		l.MaxNDJSONLineBytes = 64 << 10
		l.MaxJSONDepth = 16
		l.MaxEntries = 256
		events, err := pkg.ReadEvents(context.Background(), bytes.NewReader(data), l)
		if err != nil {
			return
		}
		var out bytes.Buffer
		for _, e := range events {
			b, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			out.Write(b)
			out.WriteByte('\n')
		}
		// The normal serializer can expand harmless input whitespace/escapes; if
		// policy rejects larger serialized bytes that is not a protocol failure.
		second, err := pkg.ReadEvents(context.Background(), bytes.NewReader(out.Bytes()), l)
		if err != nil {
			var pe *pkg.ProtocolError
			if errors.As(err, &pe) && pe.Code == pkg.ReasonResourceLimit {
				return
			}
			t.Fatal(err)
		}
		if !reflect.DeepEqual(events, second) {
			t.Fatal("accepted portable facts lost across read/write")
		}
	})
}

func TestMemoryIDsCannotReuseControlEnvelopePathIdentity(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	n := baseNote()
	s.addFile(".packtell/metadata/notes.json", jsonBytes(t, noteDocument(n)))
	// Path identity reservation is independent of the following stage's envelope
	// verification. This does not claim the placeholder is a valid signature.
	s.addFile(".packtell/verification/versions/"+string(memoryID(2))+"/"+string(n.NoteID)+".json", []byte("{}"))
	_, err := pkg.ReadPortableMemory(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidMetadata)
}
