// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

type factPolicyFunc func(context.Context, map[string][]byte) error

func (f factPolicyFunc) ApprovePortableFacts(ctx context.Context, d map[string][]byte) error {
	return f(ctx, d)
}
func approveFacts(context.Context, map[string][]byte) error { return nil }
func readMemory(t *testing.T, s *memorySource) pkg.PortableMemory {
	t.Helper()
	m, e := pkg.ReadPortableMemory(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary())
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func applyMemoryPlan(s *memorySource, p pkg.PortableMemoryPlan) {
	for path, b := range p.Documents {
		if _, exists := s.data[path]; exists {
			s.setFile(path, b)
		} else {
			s.addFile(path, b)
		}
	}
}

func TestMemoryWritePlanAppendsAndPreservesUnknownFacts(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	s := treeFixture(t, "unknown-optional-extension")
	m := readMemory(t, s)
	m.Metadata.Extra = map[string]any{"org.example.fact": map[string]any{"count": int64(7), "text": "\ufeff<>&"}}
	m.Metadata.Extensions = map[string]any{"org.example.note": map[string]any{"future": []any{true, int64(8)}}}
	m.Notes.Revisions = []pkg.NoteRevision{baseNote()}
	m.Tags.Revisions = []pkg.TagRevision{{Revision: 1, Tag: "Blue", Action: "add", OccurredAt: memoryTime}}
	m.Events = []pkg.Event{portableEvent(40, "org.example.future")}
	plan, err := pkg.PlanPortableMemoryUpdate(ctx, s, m, l, supportAllVocabulary(), factPolicyFunc(approveFacts), pkg.MemoryWriteIntent{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Documents) != 5 || len(plan.Extensions) == 0 {
		t.Fatal(plan)
	}
	applyMemoryPlan(s, plan)
	old := readMemory(t, s)
	if !reflect.DeepEqual(old.Metadata.Extra, m.Metadata.Extra) || !reflect.DeepEqual(old.Metadata.Extensions, m.Metadata.Extensions) || !reflect.DeepEqual(old.Events, m.Events) {
		t.Fatal(old, m)
	}
	next := readMemory(t, s)
	next.Metadata.Title = "mutable current title"
	n := baseNote()
	n.Revision = 2
	n.Deleted = true
	n.Body = ""
	next.Notes.Revisions = append(next.Notes.Revisions, n)
	next.Tags.Revisions = append(next.Tags.Revisions, pkg.TagRevision{Revision: 2, Tag: "Blue", Action: "remove", OccurredAt: memoryTime})
	next.Events = append(next.Events, portableEvent(41, "NOTE_DELETED"))
	plan, err = pkg.PlanPortableMemoryUpdate(ctx, s, next, l, supportAllVocabulary(), factPolicyFunc(approveFacts), pkg.MemoryWriteIntent{})
	if err != nil {
		t.Fatal(err)
	}
	applyMemoryPlan(s, plan)
	h, err := pkg.ReadHistory(ctx, s, l, supportAllVocabulary())
	if err != nil || h.Root.HeadVersion.SealedMetadata.Title != "Fixture" || h.Root.HEAD != pkg.HEAD(memoryID(2)) {
		t.Fatal(h, err)
	}
	// Unknown events/notes never replace manifest authority during restoration.
	out := &memoryPayload{}
	if err = pkg.MaterializeVersionPayload(ctx, s, pkg.VersionID(memoryID(2)), out, l, supportAllVocabulary()); err != nil || !bytes.Equal(out.files["hello.txt"].Bytes(), []byte("hello\n")) {
		t.Fatal(out, err)
	}
}
func TestMemoryAppendRejectsPriorFactRewrites(t *testing.T) {
	s := treeFixture(t, "cloud-origin-provenance")
	m := readMemory(t, s)
	m.Notes.Revisions = []pkg.NoteRevision{baseNote()}
	m.Tags.Revisions = []pkg.TagRevision{{Revision: 1, Tag: "Blue", Action: "add", OccurredAt: memoryTime}}
	m.Events = []pkg.Event{portableEvent(40, "org.example.future")}
	m.Metadata.Extra = map[string]any{"future": map[string]any{"a": int64(1), "b": int64(2)}}
	p, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, m, pkg.DefaultLimits(), supportAllVocabulary(), factPolicyFunc(approveFacts), pkg.MemoryWriteIntent{})
	if err != nil {
		t.Fatal(err)
	}
	applyMemoryPlan(s, p)
	for _, name := range []string{"note-edit", "note-remove", "tags-rewrite", "events-reorder", "event-data-edit", "provenance-edit", "provenance-remove", "provenance-insert", "optional-remove", "nested-optional-remove"} {
		t.Run(name, func(t *testing.T) {
			next := readMemory(t, s)
			switch name {
			case "note-edit":
				next.Notes.Revisions[0].Body = "rewrite"
			case "note-remove":
				next.Notes.Revisions = []pkg.NoteRevision{}
			case "tags-rewrite":
				next.Tags.Revisions[0].Tag = "New"
			case "events-reorder":
				next.Events = append([]pkg.Event{portableEvent(41, "org.example.future")}, next.Events...)
			case "event-data-edit":
				next.Events[0].Data["new"] = true
			case "provenance-edit":
				v := "changed"
				next.Provenance.Records[0].SourceRevision = &v
			case "provenance-remove":
				next.Provenance.Records = []pkg.ProvenanceRecord{}
			case "provenance-insert":
				new := next.Provenance.Records[0]
				new.ProvenanceID = pkg.ProvenanceID(memoryID(24))
				next.Provenance.Records = append([]pkg.ProvenanceRecord{new}, next.Provenance.Records...)
			case "optional-remove":
				next.Metadata.Extra = map[string]any{}
			case "nested-optional-remove":
				delete(next.Metadata.Extra["future"].(map[string]any), "a")
			}
			calls := 0
			policy := factPolicyFunc(func(context.Context, map[string][]byte) error { calls++; return nil })
			_, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, next, pkg.DefaultLimits(), supportAllVocabulary(), policy, pkg.MemoryWriteIntent{})
			requireCode(t, err, pkg.ReasonInvalidMetadata)
			if calls != 0 {
				t.Fatal("invalid facts reached approval")
			}
		})
	}
	next := readMemory(t, s)
	next.Metadata.Extra = map[string]any{}
	if _, err = pkg.PlanPortableMemoryUpdate(context.Background(), s, next, pkg.DefaultLimits(), supportAllVocabulary(), factPolicyFunc(approveFacts), pkg.MemoryWriteIntent{AllowOptionalFactRemoval: true}); err != nil {
		t.Fatal("explicit optional removal refused", err)
	}
	// New IDs may insert into Notes' sorted logical history; old revisions remain.
	next = readMemory(t, s)
	older := baseNote()
	older.NoteID = pkg.NoteID(memoryID(29))
	next.Notes.Revisions = append([]pkg.NoteRevision{older}, next.Notes.Revisions...)
	if _, err = pkg.PlanPortableMemoryUpdate(context.Background(), s, next, pkg.DefaultLimits(), supportAllVocabulary(), factPolicyFunc(approveFacts), pkg.MemoryWriteIntent{}); err != nil {
		t.Fatal(err)
	}
}
func TestFactSelectionRequiredAndOwnedExactBytes(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	m := readMemory(t, s)
	if len(m.MissingPaths) != 5 || m.Metadata.Title != "" {
		t.Fatal(m)
	}
	_, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, m, pkg.DefaultLimits(), supportAllVocabulary(), nil, pkg.MemoryWriteIntent{})
	requireCode(t, err, pkg.ReasonInvalidMetadata)
	rejected := errors.New("Host did not select these facts")
	// The Host's domain allowlist selects schema/identity/title facts only; every
	// optional business field needs an explicit selection. Parser success alone
	// does not redact or approve private runtime facts.
	safeDisplay := factPolicyFunc(func(ctx context.Context, d map[string][]byte) error {
		var v map[string]json.RawMessage
		if err := json.Unmarshal(d[".packtell/metadata/package.json"], &v); err != nil {
			return err
		}
		for key := range v {
			if key != "schema" && key != "package_id" && key != "title" {
				return rejected
			}
		}
		return ctx.Err()
	})
	for _, key := range []string{"oauth_token", "private_key", "keyring_locator", "fetch_url", "absolute_path", "sqlite_id", "cache", "worker_state", "telemetry"} {
		t.Run(key, func(t *testing.T) {
			proposed := readMemory(t, s)
			proposed.Metadata.Extra = map[string]any{key: "unselected fact"}
			_, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, proposed, pkg.DefaultLimits(), supportAllVocabulary(), safeDisplay, pkg.MemoryWriteIntent{})
			if !errors.Is(err, rejected) {
				t.Fatal(err)
			}
		})
	}
	calls := 0
	policy := factPolicyFunc(func(ctx context.Context, d map[string][]byte) error {
		calls++
		for path, b := range d {
			if !strings.HasPrefix(path, ".packtell/") {
				t.Fatal(path)
			}
			if len(b) > 0 {
				b[0] = '!'
			}
		}
		d["fake"] = []byte("bad")
		return nil
	})
	plan, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, m, pkg.DefaultLimits(), supportAllVocabulary(), policy, pkg.MemoryWriteIntent{})
	if err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	if _, exists := plan.Documents["fake"]; exists {
		t.Fatal("policy mutated plan")
	}
	applyMemoryPlan(s, plan)
	if got := readMemory(t, s); len(got.MissingPaths) != 0 {
		t.Fatal(got)
	}
}
func TestMemoryWriteResourcesInvalidDomainAndCancellation(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	calls := 0
	policy := factPolicyFunc(func(context.Context, map[string][]byte) error { calls++; return nil })
	for _, name := range []string{"float", "invalid-UTF8", "cycle", "shadow", "shared-expansion", "line-size", "aggregate-size", "depth", "entry-count"} {
		t.Run(name, func(t *testing.T) {
			m := readMemory(t, s)
			l := pkg.DefaultLimits()
			code := pkg.ReasonInvalidSchema
			switch name {
			case "float":
				m.Metadata.Extra = map[string]any{"x": 1.2}
			case "invalid-UTF8":
				m.Metadata.Title = string([]byte{0xff})
			case "cycle":
				x := map[string]any{}
				x["self"] = x
				m.Metadata.Extra = x
				code = pkg.ReasonResourceLimit
			case "shadow":
				m.Metadata.Extra = map[string]any{"title": "shadow"}
			case "shared-expansion":
				x := strings.Repeat("x", 100)
				m.Metadata.Extra = map[string]any{"values": []any{x, x, x, x}}
				l.MaxJSONBytes = 300
				code = pkg.ReasonResourceLimit
			case "line-size":
				m.Events = []pkg.Event{portableEvent(40, "PACKAGE_CREATED")}
				l.MaxNDJSONLineBytes = 20
				code = pkg.ReasonResourceLimit
			case "aggregate-size":
				l.MaxTotalJSONBytes = 600
				code = pkg.ReasonResourceLimit
			case "depth":
				m.Metadata.Extra = map[string]any{"future": map[string]any{"inner": true}}
				l.MaxJSONDepth = 2
				code = pkg.ReasonResourceLimit
			case "entry-count":
				l.MaxEntries = 12
				for i := 0; i < 13; i++ {
					m.Events = append(m.Events, portableEvent(40+i, "PACKAGE_CREATED"))
				}
				code = pkg.ReasonResourceLimit
			}
			before := calls
			_, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, m, l, supportAllVocabulary(), policy, pkg.MemoryWriteIntent{})
			requireCode(t, err, code)
			if calls != before {
				t.Fatal("invalid proposal reached fact policy")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pkg.PlanPortableMemoryUpdate(ctx, s, pkg.EmptyPortableMemory(pkg.PackageID(memoryID(1))), pkg.DefaultLimits(), supportAllVocabulary(), policy, pkg.MemoryWriteIntent{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestExtensionsVerbatimCopyAndFailure(t *testing.T) {
	s := treeFixture(t, "unknown-optional-extension")
	out := &memoryPayload{}
	if err := pkg.CopyExtensions(context.Background(), s, out, pkg.DefaultLimits(), supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	path := ".packtell/extensions/org.example.demo/value.bin"
	if !bytes.Equal(out.files[path].Bytes(), []byte{'o', 'p', 'a', 'q', 'u', 'e', 0, 255}) {
		t.Fatal(out.files)
	}
	// Unknown extension .json is opaque bytes; an empty directory survives too.
	s.addFile(".packtell/extensions/org.example.demo/bad.json", []byte{0xff, 0})
	s.entries = append(s.entries, pkg.TreeEntry{Path: ".packtell/extensions/org.example.demo/empty", Kind: "directory"})
	out = &memoryPayload{}
	if err := pkg.CopyExtensions(context.Background(), s, out, pkg.DefaultLimits(), supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.files[".packtell/extensions/org.example.demo/bad.json"].Bytes(), []byte{0xff, 0}) {
		t.Fatal(out)
	}
	injected := errors.New("extension interrupted")
	s.openOverride = func(p string, b []byte) io.ReadCloser {
		if p == path {
			return io.NopCloser(io.MultiReader(bytes.NewReader(b), portableErrorReader{injected}))
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	err := pkg.CopyExtensions(context.Background(), s, &memoryPayload{}, pkg.DefaultLimits(), supportAllVocabulary())
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	s.openOverride = func(p string, b []byte) io.ReadCloser {
		if p == path {
			return io.NopCloser(bytes.NewReader(append(bytes.Clone(b), 'x')))
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	err = pkg.CopyExtensions(context.Background(), s, &memoryPayload{}, pkg.DefaultLimits(), supportAllVocabulary())
	if !errors.Is(err, pkg.ErrUnstableWorkingTree) {
		t.Fatal(err)
	}
}
func TestCommitValidatesAndReservesMemoryIDs(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	n := baseNote()
	s.addFile(".packtell/metadata/notes.json", jsonBytes(t, noteDocument(n)))
	s.addFile("new.txt", []byte("new"))
	host := newCommitHost(s)
	commitRequest := request(pkg.HEAD(memoryID(2)))
	commitRequest.Tracking = map[string]pkg.UUID{"new.txt": pkg.UUID(n.NoteID)}
	_, err := pkg.Commit(context.Background(), host, commitRequest, pkg.DefaultLimits(), supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidSchema)
	for _, operation := range host.operations {
		if operation == "version-stage" || operation == "publish" {
			t.Fatal(host.operations)
		}
	}
	// Even a tombstoned Note ID remains reserved after ordinary successful commit.
	n.Deleted = true
	n.Body = ""
	s.setFile(".packtell/metadata/notes.json", jsonBytes(t, noteDocument(n)))
	host = newCommitHost(s)
	commitRequest.Tracking = nil
	v, err := pkg.Commit(context.Background(), host, commitRequest, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if pkg.UUID(v.Version.VersionID) == pkg.UUID(n.NoteID) {
		t.Fatal("Version reused Note ID")
	}
	for _, e := range v.Manifest.Entries {
		if e.ID() == pkg.UUID(n.NoteID) {
			t.Fatal("entry reused Note ID")
		}
	}
	bad := treeFixture(t, "core-minimal")
	n.Target.ID = memoryID(99)
	bad.addFile(".packtell/metadata/notes.json", jsonBytes(t, noteDocument(n)))
	host = newCommitHost(bad)
	_, err = pkg.Commit(context.Background(), host, request(pkg.HEAD(memoryID(2))), pkg.DefaultLimits(), supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidMetadata)
	if !reflect.DeepEqual(host.operations, []string{"begin", "abort", "close"}) {
		t.Fatal(host.operations)
	}
}

func TestLargeMemoryCollectionByteBudgetRejectsBeforeExpansion(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	m := readMemory(t, s)
	m.Notes.Revisions = make([]pkg.NoteRevision, 10000)
	for i := range m.Notes.Revisions {
		n := baseNote()
		n.Revision = int64(i) + 1
		m.Notes.Revisions[i] = n
	}
	l := pkg.DefaultLimits()
	l.MaxJSONBytes = 2048
	calls := 0
	_, err := pkg.PlanPortableMemoryUpdate(context.Background(), s, m, l, supportAllVocabulary(), factPolicyFunc(func(context.Context, map[string][]byte) error { calls++; return nil }), pkg.MemoryWriteIntent{})
	requireCode(t, err, pkg.ReasonResourceLimit)
	if calls != 0 {
		t.Fatal("oversized collection reached Host fact approval")
	}
}

func TestCommitPayloadUUIDNameDoesNotInventControlIdentity(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	path := string(memoryID(80))
	s.addFile(path, []byte("payload"))
	r := request(pkg.HEAD(memoryID(2)))
	r.Tracking = map[string]pkg.UUID{path: memoryID(80)}
	v, err := pkg.Commit(context.Background(), newCommitHost(s), r, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range v.Manifest.Entries {
		if e.Name == path {
			found = true
			if e.ID() != memoryID(80) {
				t.Fatal(e)
			}
		}
	}
	if !found {
		t.Fatal(v)
	}
}
