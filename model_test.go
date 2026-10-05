// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

var testTime = time.Date(2026, 10, 5, 0, 0, 0, 123456789, time.UTC)

const packageID pkg.PackageID = "019a0000-0000-7000-8000-000000000001"
const versionID pkg.VersionID = "019a0000-0000-7000-8000-000000000002"
const fileID pkg.FileID = "019a0000-0000-7000-8000-000000000003"
const folderID pkg.FolderID = "019a0000-0000-7000-8000-000000000004"

func sharedDocuments(t *testing.T, name string) map[string][]byte {
	t.Helper()
	raw, err := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input struct {
			Entries []struct {
				Path  string
				Bytes string `json:"bytes_base64"`
				Kind  string
			}
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range f.Input.Entries {
		if e.Kind == "file" {
			b, err := base64.StdEncoding.DecodeString(e.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			out[e.Path] = b
		}
	}
	return out
}
func manifest(t *testing.T, name string) pkg.Manifest {
	t.Helper()
	docs := sharedDocuments(t, name)
	paths := []string{}
	for p := range docs {
		if strings.HasSuffix(p, "/manifest.json") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	m, err := pkg.ReadManifest(context.Background(), bytes.NewReader(docs[paths[len(paths)-1]]), pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func versionBytes(t *testing.T) []byte {
	t.Helper()
	return sharedDocuments(t, "core-minimal")[".packtell/versions/"+string(versionID)+"/version.json"]
}
func TestS02SharedModelContracts(t *testing.T) {
	// Executes model parsing, identity and logical tree relationships only.
	// No full fixture result/Reader/Complete/codec conformance claim is made.
	for _, name := range []string{"core-minimal", "renamed-file", "moved-file", "modified-file"} {
		t.Run(name, func(t *testing.T) {
			docs := sharedDocuments(t, name)
			p, err := pkg.ReadPackage(context.Background(), bytes.NewReader(docs[".packtell/package.json"]), pkg.DefaultLimits())
			if err != nil || p.PackageID != packageID {
				t.Fatalf("Package: %#v %v", p, err)
			}
			inventory, _ := pkg.NewIdentityInventory(packageID)
			for path, b := range docs {
				if strings.HasSuffix(path, "/version.json") {
					v, err := pkg.ReadVersion(context.Background(), bytes.NewReader(b), pkg.DefaultLimits(), supportAllVocabulary())
					if err != nil || v.PackageID != packageID {
						t.Fatalf("Version: %#v %v", v, err)
					}
					if !strings.Contains(path, string(v.VersionID)) {
						t.Fatal("fixture Version/path mismatch")
					}
				}
				if strings.HasSuffix(path, "/manifest.json") {
					m, err := pkg.ReadManifest(context.Background(), bytes.NewReader(b), pkg.DefaultLimits())
					if err != nil {
						t.Fatal(err)
					}
					if err = inventory.Observe(context.Background(), m, pkg.DefaultLimits()); err != nil {
						t.Fatal(err)
					}
					if m.Entries[0].FileID != fileID {
						t.Fatal("fixture changed stable FileID")
					}
				}
			}
			m := manifest(t, name)
			e := m.Entries[0]
			if e.FileID != fileID {
				t.Fatal("lost identity")
			}
			switch name {
			case "renamed-file":
				if e.Name != "renamed.txt" {
					t.Fatal(e)
				}
			case "moved-file":
				if e.ParentFolderID == nil || *e.ParentFolderID != folderID || len(m.Entries) != 2 {
					t.Fatal(e)
				}
			case "modified-file":
				if e.ContentID == pkg.ContentIDForBytes([]byte("hello\n")) || e.Size != 8 {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestUUIDAndTimestampDomain(t *testing.T) {
	for _, s := range []string{"", "019A0000-0000-7000-8000-000000000001", "019a0000-0000-4000-8000-000000000001", "019a0000-0000-7000-7000-000000000001", "pf_123", string(fileID) + "\n"} {
		requireCode(t, pkg.UUID(s).Validate(), pkg.ReasonInvalidSchema)
	}
	for _, variant := range []string{"8", "9", "a", "b"} {
		if err := pkg.UUID("019a0000-0000-7000-" + variant + "000-000000000001").Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"0001-01-01T00:00:00.000000Z", "9999-12-31T23:59:59.999999Z", "2000-02-29T12:34:56.000001Z"} {
		if _, err := pkg.ParseTimestamp(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"0000-01-01T00:00:00.000000Z", "1900-02-29T00:00:00.000000Z", "2026-02-30T00:00:00.000000Z", "2026-01-01T00:00:60.000000Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.0000000Z", "2026-01-01T00:00:00.000000+00:00", "2026-01-01t00:00:00.000000z"} {
		_, err := pkg.ParseTimestamp(s)
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
	if s, err := pkg.Timestamp(testTime.In(time.FixedZone("Host", 3600))); err != nil || s != "2026-10-05T00:00:00.123456Z" {
		t.Fatalf("UTC/microseconds: %s %v", s, err)
	}
	if _, err := pkg.Timestamp(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted out of domain year")
	}
	if pkg.ContentIDForBytes([]byte("hello\n")) != pkg.ContentID("sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03") {
		t.Fatal("whole-file content mismatch")
	}
	if pkg.ContentIDForBytes([]byte("hello\r\n")) == pkg.ContentIDForBytes([]byte("hello\n")) {
		t.Fatal("normalized content bytes")
	}
}

type zeroEntropy struct{}

func (zeroEntropy) Read(b []byte) (int, error) { clear(b); return len(b), nil }
func TestUUIDGenerationCollisionsAndConcurrency(t *testing.T) {
	g, _ := pkg.NewIDGenerator(zeroEntropy{}, nil)
	id, err := g.Generate(context.Background(), time.UnixMilli(0))
	if err != nil || id != "00000000-0000-7000-8000-000000000000" {
		t.Fatalf("%s %v", id, err)
	}
	_, err = g.Generate(context.Background(), time.UnixMilli(0))
	requireCode(t, err, pkg.ReasonResourceLimit)
	g, _ = pkg.NewIDGenerator(zeroEntropy{}, []pkg.UUID{id})
	_, err = g.Generate(context.Background(), time.UnixMilli(0))
	requireCode(t, err, pkg.ReasonResourceLimit)
	_, err = pkg.NewIDGenerator(nil, []pkg.UUID{"bad"})
	requireCode(t, err, pkg.ReasonInvalidSchema)
	g, _ = pkg.NewIDGenerator(bytes.NewReader(nil), nil)
	if _, err = g.Generate(context.Background(), testTime); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	g, _ = pkg.NewIDGenerator(nil, nil)
	if err = g.Reserve("bad"); err == nil {
		t.Fatal("reserved malformed identity")
	}
	for _, at := range []time.Time{time.UnixMilli(-1), time.UnixMilli(0x1000000000000)} {
		_, err = g.Generate(context.Background(), at)
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = g.Generate(ctx, testTime); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[pkg.UUID]bool{}
	var wg sync.WaitGroup
	for n := 0; n < 128; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := g.Generate(context.Background(), testTime)
			if err != nil {
				t.Error(err)
				return
			}
			if err = id.Validate(); err != nil {
				t.Error(err)
			}
			raw, _ := hex.DecodeString(strings.ReplaceAll(string(id), "-", ""))
			var ms int64
			for _, v := range raw[:6] {
				ms = (ms << 8) | int64(v)
			}
			if ms != testTime.UnixMilli() {
				t.Error("incorrect UUID millisecond bits")
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[id] {
				t.Error("duplicate generation")
			}
			seen[id] = true
		}()
	}
	wg.Wait()
	if len(seen) != 128 {
		t.Fatal(len(seen))
	}
}
func TestImmutablePackageCreationFacts(t *testing.T) {
	g, _ := pkg.NewIDGenerator(nil, nil)
	p, err := pkg.NewPackage(context.Background(), g, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if p.CreatedAt != "2026-10-05T00:00:00.123456Z" || p.PackageID == "" {
		t.Fatal(p)
	}
	b, _ := json.Marshal(p)
	p2, err := pkg.ReadPackage(context.Background(), bytes.NewReader(b), pkg.DefaultLimits())
	if err != nil || p != p2 {
		t.Fatal("creation facts changed")
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, edit := range []func(map[string]any){func(m map[string]any) { m["extra"] = nil }, func(m map[string]any) { delete(m, "created_at") }, func(m map[string]any) { m["package_id"] = 123 }, func(m map[string]any) { m["created_at"] = "2026-02-30T00:00:00.000000Z" }} {
		var copy map[string]any
		json.Unmarshal(b, &copy)
		edit(copy)
		bad, _ := json.Marshal(copy)
		_, err := pkg.ReadPackage(context.Background(), bytes.NewReader(bad), pkg.DefaultLimits())
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
}
func TestVersionSchemaNegativesAndOptionalPreservation(t *testing.T) {
	base := versionBytes(t)
	for _, c := range []struct {
		name string
		edit func(map[string]any)
		code pkg.ReasonCode
	}{
		{"missing parent", func(m map[string]any) { delete(m, "parent_version_id") }, pkg.ReasonInvalidSchema},
		{"multiple parents", func(m map[string]any) { m["parent_version_id"] = []string{string(versionID)} }, pkg.ReasonInvalidSchema},
		{"zero ordinal", func(m map[string]any) { m["ordinal"] = 0 }, pkg.ReasonInvalidSchema},
		{"too large ordinal", func(m map[string]any) { m["ordinal"] = 9007199254740992 }, pkg.ReasonInvalidSchema},
		{"fractional ordinal", func(m map[string]any) { m["ordinal"] = 1.5 }, pkg.ReasonInvalidSchema},
		{"missing title", func(m map[string]any) { m["sealed_metadata"] = map[string]any{} }, pkg.ReasonInvalidSchema},
		{"null label", func(m map[string]any) { m["label"] = nil }, pkg.ReasonInvalidSchema},
		{"bad metadata namespace", func(m map[string]any) {
			m["sealed_metadata"] = map[string]any{"title": "", "extensions": map[string]any{"bad_name": true}}
		}, pkg.ReasonInvalidSchema},
		{"unsupported historical capability", func(m map[string]any) {
			m["required_capabilities"] = []string{pkg.CapabilityContentSHA256, pkg.CapabilityLinearHistory, "org.example.required"}
		}, pkg.ReasonUnknownRequiredCapability},
		{"bad protocol", func(m map[string]any) { m["protocol_version"] = "1.0" }, pkg.ReasonUnsupportedProtocol},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(base, &m)
			c.edit(m)
			b, _ := json.Marshal(m)
			_, err := pkg.ReadVersion(context.Background(), bytes.NewReader(b), pkg.DefaultLimits(), supportAllVocabulary())
			requireCode(t, err, c.code)
		})
	}
	var m map[string]any
	json.Unmarshal(base, &m)
	m["label"] = ""
	m["org.example.fact"] = map[string]any{"x": []any{true, nil, "\u2028"}}
	m["sealed_metadata"] = map[string]any{"title": "", "org.example.fact": int64(42), "extensions": map[string]any{"org.example": map[string]any{"nested": "yes"}}}
	b, _ := json.Marshal(m)
	v, err := pkg.ReadVersion(context.Background(), bytes.NewReader(b), pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := pkg.ReadVersion(context.Background(), bytes.NewReader(encoded), pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil || !reflect.DeepEqual(v, v2) {
		t.Fatalf("lost optional facts: %v", err)
	}
	if v.ParentVersionID != nil || !bytes.Contains(encoded, []byte(`"parent_version_id":null`)) {
		t.Fatal("root parent omitted")
	}
	v.Label = nil
	v.Extra["label"] = true
	if _, err = json.Marshal(v); err == nil {
		t.Fatal("extra shadows absent label")
	}
}
func TestManifestSchemaTopologyAndNFC(t *testing.T) {
	base := manifest(t, "core-minimal")
	raw, _ := json.Marshal(base)
	for _, c := range []struct {
		name string
		edit func(map[string]any)
		code pkg.ReasonCode
	}{
		{"null entries", func(m map[string]any) { m["entries"] = nil }, pkg.ReasonInvalidSchema},
		{"both identities", func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["folder_id"] = folderID }, pkg.ReasonInvalidSchema},
		{"missing parent", func(m map[string]any) { delete(m["entries"].([]any)[0].(map[string]any), "parent_folder_id") }, pkg.ReasonInvalidSchema},
		{"missing size", func(m map[string]any) { delete(m["entries"].([]any)[0].(map[string]any), "size") }, pkg.ReasonInvalidSchema},
		{"negative size", func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["size"] = -1 }, pkg.ReasonInvalidSchema},
		{"path name", func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["name"] = "a/b" }, pkg.ReasonInvalidSchema},
		{"empty name", func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["name"] = "" }, pkg.ReasonInvalidSchema},
		{"non NFC", func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["name"] = "e\u0301" }, pkg.ReasonInvalidPath},
		{"orphan", func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["parent_folder_id"] = folderID }, pkg.ReasonInvalidSchema},
		{"duplicate IDs", func(m map[string]any) { e := m["entries"].([]any)[0]; m["entries"] = []any{e, e} }, pkg.ReasonInvalidSchema},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			c.edit(m)
			b, _ := json.Marshal(m)
			_, err := pkg.ReadManifest(context.Background(), bytes.NewReader(b), pkg.DefaultLimits())
			requireCode(t, err, c.code)
		})
	}
	root := pkg.Entry{Kind: "folder", FolderID: folderID, Name: "empty"}
	m := base
	m.Entries = []pkg.Entry{root}
	if err := m.Validate(context.Background(), pkg.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	m.Entries[0].ParentFolderID = &root.FolderID
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidSchema)
	m = manifest(t, "moved-file")
	m.Entries[0].ParentFolderID = (*pkg.FolderID)(ptrFileID(fileID))
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidSchema)
	m = base
	second := base.Entries[0]
	second.FileID = "019a0000-0000-7000-8000-000000000008"
	second.Name = "another"
	second.Size++
	m.Entries = append(m.Entries, second)
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidSchema)
	second.Size = base.Entries[0].Size
	second.Name = base.Entries[0].Name
	m.Entries = []pkg.Entry{base.Entries[0], second}
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidSchema)
	m = manifest(t, "moved-file")
	m.Entries[0], m.Entries[1] = m.Entries[1], m.Entries[0]
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidSchema)
	root.Extra = map[string]any{"file_id": nil}
	if _, err := json.Marshal(root); err == nil {
		t.Fatal("extra shadows forbidden branch field")
	}
}
func ptrFileID(id pkg.FileID) *pkg.FileID { return &id }
func TestTreeIdentityOperationsAndProposalIsolation(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	m := manifest(t, "moved-file")
	before, _ := json.Marshal(m)
	m.Extra = map[string]any{"org.example": map[string]any{"fact": "old"}}
	m.Entries[0].Extra = map[string]any{"org.example": map[string]any{"fact": "old"}}
	rename, err := m.WithPlacement(ctx, pkg.UUID(fileID), m.Entries[0].ParentFolderID, "new.txt", l)
	if err != nil || rename.Entries[0].FileID != fileID || rename.Entries[0].ContentID != m.Entries[0].ContentID {
		t.Fatal(err)
	}
	rename.Extra["org.example"].(map[string]any)["fact"] = "new"
	rename.Entries[0].Extra["org.example"].(map[string]any)["fact"] = "new"
	if m.Extra["org.example"].(map[string]any)["fact"] != "old" || m.Entries[0].Extra["org.example"].(map[string]any)["fact"] != "old" {
		t.Fatal("mutated committed optional facts")
	}
	move, err := m.WithPlacement(ctx, pkg.UUID(fileID), nil, "hello.txt", l)
	if err != nil || move.Entries[0].FileID != fileID || move.Entries[0].ParentFolderID != nil {
		t.Fatal(err)
	}
	folderRename, err := m.WithPlacement(ctx, pkg.UUID(folderID), nil, "renamedFolder", l)
	if err != nil || folderRename.Entries[1].FolderID != folderID || *folderRename.Entries[0].ParentFolderID != folderID {
		t.Fatal("folder continuity")
	}
	newContent := pkg.ContentIDForBytes([]byte("updated"))
	modified, err := m.WithContent(ctx, fileID, newContent, 7, l)
	if err != nil || modified.Entries[0].FileID != fileID || modified.Entries[0].ContentID == m.Entries[0].ContentID {
		t.Fatal(err)
	}
	g, _ := pkg.NewIDGenerator(nil, nil)
	copy, err := m.CopyFile(ctx, g, testTime, fileID, nil, "copy.txt", l)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range copy.Entries {
		if e.Name == "copy.txt" {
			found = true
			if e.FileID == fileID || e.ContentID != m.Entries[0].ContentID {
				t.Fatal("copy identity/content")
			}
		}
	}
	if !found {
		t.Fatal("no copy")
	}
	f, err := pkg.NewFolderEntry(ctx, g, testTime, nil, "empty")
	if err != nil || f.FolderID == "" || f.ContentID != "" {
		t.Fatal(err)
	}
	created, err := pkg.NewFileEntry(ctx, g, testTime, nil, "new.txt", newContent, 7)
	if err != nil || created.FileID == fileID || created.FolderID != "" {
		t.Fatal(err)
	}
	m.Extra = nil
	m.Entries[0].Extra = nil
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("source manifest mutated")
	}
	if _, err = m.WithPlacement(ctx, pkg.UUID(folderID), func() *pkg.FolderID { id := folderID; return &id }(), "cycle", l); err == nil {
		t.Fatal("allowed folder cycle")
	}
	inventory, _ := pkg.NewIdentityInventory(packageID)
	if err = inventory.Observe(ctx, m, l); err != nil {
		t.Fatal(err)
	}
	changed := m
	changed.Entries = []pkg.Entry{{Kind: "folder", FolderID: pkg.FolderID(fileID), Name: "newKind"}}
	requireCode(t, inventory.Observe(ctx, changed, l), pkg.ReasonInvalidSchema)
	changed = manifest(t, "core-minimal")
	changed.PackageID = "019a0000-0000-7000-8000-000000000099"
	requireCode(t, inventory.Observe(ctx, changed, l), pkg.ReasonInvalidSchema)
}

func FuzzProtocolModels(f *testing.F) {
	for _, seed := range []string{`{}`, `{"schema":[]}`, `{"entries":[]}`, `{"entries":[null]}`, `{"parent_version_id":[]}`, `null`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l := pkg.DefaultLimits()
		l.MaxJSONBytes = 32768
		l.MaxJSONDepth = 16
		l.MaxEntries = 100
		ctx := context.Background()
		if p, err := pkg.ReadPackage(ctx, bytes.NewReader(b), l); err == nil {
			out, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pkg.ReadPackage(ctx, bytes.NewReader(out), l); err != nil {
				t.Fatal(err)
			}
		}
		if v, err := pkg.ReadVersion(ctx, bytes.NewReader(b), l, supportAllVocabulary()); err == nil {
			out, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pkg.ReadVersion(ctx, bytes.NewReader(out), l, supportAllVocabulary()); err != nil {
				t.Fatal(err)
			}
		}
		if m, err := pkg.ReadManifest(ctx, bytes.NewReader(b), l); err == nil {
			out, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pkg.ReadManifest(ctx, bytes.NewReader(out), l); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestModelLimitsCancellationAndRequiredFields(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	m := manifest(t, "moved-file")
	small := l
	small.MaxEntries = 1
	requireCode(t, m.Validate(ctx, small), pkg.ReasonResourceLimit)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := m.Validate(cancelled, l); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	v, err := pkg.ReadVersion(ctx, bytes.NewReader(versionBytes(t)), l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Validate(ctx, l, supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	v.Ordinal = 0
	requireCode(t, v.Validate(ctx, l, supportAllVocabulary()), pkg.ReasonInvalidSchema)
	var object map[string]any
	json.Unmarshal(versionBytes(t), &object)
	for key := range object {
		var c map[string]any
		json.Unmarshal(versionBytes(t), &c)
		delete(c, key)
		b, _ := json.Marshal(c)
		_, err := pkg.ReadVersion(ctx, bytes.NewReader(b), l, supportAllVocabulary())
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
	rootA := pkg.FolderID("019a0000-0000-7000-8000-000000000010")
	rootB := pkg.FolderID("019a0000-0000-7000-8000-000000000011")
	m.Entries = []pkg.Entry{{Kind: "folder", FolderID: rootA, ParentFolderID: &rootB, Name: "a"}, {Kind: "folder", FolderID: rootB, ParentFolderID: &rootA, Name: "b"}}
	requireCode(t, m.Validate(ctx, l), pkg.ReasonInvalidSchema)
}

func TestUninitializedGeneratorFailsWithoutPanic(t *testing.T) {
	for _, g := range []*pkg.IDGenerator{nil, {}} {
		if _, err := g.Generate(context.Background(), testTime); err == nil {
			t.Fatal("uninitialized generator accepted")
		}
		if err := g.Reserve(pkg.UUID(fileID)); err == nil {
			t.Fatal("uninitialized generator reserve accepted")
		}
	}
}
