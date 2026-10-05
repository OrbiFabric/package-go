// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

type memorySource struct {
	entries                []pkg.TreeEntry
	data                   map[string][]byte
	opens                  []string
	checks, closes         int
	checkError, closeError error
	openOverride           func(string, []byte) io.ReadCloser
}

func (s *memorySource) BeginSnapshot(context.Context) (pkg.TreeSnapshot, error) { return s, nil }
func (s *memorySource) List(_ context.Context, max int) ([]pkg.TreeEntry, error) {
	if len(s.entries) > max {
		return nil, &pkg.ProtocolError{Code: pkg.ReasonResourceLimit}
	}
	return append([]pkg.TreeEntry{}, s.entries...), nil
}
func (s *memorySource) Open(_ context.Context, p string) (io.ReadCloser, error) {
	s.opens = append(s.opens, p)
	b, ok := s.data[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if s.openOverride != nil {
		return s.openOverride(p, b), nil
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (s *memorySource) CheckStable(context.Context) error { s.checks++; return s.checkError }
func (s *memorySource) Close() error                      { s.closes++; return s.closeError }
func treeFixture(t *testing.T, name string) *memorySource {
	t.Helper()
	raw, err := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input struct {
			Entries []struct {
				Path, Kind string
				Bytes      string `json:"bytes_base64"`
			}
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	s := &memorySource{data: map[string][]byte{}}
	for _, e := range f.Input.Entries {
		entry := pkg.TreeEntry{Path: e.Path, Kind: e.Kind}
		if e.Kind == "file" {
			b, err := base64.StdEncoding.DecodeString(e.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			entry.Size = int64(len(b))
			s.data[e.Path] = b
		}
		s.entries = append(s.entries, entry)
	}
	return s
}
func (s *memorySource) addFile(p string, b []byte) {
	s.data[p] = bytes.Clone(b)
	s.entries = append(s.entries, pkg.TreeEntry{Path: p, Kind: "file", Size: int64(len(b))})
}
func (s *memorySource) setFile(p string, b []byte) {
	s.data[p] = bytes.Clone(b)
	for i, e := range s.entries {
		if e.Path == p {
			s.entries[i].Size = int64(len(b))
		}
	}
}
func (s *memorySource) remove(p string) {
	delete(s.data, p)
	out := []pkg.TreeEntry{}
	for _, e := range s.entries {
		if strings.TrimSuffix(e.Path, "/") != p {
			out = append(out, e)
		}
	}
	s.entries = out
}
func TestS03SharedTreeBehavior(t *testing.T) {
	for _, c := range []struct {
		name  string
		state pkg.WorkingState
		code  pkg.ReasonCode
	}{
		{"unborn", pkg.WorkingUnborn, ""}, {"invalid-head-crlf", pkg.WorkingUnreadable, pkg.ReasonInvalidHEAD}, {"dirty-working-tree", pkg.WorkingDirty, ""}, {"path-traversal", pkg.WorkingUnreadable, pkg.ReasonPathTraversal}, {"case-conflict", pkg.WorkingUnreadable, pkg.ReasonCaseConflict}, {"unicode-normalization-conflict", pkg.WorkingUnreadable, pkg.ReasonUnicodeNormalizationConflict},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := treeFixture(t, c.name)
			raw, loadErr := fs.ReadFile(conformance.Assets(), "fixtures/"+c.name+".json")
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			var shared struct{ Expected pkg.Result }
			if loadErr = json.Unmarshal(raw, &shared); loadErr != nil {
				t.Fatal(loadErr)
			}
			scan, err := pkg.Scan(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if scan.State != c.state {
				t.Fatalf("state %s want %s (%v)", scan.State, c.state, err)
			}
			if c.code != "" {
				requireCode(t, err, c.code)
			} else if err != nil {
				t.Fatal(err)
			}
			if scan.Root.Recognition != shared.Expected.Recognition {
				t.Fatalf("recognition %s want frozen %s", scan.Root.Recognition, shared.Expected.Recognition)
			}
			if shared.Expected.WorkingState != pkg.WorkingNotChecked && scan.State != shared.Expected.WorkingState {
				t.Fatalf("working state %s want frozen %s", scan.State, shared.Expected.WorkingState)
			}
			for _, code := range shared.Expected.ReasonCodes {
				if code == pkg.ReasonOK {
					if err != nil {
						t.Fatalf("frozen OK behavior failed: %v", err)
					}
				} else {
					requireCode(t, err, code)
				}
			}
			if s.checks != 1 || s.closes != 1 {
				t.Fatal("snapshot lifecycle leaked")
			}
			if c.code == pkg.ReasonPathTraversal || c.code == pkg.ReasonCaseConflict || c.code == pkg.ReasonUnicodeNormalizationConflict {
				for _, p := range s.opens {
					if p != ".packtell/format.json" {
						t.Fatalf("opened unsafe input payload/history: %q", p)
					}
				}
			}
			if c.name == "dirty-working-tree" {
				if scan.Root.HEAD != pkg.HEAD(versionID) || len(scan.Changes) != 1 || scan.Changes[0].Type != pkg.ChangeContent {
					t.Fatal("dirty changed HEAD or fabricated path change")
				}
				object := ".packtell/objects/sha256/58/5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
				if !bytes.Equal(s.data[object], []byte("hello\n")) {
					t.Fatal("dirty mutated committed object")
				}
				committed := scan.Root.HeadManifest.Entries[0]
				if err := pkg.CopyVerifiedContent(context.Background(), io.Discard, bytes.NewReader(s.data[object]), committed.ContentID, committed.Size, pkg.DefaultLimits()); err != nil {
					t.Fatal("DIRTY invalidated committed integrity", err)
				}
			}
		})
	}
	// Full history/integrity/signature/evidence dimensions are NOT_CHECKED at S03.
	// These are stage behavior checks, not seven-level conformance certification.
}
func TestRootRecognitionAndControlAllowlist(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	s := &memorySource{data: map[string][]byte{}}
	root, err := pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	if root.Recognition != pkg.NotPackage {
		t.Fatal(root.Recognition)
	}
	requireCode(t, err, pkg.ReasonNotPackage)
	s = treeFixture(t, "core-minimal")
	s.addFile("nested/.packtell/format.json", []byte(`{}`))
	if _, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary()); err != nil {
		t.Fatal("nested control altered outer authority", err)
	}
	for _, p := range []string{".packtell/cache/state.json", ".packtell/refs/main", ".packtell/version-subject.json", ".packtell/metadata/unknown.json", ".packtell/versions/" + string(versionID) + "/extra.json", ".packtell/objects/sha256/ff/" + strings.Repeat("0", 64), ".packtell/evidence/objects/not-a-uuid.json"} {
		s = treeFixture(t, "core-minimal")
		s.addFile(p, []byte("{}"))
		_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
		requireCode(t, err, pkg.ReasonInvalidSchema)
		for _, opened := range s.opens {
			if opened == "hello.txt" {
				t.Fatal("opened payload before control validation")
			}
		}
	}
	s = treeFixture(t, "core-minimal")
	s.remove(".packtell/versions/" + string(versionID) + "/manifest.json")
	_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidSchema)
	s = treeFixture(t, "unborn")
	s.setFile(".packtell/HEAD", []byte(string(versionID)+"\n"))
	_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonMissingParent)
	s = treeFixture(t, "core-minimal")
	s.setFile(".packtell/HEAD", []byte("unborn\n"))
	_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonNonLinearHistory)
	s = treeFixture(t, "unknown-required-capability")
	_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonUnknownRequiredCapability)
	if !reflect.DeepEqual(s.opens, []string{".packtell/format.json"}) {
		t.Fatal("unsupported capability read history/payload")
	}
	s = treeFixture(t, "unknown-optional-extension")
	if _, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary()); err != nil {
		t.Fatal("optional extension lost", err)
	}
	s = treeFixture(t, "core-minimal")
	s.addFile(".packtell/extensions/org.example/data", []byte("opaque"))
	_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidSchema)
	s = treeFixture(t, "core-minimal")
	var f map[string]any
	json.Unmarshal(s.data[".packtell/format.json"], &f)
	f["extensions"] = []any{map[string]any{"namespace": "org.example", "required_capability": nil}}
	b, _ := json.Marshal(f)
	s.setFile(".packtell/format.json", b)
	_, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonInvalidSchema)
	s.entries = append(s.entries, pkg.TreeEntry{Path: ".packtell/extensions/org.example/", Kind: "directory"})
	if _, err = pkg.ReadRoot(ctx, s, l, supportAllVocabulary()); err != nil {
		t.Fatal("declared empty extension rejected", err)
	}
}
func TestWorkingTreeDiffIdentityProof(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	s := treeFixture(t, "core-minimal")
	s.remove("hello.txt")
	s.addFile("renamed.txt", []byte("hello\n"))
	scan, err := pkg.Scan(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Changes) != 2 || scan.Changes[0].Type != pkg.ChangeAdded || scan.Changes[1].Type != pkg.ChangeRemoved {
		t.Fatal("equal bytes fabricated rename", scan.Changes)
	}
	s = treeFixture(t, "core-minimal")
	s.remove("hello.txt")
	s.addFile("folder/renamed.txt", []byte("updated\n"))
	scan, err = pkg.Scan(ctx, s, l, supportAllVocabulary(), map[string]pkg.UUID{"folder/renamed.txt": pkg.UUID(fileID), "folder": pkg.UUID(folderID)})
	if err != nil {
		t.Fatal(err)
	}
	path, content := false, false
	for _, c := range scan.Changes {
		if c.ID == pkg.UUID(fileID) && c.Type == pkg.ChangePath {
			path = true
		}
		if c.ID == pkg.UUID(fileID) && c.Type == pkg.ChangeContent {
			content = true
		}
	}
	if !path || !content {
		t.Fatal("path/content not reported separately", scan.Changes)
	}
	s = treeFixture(t, "core-minimal")
	s.addFile("copy.txt", []byte("hello\n"))
	scan, err = pkg.Scan(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || len(scan.Changes) != 1 || scan.Changes[0].Type != pkg.ChangeAdded || scan.Changes[0].ID != "" {
		t.Fatal("copy continuity fabricated", scan.Changes, err)
	}
	s = treeFixture(t, "core-minimal")
	s.addFile("copy.txt", []byte("hello\n"))
	_, err = pkg.Scan(ctx, s, l, supportAllVocabulary(), map[string]pkg.UUID{"copy.txt": pkg.UUID(fileID)})
	requireCode(t, err, pkg.ReasonInvalidSchema)
	s = treeFixture(t, "core-minimal")
	_, err = pkg.Scan(ctx, s, l, supportAllVocabulary(), map[string]pkg.UUID{"absent": pkg.UUID(fileID)})
	requireCode(t, err, pkg.ReasonInvalidSchema)
	s = treeFixture(t, "moved-file")
	scan, err = pkg.Scan(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || scan.State != pkg.WorkingClean {
		t.Fatal(scan.State, scan.Changes, scan.Entries, err)
	}
	s.entries = append(s.entries, pkg.TreeEntry{Path: "empty/", Kind: "directory"})
	scan, err = pkg.Scan(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || scan.State != pkg.WorkingDirty || len(scan.Changes) != 1 || scan.Changes[0].AfterPath != "empty" {
		t.Fatal("empty folder missing from diff", scan, err)
	}
}
func TestStableScanFailureDoesNotPublishPartialProposal(t *testing.T) {
	for _, failure := range []error{pkg.ErrUnstableWorkingTree, io.ErrClosedPipe} {
		s := treeFixture(t, "core-minimal")
		s.checkError = failure
		scan, err := pkg.Scan(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
		if !errors.Is(err, failure) || scan.State != pkg.WorkingUnreadable || scan.Entries != nil || scan.Changes != nil || s.closes != 1 {
			t.Fatal("partial scan advertised success", scan, err)
		}
	}
	s := treeFixture(t, "core-minimal")
	s.openOverride = func(p string, b []byte) io.ReadCloser {
		if p == "hello.txt" {
			b = append(bytes.Clone(b), '!')
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	scan, err := pkg.Scan(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if !errors.Is(err, pkg.ErrUnstableWorkingTree) || scan.State != pkg.WorkingUnreadable {
		t.Fatal("changed stream size accepted", scan, err)
	}
	s = treeFixture(t, "core-minimal")
	s.closeError = io.ErrClosedPipe
	scan, err = pkg.Scan(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if !errors.Is(err, io.ErrClosedPipe) || scan.State != pkg.WorkingUnreadable {
		t.Fatal("ignored snapshot close failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = treeFixture(t, "core-minimal")
	_, err = pkg.Scan(ctx, s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if !errors.Is(err, context.Canceled) || s.closes != 0 {
		t.Fatal("began cancelled observation")
	}
}

// diskHost is a test Host adapter for actual local filesystem changes. It uses
// file metadata solely to detect changed observations, not logical identity.
// Production authorized/no-follow adapters are a separate Host/codec stage.
type diskHost struct {
	root          string
	mutateOnClose func()
}
type diskSnapshot struct {
	host    *diskHost
	entries []pkg.TreeEntry
	tokens  map[string]string
}

func (h *diskHost) BeginSnapshot(ctx context.Context) (pkg.TreeSnapshot, error) {
	entries, tokens, err := diskInventory(ctx, h.root)
	if err != nil {
		return nil, err
	}
	return &diskSnapshot{h, entries, tokens}, nil
}
func diskInventory(ctx context.Context, root string) ([]pkg.TreeEntry, map[string]string, error) {
	entries := []pkg.TreeEntry{}
	tokens := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		kind := "file"
		size := info.Size()
		if info.IsDir() {
			kind = "directory"
			size = 0
		} else if !info.Mode().IsRegular() {
			kind = "symlink"
		}
		entries = append(entries, pkg.TreeEntry{Path: rel, Kind: kind, Size: size})
		tokens[rel] = info.ModTime().UTC().Format(time.RFC3339Nano) + "/" + info.Mode().String() + "/" + strconv.FormatInt(info.Size(), 10)
		return nil
	})
	return entries, tokens, err
}
func (s *diskSnapshot) List(_ context.Context, max int) ([]pkg.TreeEntry, error) {
	if len(s.entries) > max {
		return nil, &pkg.ProtocolError{Code: pkg.ReasonResourceLimit}
	}
	return s.entries, nil
}
func (s *diskSnapshot) Open(ctx context.Context, p string) (io.ReadCloser, error) {
	path := s.host.root
	for _, part := range strings.Split(p, "/") {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, &pkg.ProtocolError{Code: pkg.ReasonInvalidPath}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if p == "hello.txt" && s.host.mutateOnClose != nil {
		return closeHook{f, s.host.mutateOnClose}, nil
	}
	return f, nil
}
func (s *diskSnapshot) CheckStable(ctx context.Context) error {
	_, tokens, err := diskInventory(ctx, s.host.root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(tokens, s.tokens) {
		return pkg.ErrUnstableWorkingTree
	}
	return nil
}
func (*diskSnapshot) Close() error { return nil }

type closeHook struct {
	io.ReadCloser
	hook func()
}

func (c closeHook) Close() error { err := c.ReadCloser.Close(); c.hook(); return err }
func materializeTestRoot(t *testing.T, s *memorySource) string {
	t.Helper()
	root := t.TempDir()
	nodes, err := pkg.PreflightTree(context.Background(), s.entries, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range nodes {
		p := filepath.Join(root, filepath.FromSlash(e.Path))
		if e.Kind == "directory" {
			if err = os.MkdirAll(p, 0700); err != nil {
				t.Fatal(err)
			}
		} else {
			if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(p, s.data[e.Path], 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}
func TestActualFolderExternalEditAndScanRace(t *testing.T) {
	root := materializeTestRoot(t, treeFixture(t, "core-minimal"))
	host := &diskHost{root: root}
	ctx := context.Background()
	l := pkg.DefaultLimits()
	scan, err := pkg.Scan(ctx, host, l, supportAllVocabulary(), nil)
	if err != nil || scan.State != pkg.WorkingClean {
		t.Fatal(scan.State, err)
	}
	file := filepath.Join(root, "hello.txt")
	if err = os.Chtimes(file, time.Unix(10, 0), time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	scan, err = pkg.Scan(ctx, host, l, supportAllVocabulary(), nil)
	if err != nil || scan.State != pkg.WorkingClean {
		t.Fatal("mtime entered logical identity", scan.State, err)
	}
	if err = os.WriteFile(file, []byte("edited\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scan, err = pkg.Scan(ctx, host, l, supportAllVocabulary(), nil)
	if err != nil || scan.State != pkg.WorkingDirty {
		t.Fatal(scan.State, err)
	}
	head, _ := os.ReadFile(filepath.Join(root, ".packtell", "HEAD"))
	object, _ := os.ReadFile(filepath.Join(root, ".packtell", "objects", "sha256", "58", "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"))
	if string(head) != string(versionID)+"\n" || string(object) != "hello\n" {
		t.Fatal("external edit rewrote historical authority")
	}
	host.mutateOnClose = func() {
		if err := os.WriteFile(file, []byte("changed during scan\n"), 0600); err != nil {
			t.Error(err)
		}
	}
	scan, err = pkg.Scan(ctx, host, l, supportAllVocabulary(), nil)
	if !errors.Is(err, pkg.ErrUnstableWorkingTree) || scan.State != pkg.WorkingUnreadable || scan.Entries != nil {
		t.Fatal("actual scan race accepted", scan, err)
	}
	host.mutateOnClose = nil
	if err = os.Symlink(file, filepath.Join(root, "alias")); err != nil {
		t.Skipf("actual symlink creation unavailable: %v", err)
	}
	scan, err = pkg.Scan(ctx, host, l, supportAllVocabulary(), nil)
	requireCode(t, err, pkg.ReasonInvalidPath)
	if scan.State != pkg.WorkingUnreadable {
		t.Fatal("actual symlink followed")
	}
}

func TestDiffRejectsIncompleteOrInconsistentObservations(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	head := manifest(t, "core-minimal")
	content := pkg.ContentIDForBytes([]byte("hello\n"))
	_, err := pkg.Diff(ctx, head, []pkg.WorkingEntry{{Path: "a", Kind: "file", ContentID: content, Size: 6}, {Path: "b", Kind: "file", ContentID: content, Size: 7}}, l)
	requireCode(t, err, pkg.ReasonInvalidSchema)
	_, err = pkg.Diff(ctx, head, []pkg.WorkingEntry{{Path: "folder/file", Kind: "file", ContentID: content, Size: 6}}, l)
	requireCode(t, err, pkg.ReasonInvalidSchema)
	small := l
	small.MaxEntries = 1
	_, err = pkg.Diff(ctx, head, []pkg.WorkingEntry{{Path: "a", Kind: "directory"}, {Path: "b", Kind: "directory"}}, small)
	requireCode(t, err, pkg.ReasonResourceLimit)
}
