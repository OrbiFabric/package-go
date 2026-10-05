// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packagego_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

func directoryFixture(t *testing.T, name string) (string, *memorySource) {
	t.Helper()
	s := treeFixture(t, name)
	root := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := pkg.PreflightTree(context.Background(), s.entries, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		path := filepath.Join(root, filepath.FromSlash(e.Path))
		if e.Kind == "directory" {
			err = os.Mkdir(path, 0700)
		} else {
			err = os.WriteFile(path, s.data[e.Path], 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return root, s
}
func nativeDirectorySource(t *testing.T, root string) pkg.SnapshotSource {
	t.Helper()
	s, err := pkg.NewDirectorySource(root, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func nativeDirectoryHost(t *testing.T, destination string) pkg.DirectoryHost {
	t.Helper()
	h, err := pkg.NewDirectoryHost(destination, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func readDirectoryBytes(t *testing.T, root string) ([]pkg.TreeEntry, map[string][]byte) {
	t.Helper()
	ctx := context.Background()
	s, err := nativeDirectorySource(t, root).BeginSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	entries, err := s.List(ctx, 100000)
	if err != nil {
		t.Fatal(err)
	}
	data := map[string][]byte{}
	for _, e := range entries {
		if e.Kind != "file" {
			continue
		}
		r, err := s.Open(ctx, e.Path)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		err = errors.Join(err, r.Close())
		if err != nil {
			t.Fatal(err)
		}
		data[e.Path] = b
	}
	if err := s.CheckStable(ctx); err != nil {
		t.Fatal(err)
	}
	return entries, data
}
func assertNoDirectoryOutput(t *testing.T, parent, destination string) {
	t.Helper()
	if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("destination appeared: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".package-pending-") {
			t.Fatalf("pending leaked after handled failure: %s", e.Name())
		}
	}
}

func TestS08FrozenDirectoryRoundTrips(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	for _, name := range []string{"minimal-valid", "complete-history", "dirty-working-tree", "moved-file", "unknown-optional-extension"} {
		t.Run(name, func(t *testing.T) {
			root, _ := directoryFixture(t, name)
			// Explicit empty folders supplement, without editing frozen fixtures.
			if err := os.MkdirAll(filepath.Join(root, "empty", "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			beforeEntries, before := readDirectoryBytes(t, root)
			destination := filepath.Join(t.TempDir(), "output")
			result, err := pkg.PublishDirectory(ctx, nativeDirectorySource(t, root), nativeDirectoryHost(t, destination), l, support)
			if err != nil || result.PackageID == "" || result.Entries != len(beforeEntries) {
				t.Fatal(result, err)
			}
			afterEntries, after := readDirectoryBytes(t, destination)
			if !slices.Equal(beforeEntries, afterEntries) || !reflect.DeepEqual(before, after) {
				t.Fatal("tree bytes/empty directories changed")
			}
			for _, path := range []string{".packtell/HEAD", "hello.txt"} {
				if _, known := before[path]; known && !bytes.Equal(before[path], after[path]) {
					t.Fatal(path)
				}
			}
			snapshot, err := nativeDirectorySource(t, destination).BeginSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			history, err := pkg.ReadHistory(ctx, snapshot, l, support)
			if err != nil {
				t.Fatal(err)
			}
			content, err := pkg.VerifyCommittedContent(ctx, snapshot, l, support)
			if err != nil || content.Integrity != pkg.IntegrityValid || len(content.Missing) != 0 || len(content.Invalid) != 0 {
				t.Fatal(content, err)
			}
			memory, err := pkg.ReadPortableMemory(ctx, snapshot, l, support)
			if err != nil || len(memory.MissingPaths) != 0 {
				t.Fatal(memory, err)
			}
			for _, version := range history.Versions {
				original, _ := treeFixture(t, name).BeginSnapshot(ctx)
				_, want, err := pkg.DeriveSubjectAt(ctx, original, version.Version.VersionID, l, support)
				if err != nil {
					t.Fatal(err)
				}
				_, got, err := pkg.DeriveSubjectAt(ctx, snapshot, version.Version.VersionID, l, support)
				if err != nil || got != want {
					t.Fatal(got, want, err)
				}
				if err := original.Close(); err != nil {
					t.Fatal(err)
				}
				// Restore EVERY Version from the exported offline object tree into
				// real independent files, without source Working Tree or Resolver.
				restored := filepath.Join(t.TempDir(), "historical-payload")
				tx, err := nativeDirectoryHost(t, restored).BeginDirectory(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = pkg.MaterializeVersionPayload(ctx, snapshot, version.Version.VersionID, tx, l, support); err != nil {
					t.Fatal(err)
				}
				sealed, err := tx.Seal(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = sealed.List(ctx, l.MaxEntries); err != nil {
					t.Fatal(err)
				}
				if err = sealed.CheckStable(ctx); err != nil {
					t.Fatal(err)
				}
				if err = sealed.Close(); err != nil {
					t.Fatal(err)
				}
				if err = tx.Publish(ctx); err != nil {
					t.Fatal(err)
				}
				if err = tx.Abort(ctx); err != nil {
					t.Fatal(err)
				}
				paths, err := version.Manifest.Paths(ctx, l)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range version.Manifest.Entries {
					path := filepath.Join(restored, filepath.FromSlash(paths[e.ID()]))
					stat, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					if e.Kind == "folder" {
						if !stat.IsDir() {
							t.Fatal(path)
						}
						continue
					}
					object, _ := (pkg.ContentObjectRef{ContentID: e.ContentID, Size: e.Size}).ObjectPath()
					b, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(b, after[object]) {
						t.Fatal(path, err)
					}
					var fileStat, objectStat syscall.Stat_t
					if err = syscall.Stat(path, &fileStat); err != nil {
						t.Fatal(err)
					}
					if err = syscall.Stat(filepath.Join(destination, object), &objectStat); err != nil {
						t.Fatal(err)
					}
					if fileStat.Ino == objectStat.Ino && fileStat.Dev == objectStat.Dev {
						t.Fatal("restoration depends on hard links")
					}
				}
			}
			if err = snapshot.CheckStable(ctx); err != nil {
				t.Fatal(err)
			}
			if err = snapshot.Close(); err != nil {
				t.Fatal(err)
			}
			// Supplemented empty folder deliberately makes Working Tree dirty;
			// the unmodified fixture still matches its frozen Working verdict.
			fixture := treeFixture(t, name)
			scan, err := pkg.Scan(ctx, fixture, l, support, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
			var expected struct{ Expected pkg.Result }
			if err = json.Unmarshal(raw, &expected); err != nil {
				t.Fatal(err)
			}
			if scan.State != expected.Expected.WorkingState {
				t.Fatal(scan.State, expected.Expected.WorkingState)
			}
		})
	}
}

var directoryFault = errors.New("injected directory fault")

type hookedDirectoryHost struct {
	host pkg.DirectoryHost
	hook func(string, pkg.DirectoryTransaction) error
	tx   pkg.DirectoryTransaction
}

func (h *hookedDirectoryHost) BeginDirectory(ctx context.Context) (pkg.DirectoryTransaction, error) {
	tx, err := h.host.BeginDirectory(ctx)
	h.tx = tx
	if err != nil {
		return tx, err
	}
	if h.hook != nil {
		if err = h.hook("begin", tx); err != nil {
			return tx, err
		}
	}
	return &hookedDirectoryTransaction{DirectoryTransaction: tx, hook: h.hook}, nil
}

type hookedDirectoryTransaction struct {
	pkg.DirectoryTransaction
	hook func(string, pkg.DirectoryTransaction) error
}

func (t *hookedDirectoryTransaction) call(phase string) error {
	if t.hook == nil {
		return nil
	}
	return t.hook(phase, t.DirectoryTransaction)
}
func (t *hookedDirectoryTransaction) Mkdir(ctx context.Context, p string) error {
	if err := t.call("mkdir"); err != nil {
		return err
	}
	return t.DirectoryTransaction.Mkdir(ctx, p)
}
func (t *hookedDirectoryTransaction) Create(ctx context.Context, p string) (io.WriteCloser, error) {
	if err := t.call("create"); err != nil {
		return nil, err
	}
	w, err := t.DirectoryTransaction.Create(ctx, p)
	if err != nil {
		return w, err
	}
	return &hookedDirectoryWriter{WriteCloser: w, tx: t}, nil
}

type hookedDirectoryWriter struct {
	io.WriteCloser
	tx *hookedDirectoryTransaction
}

func (w *hookedDirectoryWriter) Write(p []byte) (int, error) {
	if err := w.tx.call("write"); err != nil {
		return 0, err
	}
	return w.WriteCloser.Write(p)
}
func (w *hookedDirectoryWriter) Close() error {
	return errors.Join(w.WriteCloser.Close(), w.tx.call("writer-close"))
}
func (t *hookedDirectoryTransaction) Seal(ctx context.Context) (pkg.TreeSnapshot, error) {
	if err := t.call("seal-before"); err != nil {
		return nil, err
	}
	s, err := t.DirectoryTransaction.Seal(ctx)
	if err != nil {
		return s, err
	}
	if err = t.call("seal-after"); err != nil {
		return s, err
	}
	return &hookedDirectorySnapshot{TreeSnapshot: s, tx: t}, nil
}
func (t *hookedDirectoryTransaction) Publish(ctx context.Context) error {
	if err := t.call("publish-before"); err != nil {
		return err
	}
	if err := t.DirectoryTransaction.Publish(ctx); err != nil {
		return err
	}
	if err := t.call("publish-after"); err != nil {
		return errors.Join(pkg.ErrPublicationUncertain, err)
	}
	return nil
}
func (t *hookedDirectoryTransaction) Abort(ctx context.Context) error {
	return errors.Join(t.DirectoryTransaction.Abort(ctx), t.call("abort"))
}

type hookedDirectorySnapshot struct {
	pkg.TreeSnapshot
	tx *hookedDirectoryTransaction
}

func (s *hookedDirectorySnapshot) List(ctx context.Context, max int) ([]pkg.TreeEntry, error) {
	if err := s.tx.call("pending-list"); err != nil {
		return nil, err
	}
	return s.TreeSnapshot.List(ctx, max)
}
func (s *hookedDirectorySnapshot) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := s.tx.call("pending-open"); err != nil {
		return nil, err
	}
	return s.TreeSnapshot.Open(ctx, path)
}
func (s *hookedDirectorySnapshot) CheckStable(ctx context.Context) error {
	if err := s.tx.call("pending-stable"); err != nil {
		return err
	}
	return s.TreeSnapshot.CheckStable(ctx)
}
func (s *hookedDirectorySnapshot) Close() error {
	return errors.Join(s.TreeSnapshot.Close(), s.tx.call("pending-close"))
}

func TestDirectoryPublicationFaultsHaveNoSuccessArtifact(t *testing.T) {
	for _, phase := range []string{"begin", "mkdir", "create", "write", "writer-close", "seal-before", "seal-after", "pending-list", "pending-open", "pending-stable", "pending-close", "publish-before", "publish-after", "abort"} {
		t.Run(phase, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination)}
			host.hook = func(p string, _ pkg.DirectoryTransaction) error {
				if p == phase {
					return directoryFault
				}
				if p != "publish-after" && p != "abort" {
					if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("pending exposed as destination", p, err)
					}
				}
				return nil
			}
			out, err := pkg.PublishDirectory(context.Background(), treeFixture(t, "minimal-valid"), host, pkg.DefaultLimits(), supportAllVocabulary())
			if !errors.Is(err, directoryFault) || out != (pkg.DirectoryPublication{}) {
				t.Fatal(out, err)
			}
			if phase == "publish-after" || phase == "abort" {
				_, data := readDirectoryBytes(t, destination)
				if len(data) == 0 {
					t.Fatal("cleanup removed installed output")
				}
			} else {
				assertNoDirectoryOutput(t, parent, destination)
			}
		})
	}
}

func TestDirectoryRejectsIncompleteAndInvalidInputBeforeStaging(t *testing.T) {
	for _, name := range []string{"missing-object", "object-hash-mismatch", "missing-parent", "cycle", "multiple-roots", "invalid-head-crlf", "case-conflict", "unicode-normalization-conflict"} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination), hook: func(phase string, _ pkg.DirectoryTransaction) error {
				t.Fatal("invalid input reached staging", phase)
				return nil
			}}
			out, err := pkg.PublishDirectory(context.Background(), treeFixture(t, name), host, pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || out != (pkg.DirectoryPublication{}) {
				t.Fatal(out, err)
			}
			assertNoDirectoryOutput(t, parent, destination)
		})
	}
	for _, mutation := range []string{"required-memory-missing", "invalid-memory", "tiny-policy", "source-stable", "source-close"} {
		t.Run(mutation, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			source := treeFixture(t, "minimal-valid")
			l := pkg.DefaultLimits()
			switch mutation {
			case "required-memory-missing":
				source.remove(".packtell/metadata/notes.json")
			case "invalid-memory":
				source.setFile(".packtell/metadata/notes.json", []byte("{}"))
			case "tiny-policy":
				l.MaxEntries = 1
			case "source-stable":
				source.checkError = directoryFault
			case "source-close":
				source.closeError = directoryFault
			}
			out, err := pkg.PublishDirectory(context.Background(), source, nativeDirectoryHost(t, destination), l, supportAllVocabulary())
			if err == nil || out != (pkg.DirectoryPublication{}) {
				t.Fatal(out, err)
			}
			assertNoDirectoryOutput(t, parent, destination)
		})
	}
}

func TestDirectoryDestinationAndPendingTamper(t *testing.T) {
	for _, kind := range []string{"empty-directory", "file", "symlink", "concurrent-destination", "pending-payload", "pending-after-validation", "uncertain-moved-pending"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination)}
			switch kind {
			case "empty-directory":
				if err := os.Mkdir(destination, 0700); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(destination, []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing-target", destination); err != nil {
					t.Fatal(err)
				}
			case "concurrent-destination":
				host.hook = func(phase string, _ pkg.DirectoryTransaction) error {
					if phase == "publish-before" {
						return os.WriteFile(destination, []byte("winner"), 0600)
					}
					return nil
				}
			case "pending-payload", "pending-after-validation":
				host.hook = func(phase string, _ pkg.DirectoryTransaction) error {
					selected := "seal-after"
					if kind == "pending-after-validation" {
						selected = "publish-before"
					}
					if phase == selected {
						entries, _ := os.ReadDir(parent)
						for _, e := range entries {
							if strings.HasPrefix(e.Name(), ".package-pending-") {
								return os.WriteFile(filepath.Join(parent, e.Name(), "hello.txt"), []byte("other\n"), 0600)
							}
						}
						t.Fatal("no pending output")
					}
					return nil
				}
			case "uncertain-moved-pending":
				host.hook = func(phase string, _ pkg.DirectoryTransaction) error {
					if phase != "publish-before" {
						return nil
					}
					entries, err := os.ReadDir(parent)
					if err != nil {
						return err
					}
					for _, e := range entries {
						if strings.HasPrefix(e.Name(), ".package-pending-") {
							if err := os.Rename(filepath.Join(parent, e.Name()), destination); err != nil {
								return err
							}
							// Model a Host whose move succeeded but reply was lost. The
							// native transaction has not recorded published=true.
							return errors.Join(pkg.ErrPublicationUncertain, directoryFault)
						}
					}
					return directoryFault
				}
			}
			out, err := pkg.PublishDirectory(context.Background(), treeFixture(t, "minimal-valid"), host, pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || out != (pkg.DirectoryPublication{}) {
				t.Fatal(out, err)
			}
			switch kind {
			case "file", "concurrent-destination":
				b, err := os.ReadFile(destination)
				expected := "retain"
				if kind == "concurrent-destination" {
					expected = "winner"
				}
				if err != nil || string(b) != expected {
					t.Fatal(string(b), err)
				}
			case "symlink":
				target, err := os.Readlink(destination)
				if err != nil || target != "missing-target" {
					t.Fatal(target, err)
				}
			case "empty-directory":
				entries, err := os.ReadDir(destination)
				if err != nil || len(entries) != 0 {
					t.Fatal(entries, err)
				}
			case "pending-payload", "pending-after-validation":
				assertNoDirectoryOutput(t, parent, destination)
			case "uncertain-moved-pending":
				if !errors.Is(err, pkg.ErrPublicationUncertain) {
					t.Fatal(err)
				}
				_, data := readDirectoryBytes(t, destination)
				if string(data["hello.txt"]) != "hello\n" {
					t.Fatal("abort deleted possibly published bytes")
				}
			}
		})
	}
}

func TestDirectoryPreservesAttestationsAndRequiresEmbeddedPresence(t *testing.T) {
	for _, name := range []string{"bad-signature", "later-evidence-append", "missing-embedded"} {
		t.Run(name, func(t *testing.T) {
			fixture := name
			if name == "missing-embedded" {
				fixture = "later-evidence-append"
			}
			source := treeFixture(t, fixture)
			if name == "missing-embedded" {
				anchor := anchorFromSource(t, source)
				source.remove(evidencePath(anchor.Subject.EvidenceID))
			}
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			out, err := pkg.PublishDirectory(context.Background(), source, nativeDirectoryHost(t, destination), pkg.DefaultLimits(), supportAllVocabulary())
			if name == "missing-embedded" || name == "bad-signature" {
				if err == nil || out != (pkg.DirectoryPublication{}) {
					t.Fatal(out, err)
				}
				assertNoDirectoryOutput(t, parent, destination)
				if name == "bad-signature" {
					requireCode(t, err, pkg.ReasonBadSignature)
					view, err := pkg.Verify(context.Background(), source, pkg.DefaultLimits(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
					if err != nil || view.Result.Signature != pkg.SignatureInvalid || view.Result.HistoryCompleteness != pkg.HistoryFull {
						t.Fatal("writer rejection contaminated original proof", view, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, data := readDirectoryBytes(t, destination)
			if !reflect.DeepEqual(data, source.data) {
				t.Fatal("attestation bytes lost or changed")
			}
			s, err := nativeDirectorySource(t, destination).BeginSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			report, err := pkg.VerifySignatures(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if err != nil || report.State != pkg.SignatureValid {
				t.Fatal(report, err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryIndependentBytesAndMidCopyChange(t *testing.T) {
	for _, change := range []string{"hard-linked-input", "mid-copy-change", "destination-parent-link"} {
		t.Run(change, func(t *testing.T) {
			root, fixture := directoryFixture(t, "minimal-valid")
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination)}
			switch change {
			case "hard-linked-input":
				if err := os.Remove(filepath.Join(root, "hello.txt")); err != nil {
					t.Fatal(err)
				}
				for path := range fixture.data {
					if strings.HasPrefix(path, ".packtell/objects/sha256/") {
						if err := os.Link(filepath.Join(root, path), filepath.Join(root, "hello.txt")); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "mid-copy-change":
				once := false
				host.hook = func(phase string, _ pkg.DirectoryTransaction) error {
					if phase == "write" && !once {
						once = true
						return os.WriteFile(filepath.Join(root, "hello.txt"), []byte("other\n"), 0600)
					}
					return nil
				}
			case "destination-parent-link":
				outside := t.TempDir()
				host.hook = func(phase string, _ pkg.DirectoryTransaction) error {
					if phase != "publish-before" {
						return nil
					}
					if err := os.Rename(parent, parent+"-moved"); err != nil {
						return err
					}
					t.Cleanup(func() { _ = os.RemoveAll(parent + "-moved") })
					return os.Symlink(outside, parent)
				}
			}
			out, err := pkg.PublishDirectory(context.Background(), nativeDirectorySource(t, root), host, pkg.DefaultLimits(), supportAllVocabulary())
			if change != "hard-linked-input" {
				if err == nil || out != (pkg.DirectoryPublication{}) {
					t.Fatal(out, err)
				}
				assertNoDirectoryOutput(t, parent, destination)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var user, object syscall.Stat_t
			if err = syscall.Stat(filepath.Join(destination, "hello.txt"), &user); err != nil {
				t.Fatal(err)
			}
			for path := range fixture.data {
				if strings.HasPrefix(path, ".packtell/objects/sha256/") {
					if err = syscall.Stat(filepath.Join(destination, path), &object); err != nil {
						t.Fatal(err)
					}
				}
			}
			if user.Ino == object.Ino && user.Dev == object.Dev {
				t.Fatal("export preserved hardlink dependence")
			}
		})
	}
}

func TestDirectoryNativeLinksTOCTOUAndMutation(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"file-link", "parent-link", "root-link", "fifo", "edit-restored-mtime", "rename-root", "append", "cancel-stream", "entry-limit", "traversal-open"} {
		t.Run(change, func(t *testing.T) {
			root, _ := directoryFixture(t, "minimal-valid")
			source := nativeDirectorySource(t, root)
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "hello.txt"), []byte("secret"), 0600); err != nil {
				t.Fatal(err)
			}
			if change == "root-link" {
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, alias); err != nil {
					t.Fatal(err)
				}
				_, err := nativeDirectorySource(t, alias).BeginSnapshot(ctx)
				if err == nil {
					t.Fatal("followed Root link")
				}
				return
			}
			if change == "fifo" {
				if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := source.BeginSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			}()
			max := 100000
			if change == "entry-limit" {
				max = 1
			}
			_, err = s.List(ctx, max)
			if change == "fifo" || change == "entry-limit" {
				if err == nil {
					t.Fatal("unsafe/resource tree accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			path := "hello.txt"
			switch change {
			case "file-link":
				if err = os.Remove(filepath.Join(root, path)); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(filepath.Join(outside, path), filepath.Join(root, path)); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				path = ".packtell/format.json"
				if err = os.Rename(filepath.Join(root, ".packtell"), filepath.Join(root, "saved")); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, filepath.Join(root, ".packtell")); err != nil {
					t.Fatal(err)
				}
			case "rename-root":
				if err = os.Rename(root, root+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err = s.CheckStable(ctx); err == nil {
					t.Fatal("replacement Root accepted")
				}
				return
			case "traversal-open":
				path = "../hello.txt"
			}
			if change == "file-link" || change == "parent-link" || change == "traversal-open" {
				r, err := s.Open(ctx, path)
				if r != nil {
					_ = r.Close()
					t.Fatal("opened unsafe replacement")
				}
				if err == nil {
					t.Fatal("unsafe open accepted")
				}
				return
			}
			readCtx := ctx
			var cancel context.CancelFunc
			if change == "cancel-stream" {
				readCtx, cancel = context.WithCancel(ctx)
				defer cancel()
			}
			r, err := s.Open(readCtx, path)
			if err != nil {
				t.Fatal(err)
			}
			if change == "cancel-stream" {
				cancel()
				_, err = io.ReadAll(r)
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				_ = r.Close()
				return
			}
			b, err := io.ReadAll(r)
			err = errors.Join(err, r.Close())
			if err != nil || string(b) != "hello\n" {
				t.Fatal(string(b), err)
			}
			stat, err := os.Stat(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			if change == "append" {
				err = os.WriteFile(filepath.Join(root, "added"), []byte("new"), 0600)
			} else {
				err = os.WriteFile(filepath.Join(root, path), []byte("other\n"), 0600)
				if err == nil {
					err = os.Chtimes(filepath.Join(root, path), stat.ModTime(), stat.ModTime())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.CheckStable(ctx); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestDirectoryCancellationAndConcurrentNoOverwrite(t *testing.T) {
	for _, phase := range []string{"already-canceled", "write", "seal-before", "publish-before"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination), hook: func(p string, _ pkg.DirectoryTransaction) error {
				if p == phase {
					cancel()
				}
				return nil
			}}
			if phase == "already-canceled" {
				cancel()
			}
			out, err := pkg.PublishDirectory(ctx, treeFixture(t, "minimal-valid"), host, pkg.DefaultLimits(), supportAllVocabulary())
			if !errors.Is(err, context.Canceled) || out != (pkg.DirectoryPublication{}) {
				t.Fatal(out, err)
			}
			assertNoDirectoryOutput(t, parent, destination)
		})
	}
	root, _ := directoryFixture(t, "minimal-valid")
	parent := t.TempDir()
	destination := filepath.Join(parent, "output")
	const count = 12
	start := make(chan struct{})
	ready := make(chan struct{}, count)
	var wg sync.WaitGroup
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination), hook: func(phase string, _ pkg.DirectoryTransaction) error {
				if phase == "publish-before" {
					ready <- struct{}{}
					<-start
				}
				return nil
			}}
			_, err := pkg.PublishDirectory(context.Background(), nativeDirectorySource(t, root), host, pkg.DefaultLimits(), supportAllVocabulary())
			results <- err
		}()
	}
	for i := 0; i < count; i++ {
		<-ready
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, fs.ErrExist) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("publication winners", winners)
	}
	_, data := readDirectoryBytes(t, destination)
	if string(data["hello.txt"]) != "hello\n" {
		t.Fatal("winner damaged")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatal("loser pending leaked", entries)
	}
	_, err := pkg.PublishDirectory(context.Background(), nativeDirectorySource(t, root), nativeDirectoryHost(t, filepath.Join(root, "nested")), pkg.DefaultLimits(), supportAllVocabulary())
	if err == nil {
		t.Fatal("published inside source Root")
	}
}

func TestDirectoryCrashLeavesIsolatedPending(t *testing.T) {
	// The helper exits after writing a plausible discriminator/HEAD, without
	// Seal/Publish/Abort. A real process interruption cannot create destination.
	if os.Getenv("PACKAGE_GO_DIRECTORY_CRASH_HELPER") == "1" {
		destination := os.Getenv("PACKAGE_GO_DIRECTORY_CRASH_DESTINATION")
		h, err := pkg.NewDirectoryHost(destination, pkg.DefaultLimits())
		if err != nil {
			os.Exit(90)
		}
		tx, err := h.BeginDirectory(context.Background())
		if err != nil {
			os.Exit(91)
		}
		if err = tx.Mkdir(context.Background(), ".packtell"); err != nil {
			os.Exit(92)
		}
		w, err := tx.Create(context.Background(), ".packtell/HEAD")
		if err != nil {
			os.Exit(93)
		}
		if _, err = io.WriteString(w, "unborn\n"); err != nil {
			os.Exit(94)
		}
		if err = w.Close(); err != nil {
			os.Exit(95)
		}
		os.Exit(86)
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "output")
	command := exec.Command(os.Args[0], "-test.run=^TestDirectoryCrashLeavesIsolatedPending$")
	command.Env = append(os.Environ(), "PACKAGE_GO_DIRECTORY_CRASH_HELPER=1", "PACKAGE_GO_DIRECTORY_CRASH_DESTINATION="+destination)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatal(string(output), err)
	}
	if _, err = os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("crash exposed destination", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".package-pending-") {
		t.Fatal(entries, err)
	}
	if _, err = os.Stat(filepath.Join(parent, entries[0].Name(), ".packtell", "HEAD")); err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("interrupted child exit=%d; isolated pending retained; destination absent", exit.ExitCode()))
}
