// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packagego_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

func nativeTransferArtifactHost(t *testing.T, destination string) pkg.ArtifactHost {
	t.Helper()
	h, err := pkg.NewArtifactHost(destination, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func assertNoTransferPending(t *testing.T, parent, destination string) {
	t.Helper()
	if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unexpected destination", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".package-") {
			t.Fatal("owned pending leaked", e.Name())
		}
	}
}

func TestS10ActualNativeDirectoryAndZIPHydration(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	for _, kind := range []string{"directory", "zip"} {
		t.Run(kind, func(t *testing.T) {
			root, fixture := directoryFixture(t, "complete-history")
			if err := os.MkdirAll(filepath.Join(root, "empty", "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			resolver, refs := missingHistory(t, fixture)
			for _, ref := range refs {
				path, _ := ref.ObjectPath()
				if err := os.Remove(filepath.Join(root, path)); err != nil {
					t.Fatal(err)
				}
			}
			_, before := readDirectoryBytes(t, root)
			source := nativeDirectorySource(t, root)
			plan, err := pkg.PlanExport(ctx, source, l, support, testTransferOptions())
			if err != nil {
				t.Fatal(err)
			}
			if plan.Summary().Input.HistoryCompleteness != pkg.HistoryNotFull {
				t.Fatal(plan.Summary())
			}
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			var out pkg.TransferResult
			var restored pkg.SnapshotSource
			if kind == "directory" {
				out, err = pkg.ExecuteTransferDirectory(ctx, plan, nativeDirectoryHost(t, destination), resolver)
				restored = nativeDirectorySource(t, destination)
			} else {
				stagingParent := t.TempDir()
				out, err = pkg.ExecuteTransferZIP(ctx, plan, nativeDirectoryHost(t, filepath.Join(stagingParent, "temporary-tree")), nativeTransferArtifactHost(t, destination), resolver, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Deflate})
				entries, readErr := os.ReadDir(stagingParent)
				if readErr != nil || len(entries) != 0 {
					t.Fatal("temporary tree published/leaked", entries, readErr)
				}
				if err == nil {
					b, readErr := os.ReadFile(destination)
					if readErr != nil {
						t.Fatal(readErr)
					}
					archive, sourceErr := pkg.NewFileArchiveSource(destination, l)
					if sourceErr != nil {
						t.Fatal(sourceErr)
					}
					restored, sourceErr = pkg.NewZIPSource(archive, l)
					if sourceErr != nil {
						t.Fatal(sourceErr)
					}
					if int64(len(b)) != out.ArtifactBytes {
						t.Fatal("artifact byte count")
					}
				}
			}
			if err != nil || out.Input.HistoryCompleteness != pkg.HistoryNotFull || out.Output.HistoryCompleteness != pkg.HistoryFull {
				t.Fatal(out, err)
			}
			s, err := restored.BeginSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			h, err := pkg.ReadHistory(ctx, s, l, support)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range h.Versions {
				payload := &memoryPayload{}
				if err = pkg.MaterializeVersionPayload(ctx, s, v.Version.VersionID, payload, l, support); err != nil {
					t.Fatal(err)
				}
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "zip" {
				importPlan, err := pkg.PlanImport(ctx, restored, l, support, testTransferOptions())
				if err != nil {
					t.Fatal(err)
				}
				imported := filepath.Join(t.TempDir(), "imported")
				receipt, err := pkg.ExecuteTransferDirectory(ctx, importPlan, nativeDirectoryHost(t, imported), nil)
				if err != nil || receipt.Input.HistoryCompleteness != pkg.HistoryFull || receipt.Output.HistoryCompleteness != pkg.HistoryFull {
					t.Fatal(receipt, err)
				}
				_, importedBytes := readDirectoryBytes(t, imported)
				for p, b := range before {
					if !bytes.Equal(importedBytes[p], b) {
						t.Fatal("native ZIP import changed raw fact", p)
					}
				}
			}
			_, after := readDirectoryBytes(t, root)
			if !equalTransferBytes(before, after) {
				t.Fatal("native source mutated")
			}
			for _, ref := range refs {
				if resolver.calls[ref.ContentID] != 1 {
					t.Fatal(resolver.calls)
				}
			}
			original, err := source.BeginSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := pkg.VerifyCommittedContent(ctx, original, l, support)
			if err != nil || proof.HistoryCompleteness != pkg.HistoryNotFull {
				t.Fatal(proof, err)
			}
			if err = original.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type hookArtifactHost struct {
	host pkg.ArtifactHost
	hook func(string) error
}

func (h hookArtifactHost) BeginArtifact(ctx context.Context) (pkg.ArtifactTransaction, error) {
	tx, err := h.host.BeginArtifact(ctx)
	if err != nil {
		return tx, err
	}
	if h.hook != nil {
		if err = h.hook("begin"); err != nil {
			return tx, err
		}
	}
	return &hookArtifactTx{ArtifactTransaction: tx, hook: h.hook}, nil
}

type hookArtifactTx struct {
	pkg.ArtifactTransaction
	hook func(string) error
}

func (t *hookArtifactTx) call(phase string) error {
	if t.hook == nil {
		return nil
	}
	return t.hook(phase)
}
func (t *hookArtifactTx) Write(p []byte) (int, error) {
	if err := t.call("write"); err != nil {
		return 0, err
	}
	return t.ArtifactTransaction.Write(p)
}
func (t *hookArtifactTx) Close() error {
	return errors.Join(t.ArtifactTransaction.Close(), t.call("close"))
}
func (t *hookArtifactTx) Seal(ctx context.Context) (pkg.ArchiveSnapshot, error) {
	if err := t.call("seal-before"); err != nil {
		return nil, err
	}
	s, err := t.ArtifactTransaction.Seal(ctx)
	if err != nil {
		return s, err
	}
	if err = t.call("seal-after"); err != nil {
		return s, err
	}
	return s, nil
}
func (t *hookArtifactTx) Publish(ctx context.Context) error {
	if err := t.call("publish-before"); err != nil {
		return err
	}
	if err := t.ArtifactTransaction.Publish(ctx); err != nil {
		return err
	}
	if err := t.call("publish-after"); err != nil {
		return errors.Join(pkg.ErrPublicationUncertain, err)
	}
	return nil
}
func (t *hookArtifactTx) Abort(ctx context.Context) error {
	return errors.Join(t.ArtifactTransaction.Abort(ctx), t.call("abort"))
}

func TestNativeArtifactFaultsTamperAndExistingTargets(t *testing.T) {
	fault := errors.New("native artifact fault")
	for _, phase := range []string{"begin", "write", "close", "seal-before", "seal-after", "publish-before", "publish-after", "abort", "existing-file", "existing-directory", "existing-link", "destination-race", "tamper-before-seal", "tamper-after-seal", "uncertain-move"} {
		t.Run(phase, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "output.zip")
			stagingParent := t.TempDir()
			source := treeFixture(t, "minimal-valid")
			plan, err := pkg.PlanExport(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
			if err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "existing-file":
				if err = os.WriteFile(destination, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "existing-directory":
				if err = os.Mkdir(destination, 0700); err != nil {
					t.Fatal(err)
				}
			case "existing-link":
				if err = os.Symlink("outside", destination); err != nil {
					t.Fatal(err)
				}
			}
			host := hookArtifactHost{host: nativeTransferArtifactHost(t, destination)}
			host.hook = func(p string) error {
				if p == phase {
					return fault
				}
				if phase == "destination-race" && p == "publish-before" {
					return os.WriteFile(destination, []byte("winner"), 0600)
				}
				selected := "close"
				if phase == "tamper-after-seal" || phase == "uncertain-move" {
					selected = "publish-before"
				}
				if (phase == "tamper-before-seal" || phase == "tamper-after-seal" || phase == "uncertain-move") && p == selected {
					entries, err := os.ReadDir(parent)
					if err != nil {
						return err
					}
					for _, e := range entries {
						if strings.HasPrefix(e.Name(), ".package-artifact-pending-") {
							path := filepath.Join(parent, e.Name())
							if phase == "uncertain-move" {
								if err = os.Rename(path, destination); err != nil {
									return err
								}
								return pkg.ErrPublicationUncertain
							}
							return os.WriteFile(path, []byte("tampered"), 0600)
						}
					}
					return fault
				}
				return nil
			}
			out, err := pkg.ExecuteTransferZIP(context.Background(), plan, nativeDirectoryHost(t, filepath.Join(stagingParent, "unpublished")), host, nil, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Store})
			if err == nil || out.PackageID != "" {
				t.Fatal(out, err)
			}
			entries, readErr := os.ReadDir(stagingParent)
			if readErr != nil || len(entries) != 0 {
				t.Fatal("temporary materialization leaked", entries, readErr)
			}
			switch phase {
			case "publish-after", "abort", "uncertain-move":
				b, readErr := os.ReadFile(destination)
				if readErr != nil {
					t.Fatal("installed bytes deleted", readErr)
				}
				_, data := readZIPTree(t, b, pkg.DefaultLimits())
				if string(data["hello.txt"]) != "hello\n" {
					t.Fatal("installed bytes changed")
				}
			case "existing-file", "destination-race":
				b, readErr := os.ReadFile(destination)
				expected := "existing"
				if phase == "destination-race" {
					expected = "winner"
				}
				if readErr != nil || string(b) != expected {
					t.Fatal(string(b), readErr)
				}
			case "existing-directory":
				entries, readErr := os.ReadDir(destination)
				if readErr != nil || len(entries) != 0 {
					t.Fatal(entries, readErr)
				}
			case "existing-link":
				target, readErr := os.Readlink(destination)
				if readErr != nil || target != "outside" {
					t.Fatal(target, readErr)
				}
			default:
				assertNoTransferPending(t, parent, destination)
			}
		})
	}
}

func TestNativeTransferDriftAndLateCancellation(t *testing.T) {
	ctx := context.Background()
	root, _ := directoryFixture(t, "unknown-optional-extension")
	source := nativeDirectorySource(t, root)
	plan, err := pkg.PlanImport(ctx, source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(filepath.Join(root, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "hello.txt"), []byte("other\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(filepath.Join(root, "hello.txt"), stat.ModTime(), stat.ModTime()); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "output")
	out, err := pkg.ExecuteTransferDirectory(ctx, plan, nativeDirectoryHost(t, destination), nil)
	if !errors.Is(err, pkg.ErrTransferDrift) || out.PackageID != "" {
		t.Fatal(out, err)
	}
	assertNoTransferPending(t, parent, destination)
	for _, phase := range []string{"write", "seal-before", "publish-before"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := treeFixture(t, "minimal-valid")
			plan, err := pkg.PlanExport(ctx, source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			destination := filepath.Join(parent, "output.zip")
			stagingParent := t.TempDir()
			host := hookArtifactHost{host: nativeTransferArtifactHost(t, destination), hook: func(p string) error {
				if p == phase {
					cancel()
				}
				return nil
			}}
			out, err := pkg.ExecuteTransferZIP(ctx, plan, nativeDirectoryHost(t, filepath.Join(stagingParent, "unpublished")), host, nil, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Store})
			if !errors.Is(err, context.Canceled) || out.PackageID != "" {
				t.Fatal(out, err)
			}
			assertNoTransferPending(t, parent, destination)
			entries, _ := os.ReadDir(stagingParent)
			if len(entries) != 0 {
				t.Fatal(entries)
			}
		})
	}
}

func TestNativeArtifactConcurrentNoOverwrite(t *testing.T) {
	parent := t.TempDir()
	destination := filepath.Join(parent, "output.zip")
	const count = 8
	ready := make(chan struct{}, count)
	start := make(chan struct{})
	results := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plan, err := pkg.PlanExport(context.Background(), treeFixture(t, "minimal-valid"), pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
			if err != nil {
				results <- err
				return
			}
			staging := t.TempDir()
			host := hookArtifactHost{host: nativeTransferArtifactHost(t, destination), hook: func(phase string) error {
				if phase == "publish-before" {
					ready <- struct{}{}
					<-start
				}
				return nil
			}}
			_, err = pkg.ExecuteTransferZIP(context.Background(), plan, nativeDirectoryHost(t, filepath.Join(staging, "unpublished")), host, nil, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Store})
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
		t.Fatal(winners)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
}

func TestArtifactProcessInterruptionLeavesOnlyPending(t *testing.T) {
	if os.Getenv("PACKAGE_GO_ARTIFACT_CRASH_HELPER") == "1" {
		h, err := pkg.NewArtifactHost(os.Getenv("PACKAGE_GO_ARTIFACT_CRASH_DESTINATION"), pkg.DefaultLimits())
		if err != nil {
			os.Exit(90)
		}
		tx, err := h.BeginArtifact(context.Background())
		if err != nil {
			os.Exit(91)
		}
		if _, err = io.WriteString(tx, "unfinished ZIP"); err != nil {
			os.Exit(92)
		}
		os.Exit(86)
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "output.zip")
	child := exec.Command(os.Args[0], "-test.run=^TestArtifactProcessInterruptionLeavesOnlyPending$")
	child.Env = append(os.Environ(), "PACKAGE_GO_ARTIFACT_CRASH_HELPER=1", "PACKAGE_GO_ARTIFACT_CRASH_DESTINATION="+destination)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatal(string(output), err)
	}
	if _, err = os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".package-artifact-pending-") {
		t.Fatal(entries, err)
	}
}

func TestNativeArchiveInputLinksMutationAndPolicy(t *testing.T) {
	for _, change := range []string{"file-link", "parent-link", "directory", "mutation-restored-mtime", "resource", "cancel"} {
		t.Run(change, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "input.zip")
			b, _ := zipFixture(t, "zip-wrapped")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			selected := path
			l := pkg.DefaultLimits()
			switch change {
			case "file-link":
				selected = filepath.Join(parent, "link.zip")
				if err := os.Symlink(path, selected); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
				selected = filepath.Join(alias, "input.zip")
			case "directory":
				selected = parent
			case "resource":
				l.MaxTotalBytes = 1
			}
			source, err := pkg.NewFileArchiveSource(selected, l)
			if err != nil {
				t.Fatal(err)
			}
			s, err := source.BeginArchive(context.Background())
			if change == "file-link" || change == "parent-link" || change == "directory" || change == "resource" {
				if s != nil {
					_ = s.Close()
					t.Fatal("unsafe input view exposed")
				}
				if err == nil {
					t.Fatal("unsafe/policy input accepted")
				}
				if change == "resource" {
					requireCode(t, err, pkg.ReasonResourceLimit)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if change == "cancel" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				var bytes [4]byte
				if _, err = s.ReadAt(ctx, bytes[:], 0); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else {
				stat, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				b[0] ^= 1
				if err = os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Chtimes(path, stat.ModTime(), stat.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err = s.CheckStable(context.Background()); !errors.Is(err, pkg.ErrUnstableWorkingTree) {
					t.Fatal(err)
				}
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
