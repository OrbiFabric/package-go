// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

func TestS04SharedHistoryAndObjects(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	for _, c := range []struct {
		name string
		code pkg.ReasonCode
	}{
		{"complete-history", ""}, {"missing-object", pkg.ReasonMissingObject}, {"object-hash-mismatch", pkg.ReasonObjectHashMismatch}, {"cycle", pkg.ReasonNonLinearHistory}, {"missing-parent", pkg.ReasonMissingParent}, {"multiple-roots", pkg.ReasonNonLinearHistory}, {"detached-version", pkg.ReasonNonLinearHistory}, {"multiple-parents", pkg.ReasonInvalidSchema},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, loadErr := fs.ReadFile(conformance.Assets(), "fixtures/"+c.name+".json")
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			var shared struct{ Expected pkg.Result }
			if loadErr = json.Unmarshal(raw, &shared); loadErr != nil {
				t.Fatal(loadErr)
			}
			source := treeFixture(t, c.name)
			h, err := pkg.ReadHistory(ctx, source, l, supportAllVocabulary())
			if c.name == "complete-history" || c.name == "missing-object" || c.name == "object-hash-mismatch" {
				if err != nil {
					t.Fatal(err)
				}
				report, err := pkg.VerifyCommittedContent(ctx, source, l, supportAllVocabulary())
				if err != nil {
					t.Fatal(err)
				}
				switch c.name {
				case "complete-history":
					if len(h.Versions) != 2 || len(h.Contents) != 2 || report.Integrity != pkg.IntegrityValid || len(report.Verified) != 2 || report.HistoryCompleteness != pkg.HistoryNotChecked {
						t.Fatal(h, report)
					}
					if h.Versions[0].Version.Ordinal != 1 || h.Versions[0].Version.ParentVersionID != nil || h.Versions[1].Version.ParentVersionID == nil || *h.Versions[1].Version.ParentVersionID != h.Versions[0].Version.VersionID {
						t.Fatal("not actual oldest-to-newest parent lineage")
					}
				case "missing-object":
					if report.Integrity != pkg.IntegrityUnavailable || report.HistoryCompleteness != pkg.HistoryNotFull || len(report.Missing) != 1 {
						t.Fatal(report)
					}
				case "object-hash-mismatch":
					if report.Integrity != pkg.IntegrityInvalid || report.HistoryCompleteness != pkg.HistoryInvalid || len(report.Invalid) != 1 {
						t.Fatal(report)
					}
				}
				if shared.Expected.CommittedIntegrity != pkg.IntegrityNotChecked && report.Integrity != shared.Expected.CommittedIntegrity {
					t.Fatalf("integrity %s want frozen %s", report.Integrity, shared.Expected.CommittedIntegrity)
				}
				if shared.Expected.HistoryCompleteness != pkg.HistoryFull && shared.Expected.HistoryCompleteness != pkg.HistoryNotChecked && report.HistoryCompleteness != shared.Expected.HistoryCompleteness {
					t.Fatalf("object-implied completeness %s want frozen %s", report.HistoryCompleteness, shared.Expected.HistoryCompleteness)
				}
				if c.code != "" {
					found := false
					for _, code := range report.ReasonCodes {
						if code == c.code {
							found = true
						}
					}
					if !found {
						t.Fatal("missing required reason", report)
					}
				}
			} else {
				requireCode(t, err, c.code)
				for _, code := range shared.Expected.ReasonCodes {
					requireCode(t, err, code)
				}
			}
			for _, opened := range source.opens {
				if !strings.HasPrefix(opened, ".packtell/") {
					t.Fatal("history verification borrowed Working Tree", opened)
				}
			}
		})
	}
}
func TestObjectCoverageDedupExtraAndNoHEADSubstitution(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	source := treeFixture(t, "missing-object")
	report, err := pkg.VerifyCommittedContent(ctx, source, l, supportAllVocabulary())
	if err != nil || report.Integrity != pkg.IntegrityUnavailable {
		t.Fatal(report, err)
	}
	if _, exists := source.data["hello.txt"]; !exists {
		t.Fatal("test must retain working bytes")
	}
	for _, opened := range source.opens {
		if opened == "hello.txt" {
			t.Fatal("used working bytes as committed object")
		}
	}
	source = treeFixture(t, "core-minimal")
	hash := pkg.ContentIDForBytes([]byte("extra"))
	path, _ := (pkg.ContentObjectRef{ContentID: hash, Size: 5}).ObjectPath()
	source.addFile(path, []byte("wrong"))
	report, err = pkg.VerifyCommittedContent(ctx, source, l, supportAllVocabulary())
	if err != nil || report.Integrity != pkg.IntegrityValid || report.HistoryCompleteness != pkg.HistoryInvalid || len(report.Invalid) != 1 {
		t.Fatal("trusted extra object filename", report, err)
	}
	source = treeFixture(t, "renamed-file")
	report, err = pkg.VerifyCommittedContent(ctx, source, l, supportAllVocabulary())
	if err != nil || report.Integrity != pkg.IntegrityValid || len(report.Verified) != 1 {
		t.Fatal("content not deduplicated across Versions", report, err)
	}
	count := 0
	for _, opened := range source.opens {
		if strings.HasPrefix(opened, ".packtell/objects/sha256/") {
			count++
		}
	}
	if count != 1 {
		t.Fatal("same content re-read", count)
	}
	source = treeFixture(t, "core-minimal")
	source.openOverride = func(p string, b []byte) io.ReadCloser {
		if strings.HasPrefix(p, ".packtell/objects/sha256/") {
			return io.NopCloser(errorReader{})
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	report, err = pkg.VerifyCommittedContent(ctx, source, l, supportAllVocabulary())
	if err != nil || report.Integrity != pkg.IntegrityUnavailable {
		t.Fatal("unreadable object treated as valid", report, err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestHistoryReferencesAndResourcePolicy(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	source := treeFixture(t, "complete-history")
	var version map[string]any
	oldPath := ".packtell/versions/" + string(versionID) + "/version.json"
	json.Unmarshal(source.data[oldPath], &version)
	version["required_capabilities"] = []string{pkg.CapabilityContentSHA256, pkg.CapabilityLinearHistory, "org.example.required"}
	b, _ := json.Marshal(version)
	source.setFile(oldPath, b)
	support := supportAllVocabulary()
	support.Capabilities = append(support.Capabilities, "org.example.required")
	_, err := pkg.ReadHistory(ctx, source, l, support)
	requireCode(t, err, pkg.ReasonInvalidSchema)
	source = treeFixture(t, "core-minimal")
	tiny := l
	tiny.MaxTotalJSONBytes = 10
	_, err = pkg.ReadHistory(ctx, source, tiny, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonResourceLimit)
	if len(source.opens) != 0 {
		t.Fatal("JSON allocated before aggregate budget")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	report, err := pkg.VerifyCommittedContent(cancelled, source, l, supportAllVocabulary())
	if !errors.Is(err, context.Canceled) || report.Integrity != pkg.IntegrityNotChecked {
		t.Fatal("cancellation became PASS", report, err)
	}
}

type memoryPayload struct {
	files map[string]*bytes.Buffer
	dirs  []string
}

func (w *memoryPayload) Mkdir(_ context.Context, p string) error {
	w.dirs = append(w.dirs, p)
	return nil
}
func (w *memoryPayload) Create(_ context.Context, p string) (io.WriteCloser, error) {
	if w.files == nil {
		w.files = map[string]*bytes.Buffer{}
	}
	b := &bytes.Buffer{}
	w.files[p] = b
	return payloadBuffer{b}, nil
}

type payloadBuffer struct{ *bytes.Buffer }

func (payloadBuffer) Close() error { return nil }
func TestAllHistoricalPayloadRestorationUsesOnlyObjects(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	source := treeFixture(t, "complete-history")
	h, err := pkg.ReadHistory(ctx, source, l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	source.setFile("hello.txt", []byte("uncommitted overwritten working bytes"))
	for _, record := range h.Versions {
		pending := &memoryPayload{}
		if err = pkg.MaterializeVersionPayload(ctx, source, record.Version.VersionID, pending, l, supportAllVocabulary()); err != nil {
			t.Fatal(err)
		}
		paths, err := record.Manifest.Paths(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range record.Manifest.Entries {
			if entry.Kind != "file" {
				continue
			}
			b := pending.files[paths[entry.ID()]].Bytes()
			if pkg.ContentIDForBytes(b) != entry.ContentID || int64(len(b)) != entry.Size {
				t.Fatal("historical payload mismatch")
			}
		}
	}
	for _, opened := range source.opens {
		if !strings.HasPrefix(opened, ".packtell/") {
			t.Fatal("restoration borrowed Working Tree")
		}
	}
	source = treeFixture(t, "missing-object")
	err = pkg.MaterializeVersionPayload(ctx, source, versionID, &memoryPayload{}, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonMissingObject)
}

func TestHistoricalEmptyFileAndEmptyFolder(t *testing.T) {
	source := treeFixture(t, "core-minimal")
	ctx := context.Background()
	l := pkg.DefaultLimits()
	path := ".packtell/versions/" + string(versionID) + "/manifest.json"
	var m map[string]any
	json.Unmarshal(source.data[path], &m)
	empty := pkg.ContentIDForBytes(nil)
	entry := m["entries"].([]any)[0].(map[string]any)
	entry["content_id"] = empty
	entry["size"] = 0
	m["entries"] = append(m["entries"].([]any), map[string]any{"kind": "folder", "folder_id": folderID, "parent_folder_id": nil, "name": "empty"})
	b, _ := json.Marshal(m)
	source.setFile(path, b)
	object, _ := (pkg.ContentObjectRef{ContentID: empty, Size: 0}).ObjectPath()
	source.addFile(object, nil)
	pending := &memoryPayload{}
	if err := pkg.MaterializeVersionPayload(ctx, source, versionID, pending, l, supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	if len(pending.files["hello.txt"].Bytes()) != 0 || len(pending.dirs) != 1 || pending.dirs[0] != "empty" {
		t.Fatal("empty content/folder lost", pending)
	}
}
