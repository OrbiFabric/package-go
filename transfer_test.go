// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

type transferPolicy func(context.Context, pkg.TransferFacts) error

func (p transferPolicy) ApproveTransfer(ctx context.Context, f pkg.TransferFacts) error {
	return p(ctx, f)
}
func testTransferOptions() pkg.TransferOptions {
	return pkg.TransferOptions{Facts: transferPolicy(func(context.Context, pkg.TransferFacts) error { return nil })}
}

type transferMemoryHost struct {
	tx     *transferMemoryTx
	begins int
	hook   func(string) error
}

func (h *transferMemoryHost) BeginDirectory(ctx context.Context) (pkg.DirectoryTransaction, error) {
	h.begins++
	h.tx = &transferMemoryTx{source: &memorySource{data: map[string][]byte{}}, hook: h.hook}
	if h.hook != nil {
		if err := h.hook("begin"); err != nil {
			return h.tx, err
		}
	}
	return h.tx, nil
}

type transferMemoryTx struct {
	source             *memorySource
	published, aborted bool
	hook               func(string) error
}

func (t *transferMemoryTx) call(phase string) error {
	if t.hook == nil {
		return nil
	}
	return t.hook(phase)
}
func (t *transferMemoryTx) Mkdir(ctx context.Context, p string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.call("mkdir"); err != nil {
		return err
	}
	t.source.entries = append(t.source.entries, pkg.TreeEntry{Path: p, Kind: "directory"})
	return nil
}
func (t *transferMemoryTx) Create(ctx context.Context, p string) (io.WriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := t.call("create"); err != nil {
		return nil, err
	}
	return &transferMemoryWriter{tx: t, path: p, ctx: ctx}, nil
}

type transferMemoryWriter struct {
	bytes.Buffer
	tx   *transferMemoryTx
	path string
	ctx  context.Context
}

func (w *transferMemoryWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if err := w.tx.call("write"); err != nil {
		return 0, err
	}
	return w.Buffer.Write(p)
}
func (w *transferMemoryWriter) Close() error {
	w.tx.source.addFile(w.path, w.Bytes())
	return w.tx.call("writer-close")
}
func (t *transferMemoryTx) Seal(context.Context) (pkg.TreeSnapshot, error) {
	if err := t.call("seal"); err != nil {
		return t.source, err
	}
	return t.source, nil
}
func (t *transferMemoryTx) Publish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.call("publish-before"); err != nil {
		return err
	}
	t.published = true
	if err := t.call("publish-after"); err != nil {
		return errors.Join(pkg.ErrPublicationUncertain, err)
	}
	return nil
}
func (t *transferMemoryTx) Abort(context.Context) error {
	t.aborted = true
	if !t.published {
		t.source.data = map[string][]byte{}
		t.source.entries = nil
	}
	return t.call("abort")
}

type transferResolver struct {
	data                                             map[pkg.ContentID][]byte
	calls                                            map[pkg.ContentID]int
	requests                                         []pkg.ContentRequest
	resolveError, readError, closeError, stableError error
	revision                                         string
	noStable                                         bool
	cancel                                           context.CancelFunc
	closes, stableChecks                             int
}

func (r *transferResolver) Resolve(ctx context.Context, request pkg.ContentRequest) (pkg.ResolvedContent, error) {
	if r.calls == nil {
		r.calls = map[pkg.ContentID]int{}
	}
	r.calls[request.ContentID]++
	r.requests = append(r.requests, request)
	stream := &transferResolvedStream{Reader: bytes.NewReader(bytes.Clone(r.data[request.ContentID])), resolver: r}
	var stable func(context.Context) error
	if !r.noStable {
		stable = func(ctx context.Context) error {
			r.stableChecks++
			if err := ctx.Err(); err != nil {
				return err
			}
			return r.stableError
		}
	}
	return pkg.ResolvedContent{Reader: stream, Revision: r.revision, CheckStable: stable}, r.resolveError
}

type transferResolvedStream struct {
	*bytes.Reader
	resolver *transferResolver
	closed   bool
}

func (s *transferResolvedStream) Read(p []byte) (int, error) {
	if s.resolver.cancel != nil {
		s.resolver.cancel()
	}
	if s.resolver.readError != nil {
		return 0, s.resolver.readError
	}
	return s.Reader.Read(p)
}
func (s *transferResolvedStream) Close() error {
	if !s.closed {
		s.closed = true
		s.resolver.closes++
	}
	return s.resolver.closeError
}

func missingHistory(t *testing.T, source *memorySource) (*transferResolver, []pkg.ContentObjectRef) {
	t.Helper()
	h, err := pkg.ReadHistory(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	resolver := &transferResolver{data: map[pkg.ContentID][]byte{}, revision: "selected-remote-revision"}
	for _, ref := range h.Contents {
		path, _ := ref.ObjectPath()
		resolver.data[ref.ContentID] = bytes.Clone(source.data[path])
		source.remove(path)
	}
	return resolver, h.Contents
}
func TestS10SharedOfflineObservationsAndTransfer(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	for _, name := range []string{"complete-history", "missing-object", "object-hash-mismatch", "unknown-optional-extension"} {
		t.Run(name, func(t *testing.T) {
			source := treeFixture(t, name)
			before := mapsCloneBytes(source.data)
			raw, err := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
			if err != nil {
				t.Fatal(err)
			}
			var expected struct{ Expected pkg.Result }
			if err = json.Unmarshal(raw, &expected); err != nil {
				t.Fatal(err)
			}
			objects, err := pkg.VerifyCommittedContent(ctx, source, l, support)
			if err != nil || objects.Integrity != expected.Expected.CommittedIntegrity {
				t.Fatal(objects, err)
			}
			plan, err := pkg.PlanExport(ctx, source, l, support, testTransferOptions())
			if name == "object-hash-mismatch" {
				requireCode(t, err, pkg.ReasonObjectHashMismatch)
				if plan.Summary().PackageID != "" {
					t.Fatal("invalid input got plan")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			summary := plan.Summary()
			if summary.Input.HistoryCompleteness != expected.Expected.HistoryCompleteness || summary.Input.CommittedIntegrity != expected.Expected.CommittedIntegrity {
				t.Fatal(summary.Input, expected.Expected)
			}
			host := &transferMemoryHost{}
			if name == "missing-object" {
				out, err := pkg.ExecuteTransferDirectory(ctx, plan, host, nil)
				requireCode(t, err, pkg.ReasonMissingObject)
				if out.PackageID != "" || host.begins != 0 {
					t.Fatal("offline operation invoked output", out, host.begins)
				}
				if !reflect.DeepEqual(before, source.data) {
					t.Fatal("source was modified")
				}
				return
			}
			out, err := pkg.ExecuteTransferDirectory(ctx, plan, host, nil)
			if err != nil || !host.tx.published || out.Output.HistoryCompleteness != pkg.HistoryFull || out.Output.CommittedIntegrity != pkg.IntegrityValid {
				t.Fatal(out, err)
			}
			if !reflect.DeepEqual(before, source.data) || !equalTransferBytes(before, host.tx.source.data) {
				t.Fatal("raw facts/extensions or source changed")
			}
		})
	}
}

func equalTransferBytes(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for p, v := range a {
		w, ok := b[p]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

func TestAllHistoricalRemoteOnlyHydrationDeduplicatesAndNeverRewritesInput(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	source := treeFixture(t, "complete-history")
	// Two files reference the same HEAD object, while the prior Version's
	// different object is no longer available from Working Tree.
	h, err := pkg.ReadHistory(ctx, source, l, support)
	if err != nil {
		t.Fatal(err)
	}
	record := h.Versions[len(h.Versions)-1]
	duplicate := record.Manifest.Entries[0]
	duplicate.FileID = pkg.FileID(memoryID(99))
	duplicate.Name = "duplicate.txt"
	record.Manifest.Entries = append(record.Manifest.Entries, duplicate)
	source.setFile(".packtell/versions/"+string(record.Version.VersionID)+"/manifest.json", jsonBytes(t, record.Manifest))
	source.addFile("duplicate.txt", source.data["hello.txt"])
	resolver, refs := missingHistory(t, source)
	before := mapsCloneBytes(source.data)
	options := testTransferOptions()
	options.ExpectedRevisions = map[pkg.ContentID]string{}
	for _, ref := range refs {
		options.ExpectedRevisions[ref.ContentID] = resolver.revision
	}
	plan, err := pkg.PlanExport(ctx, source, l, support, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolver.calls) != 0 || len(plan.Summary().Contents) != 2 || plan.Summary().Input.HistoryCompleteness != pkg.HistoryNotFull {
		t.Fatal(plan.Summary(), resolver.calls)
	}
	// Review-copy edits and later caller map edits cannot change the plan.
	review := plan.Summary()
	review.Contents[0].Size = 999
	review.Entries[0].Path = "../bad"
	review.Input.MissingObjects = nil
	for id := range options.ExpectedRevisions {
		options.ExpectedRevisions[id] = "caller-mutated"
	}
	host := &transferMemoryHost{}
	out, err := pkg.ExecuteTransferDirectory(ctx, plan, host, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if out.Input.HistoryCompleteness != pkg.HistoryNotFull || out.Input.CommittedIntegrity != pkg.IntegrityUnavailable || out.Output.HistoryCompleteness != pkg.HistoryFull || len(out.Hydrated) != 2 || resolver.closes != 2 || resolver.stableChecks != 2 {
		t.Fatal(out, resolver)
	}
	for _, ref := range refs {
		if resolver.calls[ref.ContentID] != 1 {
			t.Fatal("Resolver was not deduplicated", resolver.calls)
		}
		path, _ := ref.ObjectPath()
		if !bytes.Equal(host.tx.source.data[path], resolver.data[ref.ContentID]) {
			t.Fatal(path)
		}
	}
	for _, request := range resolver.requests {
		if request.ExpectedRevision != "selected-remote-revision" {
			t.Fatal("mutable selection escaped", request)
		}
	}
	if !reflect.DeepEqual(before, source.data) {
		t.Fatal("hydration wrote source")
	}
	input, err := pkg.VerifyCommittedContent(ctx, source, l, support)
	if err != nil || input.Integrity != pkg.IntegrityUnavailable || input.HistoryCompleteness != pkg.HistoryNotFull {
		t.Fatal(input, err)
	}
	history, err := pkg.ReadHistory(ctx, host.tx.source, l, support)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range history.Versions {
		restored := &memoryPayload{}
		if err = pkg.MaterializeVersionPayload(ctx, host.tx.source, v.Version.VersionID, restored, l, support); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range host.tx.source.data {
		if bytes.Contains(body, []byte(resolver.revision)) || bytes.Contains(body, []byte("caller-mutated")) {
			t.Fatal("transient revision serialized")
		}
	}
}

func TestResolverFailuresNeverPublish(t *testing.T) {
	fault := errors.New("Resolver fault")
	for _, phase := range []string{"wrong-hash", "short", "long", "wrong-revision", "missing-revision-check", "late-revision", "resolve-error", "read-error", "close-error", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := treeFixture(t, "complete-history")
			resolver, refs := missingHistory(t, source)
			options := testTransferOptions()
			options.ExpectedRevisions = map[pkg.ContentID]string{}
			for _, ref := range refs {
				options.ExpectedRevisions[ref.ContentID] = resolver.revision
			}
			plan, err := pkg.PlanExport(ctx, source, pkg.DefaultLimits(), supportAllVocabulary(), options)
			if err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "wrong-hash":
				for id, b := range resolver.data {
					resolver.data[id] = bytes.Repeat([]byte("x"), len(b))
				}
			case "short":
				for id, b := range resolver.data {
					resolver.data[id] = b[:len(b)-1]
				}
			case "long":
				for id, b := range resolver.data {
					resolver.data[id] = append(b, 'x')
				}
			case "wrong-revision":
				resolver.revision = "wrong"
			case "missing-revision-check":
				resolver.noStable = true
			case "late-revision":
				resolver.stableError = pkg.ErrContentRevisionMismatch
			case "resolve-error":
				resolver.resolveError = fault
			case "read-error":
				resolver.readError = fault
			case "close-error":
				resolver.closeError = fault
			case "cancel":
				resolver.cancel = cancel
			}
			host := &transferMemoryHost{}
			out, err := pkg.ExecuteTransferDirectory(ctx, plan, host, resolver)
			if err == nil || out.PackageID != "" || host.tx.published || !host.tx.aborted || len(host.tx.source.data) != 0 {
				t.Fatal(out, err, host.tx)
			}
			if resolver.closes != 1 {
				t.Fatal("returned stream not closed once", resolver.closes)
			}
			if phase == "wrong-hash" || phase == "short" || phase == "long" {
				requireCode(t, err, pkg.ReasonObjectHashMismatch)
			}
			if strings.Contains(phase, "revision") && !errors.Is(err, pkg.ErrContentRevisionMismatch) {
				t.Fatal(err)
			}
		})
	}
}

func TestPlanDriftFactSelectionAndSourceFailures(t *testing.T) {
	ctx := context.Background()
	fault := errors.New("transfer policy/observation failure")
	for _, change := range []string{"working", "optional-json", "extension", "memory", "object-removed", "head", "policy-revoked", "source-stable", "source-close"} {
		t.Run(change, func(t *testing.T) {
			source := treeFixture(t, "unknown-optional-extension")
			approved := true
			options := testTransferOptions()
			options.Facts = transferPolicy(func(_ context.Context, f pkg.TransferFacts) error {
				if !approved {
					return fault
				}
				for _, b := range f.Documents {
					if len(b) > 0 {
						b[0] = '!'
					}
				}
				if len(f.Entries) > 0 {
					f.Entries[0].Path = "../owned-copy"
				}
				return nil
			})
			plan, err := pkg.PlanImport(ctx, source, pkg.DefaultLimits(), supportAllVocabulary(), options)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "working":
				source.setFile("hello.txt", []byte("other\n"))
			case "optional-json":
				var m map[string]any
				path := ".packtell/package.json"
				if err = json.Unmarshal(source.data[path], &m); err != nil {
					t.Fatal(err)
				}
				m["allowed_extra"] = true
				source.setFile(path, jsonBytes(t, m))
			case "extension":
				for p := range source.data {
					if strings.HasPrefix(p, ".packtell/extensions/") {
						source.setFile(p, []byte("changed"))
						break
					}
				}
			case "memory":
				path := ".packtell/metadata/package.json"
				var m map[string]any
				if err = json.Unmarshal(source.data[path], &m); err != nil {
					t.Fatal(err)
				}
				m["title"] = "changed"
				source.setFile(path, jsonBytes(t, m))
			case "object-removed":
				for p := range source.data {
					if strings.HasPrefix(p, ".packtell/objects/sha256/") {
						source.remove(p)
						break
					}
				}
			case "head":
				source.setFile(".packtell/HEAD", []byte("unborn\n"))
			case "policy-revoked":
				approved = false
			case "source-stable":
				source.checkError = fault
			case "source-close":
				source.closeError = fault
			}
			host := &transferMemoryHost{}
			out, err := pkg.ExecuteTransferDirectory(ctx, plan, host, nil)
			if err == nil || out.PackageID != "" {
				t.Fatal(out, err)
			}
			if host.tx != nil && host.tx.published {
				t.Fatal("drift/failure published")
			}
		})
	}
	if _, err := pkg.PlanExport(ctx, treeFixture(t, "minimal-valid"), pkg.DefaultLimits(), supportAllVocabulary(), pkg.TransferOptions{}); err == nil {
		t.Fatal("missing fact policy accepted")
	}
	options := testTransferOptions()
	options.ExpectedRevisions = map[pkg.ContentID]string{pkg.ContentID("sha256:" + strings.Repeat("0", 64)): "not-actual-content"}
	if _, err := pkg.PlanExport(ctx, treeFixture(t, "minimal-valid"), pkg.DefaultLimits(), supportAllVocabulary(), options); err == nil {
		t.Fatal("unknown selection accepted")
	}
	for _, name := range []string{"missing-memory", "missing-embedded"} {
		source := treeFixture(t, "later-evidence-append")
		if name == "missing-memory" {
			source.remove(".packtell/metadata/notes.json")
		} else {
			e := anchorFromSource(t, source)
			source.remove(evidencePath(e.Subject.EvidenceID))
		}
		if _, err := pkg.PlanExport(ctx, source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions()); err == nil {
			t.Fatal("unsupplied portable facts accepted", name)
		}
	}
}

type transferArtifactHost struct {
	tx   *transferArtifactTx
	hook func(string) error
}

func (h *transferArtifactHost) BeginArtifact(context.Context) (pkg.ArtifactTransaction, error) {
	h.tx = &transferArtifactTx{hook: h.hook}
	if h.hook != nil {
		if err := h.hook("begin"); err != nil {
			return h.tx, err
		}
	}
	return h.tx, nil
}

type transferArtifactTx struct {
	bytes.Buffer
	hook               func(string) error
	published, aborted bool
}

func (t *transferArtifactTx) call(phase string) error {
	if t.hook == nil {
		return nil
	}
	return t.hook(phase)
}
func (t *transferArtifactTx) Write(p []byte) (int, error) {
	if err := t.call("write"); err != nil {
		return 0, err
	}
	return t.Buffer.Write(p)
}
func (t *transferArtifactTx) Close() error { return t.call("close") }
func (t *transferArtifactTx) Seal(ctx context.Context) (pkg.ArchiveSnapshot, error) {
	if err := t.call("seal"); err != nil {
		return nil, err
	}
	s := &testArchiveSource{data: bytes.Clone(t.Bytes())}
	return s.BeginArchive(ctx)
}
func (t *transferArtifactTx) Publish(context.Context) error {
	if err := t.call("publish-before"); err != nil {
		return err
	}
	t.published = true
	if err := t.call("publish-after"); err != nil {
		return errors.Join(pkg.ErrPublicationUncertain, err)
	}
	return nil
}
func (t *transferArtifactTx) Abort(context.Context) error {
	t.aborted = true
	if !t.published {
		t.Reset()
	}
	return t.call("abort")
}

func TestTransferZIPHydratesThenProvesActualOutput(t *testing.T) {
	ctx := context.Background()
	source := treeFixture(t, "complete-history")
	resolver, _ := missingHistory(t, source)
	before := mapsCloneBytes(source.data)
	plan, err := pkg.PlanExport(ctx, source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
	if err != nil {
		t.Fatal(err)
	}
	staging, host := &transferMemoryHost{}, &transferArtifactHost{}
	out, err := pkg.ExecuteTransferZIP(ctx, plan, staging, host, resolver, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Deflate})
	if err != nil || !host.tx.published || staging.tx.published || !staging.tx.aborted || len(staging.tx.source.data) != 0 || out.Input.HistoryCompleteness != pkg.HistoryNotFull || out.Output.HistoryCompleteness != pkg.HistoryFull {
		t.Fatal(out, err, host.tx, staging.tx)
	}
	_, data := readZIPTree(t, host.tx.Bytes(), pkg.DefaultLimits())
	for p, b := range before {
		if !bytes.Equal(data[p], b) {
			t.Fatal("portable source facts changed", p)
		}
	}
	if !reflect.DeepEqual(before, source.data) {
		t.Fatal("source changed")
	}
	for id, b := range resolver.data {
		path, _ := (pkg.ContentObjectRef{ContentID: id, Size: int64(len(b))}).ObjectPath()
		if !bytes.Equal(data[path], b) || resolver.calls[id] != 1 {
			t.Fatal("remote object omitted/repeated", path)
		}
	}
}

func TestTransferTransactionFaultsNeverClaimPublication(t *testing.T) {
	fault := errors.New("transfer transaction fault")
	for _, phase := range []string{"begin", "mkdir", "create", "write", "writer-close", "seal", "publish-before", "publish-after", "abort"} {
		t.Run("directory-"+phase, func(t *testing.T) {
			source := treeFixture(t, "minimal-valid")
			plan, err := pkg.PlanImport(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
			if err != nil {
				t.Fatal(err)
			}
			host := &transferMemoryHost{hook: func(p string) error {
				if p == phase {
					return fault
				}
				return nil
			}}
			out, err := pkg.ExecuteTransferDirectory(context.Background(), plan, host, nil)
			if !errors.Is(err, fault) || out.PackageID != "" || !host.tx.aborted {
				t.Fatal(out, err, host.tx)
			}
			if phase != "publish-after" && phase != "abort" && host.tx.published {
				t.Fatal("failure published")
			}
		})
	}
	for _, phase := range []string{"begin", "write", "close", "seal", "publish-before", "publish-after", "abort"} {
		t.Run("artifact-"+phase, func(t *testing.T) {
			source := treeFixture(t, "minimal-valid")
			plan, err := pkg.PlanExport(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
			if err != nil {
				t.Fatal(err)
			}
			staging := &transferMemoryHost{}
			host := &transferArtifactHost{hook: func(p string) error {
				if p == phase {
					return fault
				}
				return nil
			}}
			out, err := pkg.ExecuteTransferZIP(context.Background(), plan, staging, host, nil, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Store})
			if !errors.Is(err, fault) || out.PackageID != "" || !host.tx.aborted || !staging.tx.aborted {
				t.Fatal(out, err, host.tx)
			}
			if phase != "publish-after" && phase != "abort" && host.tx.published {
				t.Fatal("failure published")
			}
		})
	}
}

func TestTransferPlanResourcesAndCancelBeforeSideEffects(t *testing.T) {
	source := treeFixture(t, "complete-history")
	_, refs := missingHistory(t, source)
	l := pkg.DefaultLimits()
	l.MaxTotalBytes = 1
	if _, err := pkg.PlanExport(context.Background(), source, l, supportAllVocabulary(), testTransferOptions()); err == nil {
		t.Fatal("resource policy ignored")
	}
	plan, err := pkg.PlanExport(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary(), testTransferOptions())
	if err != nil {
		t.Fatal(err)
	}
	summary := plan.Summary()
	if len(summary.Contents) != len(refs) || !slices.Equal(summary.Input.MissingObjects, []pkg.ContentID{refs[0].ContentID, refs[1].ContentID}) {
		t.Fatal(summary)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	host := &transferMemoryHost{}
	out, err := pkg.ExecuteTransferDirectory(ctx, plan, host, nil)
	if !errors.Is(err, context.Canceled) || out.PackageID != "" || host.begins != 0 {
		t.Fatal(out, err, host.begins)
	}
}
