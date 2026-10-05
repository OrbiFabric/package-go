// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

// This is an explicit transaction contract Host, not a native production disk
// journal/authorization adapter. It persists actual SDK-produced control bytes.
type commitHost struct {
	gate               chan struct{}
	source             *memorySource
	operations         []string
	fail               string
	mutateOnSecondRead bool
	lateMutation       bool
	lateHEAD           bool
}

func newCommitHost(source *memorySource) *commitHost {
	h := &commitHost{gate: make(chan struct{}, 1), source: source}
	h.gate <- struct{}{}
	return h
}

type commitTX struct {
	host              *commitHost
	objects           map[pkg.ContentID][]byte
	pendingID         pkg.VersionID
	version, manifest []byte
	baseline          map[string][]byte
	payloadReads      map[string]int
	published         bool
}

func (h *commitHost) BeginCommit(ctx context.Context) (pkg.CommitTransaction, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.gate:
	}
	h.operations = append(h.operations, "begin")
	base := map[string][]byte{}
	for p, b := range h.source.data {
		if !strings.HasPrefix(p, ".packtell/") {
			base[p] = bytes.Clone(b)
		}
	}
	return &commitTX{host: h, objects: map[pkg.ContentID][]byte{}, baseline: base, payloadReads: map[string]int{}}, nil
}
func (tx *commitTX) List(ctx context.Context, max int) ([]pkg.TreeEntry, error) {
	return tx.host.source.List(ctx, max)
}
func (tx *commitTX) Open(ctx context.Context, p string) (io.ReadCloser, error) {
	if !strings.HasPrefix(p, ".packtell/") {
		tx.payloadReads[p]++
		if tx.host.mutateOnSecondRead && tx.payloadReads[p] == 2 {
			tx.host.source.setFile(p, []byte("other bytes"))
		}
	}
	return tx.host.source.Open(ctx, p)
}
func (tx *commitTX) ReadHEAD(ctx context.Context) (pkg.HEAD, error) {
	return pkg.ReadHEAD(ctx, bytes.NewReader(tx.host.source.data[".packtell/HEAD"]))
}
func (tx *commitTX) CheckStable(context.Context) error {
	current := map[string][]byte{}
	for p, b := range tx.host.source.data {
		if !strings.HasPrefix(p, ".packtell/") {
			current[p] = b
		}
	}
	if !reflect.DeepEqual(current, tx.baseline) {
		return pkg.ErrUnstableWorkingTree
	}
	return nil
}

type stagedObject struct {
	bytes.Buffer
	tx  *commitTX
	ref pkg.ContentObjectRef
}

func (w *stagedObject) Close() error {
	w.tx.host.operations = append(w.tx.host.operations, "object-close")
	if w.tx.host.fail == "object-close" {
		return io.ErrClosedPipe
	}
	w.tx.objects[w.ref.ContentID] = bytes.Clone(w.Bytes())
	return nil
}
func (tx *commitTX) StageObject(_ context.Context, ref pkg.ContentObjectRef) (io.WriteCloser, error) {
	tx.host.operations = append(tx.host.operations, "object-stage")
	if tx.host.fail == "object-stage" {
		return nil, io.ErrClosedPipe
	}
	return &stagedObject{tx: tx, ref: ref}, nil
}
func (tx *commitTX) StageVersion(_ context.Context, id pkg.VersionID, v, m []byte) error {
	tx.host.operations = append(tx.host.operations, "version-stage")
	if tx.host.fail == "version-stage" {
		return io.ErrClosedPipe
	}
	if tx.host.fail == "version-exists" {
		return fs.ErrExist
	}
	path := ".packtell/versions/" + string(id) + "/version.json"
	if _, exists := tx.host.source.data[path]; exists {
		return fs.ErrExist
	}
	tx.pendingID = id
	tx.version = bytes.Clone(v)
	tx.manifest = bytes.Clone(m)
	if tx.host.lateMutation {
		tx.host.source.setFile("hello.txt", []byte("late changed payload"))
	}
	if tx.host.lateHEAD {
		tx.host.source.setFile(".packtell/HEAD", []byte("019a0000-0000-7000-8000-000000000077\n"))
	}
	return nil
}
func (tx *commitTX) PublishHEAD(ctx context.Context, next pkg.HEAD) error {
	tx.host.operations = append(tx.host.operations, "publish")
	if tx.host.fail == "publish" {
		return io.ErrClosedPipe
	}
	if tx.pendingID == "" || next != pkg.HEAD(tx.pendingID) {
		return errors.New("no matching staged Version")
	}
	if tx.host.fail == "ack-without-publication" {
		return nil
	}
	for id, b := range tx.objects {
		p, _ := (pkg.ContentObjectRef{ContentID: id, Size: int64(len(b))}).ObjectPath()
		if _, exists := tx.host.source.data[p]; !exists {
			tx.host.source.addFile(p, b)
		}
	}
	dir := ".packtell/versions/" + string(tx.pendingID)
	tx.host.source.addFile(dir+"/version.json", tx.version)
	tx.host.source.addFile(dir+"/manifest.json", tx.manifest)
	b, err := next.Bytes()
	if err != nil {
		return err
	}
	tx.host.source.setFile(".packtell/HEAD", b)
	tx.published = true
	if tx.host.fail == "uncertain-after-publication" {
		return io.ErrClosedPipe
	}
	return ctx.Err()
}
func (tx *commitTX) Abort(context.Context) error {
	tx.host.operations = append(tx.host.operations, "abort")
	tx.objects = nil
	tx.version = nil
	tx.manifest = nil
	if tx.host.fail == "abort" {
		return io.ErrClosedPipe
	}
	return nil
}
func (tx *commitTX) Close() error {
	tx.host.operations = append(tx.host.operations, "close")
	tx.host.gate <- struct{}{}
	if tx.host.fail == "close" {
		return io.ErrClosedPipe
	}
	return nil
}
func request(head pkg.HEAD) pkg.CommitRequest {
	return pkg.CommitRequest{ExpectedHEAD: head, At: testTime, SealedMetadata: pkg.SealedMetadata{Title: "Unsigned Version"}}
}
func TestUnsignedCommitPublishesCompleteHistoryAndHEADLast(t *testing.T) {
	source := treeFixture(t, "core-minimal")
	oldHead := bytes.Clone(source.data[".packtell/HEAD"])
	oldVersion := bytes.Clone(source.data[".packtell/versions/"+string(versionID)+"/version.json"])
	source.setFile("hello.txt", []byte("changed\n"))
	host := newCommitHost(source)
	record, err := pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if record.Version.ParentVersionID == nil || *record.Version.ParentVersionID != versionID || record.Version.Ordinal != 2 || record.Version.VersionID == versionID || record.Manifest.Entries[0].FileID != fileID {
		t.Fatal("identity/parent/ordinal failure", record)
	}
	if bytes.Equal(source.data[".packtell/HEAD"], oldHead) || !bytes.Equal(source.data[".packtell/versions/"+string(versionID)+"/version.json"], oldVersion) {
		t.Fatal("rewrote old authority")
	}
	if !reflect.DeepEqual(host.operations, []string{"begin", "object-stage", "object-close", "version-stage", "publish", "close"}) {
		t.Fatal("HEAD not last after durable objects/docs", host.operations)
	}
	history, err := pkg.ReadHistory(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil || len(history.Versions) != 2 {
		t.Fatal(history, err)
	}
	report, err := pkg.VerifyCommittedContent(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil || report.Integrity != pkg.IntegrityValid || len(report.Verified) != 2 {
		t.Fatal(report, err)
	}
	scan, err := pkg.Scan(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || scan.State != pkg.WorkingClean {
		t.Fatal("commit differs from stable payload", scan, err)
	}
	for _, e := range source.entries {
		if strings.HasPrefix(e.Path, ".packtell/verification/") {
			t.Fatal("signature required/created implicitly")
		}
	}
}
func TestRootCommitEmptyContentFoldersAndIdentityCopies(t *testing.T) {
	source := treeFixture(t, "unborn")
	source.addFile("zero", nil)
	source.entries = append(source.entries, pkg.TreeEntry{Path: "empty/", Kind: "directory"})
	host := newCommitHost(source)
	record, err := pkg.Commit(context.Background(), host, request(pkg.UnbornHEAD), pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if record.Version.ParentVersionID != nil || record.Version.Ordinal != 1 || len(record.Manifest.Entries) != 2 {
		t.Fatal(record)
	}
	for _, e := range record.Manifest.Entries {
		if e.Kind == "file" {
			if e.Size != 0 || e.ContentID != pkg.ContentIDForBytes(nil) {
				t.Fatal("empty content lost")
			}
			p, _ := (pkg.ContentObjectRef{ContentID: e.ContentID, Size: 0}).ObjectPath()
			if b, ok := source.data[p]; !ok || len(b) != 0 {
				t.Fatal("missing committed empty copy")
			}
		}
	}
	source = treeFixture(t, "core-minimal")
	source.remove("hello.txt")
	source.addFile("renamed.txt", []byte("hello\n"))
	source.addFile("copy.txt", []byte("hello\n"))
	host = newCommitHost(source)
	r := request(pkg.HEAD(versionID))
	r.Tracking = map[string]pkg.UUID{"renamed.txt": pkg.UUID(fileID)}
	record, err = pkg.Commit(context.Background(), host, r, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range record.Manifest.Entries {
		if e.Name == "renamed.txt" && e.FileID != fileID {
			t.Fatal("rename changed identity")
		}
		if e.Name == "copy.txt" {
			found = true
			if e.FileID == fileID || e.ContentID != pkg.ContentIDForBytes([]byte("hello\n")) {
				t.Fatal("copy reused identity or changed bytes")
			}
		}
	}
	if !found {
		t.Fatal("copy absent")
	}
}
func TestConcurrentWritersRejectStaleHEADWithoutFork(t *testing.T) {
	source := treeFixture(t, "core-minimal")
	source.setFile("hello.txt", []byte("changed\n"))
	host := newCommitHost(source)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	passed, stale := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else {
			var p *pkg.ProtocolError
			if errors.As(err, &p) && p.Code == pkg.ReasonStaleHEAD {
				stale++
			} else {
				t.Fatal(err)
			}
		}
	}
	if passed != 1 || stale != 1 {
		t.Fatal(passed, stale)
	}
	h, err := pkg.ReadHistory(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil || len(h.Versions) != 2 {
		t.Fatal("concurrent branch published", h, err)
	}
}
func TestCommitFailureRollbackNeverPublishesProposal(t *testing.T) {
	for _, phase := range []string{"object-stage", "object-close", "version-stage", "version-exists", "publish"} {
		t.Run(phase, func(t *testing.T) {
			source := treeFixture(t, "core-minimal")
			source.setFile("hello.txt", []byte("changed\n"))
			before := map[string][]byte{}
			for p, b := range source.data {
				before[p] = bytes.Clone(b)
			}
			host := newCommitHost(source)
			host.fail = phase
			record, err := pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || record.Version.VersionID != "" {
				t.Fatal("failure advertised success", record, err)
			}
			if !reflect.DeepEqual(source.data, before) {
				t.Fatal("failed transaction exposed pending state")
			}
			if host.operations[len(host.operations)-2] != "abort" || host.operations[len(host.operations)-1] != "close" {
				t.Fatal("pending output/isolation leaked", host.operations)
			}
		})
	}
	for _, phase := range []string{"close", "uncertain-after-publication"} {
		t.Run(phase, func(t *testing.T) {
			source := treeFixture(t, "core-minimal")
			source.setFile("hello.txt", []byte("changed\n"))
			host := newCommitHost(source)
			host.fail = phase
			record, err := pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || record.Version.VersionID != "" {
				t.Fatal("uncertain outcome reported success")
			}
			h, err := pkg.ReadHistory(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
			if err != nil || len(h.Versions) != 2 {
				t.Fatal("cleanup deleted published history", h, err)
			}
		})
	}
}
func TestCommitScanMutationAndBadAcknowledgement(t *testing.T) {
	for _, mode := range []string{"second-read", "late-mutation", "late-head", "ack-without-publication"} {
		t.Run(mode, func(t *testing.T) {
			source := treeFixture(t, "core-minimal")
			source.setFile("hello.txt", []byte("changed\n"))
			host := newCommitHost(source)
			switch mode {
			case "second-read":
				host.mutateOnSecondRead = true
			case "late-mutation":
				host.lateMutation = true
			case "late-head":
				host.lateHEAD = true
			default:
				host.fail = mode
			}
			_, err := pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil {
				t.Fatal("unsafe commit passed")
			}
			for _, e := range source.entries {
				if strings.HasPrefix(e.Path, ".packtell/versions/") && strings.TrimSuffix(e.Path, "/") != ".packtell/versions" && !strings.Contains(e.Path, string(versionID)) {
					t.Fatal("failed proposal entered history")
				}
			}
		})
	}
}
func TestCommitPreservesUnknownFactsAndRejectsResourceLoss(t *testing.T) {
	source := treeFixture(t, "core-minimal")
	p := ".packtell/versions/" + string(versionID) + "/manifest.json"
	var m map[string]any
	json.Unmarshal(source.data[p], &m)
	m["org.example.fact"] = map[string]any{"v": "opaque"}
	m["entries"].([]any)[0].(map[string]any)["org.example.entry"] = []any{true, "😀"}
	b, _ := json.Marshal(m)
	source.setFile(p, b)
	host := newCommitHost(source)
	r := request(pkg.HEAD(versionID))
	r.ManifestExtra = map[string]any{"org.example.new": true}
	record, err := pkg.Commit(context.Background(), host, r, pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil || record.Manifest.Extra["org.example.new"] != true || record.Manifest.Extra["org.example.fact"] == nil || record.Manifest.Entries[0].Extra["org.example.entry"] == nil {
		t.Fatal("lost unknown facts", record, err)
	}
	source = treeFixture(t, "core-minimal")
	host = newCommitHost(source)
	l := pkg.DefaultLimits()
	nodes, preflightErr := pkg.PreflightTree(context.Background(), source.entries, pkg.DefaultLimits())
	if preflightErr != nil {
		t.Fatal(preflightErr)
	}
	l.MaxEntries = len(nodes) + 2
	_, err = pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonResourceLimit)
	for _, op := range host.operations {
		if op == "object-stage" || op == "version-stage" || op == "publish" {
			t.Fatal("output before full plan budget", host.operations)
		}
	}
}
func TestMaximumOrdinalAndInvalidCommitFacts(t *testing.T) {
	for _, n := range []int64{0, 1, pkg.MaxProtocolInteger - 1} {
		next, err := pkg.NextOrdinal(n)
		if err != nil || next != n+1 {
			t.Fatal(n, next, err)
		}
	}
	_, err := pkg.NextOrdinal(pkg.MaxProtocolInteger)
	requireCode(t, err, pkg.ReasonResourceLimit)
	_, err = pkg.NextOrdinal(-1)
	requireCode(t, err, pkg.ReasonInvalidSchema)
	for _, value := range []any{1.5, "\xff", map[string]any{"bad": "\xff"}} {
		host := newCommitHost(treeFixture(t, "core-minimal"))
		r := request(pkg.HEAD(versionID))
		r.VersionExtra = map[string]any{"org.example": value}
		_, err := pkg.Commit(context.Background(), host, r, pkg.DefaultLimits(), supportAllVocabulary())
		requireCode(t, err, pkg.ReasonInvalidSchema)
		if len(host.operations) != 0 {
			t.Fatal("began invalid transaction")
		}
	}
	cyclic := map[string]any{}
	cyclic["cycle"] = cyclic
	host := newCommitHost(treeFixture(t, "core-minimal"))
	r := request(pkg.HEAD(versionID))
	r.VersionExtra = cyclic
	_, err = pkg.Commit(context.Background(), host, r, pkg.DefaultLimits(), supportAllVocabulary())
	requireCode(t, err, pkg.ReasonResourceLimit)
	host = newCommitHost(treeFixture(t, "missing-object"))
	_, err = pkg.Commit(context.Background(), host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
	requireCode(t, err, pkg.ReasonMissingObject)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	host = newCommitHost(treeFixture(t, "core-minimal"))
	_, err = pkg.Commit(ctx, host, request(pkg.HEAD(versionID)), pkg.DefaultLimits(), supportAllVocabulary())
	if !errors.Is(err, context.Canceled) || len(host.operations) != 0 {
		t.Fatal("began cancelled transaction")
	}
}

func TestCommitBoundsRepeatedOptionalValuesBeforeEncoding(t *testing.T) {
	host := newCommitHost(treeFixture(t, "core-minimal"))
	r := request(pkg.HEAD(versionID))
	r.VersionExtra = map[string]any{"org.example": []any{strings.Repeat("a", 700), strings.Repeat("b", 700)}}
	l := pkg.DefaultLimits()
	l.MaxJSONBytes = 1024
	_, err := pkg.Commit(context.Background(), host, r, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonResourceLimit)
	if len(host.operations) != 0 {
		t.Fatal("serialized/began oversized optional data")
	}
}
