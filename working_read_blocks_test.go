// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	pkg "github.com/orbifabric/package-go"
)

type countingWorkingReader struct {
	io.Reader
	calls  int
	failAt int
}

func (r *countingWorkingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.failAt == r.calls {
		n, _ := r.Reader.Read(p)
		return n, errRevokedDuringScan
	}
	return r.Reader.Read(p)
}

var errRevokedDuringScan = errors.New("fixture read authority revoked")

func TestWorkingReadBlocks(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 4<<20)
	source := treeFixture(t, "unborn")
	source.addFile("a-large.bin", data)
	source.addFile("b-small.txt", bytes.Repeat([]byte("s"), 25))
	var reader *countingWorkingReader
	var failAt int
	source.openOverride = func(path string, b []byte) io.ReadCloser {
		if path == "a-large.bin" {
			reader = &countingWorkingReader{Reader: bytes.NewReader(b), failAt: failAt}
			return io.NopCloser(reader)
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	start := time.Now()
	scan, err := pkg.Scan(context.Background(), source, pkg.DefaultLimits(), pkg.CompleteSupport(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range scan.Entries {
		if e.Path == "a-large.bin" && e.Size == int64(len(data)) && e.ContentID == pkg.ContentIDForBytes(data) {
			found = true
		}
	}
	if !found {
		t.Fatal("large sibling content identity is missing")
	}
	t.Logf("SDK Scan: %d large-sibling reads, %v elapsed", reader.calls, time.Since(start))
	if reader.calls > 17 {
		t.Errorf("4 MiB sibling required %d host reads", reader.calls)
	}
	failAt = 2
	scan, err = pkg.Scan(context.Background(), source, pkg.DefaultLimits(), pkg.CompleteSupport(), nil)
	if !errors.Is(err, errRevokedDuringScan) || len(scan.Entries) != 0 || scan.State != pkg.WorkingUnreadable {
		t.Fatalf("revoked read returned entries or wrong status: %+v %v", scan, err)
	}
	verified := &countingWorkingReader{Reader: bytes.NewReader(data)}
	if err := pkg.CopyVerifiedContent(context.Background(), io.Discard, verified, pkg.ContentIDForBytes(data), int64(len(data)), pkg.DefaultLimits()); err != nil {
		t.Fatal("content verification failed", err)
	}
	t.Logf("SDK committed verification: %d large-sibling reads", verified.calls)
	if err := pkg.CopyVerifiedContent(context.Background(), io.Discard, &countingWorkingReader{Reader: bytes.NewReader(data), failAt: 2}, pkg.ContentIDForBytes(data), int64(len(data)), pkg.DefaultLimits()); !errors.Is(err, errRevokedDuringScan) {
		t.Fatal("verification accepted a post-read denial", err)
	}
	if err := pkg.CopyVerifiedContent(context.Background(), io.Discard, bytes.NewReader(data), pkg.ContentIDForBytes([]byte("wrong")), int64(len(data)), pkg.DefaultLimits()); err == nil {
		t.Fatal("verification accepted a wrong digest")
	}
	if verified.calls > 17 {
		t.Errorf("4 MiB content verification required %d host reads", verified.calls)
	}
}
