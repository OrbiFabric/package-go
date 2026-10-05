// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

func TestS03ExactHEADBytes(t *testing.T) {
	for _, s := range []string{"unborn\n", string(versionID) + "\n"} {
		h, err := pkg.ReadHEAD(context.Background(), strings.NewReader(s))
		if err != nil {
			t.Fatal(err)
		}
		b, err := h.Bytes()
		if err != nil || string(b) != s {
			t.Fatalf("%q %v", b, err)
		}
	}
	for _, s := range []string{"", "unborn", "unborn\r\n", "unborn\n\n", " unborn\n", "unborn \n", "UNBORN\n", "\xef\xbb\xbfunborn\n", `"unborn"` + "\n", string(versionID), string(versionID) + "\r\n", strings.ToUpper(string(versionID)) + "\n", strings.Repeat("x", 1000) + "\n"} {
		_, err := pkg.ReadHEAD(context.Background(), strings.NewReader(s))
		requireCode(t, err, pkg.ReasonInvalidHEAD)
	}
	for _, name := range []string{"unborn", "invalid-head-crlf"} {
		docs := sharedDocuments(t, name)
		_, err := pkg.ReadHEAD(context.Background(), bytes.NewReader(docs[".packtell/HEAD"]))
		if name == "unborn" && err != nil {
			t.Fatal(err)
		}
		if name == "invalid-head-crlf" {
			requireCode(t, err, pkg.ReasonInvalidHEAD)
		}
	}
}

type headHost struct {
	head                             pkg.HEAD
	begins, reads, publishes, closes int
	closeError                       error
}

func (h *headHost) Begin(context.Context) (pkg.HEADTransaction, error) { h.begins++; return h, nil }
func (h *headHost) ReadHEAD(context.Context) (pkg.HEAD, error)         { h.reads++; return h.head, nil }
func (h *headHost) PublishHEAD(_ context.Context, next pkg.HEAD) error {
	h.publishes++
	h.head = next
	return nil
}
func (h *headHost) Close() error { h.closes++; return h.closeError }
func TestS03ExpectedHEADShortCircuit(t *testing.T) {
	h := &headHost{head: pkg.HEAD(versionID)}
	called := false
	commit := func(ctx context.Context, tx pkg.HEADTransaction) error {
		called = true
		return tx.PublishHEAD(ctx, pkg.HEAD("019a0000-0000-7000-8000-000000000005"))
	}
	err := pkg.WithExpectedHEAD(context.Background(), h, pkg.UnbornHEAD, commit)
	requireCode(t, err, pkg.ReasonStaleHEAD)
	if called || h.publishes != 0 || h.closes != 1 || h.reads != 1 {
		t.Fatal("stale callback or leaked transaction")
	}
	if err = pkg.WithExpectedHEAD(context.Background(), h, pkg.HEAD(versionID), commit); err != nil || !called || h.publishes != 1 || h.closes != 2 {
		t.Fatal("valid expected-HEAD operation failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	starts := h.begins
	if err = pkg.WithExpectedHEAD(ctx, h, h.head, commit); !errors.Is(err, context.Canceled) || h.begins != starts {
		t.Fatal("began cancelled transaction")
	}
	h.closeError = io.ErrClosedPipe
	if err = pkg.WithExpectedHEAD(context.Background(), h, h.head, func(context.Context, pkg.HEADTransaction) error { return nil }); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("suppressed isolation close error")
	}
}
