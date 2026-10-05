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

func conformancePolicy() pkg.Limits {
	l := pkg.DefaultLimits()
	l.MaxEntries = 10000
	l.MaxFileBytes = 16777216
	l.MaxTotalBytes = 67108864
	l.MaxJSONDepth = 64
	l.MaxJSONBytes = 1048576
	l.MaxNDJSONLineBytes = 1048576
	l.MaxCompressionRatio = 1000
	return l
}

func TestRejectedZIPRecognitionNeverAcceptsAmbiguousOrBadMarker(t *testing.T) {
	for _, name := range []string{"safe-marker", "bad-marker-crc", "bad-payload-crc", "duplicate-marker", "second-root", "unstable"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "minimal-valid")
			s.addFile("../escape", []byte("unsafe payload must not be opened"))
			if name == "duplicate-marker" {
				for _, e := range s.entries {
					if e.Path == ".packtell/format.json" {
						s.entries = append(s.entries, e)
						break
					}
				}
			}
			if name == "second-root" {
				s.addFile("Other/.packtell/format.json", s.data[".packtell/format.json"])
			}
			b := writeFixtureZIP(t, s, "", zip.Store, false)
			if name == "bad-marker-crc" || name == "bad-payload-crc" {
				for _, location := range locateZIP(t, b) {
					if name == "bad-marker-crc" && location.name == ".packtell/format.json" || name == "bad-payload-crc" && location.name == "../escape" {
						b[location.data] ^= 1
					}
				}
			}
			archive := &testArchiveSource{data: b}
			if name == "unstable" {
				archive.checkError = pkg.ErrUnstableWorkingTree
			}
			codec, err := pkg.NewZIPSource(archive, conformancePolicy())
			if err != nil {
				t.Fatal(err)
			}
			got, err := pkg.Verify(context.Background(), codec, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			if err == nil || got.Result.Structure != pkg.StructureInvalid || got.Result.HistoryCompleteness != pkg.HistoryInvalid || archive.closes != 1 {
				t.Fatalf("%+v %v closes=%d", got.Result, err, archive.closes)
			}
			wantRecognized := name == "safe-marker" || name == "bad-payload-crc"
			if (got.Result.Recognition == pkg.Recognized) != wantRecognized {
				t.Fatal("marker observation was fabricated or unsafe payload read", got.Result)
			}
			code := pkg.ReasonPathTraversal
			if name == "duplicate-marker" {
				code = pkg.ReasonUnsafeArchive
			}
			if !slices.Contains(got.Result.ReasonCodes, code) {
				t.Fatal(got.Result)
			}
		})
	}
}

func TestVerifierCompletenessCouplingAndIndependentEvidence(t *testing.T) {
	for _, name := range []string{"missing-memory", "invalid-memory", "extra-bad-object", "bad-evidence", "missing-embedded"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "minimal-valid")
			wantHistory, wantStructure, wantIntegrity, wantEvidence := pkg.HistoryFull, pkg.StructureValid, pkg.IntegrityValid, pkg.EvidenceAbsent
			switch name {
			case "missing-memory":
				s.remove(".packtell/metadata/notes.json")
				wantHistory = pkg.HistoryNotFull
			case "invalid-memory":
				s.setFile(".packtell/metadata/notes.json", []byte(`{"schema":"wrong"}`))
				wantHistory, wantStructure, wantIntegrity = pkg.HistoryInvalid, pkg.StructureInvalid, pkg.IntegrityNotChecked
			case "extra-bad-object":
				id := pkg.ContentIDForBytes([]byte("expected"))
				p, _ := (pkg.ContentObjectRef{ContentID: id, Size: 3}).ObjectPath()
				s.addFile(p, []byte("bad"))
				wantHistory = pkg.HistoryInvalid
			case "bad-evidence":
				s = treeFixture(t, "later-evidence-append")
				e := anchorFromSource(t, s)
				e.KeyID = "changed attribution"
				s.setFile(evidencePath(e.Subject.EvidenceID), jsonBytes(t, e))
				wantEvidence = pkg.EvidenceInvalid
			case "missing-embedded":
				s = treeFixture(t, "later-evidence-append")
				d := deliveriesFromSource(t, s)
				for _, delivery := range d {
					for _, ref := range delivery.EvidenceRefs {
						if ref.Embedded {
							s.remove(evidencePath(ref.EvidenceID))
						}
					}
				}
				// No actual envelope remains: ABSENT is independent from the
				// broken embedded-presence obligation that makes history NOT_FULL.
				wantHistory, wantEvidence = pkg.HistoryNotFull, pkg.EvidenceAbsent
			}
			got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			if got.Result.HistoryCompleteness != wantHistory || got.Result.Structure != wantStructure || got.Result.CommittedIntegrity != wantIntegrity || got.Result.Evidence != wantEvidence {
				t.Fatalf("%+v error=%v", got.Result, err)
			}
			if name == "invalid-memory" {
				if err == nil {
					t.Fatal("invalid memory accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if name == "bad-evidence" || name == "missing-embedded" {
				if got.Result.Signature != pkg.SignatureValid || got.Result.Identity != pkg.IdentityUntrusted || got.Result.Online != pkg.OnlineNotRequested {
					t.Fatal(got.Result)
				}
			}
		})
	}
}

func TestVerifierUnsupportedOptionalMemoryIsNotInterpreted(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	var format map[string]any
	if err := json.Unmarshal(s.data[".packtell/format.json"], &format); err != nil {
		t.Fatal(err)
	}
	format["optional_capabilities"] = []string{pkg.CapabilityPortableMemory}
	s.setFile(".packtell/format.json", jsonBytes(t, format))
	s.addFile(".packtell/metadata/notes.json", []byte("opaque unsupported memory"))
	got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CoreSupport(), ProveCompleteness: true})
	if err != nil || got.Result.Structure != pkg.StructureValid || got.Result.HistoryCompleteness != pkg.HistoryNotChecked || got.Result.CommittedIntegrity != pkg.IntegrityValid {
		t.Fatalf("%+v %v", got, err)
	}
	for _, p := range s.opens {
		if p == ".packtell/metadata/notes.json" {
			t.Fatal("unsupported optional memory interpreted")
		}
	}
}

func TestVerifierCancellationAndPolicyNeverBecomeSuccess(t *testing.T) {
	for _, phase := range []string{"before", "payload", "entry-policy"} {
		t.Run(phase, func(t *testing.T) {
			s := treeFixture(t, "minimal-valid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l := conformancePolicy()
			switch phase {
			case "before":
				cancel()
			case "payload":
				s.openOverride = func(p string, b []byte) io.ReadCloser {
					if !strings.HasPrefix(p, ".packtell/") {
						cancel()
					}
					return io.NopCloser(bytes.NewReader(b))
				}
			case "entry-policy":
				l.MaxEntries = 1
			}
			got, err := pkg.Verify(ctx, s, l, pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			if err == nil || got.Result.HistoryCompleteness == pkg.HistoryFull || slices.Contains(got.Result.ReasonCodes, pkg.ReasonOK) {
				t.Fatalf("failure became success: %+v %v", got, err)
			}
			if phase == "entry-policy" {
				requireCode(t, err, pkg.ReasonResourceLimit)
				if !slices.Contains(got.Result.ReasonCodes, pkg.ReasonResourceLimit) {
					t.Fatal(got.Result)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func compareFrozenResult(t *testing.T, got, want pkg.Result) {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := 0; i < w.NumField()-1; i++ {
		if w.Field(i).String() == "NOT_CHECKED" {
			continue
		}
		if g.Field(i).String() != w.Field(i).String() {
			t.Errorf("%s=%s want %s", w.Type().Field(i).Name, g.Field(i).String(), w.Field(i).String())
		}
	}
	for _, code := range want.ReasonCodes {
		if !slices.Contains(got.ReasonCodes, code) {
			t.Errorf("missing frozen reason %s in %v", code, got.ReasonCodes)
		}
	}
}

// This is behavioral consumption of every exact manifest fixture, not fixture
// schema validation or an expected result produced by the implementation.
func TestS11SharedVerifierResults(t *testing.T) {
	if err := conformance.VerifyAssets(); err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(conformance.Assets(), "conformance/manifest.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Fixtures []struct{ ID string } }
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Fixtures) != 30 {
		t.Fatal("unexpected authority inventory", len(manifest.Fixtures))
	}
	for _, row := range manifest.Fixtures {
		t.Run(row.ID, func(t *testing.T) {
			raw, err := fs.ReadFile(conformance.Assets(), "fixtures/"+row.ID+".json")
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				Input    struct{ Kind string }
				Expected pkg.Result
			}
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			var source pkg.SnapshotSource
			if f.Input.Kind == "zip" {
				b, _ := zipFixture(t, row.ID)
				source = zipSource(t, b, conformancePolicy())
			} else {
				source = treeFixture(t, row.ID)
			}
			got, err := pkg.Verify(context.Background(), source, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			b, _ := json.Marshal(got.Result)
			t.Logf("authority=%s actual=%s error=%v", conformance.SpecCommit, b, err)
			compareFrozenResult(t, got.Result, f.Expected)
			if f.Expected.Structure == pkg.StructureValid && err != nil {
				t.Fatal(err)
			}
			if m, ok := source.(*memorySource); ok && m.closes != 1 {
				t.Fatal("owning observation must close once", m.closes)
			}
		})
	}
}

func TestVerifierObservationFailureRevokesProof(t *testing.T) {
	for _, phase := range []string{"stable", "close"} {
		t.Run(phase, func(t *testing.T) {
			s := treeFixture(t, "minimal-valid")
			failure := errors.New("Host observation failed")
			if phase == "stable" {
				s.checkError = failure
			} else {
				s.closeError = failure
			}
			got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			if !errors.Is(err, failure) || got.Result.CommittedIntegrity != pkg.IntegrityNotChecked || got.Result.HistoryCompleteness != pkg.HistoryNotChecked || got.Result.WorkingState != pkg.WorkingUnreadable || s.closes != 1 {
				t.Fatalf("%+v %v closes=%d", got, err, s.closes)
			}
		})
	}
}

func TestVerifierTrustFailureIsUncheckedNotAbsent(t *testing.T) {
	s := treeFixture(t, "valid-signature")
	failure := errors.New("Host trust policy unavailable")
	policy := trustFunc(func(context.Context, pkg.TrustRequest) (bool, error) { return false, failure })
	got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport(), Trust: policy})
	if !errors.Is(err, failure) || got.Result.Signature != pkg.SignatureNotChecked || got.Result.Identity != pkg.IdentityUnknown || got.Result.CommittedIntegrity != pkg.IntegrityValid || got.Result.HistoryCompleteness != pkg.HistoryNotChecked || slices.Contains(got.Result.ReasonCodes, pkg.ReasonOK) {
		t.Fatalf("trust failure was misreported: %+v %v", got.Result, err)
	}
}

func TestVerifierImplicitParentBudgetStopsDiagnosticReads(t *testing.T) {
	s := treeFixture(t, "minimal-valid")
	l := conformancePolicy()
	l.MaxEntries = len(s.entries)
	got, err := pkg.Verify(context.Background(), s, l, pkg.VerificationOptions{Support: pkg.CompleteSupport()})
	requireCode(t, err, pkg.ReasonResourceLimit)
	if len(s.opens) != 0 || got.Result.Structure != pkg.StructureNotChecked || got.Result.Recognition == pkg.Recognized {
		t.Fatal("Directory policy failure read discriminator", got.Result, s.opens)
	}
	b := writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Store, false)
	markerOffset := int64(-1)
	for _, location := range locateZIP(t, b) {
		if location.name == ".packtell/format.json" {
			markerOffset = int64(location.local)
		}
	}
	if markerOffset <= 0 {
		t.Fatal("test marker must differ from bounded EOCD tail offset")
	}
	reads := []int64{}
	archive := &testArchiveSource{data: b, readHook: func(offset int64) { reads = append(reads, offset) }}
	codec, err := pkg.NewZIPSource(archive, l)
	if err != nil {
		t.Fatal(err)
	}
	got, err = pkg.Verify(context.Background(), codec, l, pkg.VerificationOptions{Support: pkg.CompleteSupport()})
	requireCode(t, err, pkg.ReasonResourceLimit)
	if slices.Contains(reads, markerOffset) || got.Result.Recognition == pkg.Recognized || got.Result.Structure != pkg.StructureNotChecked || archive.closes != 1 {
		t.Fatal("ZIP policy failure read discriminator", got.Result, reads, archive.closes)
	}
}

func TestVerifierCoreProofAndUnsupportedSigning(t *testing.T) {
	s := treeFixture(t, "core-minimal")
	got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CoreSupport(), ProveCompleteness: true})
	if err != nil || got.Result.HistoryCompleteness != pkg.HistoryFull || got.Result.CommittedIntegrity != pkg.IntegrityValid {
		t.Fatalf("%+v %v", got, err)
	}
	s = treeFixture(t, "valid-signature")
	support := pkg.CompleteSupport()
	support.Capabilities = slices.DeleteFunc(support.Capabilities, func(c string) bool { return c == pkg.CapabilityVersionSignature })
	got, err = pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: support})
	if err != nil || got.Result.Signature != pkg.SignatureNotChecked || got.Result.Identity != pkg.IdentityUnknown {
		t.Fatalf("%+v %v", got, err)
	}
	for _, p := range s.opens {
		if len(p) > len(".packtell/verification/") && p[:len(".packtell/verification/")] == ".packtell/verification/" {
			t.Fatal("unsupported optional signature read", p)
		}
	}
}
