// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

func deliveriesFromSource(t *testing.T, s *memorySource) []pkg.Delivery {
	t.Helper()
	out := []pkg.Delivery{}
	for _, entry := range s.entries {
		if entry.Kind == "file" && strings.HasSuffix(entry.Path, "/delivery.json") {
			d, err := pkg.ReadDelivery(context.Background(), bytes.NewReader(s.data[entry.Path]), pkg.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
	}
	return out
}
func anchorFromSource(t *testing.T, s *memorySource) pkg.EvidenceEnvelope {
	t.Helper()
	e, err := pkg.ReadEvidenceEnvelope(context.Background(), bytes.NewReader(s.data[".packtell/evidence/objects/"+string(memoryID(40))+".json"]), pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func evidencePath(id pkg.EvidenceID) string {
	return ".packtell/evidence/objects/" + string(id) + ".json"
}
func resignEvidence(t *testing.T, e pkg.EvidenceEnvelope) pkg.EvidenceEnvelope {
	t.Helper()
	digest, err := pkg.EvidenceSubjectDigest(context.Background(), e.Subject, e.Kind, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	e.SubjectDigest = digest
	input, err := pkg.EvidenceSigningInput(context.Background(), e, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(vectorPrivate(t), input))
	return e
}
func TestS07SharedDeliveryEvidenceAndAppendInvariants(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	var beforeDigest pkg.ContentID
	for _, name := range []string{"multi-delivery", "later-evidence-append", "bad-signature"} {
		t.Run(name, func(t *testing.T) {
			b, err := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
			if err != nil {
				t.Fatal(err)
			}
			var expected struct{ Expected pkg.Result }
			if err = json.Unmarshal(b, &expected); err != nil {
				t.Fatal(err)
			}
			s := treeFixture(t, name)
			report, err := pkg.VerifyEvidence(ctx, s, l, supportAllVocabulary(), nil)
			if err != nil || report.State != expected.Expected.Evidence || report.Online != expected.Expected.Online || len(report.MissingEmbedded) != 0 {
				t.Fatal(report, expected, err)
			}
			coverage, err := pkg.VerifyCommittedContent(ctx, s, l, supportAllVocabulary())
			if err != nil || coverage.Integrity != expected.Expected.CommittedIntegrity {
				t.Fatal(coverage, err)
			}
			sigs, err := pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), nil)
			if err != nil || sigs.State != expected.Expected.Signature {
				t.Fatal(sigs, err)
			}
			if name != "bad-signature" {
				if len(report.Deliveries) != 2 {
					t.Fatal(report)
				}
				for _, d := range report.Deliveries {
					if !d.Valid {
						t.Fatal(d)
					}
				}
				d := report.Deliveries[0]
				if name == "multi-delivery" {
					beforeDigest = d.Digest
				} else if beforeDigest != d.Digest {
					t.Fatal("evidence append changed Delivery digest", beforeDigest, d.Digest)
				}
				subject, digest, err := pkg.DeriveSubjectAt(ctx, s, pkg.VersionID(memoryID(2)), l, supportAllVocabulary())
				if err != nil || digest != readCryptoVector(t).SubjectDigest || subject.VersionID != pkg.VersionID(memoryID(2)) {
					t.Fatal(subject, digest, err)
				}
			}
			for _, path := range s.opens {
				if !strings.HasPrefix(path, ".packtell/") {
					t.Fatal("evidence borrowed Working bytes", path)
				}
			}
		})
	}
}
func TestAllFourSubjectsActualReceiptEventBindingsAndPurposeTrust(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	s := treeFixture(t, "later-evidence-append")
	anchor := anchorFromSource(t, s)
	deliveries := deliveriesFromSource(t, s)
	dDigest, err := pkg.DeliveryDigest(ctx, deliveries[0], l)
	if err != nil {
		t.Fatal(err)
	}
	event := portableEvent(70, "PACKAGE_EXPORTED")
	s.setFile(".packtell/history/events.ndjson", eventBytes(t, event))
	eDigest, err := pkg.EventDigest(ctx, event, l)
	if err != nil {
		t.Fatal(err)
	}
	for i, kind := range []string{"package_witness", "delivery_receipt", "lifecycle_witness"} {
		e := anchor
		e.Kind = kind
		e.Subject.Schema, err = pkg.EvidenceSubjectSchema(kind)
		if err != nil {
			t.Fatal(err)
		}
		e.Subject.EvidenceID = pkg.EvidenceID(memoryID(41 + i))
		if kind == "delivery_receipt" {
			e.Subject.DeliveryID = deliveries[0].DeliveryID
			e.Subject.DeliveryDigest = dDigest
			e.Subject.Outcome = "verified"
		}
		if kind == "lifecycle_witness" {
			e.Subject.EventID = event.EventID
			e.Subject.EventDigest = eDigest
		}
		e = resignEvidence(t, e)
		s.addFile(evidencePath(e.Subject.EvidenceID), jsonBytes(t, e))
	}
	purposes := map[string]bool{}
	policy := trustFunc(func(ctx context.Context, r pkg.TrustRequest) (bool, error) {
		purposes[r.Purpose] = true
		if r.Purpose == pkg.VersionSignatureDomain || r.Issuer != "TEST ONLY" || len(r.Official) != 0 {
			t.Fatal("wrong evidence trust input", r.Purpose, r.Issuer)
		}
		return r.Purpose == "orbifabric.package.cloud-anchor-subject.v1", nil
	})
	report, err := pkg.VerifyEvidence(ctx, s, l, supportAllVocabulary(), policy)
	if err != nil || report.State != pkg.EvidenceValid || len(report.Items) != 4 || len(purposes) != 4 {
		t.Fatal(report, purposes, err)
	}
	for _, item := range report.Items {
		if item.Kind == "cloud_anchor" {
			if item.Identity != pkg.IdentityTrusted {
				t.Fatal(item)
			}
		} else if item.Identity != pkg.IdentityUntrusted {
			t.Fatal("issuer purpose improperly reused", item)
		}
	}
	for _, kind := range []string{"cloud_anchor", "package_witness", "delivery_receipt", "lifecycle_witness"} {
		schema, _ := pkg.EvidenceSubjectSchema(kind)
		if !purposes[schema] {
			t.Fatal(schema)
		}
	}
}
func TestBadDeliveryReferencesNeverHiddenAndEvidenceIndependent(t *testing.T) {
	for _, name := range []string{"missing-signature", "bad-signature", "wrong-Version", "wrong-subject", "wrong-path-ID", "unsorted-signatures", "duplicate-evidence-ID", "wrong-reference-kind"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "later-evidence-append")
			d := deliveriesFromSource(t, s)[0]
			path := ".packtell/evidence/deliveries/" + string(d.DeliveryID) + "/delivery.json"
			switch name {
			case "missing-signature":
				d.SignatureIDs = append(d.SignatureIDs, pkg.SignatureID(memoryID(99)))
			case "bad-signature":
				bad := vectorEnvelope(t)
				bad.SignatureID = pkg.SignatureID(memoryID(23))
				bad.KeyID = "tampered"
				s.addFile(sigPath(bad), jsonBytes(t, bad))
				d.SignatureIDs = append(d.SignatureIDs, bad.SignatureID)
			case "wrong-Version":
				d.VersionID = pkg.VersionID(memoryID(99))
			case "wrong-subject":
				d.SubjectDigest = pkg.ContentIDForBytes(nil)
			case "wrong-path-ID":
				d.DeliveryID = pkg.DeliveryID(memoryID(99))
			case "unsorted-signatures":
				d.SignatureIDs = []pkg.SignatureID{pkg.SignatureID(memoryID(99)), d.SignatureIDs[0]}
			case "duplicate-evidence-ID":
				d.EvidenceRefs = append(d.EvidenceRefs, d.EvidenceRefs[0])
			case "wrong-reference-kind":
				d.EvidenceRefs[0].Kind = "package_witness"
			}
			s.setFile(path, jsonBytes(t, d))
			report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if err != nil || report.State != pkg.EvidenceInvalid || !containsCode(report.ReasonCodes, pkg.ReasonInvalidEvidence) {
				t.Fatal(report, err)
			}
			coverage, err := pkg.VerifyCommittedContent(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary())
			if err != nil || coverage.Integrity != pkg.IntegrityValid {
				t.Fatal("evidence contaminated content integrity", coverage, err)
			}
		})
	}
}
func TestEvidenceClaimCryptoVariantAndPathFailures(t *testing.T) {
	for _, name := range []string{"wrong-ID", "wrong-Version", "wrong-Version-digest", "wrong-subject-digest", "wrong-fingerprint", "bad-signature", "kind-subject-mismatch", "unknown-field"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "later-evidence-append")
			e := anchorFromSource(t, s)
			path := evidencePath(e.Subject.EvidenceID)
			switch name {
			case "wrong-ID":
				e.Subject.EvidenceID = pkg.EvidenceID(memoryID(99))
			case "wrong-Version":
				e.Subject.VersionID = pkg.VersionID(memoryID(99))
			case "wrong-Version-digest":
				e.Subject.VersionSubjectDigest = pkg.ContentIDForBytes(nil)
			case "wrong-subject-digest":
				e.SubjectDigest = pkg.ContentIDForBytes(nil)
			case "wrong-fingerprint":
				e.Fingerprint = pkg.ContentIDForBytes(nil)
			case "bad-signature":
				e.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			case "kind-subject-mismatch":
				e.Kind = "package_witness"
			}
			b := jsonBytes(t, e)
			if name == "unknown-field" {
				b = []byte(strings.Replace(string(b), `"kind":`, `"online":"CURRENT","kind":`, 1))
			}
			s.setFile(path, b)
			report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if err != nil || report.State != pkg.EvidenceInvalid || !containsCode(report.ReasonCodes, pkg.ReasonInvalidEvidence) {
				t.Fatal(report, err)
			}
		})
	}
}
func TestDeliveryAndEvidenceImmutabilityAndClosedVariants(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	before := treeFixture(t, "multi-delivery")
	after := treeFixture(t, "later-evidence-append")
	old := deliveriesFromSource(t, before)[0]
	next := deliveriesFromSource(t, after)[0]
	if err := pkg.ValidateDeliveryAppend(ctx, old, next, l); err != nil {
		t.Fatal(err)
	}
	digest, err := pkg.DeliveryDigest(ctx, old, l)
	if err != nil {
		t.Fatal(err)
	}
	appended, err := pkg.AppendEvidenceRefs(ctx, old, next.EvidenceRefs, l)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := pkg.DeliveryDigest(ctx, appended, l); err != nil || actual != digest {
		t.Fatal(actual, err)
	}
	changed := next
	recipient := "another"
	changed.Recipient = &recipient
	err = pkg.ValidateDeliveryAppend(ctx, next, changed, l)
	requireCode(t, err, pkg.ReasonInvalidEvidence)
	err = pkg.ValidateDeliveryAppend(ctx, next, old, l)
	requireCode(t, err, pkg.ReasonInvalidEvidence)
	_, err = pkg.AppendEvidenceRefs(ctx, next, next.EvidenceRefs, l)
	requireCode(t, err, pkg.ReasonInvalidEvidence)
	e := anchorFromSource(t, after)
	if err = pkg.ValidateEvidenceUnchanged(ctx, e, e, l); err != nil {
		t.Fatal(err)
	}
	changedE := e
	changedE.Subject.ObservedAt = "2026-10-06T00:00:00.000000Z"
	err = pkg.ValidateEvidenceUnchanged(ctx, e, changedE, l)
	requireCode(t, err, pkg.ReasonInvalidEvidence)
	e.Subject.EventID = pkg.EventID(memoryID(70))
	_, err = pkg.EvidenceSubjectDigest(ctx, e.Subject, e.Kind, l)
	requireCode(t, err, pkg.ReasonInvalidSchema)
}
func TestMissingEmbeddedAndExternalInventoryNeverFetch(t *testing.T) {
	s := treeFixture(t, "later-evidence-append")
	e := anchorFromSource(t, s)
	s.remove(evidencePath(e.Subject.EvidenceID))
	report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || len(report.MissingEmbedded) != 1 || report.MissingEmbedded[0] != e.Subject.EvidenceID || report.Online != pkg.OnlineNotRequested {
		t.Fatal(report, err)
	}
	d := deliveriesFromSource(t, s)[0]
	d.EvidenceRefs[0].Embedded = false
	s.setFile(".packtell/evidence/deliveries/"+string(d.DeliveryID)+"/delivery.json", jsonBytes(t, d))
	report, err = pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || len(report.MissingEmbedded) != 0 || len(report.External) != 1 || report.State != pkg.EvidenceAbsent || report.Online != pkg.OnlineNotRequested {
		t.Fatal(report, err)
	}
	for _, p := range s.opens {
		if p == evidencePath(e.Subject.EvidenceID) {
			t.Fatal("absent external evidence opened", p)
		}
	}
}

func TestReceiptAndEventWitnessWrongBindingsWithValidCryptoReject(t *testing.T) {
	for _, name := range []string{"receipt-hash", "receipt-Delivery", "event-hash", "event-ID"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "later-evidence-append")
			e := anchorFromSource(t, s)
			d := deliveriesFromSource(t, s)[0]
			e.Subject.EvidenceID = pkg.EvidenceID(memoryID(42))
			e.Kind = "delivery_receipt"
			e.Subject.Schema, _ = pkg.EvidenceSubjectSchema(e.Kind)
			e.Subject.DeliveryID = d.DeliveryID
			e.Subject.DeliveryDigest, _ = pkg.DeliveryDigest(context.Background(), d, pkg.DefaultLimits())
			e.Subject.Outcome = "received"
			switch name {
			case "receipt-hash":
				e.Subject.DeliveryDigest = pkg.ContentIDForBytes(nil)
			case "receipt-Delivery":
				e.Subject.DeliveryID = pkg.DeliveryID(memoryID(99))
			case "event-hash", "event-ID":
				e.Kind = "lifecycle_witness"
				e.Subject.Schema, _ = pkg.EvidenceSubjectSchema(e.Kind)
				e.Subject.DeliveryID = ""
				e.Subject.DeliveryDigest = ""
				e.Subject.Outcome = ""
				event := portableEvent(70, "PACKAGE_EXPORTED")
				s.setFile(".packtell/history/events.ndjson", eventBytes(t, event))
				e.Subject.EventID = event.EventID
				e.Subject.EventDigest, _ = pkg.EventDigest(context.Background(), event, pkg.DefaultLimits())
				if name == "event-ID" {
					e.Subject.EventID = pkg.EventID(memoryID(99))
				} else {
					e.Subject.EventDigest = pkg.ContentIDForBytes(nil)
				}
			}
			e = resignEvidence(t, e)
			s.addFile(evidencePath(e.Subject.EvidenceID), jsonBytes(t, e))
			report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if err != nil || report.State != pkg.EvidenceInvalid {
				t.Fatal(report, err)
			}
		})
	}
}
func TestCreateDeliveryNeedsEverySelectedSignatureAndOwnsSafeFacts(t *testing.T) {
	s := treeFixture(t, "multi-delivery")
	before := map[string][]byte{}
	for p, b := range s.data {
		before[p] = bytes.Clone(b)
	}
	recipient := "selected opaque recipient"
	request := pkg.DeliveryRequest{VersionID: pkg.VersionID(memoryID(2)), At: testTime, SignatureIDs: []pkg.SignatureID{pkg.SignatureID(memoryID(20))}, Recipient: &recipient}
	calls := 0
	policy := factPolicyFunc(func(ctx context.Context, docs map[string][]byte) error {
		calls++
		for path, b := range docs {
			if !strings.HasSuffix(path, "/delivery.json") {
				t.Fatal(path)
			}
			b[0] = '!'
		}
		return nil
	})
	d, err := pkg.CreateDelivery(context.Background(), s, request, pkg.DefaultLimits(), supportAllVocabulary(), policy)
	if err != nil || calls != 1 || s.closes != 1 || *d.Recipient != recipient || !reflect.DeepEqual(before, s.data) {
		t.Fatal(d, err, calls, s.closes)
	}
	if d.DeliveryID == pkg.DeliveryID(memoryID(30)) || d.DeliveryID == pkg.DeliveryID(memoryID(31)) {
		t.Fatal("existing Delivery ID reused", d)
	}
	path := ".packtell/evidence/deliveries/" + string(d.DeliveryID) + "/delivery.json"
	s.addFile(path, jsonBytes(t, d))
	report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.EvidenceAbsent || len(report.Deliveries) != 3 {
		t.Fatal(report, err)
	}
	for _, name := range []string{"missing", "bad", "policy-fail", "source-change", "close-fail"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "multi-delivery")
			r := request
			injected := errors.New("Delivery Host rejected")
			selector := factPolicyFunc(approveFacts)
			switch name {
			case "missing":
				r.SignatureIDs = append(append([]pkg.SignatureID{}, r.SignatureIDs...), pkg.SignatureID(memoryID(99)))
			case "bad":
				bad := vectorEnvelope(t)
				bad.SignatureID = pkg.SignatureID(memoryID(23))
				bad.KeyID = "tampered"
				s.addFile(sigPath(bad), jsonBytes(t, bad))
				r.SignatureIDs = append(append([]pkg.SignatureID{}, r.SignatureIDs...), bad.SignatureID)
			case "policy-fail":
				selector = factPolicyFunc(func(context.Context, map[string][]byte) error { return injected })
			case "source-change":
				selector = factPolicyFunc(func(context.Context, map[string][]byte) error { s.checkError = injected; return nil })
			case "close-fail":
				s.closeError = injected
			}
			d, err := pkg.CreateDelivery(context.Background(), s, r, pkg.DefaultLimits(), supportAllVocabulary(), selector)
			if err == nil || d.DeliveryID != "" || s.closes != 1 {
				t.Fatal(d, err, s.closes)
			}
		})
	}
}

type onlineEvidenceFunc func(context.Context, pkg.EvidenceStatusRequest) (pkg.OnlineState, error)

func (f onlineEvidenceFunc) Status(ctx context.Context, r pkg.EvidenceStatusRequest) (pkg.OnlineState, error) {
	return f(ctx, r)
}
func TestOnlineStatusExplicitAndNeverRewritesPortableFacts(t *testing.T) {
	s := treeFixture(t, "later-evidence-append")
	e := anchorFromSource(t, s)
	before := bytes.Clone(s.data[evidencePath(e.Subject.EvidenceID)])
	calls := 0
	port := onlineEvidenceFunc(func(ctx context.Context, r pkg.EvidenceStatusRequest) (pkg.OnlineState, error) {
		calls++
		if r.EvidenceID != e.Subject.EvidenceID || r.Kind != e.Kind {
			t.Fatal(r)
		}
		return pkg.OnlineRevoked, nil
	})
	report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || report.Online != pkg.OnlineNotRequested || calls != 0 {
		t.Fatal(report, err, calls)
	}
	state, err := pkg.QueryEvidenceOnline(context.Background(), port, pkg.EvidenceStatusRequest{EvidenceID: e.Subject.EvidenceID, Kind: e.Kind})
	if err != nil || state != pkg.OnlineRevoked || calls != 1 || !bytes.Equal(before, s.data[evidencePath(e.Subject.EvidenceID)]) {
		t.Fatal(state, err, calls)
	}
	report, err = pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.EvidenceValid || report.Online != pkg.OnlineNotRequested {
		t.Fatal("online revocation changed historical proof", report, err)
	}
	injected := errors.New("status unavailable")
	state, err = pkg.QueryEvidenceOnline(context.Background(), onlineEvidenceFunc(func(context.Context, pkg.EvidenceStatusRequest) (pkg.OnlineState, error) {
		return pkg.OnlineCurrent, injected
	}), pkg.EvidenceStatusRequest{EvidenceID: e.Subject.EvidenceID, Kind: e.Kind})
	if state != pkg.OnlineUnavailable || !errors.Is(err, injected) {
		t.Fatal(state, err)
	}
}

func TestEvidenceResourcesInterruptionsAndTrustFailuresNeverPass(t *testing.T) {
	s := treeFixture(t, "later-evidence-append")
	e := anchorFromSource(t, s)
	injected := errors.New("evidence stream interrupted")
	s.openOverride = func(path string, b []byte) io.ReadCloser {
		if path == evidencePath(e.Subject.EvidenceID) {
			return io.NopCloser(io.MultiReader(bytes.NewReader(b), portableErrorReader{injected}))
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	report, err := pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if !errors.Is(err, injected) || report.State != pkg.EvidenceNotChecked {
		t.Fatal(report, err)
	}
	s = treeFixture(t, "later-evidence-append")
	report, err = pkg.VerifyEvidence(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), trustFunc(func(context.Context, pkg.TrustRequest) (bool, error) { return true, injected }))
	if !errors.Is(err, injected) || report.State != pkg.EvidenceNotChecked {
		t.Fatal(report, err)
	}
	l := pkg.DefaultLimits()
	l.MaxTotalJSONBytes = 100
	s = treeFixture(t, "later-evidence-append")
	report, err = pkg.VerifyEvidence(context.Background(), s, l, supportAllVocabulary(), nil)
	requireCode(t, err, pkg.ReasonResourceLimit)
	if report.State != pkg.EvidenceNotChecked || len(s.opens) != 0 {
		t.Fatal(report, s.opens)
	}
	l = pkg.DefaultLimits()
	l.MaxJSONBytes = 128
	d := deliveriesFromSource(t, s)[0]
	d.EvidenceRefs = make([]pkg.EvidenceRef, 10000)
	_, err = pkg.DeliveryDigest(context.Background(), d, l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err = pkg.VerifyEvidence(ctx, s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if !errors.Is(err, context.Canceled) || report.State != pkg.EvidenceNotChecked {
		t.Fatal(report, err)
	}
}
func FuzzEvidenceEnvelopeRestrictedDomain(f *testing.F) {
	raw, err := fs.ReadFile(conformance.Assets(), "fixtures/later-evidence-append.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct {
		Input struct {
			Entries []struct {
				Path  string
				Bytes string `json:"bytes_base64"`
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, entry := range fixture.Input.Entries {
		if strings.HasPrefix(entry.Path, ".packtell/evidence/objects/") {
			b, err := base64.StdEncoding.DecodeString(entry.Bytes)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"kind":"cloud_anchor","kind":"package_witness"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l := pkg.DefaultLimits()
		l.MaxJSONBytes = 64 << 10
		l.MaxJSONDepth = 16
		l.MaxEntries = 256
		e, err := pkg.ReadEvidenceEnvelope(context.Background(), bytes.NewReader(b), l)
		if err != nil {
			return
		}
		again, err := pkg.ReadEvidenceEnvelope(context.Background(), bytes.NewReader(jsonBytes(t, e)), l)
		if err != nil || !reflect.DeepEqual(e, again) {
			t.Fatal("evidence facts lost", err)
		}
		first, err := pkg.EvidenceSubjectDigest(context.Background(), e.Subject, e.Kind, l)
		if err != nil {
			var pe *pkg.ProtocolError
			if errors.As(err, &pe) && pe.Code == pkg.ReasonResourceLimit {
				return
			}
			t.Fatal(err)
		}
		second, err := pkg.EvidenceSubjectDigest(context.Background(), again.Subject, again.Kind, l)
		if err != nil || first != second {
			t.Fatal("evidence subject digest changed", err)
		}
	})
}

func TestFrozenEvidenceAppendPreservesOriginalAuthorityAndSignatureBytes(t *testing.T) {
	before := treeFixture(t, "multi-delivery")
	after := treeFixture(t, "later-evidence-append")
	e := vectorEnvelope(t)
	for _, path := range []string{".packtell/package.json", ".packtell/HEAD", ".packtell/versions/" + string(e.VersionID) + "/version.json", ".packtell/versions/" + string(e.VersionID) + "/manifest.json", sigPath(e)} {
		if !bytes.Equal(before.data[path], after.data[path]) {
			t.Fatal("frozen append changed immutable authority", path)
		}
	}
	old := deliveriesFromSource(t, before)[0]
	next := deliveriesFromSource(t, after)[0]
	if err := pkg.ValidateDeliveryAppend(context.Background(), old, next, pkg.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}
