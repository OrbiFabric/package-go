// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/orbifabric/package-go/conformance"
	"io"
	"io/fs"
	"reflect"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

type selectedTestSigner struct {
	private                    ed25519.PrivateKey
	profile                    pkg.SigningProfile
	profileCalls, signCalls    int
	failProfile, failSign      error
	alterResponse, mutateInput bool
	duringSign                 func()
}

func (s *selectedTestSigner) Profile(ctx context.Context) (pkg.SigningProfile, error) {
	s.profileCalls++
	return s.profile, s.failProfile
}
func (s *selectedTestSigner) Sign(ctx context.Context, input []byte) ([]byte, error) {
	s.signCalls++
	if s.duringSign != nil {
		s.duringSign()
	}
	if s.failSign != nil {
		return nil, s.failSign
	}
	if s.mutateInput {
		input[0] ^= 255
	}
	sig := ed25519.Sign(s.private, input)
	if s.alterResponse {
		sig[0] ^= 1
	}
	return sig, nil
}
func selectedSigner(t *testing.T) *selectedTestSigner {
	t.Helper()
	p := vectorPrivate(t)
	return &selectedTestSigner{private: p, profile: pkg.SigningProfile{SignerType: "local_device", PublicKey: p.Public().(ed25519.PublicKey)}}
}
func signRequest(t *testing.T) pkg.SignVersionRequest {
	t.Helper()
	return pkg.SignVersionRequest{VersionID: pkg.VersionID(memoryID(2)), At: testTime, KeyID: "test-only-key", SignerType: "local_device", PublicKey: vectorPrivate(t).Public().(ed25519.PublicKey)}
}
func TestCreateSignatureOnlyFromSelectedProfileWithoutAuthorityMutation(t *testing.T) {
	ctx := context.Background()
	s := treeFixture(t, "complete-history")
	before := map[string][]byte{}
	for p, b := range s.data {
		before[p] = bytes.Clone(b)
	}
	signer := selectedSigner(t)
	e, err := pkg.CreateVersionSignature(ctx, s, signer, signRequest(t), pkg.DefaultLimits(), supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if signer.profileCalls != 1 || signer.signCalls != 1 || s.closes != 1 || s.checks != 3 || !reflect.DeepEqual(s.data, before) {
		t.Fatalf("profile/sign calls=%d/%d checks/close=%d/%d", signer.profileCalls, signer.signCalls, s.checks, s.closes)
	}
	if e.SignatureID == pkg.SignatureID(memoryID(1)) || e.SignatureID == pkg.SignatureID(memoryID(2)) || e.SignatureID == pkg.SignatureID(memoryID(3)) {
		t.Fatal("reused entity ID", e)
	}
	if e.Official != nil || e.SignerType != "local_device" {
		t.Fatal(e)
	}
	s.addFile(sigPath(e), jsonBytes(t, e))
	report, err := pkg.VerifySignatures(ctx, s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureValid || report.Identity != pkg.IdentityUntrusted {
		t.Fatal(report, err)
	}
}
func TestSelectedSignerFailuresNeverFallbackOrPublish(t *testing.T) {
	for _, name := range []string{"profile-failure", "sign-failure", "changed-key", "changed-type", "invalid-curve-key", "bad-response", "mutated-input", "local-official-facts", "snapshot-before-sign", "snapshot-after-sign", "close-failure", "cancel-during-sign", "missing-capability", "missing-version"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "complete-history")
			signer := selectedSigner(t)
			request := signRequest(t)
			injected := errors.New("selected signer failed")
			want := injected
			wantSign := 0
			wantClose := 1
			switch name {
			case "profile-failure":
				signer.failProfile = injected
			case "sign-failure":
				signer.failSign = injected
				wantSign = 1
			case "changed-key":
				signer.profile.PublicKey = bytes.Repeat([]byte{7}, 32)
				want = nil
			case "changed-type":
				signer.profile.SignerType = "orbifabric_official"
				want = nil
			case "invalid-curve-key":
				wantClose = 0
				request.PublicKey = make([]byte, 32)
				signer.profile.PublicKey = make([]byte, 32)
				want = nil
				wantSign = 0
			case "bad-response":
				signer.alterResponse = true
				want = nil
				wantSign = 1
			case "mutated-input":
				signer.mutateInput = true
				want = nil
				wantSign = 1
			case "local-official-facts":
				signer.profile.Official = json.RawMessage(`{}`)
				want = nil
			case "snapshot-before-sign":
				s.checkError = injected
			case "snapshot-after-sign":
				signer.duringSign = func() { s.checkError = injected }
				wantSign = 1
			case "close-failure":
				s.closeError = injected
				wantSign = 1
			case "cancel-during-sign":
				want = context.Canceled
				wantSign = 1
			case "missing-capability":
				var f pkg.Format
				if err := json.Unmarshal(s.data[".packtell/format.json"], &f); err != nil {
					t.Fatal(err)
				}
				f.OptionalCapabilities = []string{pkg.CapabilityDeliveryEvidence}
				s.setFile(".packtell/format.json", jsonBytes(t, f))
				want = nil
			case "missing-version":
				request.VersionID = pkg.VersionID(memoryID(99))
				want = nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "cancel-during-sign" {
				signer.duringSign = cancel
			}
			before := map[string][]byte{}
			for p, b := range s.data {
				before[p] = bytes.Clone(b)
			}
			e, err := pkg.CreateVersionSignature(ctx, s, signer, request, pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || e.SignatureID != "" || s.closes != wantClose || signer.signCalls != wantSign || !reflect.DeepEqual(before, s.data) {
				t.Fatalf("signature=%s error=%v profile/sign calls=%d/%d close=%d", e.SignatureID, err, signer.profileCalls, signer.signCalls, s.closes)
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatal(err, want)
			}
			if signer.profileCalls > 1 || signer.signCalls > 1 {
				t.Fatalf("silent fallback/retry calls=%d/%d", signer.profileCalls, signer.signCalls)
			}
		})
	}
}
func TestOfficialAttributionRequiresSelectedEnvironmentProfileAndHostTrust(t *testing.T) {
	for _, name := range []string{"valid", "changed-environment", "changed-profile", "missing-issuer", "extra-field", "missing-profile-selection"} {
		t.Run(name, func(t *testing.T) {
			s := treeFixture(t, "complete-history")
			signer := selectedSigner(t)
			request := signRequest(t)
			request.SignerType = "orbifabric_official"
			request.OfficialEnvironment = "test"
			request.OfficialProfileID = "test-only-profile"
			signer.profile.SignerType = "orbifabric_official"
			official := pkg.OfficialSignerFacts{Issuer: "OrbiFabric", Environment: "test", ProfileID: "test-only-profile", RequestID: "test-only-request"}
			switch name {
			case "changed-environment":
				official.Environment = "production"
			case "changed-profile":
				official.ProfileID = "other"
			case "missing-issuer":
				official.Issuer = ""
			case "missing-profile-selection":
				request.OfficialProfileID = ""
			}
			signer.profile.Official = jsonBytes(t, official)
			if name == "extra-field" {
				signer.profile.Official = json.RawMessage(`{"issuer":"OrbiFabric","environment":"test","profile_id":"test-only-profile","request_id":"test-only-request","extra":1}`)
			}
			e, err := pkg.CreateVersionSignature(context.Background(), s, signer, request, pkg.DefaultLimits(), supportAllVocabulary())
			if name != "valid" {
				if err == nil || e.SignatureID != "" || signer.signCalls != 0 {
					t.Fatalf("signature=%s error=%v profile/sign calls=%d/%d", e.SignatureID, err, signer.profileCalls, signer.signCalls)
				}
				return
			}
			if err != nil || e.Official == nil || *e.Official != official {
				t.Fatal(e, err)
			}
			s.addFile(sigPath(e), jsonBytes(t, e))
			report, err := pkg.VerifySignatures(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if err != nil || report.Identity != pkg.IdentityUntrusted {
				t.Fatal("embedded official self-claims granted trust", report, err)
			}
			seen := 0
			pin := trustFunc(func(ctx context.Context, r pkg.TrustRequest) (bool, error) {
				seen++
				var f pkg.OfficialSignerFacts
				if err := json.Unmarshal(r.Official, &f); err != nil {
					t.Fatal(err)
				}
				return r.Purpose == pkg.VersionSignatureDomain && f.Environment == "test" && f.ProfileID == "test-only-profile" && bytes.Equal(r.PublicKey, request.PublicKey), nil
			})
			report, err = pkg.VerifySignatures(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), pin)
			if err != nil || report.Identity != pkg.IdentityTrusted || seen != 1 {
				t.Fatal(report, err)
			}
		})
	}
}
func TestSignatureReadInterruptionResourceAndCancellationNeverPass(t *testing.T) {
	l := pkg.DefaultLimits()
	s := treeFixture(t, "valid-signature")
	injected := errors.New("signature stream interrupted")
	e := vectorEnvelope(t)
	s.openOverride = func(path string, b []byte) io.ReadCloser {
		if path == sigPath(e) {
			return io.NopCloser(io.MultiReader(bytes.NewReader(b), portableErrorReader{injected}))
		}
		return io.NopCloser(bytes.NewReader(b))
	}
	report, err := pkg.VerifySignatures(context.Background(), s, l, supportAllVocabulary(), nil)
	if !errors.Is(err, injected) || report.State != pkg.SignatureNotChecked {
		t.Fatal(report, err)
	}
	s = treeFixture(t, "valid-signature")
	l.MaxTotalJSONBytes = 100
	report, err = pkg.VerifySignatures(context.Background(), s, l, supportAllVocabulary(), nil)
	requireCode(t, err, pkg.ReasonResourceLimit)
	if report.State != pkg.SignatureNotChecked || len(s.opens) != 0 {
		t.Fatal(report, s.opens)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = treeFixture(t, "valid-signature")
	report, err = pkg.VerifySignatures(ctx, s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if !errors.Is(err, context.Canceled) || report.State != pkg.SignatureNotChecked {
		t.Fatal(report, err)
	}
}
func FuzzSignatureEnvelopeRestrictedDomain(f *testing.F) {
	b, err := fs.ReadFile(conformance.Assets(), "vectors/crypto.v2.json")
	if err != nil {
		f.Fatal(err)
	}
	var vec struct {
		Envelope json.RawMessage `json:"signature_envelope"`
	}
	if err = json.Unmarshal(b, &vec); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(vec.Envelope))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"x","schema":"y"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l := pkg.DefaultLimits()
		l.MaxJSONBytes = 64 << 10
		l.MaxJSONDepth = 16
		l.MaxEntries = 256
		e, err := pkg.ReadVersionSignature(context.Background(), bytes.NewReader(b), l)
		if err != nil {
			return
		}
		input, err := pkg.SignatureSigningInput(context.Background(), e, l)
		if err != nil {
			var p *pkg.ProtocolError
			if errors.As(err, &p) && p.Code == pkg.ReasonResourceLimit {
				return
			}
			t.Fatal(err)
		}
		again, err := pkg.ReadVersionSignature(context.Background(), bytes.NewReader(jsonBytes(t, e)), l)
		if err != nil || !reflect.DeepEqual(e, again) {
			t.Fatal("signature fields lost", err)
		}
		next, err := pkg.SignatureSigningInput(context.Background(), again, l)
		if err != nil || !bytes.Equal(input, next) {
			t.Fatal("signing input changed", err)
		}
	})
}

type signingBeginFunc func(context.Context) (pkg.TreeSnapshot, error)

func (f signingBeginFunc) BeginSnapshot(ctx context.Context) (pkg.TreeSnapshot, error) { return f(ctx) }
func TestSigningSnapshotBeginFailureClosesReturnedResource(t *testing.T) {
	s := treeFixture(t, "complete-history")
	beginErr := errors.New("snapshot begin failed")
	closeErr := errors.New("snapshot close failed")
	s.closeError = closeErr
	signer := selectedSigner(t)
	e, err := pkg.CreateVersionSignature(context.Background(), signingBeginFunc(func(context.Context) (pkg.TreeSnapshot, error) { return s, beginErr }), signer, signRequest(t), pkg.DefaultLimits(), supportAllVocabulary())
	if e.SignatureID != "" || !errors.Is(err, beginErr) || !errors.Is(err, closeErr) || s.closes != 1 || signer.profileCalls != 0 || signer.signCalls != 0 {
		t.Fatal(e.SignatureID, err, s.closes, signer.profileCalls, signer.signCalls)
	}
}
