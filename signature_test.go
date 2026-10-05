// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"math/big"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

// This is the published TEST ONLY frozen vector, never a production signer/key.
func vectorPrivate(t *testing.T) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(decodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
}
func vectorEnvelope(t *testing.T) pkg.VersionSignature {
	t.Helper()
	e, err := pkg.ReadVersionSignature(context.Background(), bytes.NewReader(readCryptoVector(t).Envelope), pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func sigPath(e pkg.VersionSignature) string {
	return ".packtell/verification/versions/" + string(e.VersionID) + "/" + string(e.SignatureID) + ".json"
}

type trustFunc func(context.Context, pkg.TrustRequest) (bool, error)

func (f trustFunc) Trusted(ctx context.Context, r pkg.TrustRequest) (bool, error) { return f(ctx, r) }
func TestFrozenSigningInputSignatureAndIndependentTrust(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	vec := readCryptoVector(t)
	e := vectorEnvelope(t)
	input, err := pkg.SignatureSigningInput(ctx, e, l)
	if err != nil || !bytes.Equal(input, decodeHex(t, vec.SigningHex)) {
		t.Fatal(input, err)
	}
	sig := ed25519.Sign(vectorPrivate(t), input)
	if base64.RawURLEncoding.EncodeToString(sig) != e.Signature {
		t.Fatal("fixed frozen signature mismatch")
	}
	pk := vectorPrivate(t).Public().(ed25519.PublicKey)
	if err = pkg.VerifyEd25519Strict(ctx, pk, input, sig, l); err != nil {
		t.Fatal(err)
	}
	p, v, m := cryptoModels(t)
	item, err := pkg.VerifyVersionSignature(ctx, p, v, m, e, l, supportAllVocabulary(), nil)
	if err != nil || item.State != pkg.SignatureValid || item.Identity != pkg.IdentityUntrusted {
		t.Fatal(item, err)
	}
	calls := 0
	pin := trustFunc(func(ctx context.Context, r pkg.TrustRequest) (bool, error) {
		calls++
		if r.Purpose != pkg.VersionSignatureDomain || !bytes.Equal(r.PublicKey, pk) || len(r.Official) != 0 {
			t.Fatal(r)
		}
		r.PublicKey[0] ^= 255
		return true, nil
	})
	item, err = pkg.VerifyVersionSignature(ctx, p, v, m, e, l, supportAllVocabulary(), pin)
	if err != nil || item.Identity != pkg.IdentityTrusted || calls != 1 {
		t.Fatal(item, err)
	}
	// A bad signature never reaches trust, and self-described attribution alone
	// never grants identity trust. Full content verification is independent.
	e.SignedAt = "2026-10-06T00:00:00.000000Z"
	item, err = pkg.VerifyVersionSignature(ctx, p, v, m, e, l, supportAllVocabulary(), pin)
	if err != nil || item.State != pkg.SignatureInvalid || calls != 1 {
		t.Fatal(item, err)
	}
}
func TestS06SharedSignatureBehavior(t *testing.T) {
	for _, name := range []string{"valid-signature", "bad-signature"} {
		t.Run(name, func(t *testing.T) {
			raw, err := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
			if err != nil {
				t.Fatal(err)
			}
			var shared struct{ Expected pkg.Result }
			if err = json.Unmarshal(raw, &shared); err != nil {
				t.Fatal(err)
			}
			s := treeFixture(t, name)
			report, err := pkg.VerifySignatures(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
			if err != nil || report.State != shared.Expected.Signature || report.Identity != shared.Expected.Identity || len(report.Items) != 1 {
				t.Fatal(report, shared.Expected, err)
			}
			coverage, err := pkg.VerifyCommittedContent(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary())
			if err != nil || coverage.Integrity != shared.Expected.CommittedIntegrity {
				t.Fatal(coverage, err)
			}
			for _, code := range shared.Expected.ReasonCodes {
				if code == pkg.ReasonOK && report.State == pkg.SignatureValid {
					continue
				}
				if !containsCode(report.ReasonCodes, code) {
					t.Fatal("frozen reason absent", code, report)
				}
			}
			for _, p := range s.opens {
				if !strings.HasPrefix(p, ".packtell/") {
					t.Fatal("signature verification borrowed Working bytes", p)
				}
			}
		})
	}
}
func containsCode(a []pkg.ReasonCode, c pkg.ReasonCode) bool {
	for _, v := range a {
		if v == c {
			return true
		}
	}
	return false
}
func TestStrictEd25519CanonicalScalarPointAndLengths(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	e := vectorEnvelope(t)
	message, err := pkg.SignatureSigningInput(ctx, e, l)
	if err != nil {
		t.Fatal(err)
	}
	pk := vectorPrivate(t).Public().(ed25519.PublicKey)
	sig, _ := base64.RawURLEncoding.DecodeString(e.Signature)
	pField := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	order := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), mustTestInteger(t, "27742317777372353535851937790883648493"))
	for _, name := range []string{"short-key", "long-signature", "short-signature", "S-equals-L", "S-plus-L", "noncanonical-key-y", "noncanonical-R-y", "negative-zero-key", "negative-zero-R", "off-curve-key", "identity-key", "identity-R", "wrong-message"} {
		t.Run(name, func(t *testing.T) {
			key, sig, msg := bytes.Clone(pk), bytes.Clone(sig), bytes.Clone(message)
			switch name {
			case "short-key":
				key = key[:31]
			case "long-signature":
				sig = append(sig, 0)
			case "short-signature":
				sig = sig[:63]
			case "S-equals-L":
				copy(sig[32:], littleTest(order, 32))
			case "S-plus-L":
				s := integerLittle(sig[32:])
				s.Add(s, order)
				copy(sig[32:], littleTest(s, 32))
			case "noncanonical-key-y":
				key = littleTest(pField, 32)
			case "noncanonical-R-y":
				copy(sig[:32], littleTest(pField, 32))
			case "negative-zero-key":
				key = make([]byte, 32)
				key[0] = 1
				key[31] = 128
			case "negative-zero-R":
				copy(sig[:32], make([]byte, 32))
				sig[0] = 1
				sig[31] = 128
			case "off-curve-key":
				key = make([]byte, 32)
				key[0] = 2
			case "identity-key":
				key = make([]byte, 32)
				key[0] = 1
			case "identity-R":
				copy(sig[:32], make([]byte, 32))
				sig[0] = 1
			case "wrong-message":
				msg = append(msg, 'x')
			}
			err := pkg.VerifyEd25519Strict(ctx, key, msg, sig, l)
			requireCode(t, err, pkg.ReasonBadSignature)
		})
	}
	// RFC8032 section 7.1 TEST 1, independent positive empty-message vector.
	rfcKey := decodeHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	rfcSig := decodeHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if err = pkg.VerifyEd25519Strict(ctx, rfcKey, nil, rfcSig, l); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err = pkg.VerifyEd25519Strict(canceled, pk, message, sig, l)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	l.MaxJSONBytes = 1
	err = pkg.VerifyEd25519Strict(ctx, pk, message, sig, l)
	requireCode(t, err, pkg.ReasonResourceLimit)
}
func mustTestInteger(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatal(s)
	}
	return n
}
func littleTest(n *big.Int, size int) []byte {
	out := make([]byte, size)
	b := n.Bytes()
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
func integerLittle(b []byte) *big.Int {
	out := bytes.Clone(b)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return new(big.Int).SetBytes(out)
}
func TestSignatureSchemaBase64FingerprintAndSignedFacts(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	p, v, m := cryptoModels(t)
	for _, name := range []string{"fingerprint", "public-padding", "signature-padding", "public-newline", "signature-noncanonical-tail", "official-on-local", "missing-official", "wrong-schema", "keyID-empty", "keyID-length", "closed-field", "wrong-version", "wrong-package", "wrong-subject", "signed-time", "key-label"} {
		t.Run(name, func(t *testing.T) {
			e := vectorEnvelope(t)
			code := pkg.ReasonBadSignature
			switch name {
			case "fingerprint":
				e.Fingerprint = pkg.ContentIDForBytes([]byte("other"))
			case "public-padding":
				e.PublicKey += "="
				code = pkg.ReasonInvalidSchema
			case "signature-padding":
				e.Signature += "="
				code = pkg.ReasonInvalidSchema
			case "public-newline":
				e.PublicKey = "\n" + e.PublicKey[1:]
				code = pkg.ReasonInvalidSchema
			case "signature-noncanonical-tail":
				e.Signature = e.Signature[:85] + "x"
			case "official-on-local":
				e.Official = &pkg.OfficialSignerFacts{}
				code = pkg.ReasonInvalidSchema
			case "missing-official":
				e.SignerType = "orbifabric_official"
				code = pkg.ReasonInvalidSchema
			case "wrong-schema":
				e.Schema = "other"
				code = pkg.ReasonInvalidSchema
			case "keyID-empty":
				e.KeyID = ""
				code = pkg.ReasonInvalidSchema
			case "keyID-length":
				e.KeyID = strings.Repeat("😀", 257)
				code = pkg.ReasonInvalidSchema
			case "closed-field":
				code = pkg.ReasonInvalidSchema
			case "wrong-version":
				e.VersionID = pkg.VersionID(memoryID(99))
			case "wrong-package":
				e.PackageID = pkg.PackageID(memoryID(99))
			case "wrong-subject":
				e.SubjectDigest = pkg.ContentIDForBytes(nil)
			case "signed-time":
				e.SignedAt = "2026-10-06T00:00:00.000000Z"
			case "key-label":
				e.KeyID = "another-key"
			}
			if name == "closed-field" {
				raw := strings.Replace(string(jsonBytes(t, e)), `"schema":`, `"extra":1,"schema":`, 1)
				_, err := pkg.ReadVersionSignature(ctx, strings.NewReader(raw), l)
				requireCode(t, err, code)
				return
			}
			item, err := pkg.VerifyVersionSignature(ctx, p, v, m, e, l, supportAllVocabulary(), nil)
			if err != nil || item.State != pkg.SignatureInvalid || !containsCode(item.ReasonCodes, code) {
				t.Fatal(item, err)
			}
		})
	}
}
func TestSignatureAggregationPathCapabilitiesIOAndTrustFailure(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	s := treeFixture(t, "valid-signature")
	e := vectorEnvelope(t)
	bad := e
	bad.SignatureID = pkg.SignatureID(memoryID(23))
	bad.KeyID = "tampered"
	s.addFile(sigPath(bad), jsonBytes(t, bad))
	report, err := pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureInvalid || report.Identity != pkg.IdentityUntrusted || len(report.Items) != 2 || report.Items[0].State != pkg.SignatureValid || report.Items[1].State != pkg.SignatureInvalid {
		t.Fatal(report, err)
	}
	s = treeFixture(t, "core-minimal")
	report, err = pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureAbsent || report.Identity != pkg.IdentityUnknown {
		t.Fatal(report, err)
	}
	s = treeFixture(t, "valid-signature")
	s.remove(sigPath(e))
	bad = e
	bad.SignatureID = pkg.SignatureID(memoryID(24))
	s.addFile(sigPath(e), jsonBytes(t, bad))
	report, err = pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureInvalid || !containsCode(report.ReasonCodes, pkg.ReasonBadSignature) {
		t.Fatal(report, err)
	}
	s = treeFixture(t, "valid-signature")
	s.remove(sigPath(e))
	s.addFile(".packtell/verification/versions/"+string(memoryID(99))+"/"+string(e.SignatureID)+".json", jsonBytes(t, e))
	report, err = pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureInvalid || !containsCode(report.ReasonCodes, pkg.ReasonInvalidSchema) {
		t.Fatal(report, err)
	}
	s = treeFixture(t, "valid-signature")
	var format pkg.Format
	if err = json.Unmarshal(s.data[".packtell/format.json"], &format); err != nil {
		t.Fatal(err)
	}
	format.OptionalCapabilities = []string{pkg.CapabilityDeliveryEvidence}
	s.setFile(".packtell/format.json", jsonBytes(t, format))
	report, err = pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureInvalid || !containsCode(report.ReasonCodes, pkg.ReasonInvalidSchema) {
		t.Fatal(report, err)
	}
	injected := errors.New("trust unavailable")
	s = treeFixture(t, "valid-signature")
	report, err = pkg.VerifySignatures(ctx, s, l, supportAllVocabulary(), trustFunc(func(context.Context, pkg.TrustRequest) (bool, error) { return false, injected }))
	if !errors.Is(err, injected) || report.State != pkg.SignatureNotChecked || report.Identity != pkg.IdentityUnknown {
		t.Fatal(report, err)
	}

}

func TestSignatureClosedFieldTypesRemainSchemaFailures(t *testing.T) {
	for _, field := range []string{"public_key", "signature", "key_id", "signed_at", "signature_id", "algorithm"} {
		e := vectorEnvelope(t)
		var value map[string]any
		if err := json.Unmarshal(jsonBytes(t, e), &value); err != nil {
			t.Fatal(err)
		}
		value[field] = int64(1)
		_, err := pkg.ReadVersionSignature(context.Background(), bytes.NewReader(jsonBytes(t, value)), pkg.DefaultLimits())
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
}

func TestSignatureEntityIDReuseIsRejectedEvenWithValidMathematics(t *testing.T) {
	s := treeFixture(t, "valid-signature")
	e := vectorEnvelope(t)
	s.remove(sigPath(e))
	e.SignatureID = pkg.SignatureID(memoryID(3))
	input, err := pkg.SignatureSigningInput(context.Background(), e, pkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(vectorPrivate(t), input))
	s.addFile(sigPath(e), jsonBytes(t, e))
	report, err := pkg.VerifySignatures(context.Background(), s, pkg.DefaultLimits(), supportAllVocabulary(), nil)
	if err != nil || report.State != pkg.SignatureInvalid || !containsCode(report.ReasonCodes, pkg.ReasonInvalidSchema) {
		t.Fatal(report, err)
	}
}
