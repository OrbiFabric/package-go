// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/orbifabric/package-go/internal/strict25519"
)

const VersionSignatureDomain = "orbifabric.package.version-signature.v2"

type SignatureID UUID
type OfficialSignerFacts struct {
	Issuer      string `json:"issuer"`
	Environment string `json:"environment"`
	ProfileID   string `json:"profile_id"`
	RequestID   string `json:"request_id"`
}
type VersionSignature struct {
	Schema        string               `json:"schema"`
	SignatureID   SignatureID          `json:"signature_id"`
	PackageID     PackageID            `json:"package_id"`
	VersionID     VersionID            `json:"package_version_id"`
	SubjectDigest ContentID            `json:"subject_digest"`
	SignerType    string               `json:"signer_type"`
	KeyID         string               `json:"key_id"`
	Algorithm     string               `json:"algorithm"`
	PublicKey     string               `json:"public_key"`
	Fingerprint   ContentID            `json:"fingerprint"`
	SignedAt      string               `json:"signed_at"`
	Official      *OfficialSignerFacts `json:"official,omitempty"`
	Signature     string               `json:"signature"`
}

func canonicalBase64(s string, size int) ([]byte, error) {
	if len(s) != (size*8+5)/6 {
		return nil, schemaError("invalid base64url schema length")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return nil, schemaError("invalid base64url schema alphabet")
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != size || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, protocolError(ReasonBadSignature, "noncanonical base64url")
	}
	return b, nil
}
func parseOfficial(v any) (*OfficialSignerFacts, error) {
	m, err := closedObject(v, "issuer", "environment", "profile_id", "request_id")
	if err != nil {
		return nil, err
	}
	f := &OfficialSignerFacts{asString(m["issuer"]), asString(m["environment"]), asString(m["profile_id"]), asString(m["request_id"])}
	if f.Issuer != "OrbiFabric" || !containsText([]string{"development", "test", "production"}, f.Environment) || f.ProfileID == "" || f.RequestID == "" {
		return nil, schemaError("invalid official signing facts")
	}
	return f, nil
}
func parseVersionSignature(m map[string]any) (VersionSignature, error) {
	_, err := requiredObject(m, []string{"schema", "signature_id", "package_id", "package_version_id", "subject_digest", "signer_type", "key_id", "algorithm", "public_key", "fingerprint", "signed_at", "signature"}, "official")
	if err != nil {
		return VersionSignature{}, err
	}
	for _, field := range []string{"schema", "signature_id", "package_id", "package_version_id", "subject_digest", "signer_type", "key_id", "algorithm", "public_key", "fingerprint", "signed_at", "signature"} {
		if _, ok := m[field].(string); !ok {
			return VersionSignature{}, schemaError("signature field must be text")
		}
	}
	e := VersionSignature{Schema: asString(m["schema"]), SignatureID: SignatureID(asString(m["signature_id"])), PackageID: PackageID(asString(m["package_id"])), VersionID: VersionID(asString(m["package_version_id"])), SubjectDigest: ContentID(asString(m["subject_digest"])), SignerType: asString(m["signer_type"]), KeyID: asString(m["key_id"]), Algorithm: asString(m["algorithm"]), PublicKey: asString(m["public_key"]), Fingerprint: ContentID(asString(m["fingerprint"])), SignedAt: asString(m["signed_at"]), Signature: asString(m["signature"])}
	if e.Schema != VersionSignatureDomain || e.Algorithm != "ed25519" || !containsText([]string{"local_device", "orbifabric_official"}, e.SignerType) {
		return e, schemaError("invalid Version signature constants")
	}
	for _, id := range []UUID{UUID(e.SignatureID), UUID(e.PackageID), UUID(e.VersionID)} {
		if err = id.Validate(); err != nil {
			return e, err
		}
	}
	for _, id := range []ContentID{e.SubjectDigest, e.Fingerprint} {
		if err = id.Validate(); err != nil {
			return e, err
		}
	}
	if n := utf8.RuneCountInString(e.KeyID); n < 1 || n > 256 {
		return e, schemaError("invalid signature key_id length")
	}
	if _, err = ParseTimestamp(e.SignedAt); err != nil {
		return e, err
	}
	f, present := m["official"]
	if e.SignerType == "orbifabric_official" {
		if !present {
			return e, schemaError("official signer omits official facts")
		}
		e.Official, err = parseOfficial(f)
		if err != nil {
			return e, err
		}
	} else if present {
		return e, schemaError("local signer carries official facts")
	}
	pk, err := canonicalBase64(e.PublicKey, 32)
	if err != nil {
		return e, err
	}
	if _, err = canonicalBase64(e.Signature, 64); err != nil {
		return e, err
	}
	if ContentIDForBytes(pk) != e.Fingerprint {
		return e, protocolError(ReasonBadSignature, "fingerprint disagrees with public key")
	}
	return e, nil
}
func ReadVersionSignature(ctx context.Context, r io.Reader, l Limits) (VersionSignature, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return VersionSignature{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return VersionSignature{}, schemaError("invalid signature envelope object")
	}
	return parseVersionSignature(m)
}
func signatureValue(e VersionSignature, includeSignature bool) map[string]any {
	m := map[string]any{"schema": e.Schema, "signature_id": string(e.SignatureID), "package_id": string(e.PackageID), "package_version_id": string(e.VersionID), "subject_digest": string(e.SubjectDigest), "signer_type": e.SignerType, "key_id": e.KeyID, "algorithm": e.Algorithm, "public_key": e.PublicKey, "fingerprint": string(e.Fingerprint), "signed_at": e.SignedAt}
	if includeSignature {
		m["signature"] = e.Signature
	}
	if e.Official != nil {
		m["official"] = map[string]any{"issuer": e.Official.Issuer, "environment": e.Official.Environment, "profile_id": e.Official.ProfileID, "request_id": e.Official.RequestID}
	}
	return m
}
func validateSignatureModel(ctx context.Context, e VersionSignature, l Limits) (VersionSignature, error) {
	if err := l.Validate(); err != nil {
		return VersionSignature{}, err
	}
	v := signatureValue(e, true)
	if err := validateOptionalValue(ctx, v, l, 0); err != nil {
		return VersionSignature{}, err
	}
	return parseVersionSignature(v)
}

// SignatureSigningInput returns the exact canonical envelope without signature.
// Claimed subject_digest remains a claim; verification derives actual authority.
func SignatureSigningInput(ctx context.Context, e VersionSignature, l Limits) ([]byte, error) {
	// A placeholder is only for preparing unsigned input, never a verification
	// success. The signature field is omitted from the domain-separated message.
	if e.Signature == "" {
		e.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	}
	e, err := validateSignatureModel(ctx, e, l)
	if err != nil {
		return nil, err
	}
	b, err := CanonicalJSON(ctx, signatureValue(e, false), l)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(VersionSignatureDomain), '\n'), b...), nil
}

// VerifyEd25519Strict implements PKG-CONTRACT-012/022: canonical A/R/S,
// non-small-order points, pure RFC8032 and the uncofactored equation. Variable
// time point checks handle public data only; signing is always a Host operation.
func VerifyEd25519Strict(ctx context.Context, publicKey, message, signature []byte, l Limits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if int64(len(message)) > l.MaxFileBytes || int64(len(message)) > l.MaxTotalBytes || (int64(len(message)) > l.MaxJSONBytes && int64(len(message))-l.MaxJSONBytes > 128) {
		return protocolError(ReasonResourceLimit, "signature message byte policy")
	}
	err := strict25519.Verify(ctx, publicKey, message, signature)
	if errors.Is(err, strict25519.ErrInvalid) {
		return protocolError(ReasonBadSignature, "strict Ed25519 verification failed")
	}
	return err
}
func officialJSON(f *OfficialSignerFacts) json.RawMessage {
	if f == nil {
		return nil
	}
	b, _ := json.Marshal(f)
	return b
}

// VerifyVersionSignature derives actual immutable authority before validating
// the envelope. A pure model caller is responsible for actual history lineage;
// VerifySignatures reads the actual tree/history and path inventory itself.
func VerifyVersionSignature(ctx context.Context, p Package, v Version, m Manifest, e VersionSignature, l Limits, support CapabilitySupport, trust TrustPolicy) (SignatureItem, error) {
	_, digest, err := DeriveVersionSubject(ctx, p, v, m, l, support)
	if err != nil {
		return SignatureItem{}, err
	}
	if !declaredVersionSigning(v.RequiredCapabilities, v.OptionalCapabilities) {
		return signatureFailure(SignatureItem{SignatureID: e.SignatureID, VersionID: v.VersionID}, schemaError("Version omits signature capability"))
	}
	item, err := verifySignature(ctx, p.PackageID, v.VersionID, digest, e, l, trust)
	if err != nil {
		return signatureFailure(item, err)
	}
	return item, nil
}
func verifySignature(ctx context.Context, pid PackageID, vid VersionID, digest ContentID, e VersionSignature, l Limits, trust TrustPolicy) (SignatureItem, error) {
	item := SignatureItem{SignatureID: e.SignatureID, VersionID: vid, State: SignatureNotChecked, Identity: IdentityUnknown, ReasonCodes: []ReasonCode{}}
	normalized, err := validateSignatureModel(ctx, e, l)
	if err != nil {
		return item, err
	}
	e = normalized
	item.Identity = IdentityUntrusted
	if e.PackageID != pid || e.VersionID != vid || e.SubjectDigest != digest {
		return item, protocolError(ReasonBadSignature, "signature subject or identities disagree with authority")
	}
	input, err := SignatureSigningInput(ctx, e, l)
	if err != nil {
		return item, err
	}
	pk, _ := canonicalBase64(e.PublicKey, 32)
	sig, _ := canonicalBase64(e.Signature, 64)
	if err = VerifyEd25519Strict(ctx, pk, input, sig, l); err != nil {
		return item, err
	}
	item.State = SignatureValid
	item.Identity = IdentityUntrusted
	if trust != nil {
		trusted, err := trust.Trusted(ctx, TrustRequest{Purpose: VersionSignatureDomain, PublicKey: bytes.Clone(pk), Official: officialJSON(e.Official)})
		if err != nil {
			return item, err
		}
		if trusted {
			item.Identity = IdentityTrusted
		}
	}
	if err = ctx.Err(); err != nil {
		return item, err
	}
	item.ReasonCodes = []ReasonCode{ReasonOK}
	return item, nil
}
