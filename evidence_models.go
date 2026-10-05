// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const EvidenceEnvelopeSchema = "orbifabric.package.evidence-envelope.v1"

// EvidenceSubject is the closed discriminated union of four subject schemas.
// Only Receipt has Delivery facts and only Lifecycle has Event facts. Empty
// unused fields are omitted; inappropriate nonempty variant fields reject.
type EvidenceSubject struct {
	Schema               string
	EvidenceID           EvidenceID
	PackageID            PackageID
	VersionID            VersionID
	VersionSubjectDigest ContentID
	Issuer               string
	CreatedAt            string
	ObservedAt           string
	DeliveryID           DeliveryID
	DeliveryDigest       ContentID
	Outcome              string
	EventID              EventID
	EventDigest          ContentID
}

func EvidenceSubjectSchema(kind string) (string, error) {
	if !containsText(evidenceKinds, kind) {
		return "", schemaError("unknown evidence kind")
	}
	return "orbifabric.package." + strings.ReplaceAll(kind, "_", "-") + "-subject.v1", nil
}
func subjectValue(s EvidenceSubject, kind string) map[string]any {
	m := map[string]any{"schema": s.Schema, "evidence_id": string(s.EvidenceID), "package_id": string(s.PackageID), "package_version_id": string(s.VersionID), "version_subject_digest": string(s.VersionSubjectDigest), "issuer": s.Issuer, "created_at": s.CreatedAt, "observed_at": s.ObservedAt}
	if kind == "delivery_receipt" {
		m["delivery_id"] = string(s.DeliveryID)
		m["delivery_digest"] = string(s.DeliveryDigest)
		m["outcome"] = s.Outcome
	}
	if kind == "lifecycle_witness" {
		m["event_id"] = string(s.EventID)
		m["event_digest"] = string(s.EventDigest)
	}
	return m
}
func parseEvidenceSubject(v any, kind string) (EvidenceSubject, error) {
	schema, err := EvidenceSubjectSchema(kind)
	if err != nil {
		return EvidenceSubject{}, err
	}
	fields := []string{"schema", "evidence_id", "package_id", "package_version_id", "version_subject_digest", "issuer", "created_at", "observed_at"}
	if kind == "delivery_receipt" {
		fields = append(fields, "delivery_id", "delivery_digest", "outcome")
	}
	if kind == "lifecycle_witness" {
		fields = append(fields, "event_id", "event_digest")
	}
	m, err := closedObject(v, fields...)
	if err != nil {
		return EvidenceSubject{}, err
	}
	for _, k := range fields {
		if _, ok := m[k].(string); !ok {
			return EvidenceSubject{}, schemaError("evidence subject field must be text")
		}
	}
	s := EvidenceSubject{Schema: asString(m["schema"]), EvidenceID: EvidenceID(asString(m["evidence_id"])), PackageID: PackageID(asString(m["package_id"])), VersionID: VersionID(asString(m["package_version_id"])), VersionSubjectDigest: ContentID(asString(m["version_subject_digest"])), Issuer: asString(m["issuer"]), CreatedAt: asString(m["created_at"]), ObservedAt: asString(m["observed_at"])}
	if s.Schema != schema || s.Issuer == "" {
		return s, schemaError("invalid evidence subject schema/issuer")
	}
	for _, id := range []UUID{UUID(s.EvidenceID), UUID(s.PackageID), UUID(s.VersionID)} {
		if err = id.Validate(); err != nil {
			return s, err
		}
	}
	if err = s.VersionSubjectDigest.Validate(); err != nil {
		return s, err
	}
	for _, at := range []string{s.CreatedAt, s.ObservedAt} {
		if _, err = ParseTimestamp(at); err != nil {
			return s, err
		}
	}
	if kind == "delivery_receipt" {
		s.DeliveryID = DeliveryID(asString(m["delivery_id"]))
		s.DeliveryDigest = ContentID(asString(m["delivery_digest"]))
		s.Outcome = asString(m["outcome"])
		if err = UUID(s.DeliveryID).Validate(); err != nil {
			return s, err
		}
		if err = s.DeliveryDigest.Validate(); err != nil {
			return s, err
		}
		if !containsText([]string{"received", "verified", "rejected"}, s.Outcome) {
			return s, schemaError("invalid receipt outcome")
		}
	}
	if kind == "lifecycle_witness" {
		s.EventID = EventID(asString(m["event_id"]))
		s.EventDigest = ContentID(asString(m["event_digest"]))
		if err = UUID(s.EventID).Validate(); err != nil {
			return s, err
		}
		if err = s.EventDigest.Validate(); err != nil {
			return s, err
		}
	}
	return s, nil
}
func validatedEvidenceSubject(ctx context.Context, s EvidenceSubject, kind string, l Limits) (EvidenceSubject, error) {
	if kind != "delivery_receipt" && (s.DeliveryID != "" || s.DeliveryDigest != "" || s.Outcome != "") {
		return EvidenceSubject{}, schemaError("non-receipt carries Delivery facts")
	}
	if kind != "lifecycle_witness" && (s.EventID != "" || s.EventDigest != "") {
		return EvidenceSubject{}, schemaError("non-lifecycle carries Event facts")
	}
	v := subjectValue(s, kind)
	if err := validateOptionalValue(ctx, v, l, 0); err != nil {
		return EvidenceSubject{}, err
	}
	return parseEvidenceSubject(v, kind)
}
func EvidenceSubjectDigest(ctx context.Context, s EvidenceSubject, kind string, l Limits) (ContentID, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	s, err := validatedEvidenceSubject(ctx, s, kind, l)
	if err != nil {
		return "", err
	}
	b, err := CanonicalJSON(ctx, subjectValue(s, kind), l)
	if err != nil {
		return "", err
	}
	return domainDigest(s.Schema, b), nil
}

type EvidenceEnvelope struct {
	Schema        string
	Kind          string
	Subject       EvidenceSubject
	SubjectDigest ContentID
	KeyID         string
	Algorithm     string
	PublicKey     string
	Fingerprint   ContentID
	Signature     string
}

func evidenceValue(e EvidenceEnvelope, signature bool) map[string]any {
	m := map[string]any{"schema": e.Schema, "kind": e.Kind, "subject": subjectValue(e.Subject, e.Kind), "subject_digest": string(e.SubjectDigest), "key_id": e.KeyID, "algorithm": e.Algorithm, "public_key": e.PublicKey, "fingerprint": string(e.Fingerprint)}
	if signature {
		m["signature"] = e.Signature
	}
	return m
}
func parseEvidenceEnvelope(v any) (EvidenceEnvelope, error) {
	m, err := closedObject(v, "schema", "kind", "subject", "subject_digest", "key_id", "algorithm", "public_key", "fingerprint", "signature")
	if err != nil {
		return EvidenceEnvelope{}, err
	}
	for _, k := range []string{"schema", "kind", "subject_digest", "key_id", "algorithm", "public_key", "fingerprint", "signature"} {
		if _, ok := m[k].(string); !ok {
			return EvidenceEnvelope{}, schemaError("evidence envelope field must be text")
		}
	}
	e := EvidenceEnvelope{Schema: asString(m["schema"]), Kind: asString(m["kind"]), SubjectDigest: ContentID(asString(m["subject_digest"])), KeyID: asString(m["key_id"]), Algorithm: asString(m["algorithm"]), PublicKey: asString(m["public_key"]), Fingerprint: ContentID(asString(m["fingerprint"])), Signature: asString(m["signature"])}
	if e.Schema != EvidenceEnvelopeSchema || e.Algorithm != "ed25519" {
		return e, schemaError("invalid evidence envelope constants")
	}
	e.Subject, err = parseEvidenceSubject(m["subject"], e.Kind)
	if err != nil {
		return e, err
	}
	if n := utf8.RuneCountInString(e.KeyID); n < 1 || n > 256 {
		return e, schemaError("invalid evidence key label")
	}
	for _, id := range []ContentID{e.SubjectDigest, e.Fingerprint} {
		if err = id.Validate(); err != nil {
			return e, err
		}
	}
	key, err := canonicalBase64(e.PublicKey, 32)
	if err != nil {
		return e, err
	}
	if _, err = canonicalBase64(e.Signature, 64); err != nil {
		return e, err
	}
	if ContentIDForBytes(key) != e.Fingerprint {
		return e, protocolError(ReasonInvalidEvidence, "evidence fingerprint disagrees")
	}
	return e, nil
}
func ReadEvidenceEnvelope(ctx context.Context, r io.Reader, l Limits) (EvidenceEnvelope, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return EvidenceEnvelope{}, err
	}
	return parseEvidenceEnvelope(v)
}
func validatedEvidenceEnvelope(ctx context.Context, e EvidenceEnvelope, l Limits) (EvidenceEnvelope, error) {
	if err := l.Validate(); err != nil {
		return EvidenceEnvelope{}, err
	}
	if _, err := validatedEvidenceSubject(ctx, e.Subject, e.Kind, l); err != nil {
		return EvidenceEnvelope{}, err
	}
	v := evidenceValue(e, true)
	if err := validateOptionalValue(ctx, v, l, 0); err != nil {
		return EvidenceEnvelope{}, err
	}
	return parseEvidenceEnvelope(v)
}
func EvidenceSigningInput(ctx context.Context, e EvidenceEnvelope, l Limits) ([]byte, error) {
	if e.Signature == "" {
		e.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	}
	e, err := validatedEvidenceEnvelope(ctx, e, l)
	if err != nil {
		return nil, err
	}
	b, err := CanonicalJSON(ctx, evidenceValue(e, false), l)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(EvidenceEnvelopeSchema), '\n'), b...), nil
}

// ValidateEvidenceUnchanged rejects rewriting any historical envelope/subject
// facts. A fresh issuer observation gets a new EvidenceID; online status is not
// an edit to old portable facts. Append inventories use their separate API.
func ValidateEvidenceUnchanged(ctx context.Context, prior, next EvidenceEnvelope, l Limits) error {
	prior, err := validatedEvidenceEnvelope(ctx, prior, l)
	if err != nil {
		return err
	}
	next, err = validatedEvidenceEnvelope(ctx, next, l)
	if err != nil {
		return err
	}
	a, err := CanonicalJSON(ctx, evidenceValue(prior, true), l)
	if err != nil {
		return err
	}
	b, err := CanonicalJSON(ctx, evidenceValue(next, true), l)
	if err != nil {
		return err
	}
	if string(a) != string(b) {
		return protocolError(ReasonInvalidEvidence, "historical evidence facts rewritten")
	}
	return nil
}

func (s EvidenceSubject) MarshalJSON() ([]byte, error) {
	for _, kind := range evidenceKinds {
		schema, _ := EvidenceSubjectSchema(kind)
		if schema == s.Schema {
			return json.Marshal(subjectValue(s, kind))
		}
	}
	return nil, schemaError("unknown evidence subject schema")
}
func (e EvidenceEnvelope) MarshalJSON() ([]byte, error) { return json.Marshal(evidenceValue(e, true)) }
