// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"io"
	"reflect"
)

const DeliverySchema = "orbifabric.package.delivery.v1"

type DeliveryID UUID
type EvidenceID UUID
type EvidenceRef struct {
	EvidenceID EvidenceID `json:"evidence_id"`
	Kind       string     `json:"kind"`
	Embedded   bool       `json:"embedded"`
}
type Delivery struct {
	Schema        string        `json:"schema"`
	DeliveryID    DeliveryID    `json:"delivery_id"`
	PackageID     PackageID     `json:"package_id"`
	VersionID     VersionID     `json:"package_version_id"`
	SubjectDigest ContentID     `json:"subject_digest"`
	CreatedAt     string        `json:"created_at"`
	Recipient     *string       `json:"recipient,omitempty"`
	Purpose       *string       `json:"purpose,omitempty"`
	Channel       *string       `json:"channel,omitempty"`
	SignatureIDs  []SignatureID `json:"signature_ids"`
	EvidenceRefs  []EvidenceRef `json:"evidence_refs"`
}

var evidenceKinds = []string{"cloud_anchor", "package_witness", "delivery_receipt", "lifecycle_witness"}

func parseDelivery(v any) (Delivery, error) {
	m, err := requiredObject(v, []string{"schema", "delivery_id", "package_id", "package_version_id", "subject_digest", "created_at", "signature_ids", "evidence_refs"}, "recipient", "purpose", "channel")
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{Schema: asString(m["schema"]), DeliveryID: DeliveryID(asString(m["delivery_id"])), PackageID: PackageID(asString(m["package_id"])), VersionID: VersionID(asString(m["package_version_id"])), SubjectDigest: ContentID(asString(m["subject_digest"])), CreatedAt: asString(m["created_at"]), SignatureIDs: []SignatureID{}, EvidenceRefs: []EvidenceRef{}}
	if d.Schema != DeliverySchema {
		return d, schemaError("invalid Delivery schema")
	}
	for _, id := range []UUID{UUID(d.DeliveryID), UUID(d.PackageID), UUID(d.VersionID)} {
		if err = id.Validate(); err != nil {
			return d, err
		}
	}
	if err = d.SubjectDigest.Validate(); err != nil {
		return d, err
	}
	if _, err = ParseTimestamp(d.CreatedAt); err != nil {
		return d, err
	}
	d.Recipient, err = optionalText(m, "recipient")
	if err != nil {
		return d, err
	}
	d.Purpose, err = optionalText(m, "purpose")
	if err != nil {
		return d, err
	}
	d.Channel, err = optionalText(m, "channel")
	if err != nil {
		return d, err
	}
	sigs, ok := m["signature_ids"].([]any)
	if !ok || len(sigs) == 0 {
		return d, schemaError("Delivery requires signature references")
	}
	var prior SignatureID
	for _, v := range sigs {
		id := SignatureID(asString(v))
		if err = UUID(id).Validate(); err != nil {
			return d, err
		}
		if id <= prior {
			return d, schemaError("signature references must sort uniquely")
		}
		prior = id
		d.SignatureIDs = append(d.SignatureIDs, id)
	}
	refs, ok := m["evidence_refs"].([]any)
	if !ok {
		return d, schemaError("invalid evidence reference array")
	}
	seen := map[EvidenceID]bool{}
	for _, v := range refs {
		r, err := closedObject(v, "evidence_id", "kind", "embedded")
		if err != nil {
			return d, err
		}
		id := EvidenceID(asString(r["evidence_id"]))
		if err = UUID(id).Validate(); err != nil {
			return d, err
		}
		kind := asString(r["kind"])
		embedded, ok := r["embedded"].(bool)
		if !ok || !containsText(evidenceKinds, kind) {
			return d, schemaError("invalid evidence reference kind/flag")
		}
		if seen[id] {
			return d, protocolError(ReasonInvalidEvidence, "duplicate evidence reference")
		}
		seen[id] = true
		d.EvidenceRefs = append(d.EvidenceRefs, EvidenceRef{id, kind, embedded})
	}
	return d, nil
}
func ReadDelivery(ctx context.Context, r io.Reader, l Limits) (Delivery, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return Delivery{}, err
	}
	return parseDelivery(v)
}
func deliveryValue(d Delivery, refs bool) map[string]any {
	m := map[string]any{"schema": d.Schema, "delivery_id": string(d.DeliveryID), "package_id": string(d.PackageID), "package_version_id": string(d.VersionID), "subject_digest": string(d.SubjectDigest), "created_at": d.CreatedAt}
	if d.Recipient != nil {
		m["recipient"] = *d.Recipient
	}
	if d.Purpose != nil {
		m["purpose"] = *d.Purpose
	}
	if d.Channel != nil {
		m["channel"] = *d.Channel
	}
	ids := make([]any, 0, len(d.SignatureIDs))
	for _, id := range d.SignatureIDs {
		ids = append(ids, string(id))
	}
	m["signature_ids"] = ids
	if refs {
		a := make([]any, 0, len(d.EvidenceRefs))
		for _, r := range d.EvidenceRefs {
			a = append(a, map[string]any{"evidence_id": string(r.EvidenceID), "kind": r.Kind, "embedded": r.Embedded})
		}
		m["evidence_refs"] = a
	}
	return m
}
func validatedDelivery(ctx context.Context, d Delivery, l Limits) (Delivery, error) {
	if err := l.Validate(); err != nil {
		return Delivery{}, err
	}
	if len(d.SignatureIDs) > l.MaxEntries || len(d.EvidenceRefs) > l.MaxEntries {
		return Delivery{}, protocolError(ReasonResourceLimit, "Delivery reference policy")
	}
	if int64(len(d.SignatureIDs))+int64(len(d.EvidenceRefs)) > min(l.MaxJSONBytes, l.MaxTotalJSONBytes)/36 {
		return Delivery{}, protocolError(ReasonResourceLimit, "Delivery reference allocation byte policy")
	}
	if d.SignatureIDs == nil || d.EvidenceRefs == nil {
		return Delivery{}, schemaError("Delivery reference arrays must not be null")
	}
	v := deliveryValue(d, true)
	if err := validateOptionalValue(ctx, v, l, 0); err != nil {
		return Delivery{}, err
	}
	return parseDelivery(v)
}

// DeliveryDigest excludes only evidence_refs, allowing append without changing
// receipt-bound identity/creation/recipient/purpose/channel/signature facts.
func DeliveryDigest(ctx context.Context, d Delivery, l Limits) (ContentID, error) {
	d, err := validatedDelivery(ctx, d, l)
	if err != nil {
		return "", err
	}
	b, err := CanonicalJSON(ctx, deliveryValue(d, false), l)
	if err != nil {
		return "", err
	}
	return ContentIDForBytes(b), nil
}

// AppendEvidenceRefs owns validated values and never rewrites prior facts.
// Tree/history/signature/evidence verification and atomic publication remain
// separate required operations before this proposal can be published.
func AppendEvidenceRefs(ctx context.Context, d Delivery, appendRefs []EvidenceRef, l Limits) (Delivery, error) {
	d, err := validatedDelivery(ctx, d, l)
	if err != nil {
		return Delivery{}, err
	}
	if len(appendRefs) > l.MaxEntries-len(d.EvidenceRefs) {
		return Delivery{}, protocolError(ReasonResourceLimit, "appended evidence count")
	}
	d.EvidenceRefs = append(append([]EvidenceRef{}, d.EvidenceRefs...), appendRefs...)
	return validatedDelivery(ctx, d, l)
}
func ValidateDeliveryAppend(ctx context.Context, prior, next Delivery, l Limits) error {
	prior, err := validatedDelivery(ctx, prior, l)
	if err != nil {
		return err
	}
	next, err = validatedDelivery(ctx, next, l)
	if err != nil {
		return err
	}
	a, err := DeliveryDigest(ctx, prior, l)
	if err != nil {
		return err
	}
	b, err := DeliveryDigest(ctx, next, l)
	if err != nil {
		return err
	}
	if a != b || len(next.EvidenceRefs) < len(prior.EvidenceRefs) || !reflect.DeepEqual(prior.EvidenceRefs, next.EvidenceRefs[:len(prior.EvidenceRefs)]) {
		return protocolError(ReasonInvalidEvidence, "Delivery facts or prior evidence references rewritten")
	}
	return nil
}
