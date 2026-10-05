// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type DeliveryRequest struct {
	VersionID                   VersionID
	At                          time.Time
	SignatureIDs                []SignatureID
	Recipient, Purpose, Channel *string
}

// CreateDelivery derives identity/subject/signature facts from one stable
// snapshot, then asks the explicit Host policy to approve selected portable
// display facts. It returns an unsigned Delivery descriptor proposal, never
// publishes, signs, changes Version/HEAD or calls a Provider. At least one valid
// referenced signature is mandatory and none of its bad references are ignored.
func CreateDelivery(ctx context.Context, source SnapshotSource, request DeliveryRequest, l Limits, support CapabilitySupport, policy PortableFactPolicy) (out Delivery, err error) {
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = UUID(request.VersionID).Validate(); err != nil {
		return out, err
	}
	at, err := Timestamp(request.At)
	if err != nil {
		return out, err
	}
	if source == nil || policy == nil {
		return out, schemaError("Delivery needs explicit snapshot/fact policy")
	}
	if len(request.SignatureIDs) < 1 {
		return out, schemaError("Delivery requires signature selection")
	}
	if len(request.SignatureIDs) > l.MaxEntries {
		return out, protocolError(ReasonResourceLimit, "Delivery signature count policy")
	}
	// Check caller text/domain/bytes before Host effects and own optional values.
	selected := map[string]any{}
	for k, p := range map[string]*string{"recipient": request.Recipient, "purpose": request.Purpose, "channel": request.Channel} {
		if p != nil {
			selected[k] = *p
		}
	}
	if err = validateOptionalValue(ctx, selected, l, 0); err != nil {
		return out, err
	}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("missing Delivery snapshot")
	}
	defer func() {
		err = errors.Join(err, snapshot.Close())
		if err != nil {
			out = Delivery{}
		}
	}()
	h, err := ReadHistory(ctx, snapshot, l, support)
	if err != nil {
		return out, err
	}
	memory, err := readPortableMemory(ctx, snapshot, h, l)
	if err != nil {
		return out, err
	}
	var version *Version
	for _, v := range h.Versions {
		if v.Version.VersionID == request.VersionID {
			copy := v.Version
			version = &copy
			break
		}
	}
	if version == nil || !declaredEvidence(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) || !declaredEvidence(version.RequiredCapabilities, version.OptionalCapabilities) {
		return out, protocolError(ReasonInvalidEvidence, "Delivery Version/capability absent")
	}
	signatures, err := verifySignatures(ctx, snapshot, h, l, support, nil)
	if err != nil {
		return out, err
	}
	known := map[SignatureID]SignatureItem{}
	for _, s := range signatures.Items {
		known[s.SignatureID] = s
	}
	var previous SignatureID
	for _, id := range request.SignatureIDs {
		if err = UUID(id).Validate(); err != nil {
			return out, err
		}
		s, exists := known[id]
		if id <= previous || !exists || s.VersionID != request.VersionID || s.State != SignatureValid {
			return out, protocolError(ReasonInvalidEvidence, "selected Delivery signature missing/wrong/invalid/unsorted")
		}
		previous = id
	}
	_, digest, err := DeriveSubjectAt(ctx, snapshot, request.VersionID, l, support)
	if err != nil {
		return out, err
	}
	ids := append(h.KnownIDs(), memory.KnownIDs()...)
	for _, e := range h.Root.Entries {
		if !strings.HasPrefix(e.Path, ".packtell/verification/") && !strings.HasPrefix(e.Path, ".packtell/evidence/") {
			continue
		}
		for _, p := range strings.Split(e.Path, "/") {
			p = strings.TrimSuffix(p, ".json")
			if validUUID(p) {
				ids = append(ids, UUID(p))
			}
		}
	}
	generator, err := NewIDGenerator(nil, ids)
	if err != nil {
		return out, err
	}
	id, err := generator.Generate(ctx, request.At)
	if err != nil {
		return out, err
	}
	d := Delivery{Schema: DeliverySchema, DeliveryID: DeliveryID(id), PackageID: h.Root.Package.PackageID, VersionID: request.VersionID, SubjectDigest: digest, CreatedAt: at, SignatureIDs: append([]SignatureID{}, request.SignatureIDs...), EvidenceRefs: []EvidenceRef{}}
	if v, ok := selected["recipient"]; ok {
		s := v.(string)
		d.Recipient = &s
	}
	if v, ok := selected["purpose"]; ok {
		s := v.(string)
		d.Purpose = &s
	}
	if v, ok := selected["channel"]; ok {
		s := v.(string)
		d.Channel = &s
	}
	d, err = validatedDelivery(ctx, d, l)
	if err != nil {
		return out, err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	path := ".packtell/evidence/deliveries/" + string(d.DeliveryID) + "/delivery.json"
	if err = policy.ApprovePortableFacts(ctx, map[string][]byte{path: append([]byte{}, b...)}); err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	return d, nil
}
