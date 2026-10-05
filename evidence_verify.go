// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"errors"
	"strings"
)

type DeliveryItem struct {
	Path        string
	Delivery    Delivery
	Digest      ContentID
	Valid       bool
	ReasonCodes []ReasonCode
}
type EvidenceItem struct {
	Path        string
	EvidenceID  EvidenceID
	Kind        string
	State       EvidenceState
	Identity    IdentityState
	ReasonCodes []ReasonCode
}
type EvidenceVerification struct {
	State           EvidenceState
	Online          OnlineState
	Deliveries      []DeliveryItem
	Items           []EvidenceItem
	External        []EvidenceRef
	MissingEmbedded []EvidenceID
	ReasonCodes     []ReasonCode
}

func evidenceFailure(item EvidenceItem, err error) (EvidenceItem, error) {
	var p *ProtocolError
	if errors.As(err, &p) && (p.Code == ReasonInvalidEvidence || p.Code == ReasonInvalidSchema || p.Code == ReasonBadSignature) {
		item.State = EvidenceInvalid
		item.ReasonCodes = []ReasonCode{ReasonInvalidEvidence}
		if p.Code == ReasonInvalidSchema {
			item.ReasonCodes = append(item.ReasonCodes, ReasonInvalidSchema)
		}
		return item, nil
	}
	item.State = EvidenceNotChecked
	item.Identity = IdentityUnknown
	return item, err
}
func declaredEvidence(required, optional []string) bool {
	return containsText(required, CapabilityDeliveryEvidence) || containsText(optional, CapabilityDeliveryEvidence)
}
func VerifyEvidence(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport, trust TrustPolicy) (EvidenceVerification, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return EvidenceVerification{State: EvidenceNotChecked, Online: OnlineNotRequested}, err
	}
	memory, err := readPortableMemory(ctx, source, h, l)
	if err != nil {
		return EvidenceVerification{State: EvidenceNotChecked, Online: OnlineNotRequested}, err
	}
	return verifyEvidence(ctx, source, h, memory, l, support, trust)
}
func verifyEvidence(ctx context.Context, source TreeReader, h History, memory PortableMemory, l Limits, support CapabilitySupport, trust TrustPolicy) (out EvidenceVerification, err error) {
	out = EvidenceVerification{State: EvidenceNotChecked, Online: OnlineNotRequested, Deliveries: []DeliveryItem{}, Items: []EvidenceItem{}, External: []EvidenceRef{}, MissingEmbedded: []EvidenceID{}, ReasonCodes: []ReasonCode{}}
	defer func() {
		if err != nil {
			out.State = EvidenceNotChecked
		}
	}()
	nodes := map[string]TreeEntry{}
	records := map[VersionID]CommittedVersion{}
	versionDigests := map[VersionID]ContentID{}
	events := map[EventID]Event{}
	for _, e := range h.Root.Entries {
		nodes[e.Path] = e
	}
	for _, v := range h.Versions {
		records[v.Version.VersionID] = v
	}
	for _, e := range memory.Events {
		events[e.EventID] = e
	}
	signatures, err := verifySignatures(ctx, source, h, l, support, nil)
	if err != nil {
		return out, err
	}
	signatureItems := map[SignatureID]SignatureItem{}
	for _, s := range signatures.Items {
		signatureItems[s.SignatureID] = s
	}
	actualDigest := func(id VersionID) (ContentID, error) {
		if digest, ok := versionDigests[id]; ok {
			return digest, nil
		}
		v, ok := records[id]
		if !ok {
			return "", protocolError(ReasonInvalidEvidence, "evidence Version absent from history")
		}
		_, digest, err := DeriveVersionSubject(ctx, h.Root.Package, v.Version, v.Manifest, l, support)
		if err == nil {
			versionDigests[id] = digest
		}
		return digest, err
	}
	addReason := func(code ReasonCode) {
		if !containsReason(out.ReasonCodes, code) {
			out.ReasonCodes = append(out.ReasonCodes, code)
		}
	}
	deliveries := map[DeliveryID]DeliveryItem{}
	anyInvalid := false
	for _, entry := range h.Root.Entries {
		if entry.Kind != "file" || !strings.HasPrefix(entry.Path, ".packtell/evidence/deliveries/") {
			continue
		}
		if err = ctx.Err(); err != nil {
			return out, err
		}
		parts := strings.Split(entry.Path, "/")
		id := DeliveryID(parts[3])
		item := DeliveryItem{Path: entry.Path, ReasonCodes: []ReasonCode{}}
		b, readErr := readRootBytes(ctx, source, nodes, entry.Path, l.MaxJSONBytes)
		if readErr != nil {
			return out, readErr
		}
		d, checkErr := ReadDelivery(ctx, bytes.NewReader(b), l)
		item.Delivery = d
		if checkErr == nil {
			if d.DeliveryID != id || d.PackageID != h.Root.Package.PackageID {
				checkErr = protocolError(ReasonInvalidEvidence, "Delivery identity/path/Package mismatch")
			}
			record, exists := records[d.VersionID]
			if checkErr == nil && (!exists || !declaredEvidence(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) || !declaredEvidence(record.Version.RequiredCapabilities, record.Version.OptionalCapabilities)) {
				checkErr = protocolError(ReasonInvalidEvidence, "Delivery Version/capability absent")
			}
			if checkErr == nil {
				digest, digestErr := actualDigest(d.VersionID)
				if digestErr != nil {
					return out, digestErr
				}
				if d.SubjectDigest != digest {
					checkErr = protocolError(ReasonInvalidEvidence, "Delivery subject digest mismatch")
				}
			}
			if checkErr == nil {
				for _, sid := range d.SignatureIDs {
					s, ok := signatureItems[sid]
					if !ok || s.VersionID != d.VersionID || s.State != SignatureValid {
						checkErr = protocolError(ReasonInvalidEvidence, "Delivery references absent/wrong/invalid signature")
						break
					}
				}
			}
			if checkErr == nil {
				item.Digest, checkErr = DeliveryDigest(ctx, d, l)
			}
		}
		if checkErr != nil {
			var p *ProtocolError
			if !errors.As(checkErr, &p) || p.Code == ReasonResourceLimit {
				return out, checkErr
			}
			item.ReasonCodes = []ReasonCode{ReasonInvalidEvidence}
			if p.Code == ReasonInvalidSchema {
				item.ReasonCodes = append(item.ReasonCodes, p.Code)
			}
			anyInvalid = true
			for _, c := range item.ReasonCodes {
				addReason(c)
			}
		} else {
			item.Valid = true
			item.ReasonCodes = []ReasonCode{ReasonOK}
		}
		deliveries[id] = item
		out.Deliveries = append(out.Deliveries, item)
	}
	envelopes := map[EvidenceID]EvidenceEnvelope{}
	evidenceItems := map[EvidenceID]EvidenceItem{}
	for _, entry := range h.Root.Entries {
		if entry.Kind != "file" || !strings.HasPrefix(entry.Path, ".packtell/evidence/objects/") {
			continue
		}
		if err = ctx.Err(); err != nil {
			return out, err
		}
		id := EvidenceID(strings.TrimSuffix(strings.TrimPrefix(entry.Path, ".packtell/evidence/objects/"), ".json"))
		item := EvidenceItem{Path: entry.Path, EvidenceID: id, State: EvidenceNotChecked, Identity: IdentityUnknown, ReasonCodes: []ReasonCode{}}
		b, readErr := readRootBytes(ctx, source, nodes, entry.Path, l.MaxJSONBytes)
		if readErr != nil {
			return out, readErr
		}
		e, checkErr := ReadEvidenceEnvelope(ctx, bytes.NewReader(b), l)
		item.Kind = e.Kind
		if checkErr == nil {
			envelopes[id] = e
			item.Identity = IdentityUntrusted
			record, exists := records[e.Subject.VersionID]
			if e.Subject.EvidenceID != id || e.Subject.PackageID != h.Root.Package.PackageID || !exists || !declaredEvidence(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) || !declaredEvidence(record.Version.RequiredCapabilities, record.Version.OptionalCapabilities) {
				checkErr = protocolError(ReasonInvalidEvidence, "evidence identity/path/Version/capability mismatch")
			}
			if checkErr == nil {
				digest, digestErr := actualDigest(e.Subject.VersionID)
				if digestErr != nil {
					return out, digestErr
				}
				if e.Subject.VersionSubjectDigest != digest {
					checkErr = protocolError(ReasonInvalidEvidence, "evidence Version subject digest mismatch")
				}
			}
			if checkErr == nil && e.Kind == "delivery_receipt" {
				d, ok := deliveries[e.Subject.DeliveryID]
				if !ok || !d.Valid || d.Delivery.VersionID != e.Subject.VersionID || d.Digest != e.Subject.DeliveryDigest {
					checkErr = protocolError(ReasonInvalidEvidence, "receipt Delivery/digest/reference mismatch")
				}
			}
			if checkErr == nil && e.Kind == "lifecycle_witness" {
				event, ok := events[e.Subject.EventID]
				if !ok {
					checkErr = protocolError(ReasonInvalidEvidence, "lifecycle event absent")
				} else {
					digest, digestErr := EventDigest(ctx, event, l)
					if digestErr != nil {
						return out, digestErr
					}
					if digest != e.Subject.EventDigest {
						checkErr = protocolError(ReasonInvalidEvidence, "lifecycle event digest mismatch")
					}
				}
			}
			if checkErr == nil {
				checkErr = verifyEvidenceCryptography(ctx, e, l)
			}
			if checkErr == nil {
				item.State = EvidenceValid
				item.ReasonCodes = []ReasonCode{ReasonOK}
				if trust != nil {
					key, _ := canonicalBase64(e.PublicKey, 32)
					purpose, _ := EvidenceSubjectSchema(e.Kind)
					trusted, trustErr := trust.Trusted(ctx, TrustRequest{Purpose: purpose, PublicKey: bytes.Clone(key), Issuer: e.Subject.Issuer, KeyID: e.KeyID})
					if trustErr != nil {
						item.Identity = IdentityUnknown
						out.Items = append(out.Items, item)
						return out, trustErr
					}
					if err = ctx.Err(); err != nil {
						return out, err
					}
					if trusted {
						item.Identity = IdentityTrusted
					}
				}
			}
		}
		if checkErr != nil {
			item, checkErr = evidenceFailure(item, checkErr)
			if checkErr != nil {
				out.Items = append(out.Items, item)
				return out, checkErr
			}
		}
		if item.State == EvidenceInvalid {
			anyInvalid = true
		}
		for _, code := range item.ReasonCodes {
			if code != ReasonOK {
				addReason(code)
			}
		}
		evidenceItems[id] = item
		out.Items = append(out.Items, item)
	}
	seenExternal := map[EvidenceID]bool{}
	seenMissing := map[EvidenceID]bool{}
	for i, ditem := range out.Deliveries {
		d := ditem.Delivery
		for _, ref := range d.EvidenceRefs {
			if err = ctx.Err(); err != nil {
				return out, err
			}
			e, exists := envelopes[ref.EvidenceID]
			if !ref.Embedded && !seenExternal[ref.EvidenceID] {
				out.External = append(out.External, ref)
				seenExternal[ref.EvidenceID] = true
			}
			if ref.Embedded {
				if _, present := nodes[".packtell/evidence/objects/"+string(ref.EvidenceID)+".json"]; !present {
					if !seenMissing[ref.EvidenceID] {
						out.MissingEmbedded = append(out.MissingEmbedded, ref.EvidenceID)
						seenMissing[ref.EvidenceID] = true
					}
					addReason(ReasonInvalidEvidence)
					continue
				}
			}
			if exists && (e.Kind != ref.Kind || e.Subject.VersionID != d.VersionID || e.Subject.PackageID != d.PackageID || (e.Kind == "delivery_receipt" && e.Subject.DeliveryID != d.DeliveryID)) {
				out.Deliveries[i].Valid = false
				out.Deliveries[i].ReasonCodes = []ReasonCode{ReasonInvalidEvidence}
				anyInvalid = true
				addReason(ReasonInvalidEvidence)
			}
			if exists && evidenceItems[ref.EvidenceID].State == EvidenceInvalid {
				anyInvalid = true
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	out.State = EvidenceAbsent
	if len(out.Items) > 0 {
		out.State = EvidenceValid
	}
	if anyInvalid {
		out.State = EvidenceInvalid
	}
	if len(out.ReasonCodes) == 0 {
		out.ReasonCodes = []ReasonCode{ReasonOK}
	}
	return out, nil
}
func verifyEvidenceCryptography(ctx context.Context, e EvidenceEnvelope, l Limits) error {
	digest, err := EvidenceSubjectDigest(ctx, e.Subject, e.Kind, l)
	if err != nil {
		return err
	}
	if digest != e.SubjectDigest {
		return protocolError(ReasonInvalidEvidence, "evidence subject digest mismatch")
	}
	input, err := EvidenceSigningInput(ctx, e, l)
	if err != nil {
		return err
	}
	key, _ := canonicalBase64(e.PublicKey, 32)
	signature, _ := canonicalBase64(e.Signature, 64)
	return VerifyEd25519Strict(ctx, key, input, signature, l)
}
func EventDigest(ctx context.Context, event Event, l Limits) (ContentID, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	v := eventValue(event)
	if err := validateOptionalValue(ctx, v, l, 0); err != nil {
		return "", err
	}
	b, err := CanonicalJSON(ctx, v, l)
	if err != nil {
		return "", err
	}
	if _, err = ReadEvent(ctx, bytes.NewReader(b), l); err != nil {
		return "", err
	}
	return ContentIDForBytes(b), nil
}
