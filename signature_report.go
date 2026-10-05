// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"errors"
	"strings"
)

type SignatureItem struct {
	Path        string
	SignatureID SignatureID
	VersionID   VersionID
	State       SignatureState
	Identity    IdentityState
	ReasonCodes []ReasonCode
}
type SignatureVerification struct {
	State       SignatureState
	Identity    IdentityState
	Items       []SignatureItem
	ReasonCodes []ReasonCode
}

func declaredVersionSigning(required, optional []string) bool {
	return containsText(required, CapabilityVersionSignature) || containsText(optional, CapabilityVersionSignature)
}
func signatureFailure(item SignatureItem, err error) (SignatureItem, error) {
	var p *ProtocolError
	if errors.As(err, &p) && (p.Code == ReasonBadSignature || p.Code == ReasonInvalidSchema) {
		item.State = SignatureInvalid
		item.ReasonCodes = []ReasonCode{p.Code}
		return item, nil
	}
	item.State = SignatureNotChecked
	item.Identity = IdentityUnknown
	item.ReasonCodes = []ReasonCode{}
	return item, err
}

// VerifySignatures verifies every actual signature file across actual history.
// It never substitutes a caller-claimed subject, performs content verification,
// accesses a signer/Resolver/network, or modifies integrity/completeness facts.
// Callers hold one stable Host observation when coupling these dimensions.
func VerifySignatures(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport, trust TrustPolicy) (SignatureVerification, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return SignatureVerification{State: SignatureNotChecked, Identity: IdentityUnknown}, err
	}
	return verifySignatures(ctx, source, h, l, support, trust)
}
func verifySignatures(ctx context.Context, source TreeReader, h History, l Limits, support CapabilitySupport, trust TrustPolicy) (out SignatureVerification, err error) {
	out = SignatureVerification{State: SignatureNotChecked, Identity: IdentityUnknown, Items: []SignatureItem{}, ReasonCodes: []ReasonCode{}}
	records := map[VersionID]CommittedVersion{}
	nodes := map[string]TreeEntry{}
	digests := map[VersionID]ContentID{}
	for _, v := range h.Versions {
		records[v.Version.VersionID] = v
	}
	for _, e := range h.Root.Entries {
		nodes[e.Path] = e
	}
	if !containsText(support.Capabilities, CapabilityVersionSignature) {
		for _, e := range h.Root.Entries {
			if e.Kind == "file" && strings.HasPrefix(e.Path, ".packtell/verification/versions/") {
				parts := strings.Split(e.Path, "/")
				out.Items = append(out.Items, SignatureItem{Path: e.Path, SignatureID: SignatureID(strings.TrimSuffix(parts[4], ".json")), VersionID: VersionID(parts[3]), State: SignatureNotChecked, Identity: IdentityUnknown, ReasonCodes: []ReasonCode{}})
			}
		}
		if len(out.Items) == 0 {
			out.State = SignatureAbsent
			out.ReasonCodes = []ReasonCode{ReasonOK}
		}
		return out, nil
	}
	addReason := func(code ReasonCode) {
		if !containsReason(out.ReasonCodes, code) {
			out.ReasonCodes = append(out.ReasonCodes, code)
		}
	}
	defer func() {
		if err != nil {
			out.State = SignatureNotChecked
			out.Identity = IdentityUnknown
		}
	}()
	usedIDs := map[UUID]bool{}
	for _, id := range h.KnownIDs() {
		if len(usedIDs) >= l.MaxEntries {
			return out, protocolError(ReasonResourceLimit, "signature identity inventory")
		}
		usedIDs[id] = true
	}
	anyInvalid, anyTrusted, anySigner := false, false, false
	for _, entry := range h.Root.Entries {
		if entry.Kind != "file" || !strings.HasPrefix(entry.Path, ".packtell/verification/versions/") {
			continue
		}
		if err = ctx.Err(); err != nil {
			return out, err
		}
		parts := strings.Split(entry.Path, "/")
		vid := VersionID(parts[3])
		sid := SignatureID(strings.TrimSuffix(parts[4], ".json"))
		item := SignatureItem{Path: entry.Path, SignatureID: sid, VersionID: vid, State: SignatureNotChecked, Identity: IdentityUnknown, ReasonCodes: []ReasonCode{}}
		record, exists := records[vid]
		var checkErr error
		if usedIDs[UUID(sid)] {
			checkErr = schemaError("signature identity reuses another entity")
		} else if !exists {
			checkErr = schemaError("signature path refers to absent Version")
		} else if !declaredVersionSigning(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) || !declaredVersionSigning(record.Version.RequiredCapabilities, record.Version.OptionalCapabilities) {
			checkErr = schemaError("signature capability is not declared")
		} else {
			digest, known := digests[vid]
			if !known {
				_, digest, err = DeriveVersionSubject(ctx, h.Root.Package, record.Version, record.Manifest, l, support)
				if err != nil {
					return out, err
				}
				digests[vid] = digest
			}
			var b []byte
			b, err = readRootBytes(ctx, source, nodes, entry.Path, l.MaxJSONBytes)
			if err != nil {
				return out, err
			}
			var envelope VersionSignature
			envelope, checkErr = ReadVersionSignature(ctx, bytes.NewReader(b), l)
			if checkErr == nil {
				item.Identity = IdentityUntrusted
				if envelope.SignatureID != sid {
					checkErr = protocolError(ReasonBadSignature, "signature ID disagrees with control path")
				} else {
					item, checkErr = verifySignature(ctx, h.Root.Package.PackageID, vid, digest, envelope, l, trust)
					item.Path = entry.Path
					item.SignatureID = sid
				}
			}
		}
		if !usedIDs[UUID(sid)] {
			if len(usedIDs) >= l.MaxEntries {
				return out, protocolError(ReasonResourceLimit, "signature identity inventory")
			}
			usedIDs[UUID(sid)] = true
		}
		if checkErr != nil {
			item, checkErr = signatureFailure(item, checkErr)
			if checkErr != nil {
				out.Items = append(out.Items, item)
				return out, checkErr
			}
		}
		if item.State == SignatureInvalid {
			anyInvalid = true
		}
		if item.Identity == IdentityUntrusted || item.Identity == IdentityTrusted {
			anySigner = true
		}
		if item.Identity == IdentityTrusted {
			anyTrusted = true
		}
		for _, code := range item.ReasonCodes {
			if code != ReasonOK {
				addReason(code)
			}
		}
		out.Items = append(out.Items, item)
	}
	if len(out.Items) == 0 {
		out.State = SignatureAbsent
		out.ReasonCodes = []ReasonCode{ReasonOK}
		return out, nil
	}
	out.State = SignatureValid
	if anyInvalid {
		out.State = SignatureInvalid
	}
	if anySigner {
		out.Identity = IdentityUntrusted
	}
	if anyTrusted {
		out.Identity = IdentityTrusted
	}
	if len(out.ReasonCodes) == 0 {
		out.ReasonCodes = []ReasonCode{ReasonOK}
	}
	return out, nil
}
