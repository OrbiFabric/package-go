// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
)

// ContentVerification proves only committed object coverage, separately from
// portable memory, signatures, identity, evidence and online status. Complete
// history cannot be called FULL from object coverage alone.
type ContentVerification struct {
	Integrity           IntegrityState
	HistoryCompleteness CompletenessState
	Verified            []ContentID
	Missing             []ContentID
	Invalid             []ContentID
	ReasonCodes         []ReasonCode
}

func (report *ContentVerification) addReason(code ReasonCode) {
	if !containsReason(report.ReasonCodes, code) {
		report.ReasonCodes = append(report.ReasonCodes, code)
	}
}
func containsReason(codes []ReasonCode, code ReasonCode) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

// VerifyCommittedContent reads every all-history object once and checks extra
// object names/hashes too. It cannot fall back to Working Tree or ContentResolver.
// It returns UNAVAILABLE for missing/unreadable objects and INVALID for wrong
// bytes/size. Host policy/cancellation stays an error rather than semantic PASS.
func VerifyCommittedContent(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport) (ContentVerification, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return ContentVerification{Integrity: IntegrityNotChecked, HistoryCompleteness: HistoryNotChecked}, err
	}
	return verifyCommittedContent(ctx, source, h, l)
}
func verifyCommittedContent(ctx context.Context, source TreeReader, h History, l Limits) (ContentVerification, error) {
	report := ContentVerification{Integrity: IntegrityNotChecked, HistoryCompleteness: HistoryNotChecked, Verified: []ContentID{}, Missing: []ContentID{}, Invalid: []ContentID{}, ReasonCodes: []ReasonCode{}}
	if err := l.Validate(); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	refs := map[ContentID]ContentObjectRef{}
	required := map[ContentID]bool{}
	for _, ref := range h.Contents {
		if err := ref.ContentID.Validate(); err != nil {
			return report, err
		}
		refs[ref.ContentID] = ref
		required[ref.ContentID] = true
	}
	// Extra objects are not exempt: their path name must commit their raw bytes.
	for _, e := range h.Root.Entries {
		if e.Kind == "file" && strings.HasPrefix(e.Path, ".packtell/objects/sha256/") {
			parts := strings.Split(e.Path, "/")
			if len(parts) != 5 || !validDigest(parts[4]) || parts[3] != parts[4][:2] {
				return report, schemaError("invalid object path")
			}
			id := ContentID("sha256:" + parts[4])
			if _, known := refs[id]; !known {
				refs[id] = ContentObjectRef{id, e.Size}
			}
		}
	}
	// Enumerate through the validated Root plan, with deterministic ContentID order.
	ordered := make([]ContentObjectRef, 0, len(refs))
	for _, ref := range refs {
		ordered = append(ordered, ref)
	}
	sortContentRefs(ordered)
	var total int64
	coverageInvalid, coverageMissing := false, false
	report.Integrity = IntegrityValid
	for _, ref := range ordered {
		if err := ctx.Err(); err != nil {
			report.Integrity = IntegrityNotChecked
			return report, err
		}
		if ref.Size < 0 || ref.Size > MaxProtocolInteger {
			return report, schemaError("invalid historical content size")
		}
		if ref.Size > l.MaxFileBytes || ref.Size > l.MaxTotalBytes-total {
			report.Integrity = IntegrityNotChecked
			return report, protocolError(ReasonResourceLimit, "object verification byte budget")
		}
		total += ref.Size
		path, err := ref.ObjectPath()
		if err != nil {
			return report, err
		}
		r, err := source.Open(ctx, path)
		if err != nil || r == nil {
			if r != nil {
				_ = r.Close()
			}
			if ctx.Err() != nil {
				report.Integrity = IntegrityNotChecked
				return report, ctx.Err()
			}
			var p *ProtocolError
			if errors.As(err, &p) && (p.Code == ReasonResourceLimit || p.Code == ReasonUnsafeArchive) {
				report.Integrity = IntegrityNotChecked
				return report, err
			}
			report.Missing = append(report.Missing, ref.ContentID)
			report.addReason(ReasonMissingObject)
			coverageMissing = true
			if required[ref.ContentID] && report.Integrity != IntegrityInvalid {
				report.Integrity = IntegrityUnavailable
			}
			continue
		}
		verifyErr := CopyVerifiedContent(ctx, io.Discard, r, ref.ContentID, ref.Size, l)
		closeErr := r.Close()
		if verifyErr == nil && closeErr == nil {
			report.Verified = append(report.Verified, ref.ContentID)
			continue
		}
		var p *ProtocolError
		// A codec or input-policy failure is not an ordinary missing object,
		// including when reported by stream Close after a successful hash.
		for _, failure := range []error{verifyErr, closeErr} {
			if errors.As(failure, &p) && (p.Code == ReasonResourceLimit || p.Code == ReasonUnsafeArchive) {
				report.Integrity = IntegrityNotChecked
				return report, errors.Join(verifyErr, closeErr)
			}
		}
		if errors.As(verifyErr, &p) && p.Code == ReasonObjectHashMismatch {
			coverageInvalid = true
			if required[ref.ContentID] {
				report.Integrity = IntegrityInvalid
			}
			report.Invalid = append(report.Invalid, ref.ContentID)
			report.addReason(ReasonObjectHashMismatch)
			continue
		}
		if ctx.Err() != nil {
			report.Integrity = IntegrityNotChecked
			return report, ctx.Err()
		}
		report.Missing = append(report.Missing, ref.ContentID)
		report.addReason(ReasonMissingObject)
		coverageMissing = true
		if required[ref.ContentID] && report.Integrity != IntegrityInvalid {
			report.Integrity = IntegrityUnavailable
		}
	}
	if coverageInvalid {
		report.HistoryCompleteness = HistoryInvalid
	} else if coverageMissing {
		report.HistoryCompleteness = HistoryNotFull
	}
	if len(report.ReasonCodes) == 0 {
		report.addReason(ReasonOK)
	}
	return report, nil
}
func sortContentRefs(refs []ContentObjectRef) {
	slices.SortFunc(refs, func(a, b ContentObjectRef) int { return strings.Compare(string(a.ContentID), string(b.ContentID)) })
}
