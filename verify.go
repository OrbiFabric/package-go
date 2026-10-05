// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
)

// CompleteSupport names the semantics implemented by this SDK. Recognition
// with this inventory is not a conformance certificate or Host trust policy.
func CompleteSupport() CapabilitySupport {
	return CapabilitySupport{Capabilities: []string{CapabilityLinearHistory, CapabilityContentSHA256, CapabilityPortableMemory, CapabilityVersionSignature, CapabilityDeliveryEvidence}, Profiles: []string{ProfileComplete}}
}

type VerificationOptions struct {
	Support CapabilitySupport
	Trust   TrustPolicy
	// ProveCompleteness also executes the full proof for a Core-only input.
	// Complete-labelled input always requires it; labels never prove FULL.
	ProveCompleteness bool
}

// Verification retains individual content/signature/evidence observations.
// Result dimensions describe one stable offline input, never hydrated output.
type Verification struct {
	Result     Result
	Content    ContentVerification
	Signatures SignatureVerification
	Evidence   EvidenceVerification
}

// Verify owns one explicitly selected snapshot and performs no network,
// Resolver, signer, publication, discovery or package execution. Protocol
// rejection returns both independent observations and an error. Host I/O,
// cancellation and policy errors are never converted into semantic success.
func Verify(ctx context.Context, source SnapshotSource, l Limits, options VerificationOptions) (out Verification, err error) {
	out.Result = UncheckedResult()
	defer func() {
		var p *ProtocolError
		if errors.As(err, &p) {
			out.Result.AddReason(p.Code)
		}
	}()
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if source == nil {
		return out, schemaError("missing verifier source")
	}
	options.Support = CapabilitySupport{slices.Clone(options.Support.Capabilities), slices.Clone(options.Support.Profiles)}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		var rejection *zipRejection
		if errors.As(err, &rejection) {
			_, out.Result.Recognition, _ = ReadFormat(ctx, bytes.NewReader(rejection.marker), l, options.Support)
			if !rejection.evidencePresent {
				out.Result.Evidence = EvidenceAbsent
			}
		}
		out.Result = rejectedVerification(out.Result, err, false)
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("missing verifier observation")
	}
	defer func() {
		observationErr := errors.Join(ctx.Err(), snapshot.CheckStable(ctx), snapshot.Close())
		if observationErr != nil {
			recognition := out.Result.Recognition
			out = Verification{Result: UncheckedResult()}
			out.Result.Recognition = recognition
			out.Result.WorkingState = WorkingUnreadable
		}
		err = errors.Join(err, observationErr)
	}()
	root, err := ReadRoot(ctx, snapshot, l, options.Support)
	out.Result.Recognition = root.Recognition
	if root.evidenceObserved && !root.evidencePresent {
		out.Result.Evidence = EvidenceAbsent
	}
	if err != nil {
		out.Result = rejectedVerification(out.Result, err, true)
		return out, err
	}
	h, err := readHistory(ctx, snapshot, root, l, options.Support)
	if err != nil {
		out.Result = rejectedVerification(out.Result, err, false)
		return out, err
	}
	// Portable schema/references precede content. Core missing files are empty
	// observations; required Complete presence is coupled only after all checks.
	memoryPresent := false
	for _, e := range root.Entries {
		memoryPresent = memoryPresent || e.Kind == "file" && slices.Contains(portablePaths, e.Path)
	}
	memoryChecked := !memoryPresent || containsText(options.Support.Capabilities, CapabilityPortableMemory)
	memory := EmptyPortableMemory(root.Package.PackageID)
	if memoryChecked {
		memory, err = readPortableMemory(ctx, snapshot, h, l)
		if err != nil {
			out.Result = rejectedVerification(out.Result, err, false)
			return out, err
		}
	}
	out.Result.Structure = StructureValid
	out.Content, err = verifyCommittedContent(ctx, snapshot, h, l)
	if err != nil {
		return out, err
	}
	out.Result.CommittedIntegrity = out.Content.Integrity
	mergeVerificationReasons(&out.Result, out.Content.ReasonCodes)
	signingPresent, evidencePresent := false, false
	for _, entry := range root.Entries {
		if entry.Kind != "file" {
			continue
		}
		signingPresent = signingPresent || strings.HasPrefix(entry.Path, ".packtell/verification/versions/")
		evidencePresent = evidencePresent || strings.HasPrefix(entry.Path, ".packtell/evidence/")
	}
	out.Result.Signature = SignatureNotChecked
	if !signingPresent {
		out.Result.Signature = SignatureAbsent
	}
	if !signingPresent || containsText(options.Support.Capabilities, CapabilityVersionSignature) {
		out.Signatures, err = verifySignatures(ctx, snapshot, h, l, options.Support, options.Trust)
		out.Result.Signature, out.Result.Identity = out.Signatures.State, out.Signatures.Identity
		if err != nil {
			return out, err
		}
		mergeVerificationReasons(&out.Result, out.Signatures.ReasonCodes)
	} else {
		out.Result.Signature = SignatureNotChecked
	}
	if !evidencePresent || memoryChecked && containsText(options.Support.Capabilities, CapabilityDeliveryEvidence) {
		out.Evidence, err = verifyEvidence(ctx, snapshot, h, memory, l, options.Support, options.Trust)
		if err != nil {
			return out, err
		}
		out.Result.Evidence = out.Evidence.State
		mergeVerificationReasons(&out.Result, out.Evidence.ReasonCodes)
	} else {
		out.Result.Evidence = EvidenceNotChecked
	}
	complete := containsText(root.Format.Profiles, ProfileComplete)
	for _, v := range h.Versions {
		complete = complete || containsText(v.Version.Profiles, ProfileComplete)
	}
	if complete || options.ProveCompleteness {
		// Uninterpreted optional evidence cannot establish embedded presence.
		if memoryChecked && out.Result.Evidence != EvidenceNotChecked {
			out.Result.HistoryCompleteness = HistoryFull
			if len(out.Content.Invalid) != 0 {
				out.Result.HistoryCompleteness = HistoryInvalid
			} else if len(out.Content.Missing) != 0 || complete && len(memory.MissingPaths) != 0 || len(out.Evidence.MissingEmbedded) != 0 {
				out.Result.HistoryCompleteness = HistoryNotFull
			}
		}
		if complete && len(memory.MissingPaths) != 0 {
			out.Result.AddReason(ReasonInvalidMetadata)
		}
	}
	// Borrowing binds Scan to this same observation; it cannot close or reopen
	// the owning source. A working-only failure cannot rewrite committed facts.
	scan, scanErr := Scan(ctx, borrowedTransferTree{snapshot}, l, options.Support, nil)
	out.Result.WorkingState = scan.State
	if scanErr != nil {
		var p *ProtocolError
		if errors.As(scanErr, &p) {
			out.Result.AddReason(p.Code)
		}
		return out, scanErr
	}
	if len(out.Result.ReasonCodes) == 0 {
		out.Result.AddReason(ReasonOK)
	}
	return out, nil
}

func mergeVerificationReasons(result *Result, codes []ReasonCode) {
	for _, code := range codes {
		if code != ReasonOK {
			result.AddReason(code)
		}
	}
}

func rejectedVerification(result Result, err error, rootPhase bool) Result {
	var p *ProtocolError
	if !errors.As(err, &p) {
		return result
	}
	result.AddReason(p.Code)
	switch p.Code {
	case ReasonUnsupportedProtocol, ReasonUnknownRequiredCapability:
		result.Recognition = Unsupported
	case ReasonNotPackage:
		result.Recognition = NotPackage
	case ReasonResourceLimit:
		// Resource rejection is an incomplete observation, not damaged topology.
	default:
		result.Structure = StructureInvalid
		result.HistoryCompleteness = HistoryInvalid
		if rootPhase && (p.Code == ReasonPathTraversal || p.Code == ReasonCaseConflict || p.Code == ReasonUnicodeNormalizationConflict || p.Code == ReasonInvalidPath) {
			result.WorkingState = WorkingUnreadable
		}
	}
	return result
}
