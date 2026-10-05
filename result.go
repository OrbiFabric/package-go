// SPDX-License-Identifier: Apache-2.0
package packagego

// Separate types prevent mixing facts from unrelated verification dimensions.
type Recognition string
type StructureState string
type WorkingState string
type IntegrityState string
type CompletenessState string
type SignatureState string
type IdentityState string
type EvidenceState string
type OnlineState string
type ReasonCode string

const (
	Recognized                         Recognition       = "RECOGNIZED"
	NotPackage                         Recognition       = "NOT_PACKAGE"
	Unsupported                        Recognition       = "UNSUPPORTED"
	StructureValid                     StructureState    = "VALID"
	StructureInvalid                   StructureState    = "INVALID"
	StructureNotChecked                StructureState    = "NOT_CHECKED"
	WorkingUnborn                      WorkingState      = "UNBORN"
	WorkingClean                       WorkingState      = "CLEAN"
	WorkingDirty                       WorkingState      = "DIRTY"
	WorkingUnreadable                  WorkingState      = "UNREADABLE"
	WorkingNotChecked                  WorkingState      = "NOT_CHECKED"
	IntegrityValid                     IntegrityState    = "VALID"
	IntegrityInvalid                   IntegrityState    = "INVALID"
	IntegrityUnavailable               IntegrityState    = "UNAVAILABLE"
	IntegrityNotChecked                IntegrityState    = "NOT_CHECKED"
	HistoryFull                        CompletenessState = "FULL"
	HistoryNotFull                     CompletenessState = "NOT_FULL"
	HistoryInvalid                     CompletenessState = "INVALID"
	HistoryNotChecked                  CompletenessState = "NOT_CHECKED"
	SignatureValid                     SignatureState    = "VALID"
	SignatureInvalid                   SignatureState    = "INVALID"
	SignatureAbsent                    SignatureState    = "ABSENT"
	SignatureNotChecked                SignatureState    = "NOT_CHECKED"
	IdentityUntrusted                  IdentityState     = "UNTRUSTED"
	IdentityTrusted                    IdentityState     = "TRUSTED"
	IdentityUnknown                    IdentityState     = "UNKNOWN"
	EvidenceValid                      EvidenceState     = "VALID"
	EvidenceInvalid                    EvidenceState     = "INVALID"
	EvidenceAbsent                     EvidenceState     = "ABSENT"
	EvidenceNotChecked                 EvidenceState     = "NOT_CHECKED"
	OnlineNotRequested                 OnlineState       = "NOT_REQUESTED"
	OnlineCurrent                      OnlineState       = "CURRENT"
	OnlineRevoked                      OnlineState       = "REVOKED"
	OnlineUnavailable                  OnlineState       = "UNAVAILABLE"
	ReasonOK                           ReasonCode        = "OK"
	ReasonNotPackage                   ReasonCode        = "NOT_PACKAGE"
	ReasonUnsupportedProtocol          ReasonCode        = "UNSUPPORTED_PROTOCOL"
	ReasonUnknownRequiredCapability    ReasonCode        = "UNKNOWN_REQUIRED_CAPABILITY"
	ReasonInvalidSchema                ReasonCode        = "INVALID_SCHEMA"
	ReasonInvalidHEAD                  ReasonCode        = "INVALID_HEAD"
	ReasonNonLinearHistory             ReasonCode        = "NON_LINEAR_HISTORY"
	ReasonMissingParent                ReasonCode        = "MISSING_PARENT"
	ReasonMissingObject                ReasonCode        = "MISSING_OBJECT"
	ReasonObjectHashMismatch           ReasonCode        = "OBJECT_HASH_MISMATCH"
	ReasonBadSignature                 ReasonCode        = "BAD_SIGNATURE"
	ReasonPathTraversal                ReasonCode        = "PATH_TRAVERSAL"
	ReasonCaseConflict                 ReasonCode        = "CASE_CONFLICT"
	ReasonUnicodeNormalizationConflict ReasonCode        = "UNICODE_NORMALIZATION_CONFLICT"
	ReasonInvalidPath                  ReasonCode        = "INVALID_PATH"
	ReasonResourceLimit                ReasonCode        = "RESOURCE_LIMIT"
	ReasonUnsafeArchive                ReasonCode        = "UNSAFE_ARCHIVE"
	ReasonStaleHEAD                    ReasonCode        = "STALE_HEAD"
	ReasonInvalidMetadata              ReasonCode        = "INVALID_METADATA"
	ReasonInvalidEvidence              ReasonCode        = "INVALID_EVIDENCE"
)

type Result struct {
	Recognition         Recognition       `json:"recognition"`
	Structure           StructureState    `json:"structure"`
	WorkingState        WorkingState      `json:"working_state"`
	CommittedIntegrity  IntegrityState    `json:"committed_integrity"`
	HistoryCompleteness CompletenessState `json:"history_completeness"`
	Signature           SignatureState    `json:"signature"`
	Identity            IdentityState     `json:"identity"`
	Evidence            EvidenceState     `json:"evidence"`
	Online              OnlineState       `json:"online"`
	ReasonCodes         []ReasonCode      `json:"reason_codes"`
}

// UncheckedResult never advertises successful checks. Recognition has no
// NOT_CHECKED vocabulary value and stays unset until a discriminator is read.
func UncheckedResult() Result {
	return Result{Structure: StructureNotChecked, WorkingState: WorkingNotChecked,
		CommittedIntegrity: IntegrityNotChecked, HistoryCompleteness: HistoryNotChecked,
		Signature: SignatureNotChecked, Identity: IdentityUnknown,
		Evidence: EvidenceNotChecked, Online: OnlineNotRequested, ReasonCodes: []ReasonCode{}}
}

func (r *Result) AddReason(code ReasonCode) {
	for _, old := range r.ReasonCodes {
		if old == code {
			return
		}
	}
	r.ReasonCodes = append(r.ReasonCodes, code)
}

// ProtocolError denotes a protocol reason, not cancellation or Host I/O failure.
// Detail must describe protocol facts without credentials or private locators.
type ProtocolError struct {
	Code   ReasonCode
	Detail string
}

func (e *ProtocolError) Error() string                   { return string(e.Code) + ": " + e.Detail }
func protocolError(code ReasonCode, detail string) error { return &ProtocolError{code, detail} }
