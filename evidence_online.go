// SPDX-License-Identifier: Apache-2.0
package packagego

import "context"

// EvidenceStatusReader is an explicit transient Host query, never part of
// offline verification/portable subjects/digests. It owns service authority and
// credentials; IDs are not fetch URLs. No SDK network client is instantiated.
type EvidenceStatusRequest struct {
	EvidenceID EvidenceID
	Kind       string
}
type EvidenceStatusReader interface {
	Status(ctx context.Context, request EvidenceStatusRequest) (OnlineState, error)
}

func QueryEvidenceOnline(ctx context.Context, reader EvidenceStatusReader, request EvidenceStatusRequest) (OnlineState, error) {
	if err := ctx.Err(); err != nil {
		return OnlineUnavailable, err
	}
	if err := UUID(request.EvidenceID).Validate(); err != nil {
		return OnlineUnavailable, err
	}
	if !containsText(evidenceKinds, request.Kind) {
		return OnlineUnavailable, schemaError("unknown evidence status kind")
	}
	if reader == nil {
		return OnlineUnavailable, schemaError("missing explicitly requested status Host")
	}
	state, err := reader.Status(ctx, request)
	if err != nil {
		return OnlineUnavailable, err
	}
	if err = ctx.Err(); err != nil {
		return OnlineUnavailable, err
	}
	if state != OnlineCurrent && state != OnlineRevoked && state != OnlineUnavailable {
		return OnlineUnavailable, schemaError("invalid transient online state")
	}
	return state, nil
}
