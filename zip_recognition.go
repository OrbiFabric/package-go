// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"errors"
	"strings"
)

// A rejected archive never exposes a tree or unsafe entry stream. Like the
// Directory rejection diagnostic, it may retain only one exact, known-safe
// discriminator after bounded central parsing. This is not archive acceptance.
type zipRejection struct {
	cause           error
	marker          []byte
	evidencePresent bool
}

func (e *zipRejection) Error() string { return e.cause.Error() }
func (e *zipRejection) Unwrap() error { return e.cause }

func rejectedZIPMarker(ctx context.Context, a ArchiveSnapshot, end zipEnd, records []zipRecord, l Limits, cause error) error {
	var policy *ProtocolError
	if errors.As(cause, &policy) && policy.Code == ReasonResourceLimit {
		return cause
	}
	if ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	var candidate *zipRecord
	for _, record := range records {
		if record.kind != "file" {
			continue
		}
		marker := record.name == ".packtell/format.json"
		if !marker && strings.Count(record.name, "/") == 2 && strings.HasSuffix(record.name, "/.packtell/format.json") {
			wrapper := strings.SplitN(record.name, "/", 2)[0]
			marker = ValidateComponent(wrapper) == nil
		}
		if !marker {
			continue
		}
		if candidate != nil {
			return cause
		} // Ambiguous authority is not recognized.
		r := record
		candidate = &r
	}
	if candidate == nil || candidate.size > l.MaxJSONBytes {
		return cause
	}
	// Validate the single control member's local framing/boundary before its
	// bounded expansion. No other local header or payload is read on rejection.
	next := end.offset
	for _, r := range records {
		if r.name == candidate.name && r.offset == candidate.offset {
			continue
		}
		if r.offset == candidate.offset {
			return cause
		}
		if r.offset > candidate.offset && r.offset < next {
			next = r.offset
		}
		if r.offset < candidate.offset && r.compressed > candidate.offset-r.offset-30-int64(len(r.name)) {
			return cause
		}
	}
	if err := validateZIPLocal(ctx, a, candidate, next); err != nil {
		return errors.Join(cause, ctx.Err())
	}
	stream := openZIPRecord(ctx, a, *candidate)
	b, err := ReadBounded(ctx, stream, l.MaxJSONBytes)
	err = errors.Join(err, stream.Close())
	if err != nil {
		return errors.Join(cause, ctx.Err())
	}
	if err = a.CheckStable(ctx); err != nil {
		return errors.Join(cause, err)
	}
	root := strings.TrimSuffix(candidate.name, ".packtell/format.json")
	evidencePresent := false
	for _, r := range records {
		evidencePresent = evidencePresent || r.kind != "directory" && strings.HasPrefix(r.name, root+".packtell/evidence/")
	}
	return &zipRejection{cause, b, evidencePresent}
}
