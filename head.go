// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"io"
)

// HEAD is either the exact unborn token or a lowercase UUIDv7. This type is
// independent of Working Tree state, file content and Host DB projections.
type HEAD string

const UnbornHEAD HEAD = "unborn"

func (h HEAD) Validate() error {
	if h == UnbornHEAD {
		return nil
	}
	if err := UUID(h).Validate(); err != nil {
		return protocolError(ReasonInvalidHEAD, "HEAD is not unborn or lowercase UUIDv7")
	}
	return nil
}
func (h HEAD) Bytes() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return []byte(string(h) + "\n"), nil
}

// ReadHEAD accepts only the canonical 7-byte unborn or 37-byte committed value.
// This validates encoding only; Version existence/history belongs to inspection.
func ReadHEAD(ctx context.Context, r io.Reader) (HEAD, error) {
	b, err := ReadBounded(ctx, r, 37)
	if err != nil {
		if p, ok := err.(*ProtocolError); ok && p.Code == ReasonResourceLimit {
			return "", protocolError(ReasonInvalidHEAD, "HEAD length is not canonical")
		}
		return "", err
	}
	if (len(b) != 7 && len(b) != 37) || b[len(b)-1] != '\n' {
		return "", protocolError(ReasonInvalidHEAD, "HEAD bytes are not canonical")
	}
	h := HEAD(b[:len(b)-1])
	return h, h.Validate()
}
func CheckExpectedHEAD(expected, actual HEAD) error {
	if err := expected.Validate(); err != nil {
		return err
	}
	if err := actual.Validate(); err != nil {
		return err
	}
	if expected != actual {
		return protocolError(ReasonStaleHEAD, "expected HEAD no longer matches authority")
	}
	return nil
}

// HEADAuthority begins Host isolation spanning compare, stable payload reads,
// objects/Version writes and HEAD-last publication. Lock/journal state stays
// outside the portable tree. Implementations must honor cancellation and hide
// intermediate states from readers; a DB projection alone is not HEAD authority.
type HEADAuthority interface {
	Begin(ctx context.Context) (HEADTransaction, error)
}
type HEADTransaction interface {
	ReadHEAD(ctx context.Context) (HEAD, error)
	// PublishHEAD must publish only after complete stable Version/object writes,
	// and must not expose a partial transaction as a completed Package.
	PublishHEAD(ctx context.Context, next HEAD) error
	Close() error
}

// WithExpectedHEAD checks the actual HEAD inside Host isolation before any
// callback effects. A stale input never runs the callback. The callback is a
// commit mechanism supplied by later stages, not an automatic DB/network write.
func WithExpectedHEAD(ctx context.Context, authority HEADAuthority, expected HEAD, commit func(context.Context, HEADTransaction) error) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = expected.Validate(); err != nil {
		return err
	}
	if authority == nil || commit == nil {
		return schemaError("missing HEAD authority or commit operation")
	}
	tx, err := authority.Begin(ctx)
	if err != nil {
		return err
	}
	if tx == nil {
		return schemaError("HEAD authority returned no transaction")
	}
	defer func() {
		closeErr := tx.Close()
		if err == nil {
			err = closeErr
		}
	}()
	actual, err := tx.ReadHEAD(ctx)
	if err != nil {
		return err
	}
	if err = CheckExpectedHEAD(expected, actual); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	err = commit(ctx, tx)
	if err == nil {
		err = ctx.Err()
	}
	return err
}
