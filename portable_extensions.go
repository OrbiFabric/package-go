// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
)

// CopyExtensions preserves declared extension bytes verbatim into Host-isolated
// output. The caller holds a stable source view and discards the entire pending
// output on error. All paths are preflighted; unknown facts are never executed,
// parsed as Core or treated as privacy-approved merely because they are copied.
// A representation export must separately apply its Host fact-selection policy.
func CopyExtensions(ctx context.Context, source TreeReader, pending PayloadWriter, l Limits, support CapabilitySupport) error {
	if pending == nil {
		return schemaError("missing pending extension writer")
	}
	root, err := ReadRoot(ctx, source, l, support)
	if err != nil {
		return err
	}
	for _, entry := range root.Entries {
		if !strings.HasPrefix(entry.Path, ".packtell/extensions/") {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if entry.Kind == "directory" {
			if err = pending.Mkdir(ctx, entry.Path); err != nil {
				return err
			}
			continue
		}
		if entry.Size == math.MaxInt64 {
			return protocolError(ReasonResourceLimit, "extension cannot be bounded with overflow")
		}
		r, err := source.Open(ctx, entry.Path)
		if err != nil {
			if r != nil {
				_ = r.Close()
			}
			return err
		}
		if r == nil {
			return schemaError("missing extension stream")
		}
		w, err := pending.Create(ctx, entry.Path)
		if err != nil {
			if w != nil {
				_ = w.Close()
			}
			_ = r.Close()
			return err
		}
		if w == nil {
			_ = r.Close()
			return schemaError("missing pending extension stream")
		}
		n, copyErr := io.Copy(w, io.LimitReader(contextReader{ctx, r}, entry.Size+1))
		err = errors.Join(copyErr, r.Close(), w.Close())
		if err != nil {
			return err
		}
		if n != entry.Size {
			return ErrUnstableWorkingTree
		}
	}
	return ctx.Err()
}
