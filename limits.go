// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
)

// Limits are Host policy, not normative protocol maxima. All fields must be
// positive. Codecs must enforce these before allocation/expansion/publication.
type Limits struct {
	MaxEntries          int
	MaxFileBytes        int64
	MaxTotalBytes       int64
	MaxJSONBytes        int64
	MaxJSONDepth        int
	MaxNDJSONLineBytes  int64
	MaxCompressionRatio float64
}

func DefaultLimits() Limits {
	return Limits{100000, 8 << 30, 64 << 30, 16 << 20, 64, 1 << 20, 1000}
}
func (l Limits) Validate() error {
	if l.MaxEntries <= 0 || l.MaxFileBytes <= 0 || l.MaxTotalBytes <= 0 ||
		l.MaxJSONBytes <= 0 || l.MaxJSONBytes == math.MaxInt64 || l.MaxJSONDepth <= 0 ||
		l.MaxNDJSONLineBytes <= 0 || l.MaxCompressionRatio <= 0 ||
		math.IsNaN(l.MaxCompressionRatio) || math.IsInf(l.MaxCompressionRatio, 0) {
		return protocolError(ReasonResourceLimit, "invalid resource policy")
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if cancel := r.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}

// ReadBounded checks cancellation between reads and reads at most max+1 bytes.
// A Host supplying blocking I/O must itself make those reads cancellable.
func ReadBounded(ctx context.Context, r io.Reader, max int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if max <= 0 || max == math.MaxInt64 {
		return nil, protocolError(ReasonResourceLimit, "invalid byte limit")
	}
	if r == nil {
		return nil, fmt.Errorf("nil input stream")
	}
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx, r}, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, protocolError(ReasonResourceLimit, "input exceeds byte limit")
	}
	return b, nil
}

// CopyVerifiedContent writes only to caller-isolated pending output. Even on
// success it does not publish output. Host errors, cancellation, count or hash
// failures require discarding that pending output; Working Tree bytes may not
// substitute for a missing committed content object.
func CopyVerifiedContent(ctx context.Context, dst io.Writer, src io.Reader, contentID ContentID, size int64, limits Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < 0 {
		return protocolError(ReasonInvalidSchema, "negative content size")
	}
	if size > limits.MaxFileBytes || size > limits.MaxTotalBytes || size == math.MaxInt64 {
		return protocolError(ReasonResourceLimit, "content exceeds byte policy")
	}
	if err := contentID.Validate(); err != nil {
		return err
	}
	if src == nil || dst == nil {
		return fmt.Errorf("nil content stream")
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(contextReader{ctx, src}, size+1))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if n != size || ContentID("sha256:"+hex.EncodeToString(hash.Sum(nil))) != contentID {
		return protocolError(ReasonObjectHashMismatch, "content bytes or size disagree")
	}
	return nil
}
