// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bufio"
	"compress/flate"
	"context"
	"errors"
	"hash"
	"hash/crc32"
	"io"
)

type zipContextReaderAt struct {
	ctx    context.Context
	source ArchiveSnapshot
}

func (r zipContextReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.source.ReadAt(r.ctx, p, offset)
	if cancel := r.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}

type zipCompressedStream struct {
	source *bufio.Reader
	n      int64
}

func (r *zipCompressedStream) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.n += int64(n)
	return n, err
}
func (r *zipCompressedStream) ReadByte() (byte, error) {
	b, err := r.source.ReadByte()
	if err == nil {
		r.n++
	}
	return b, err
}

type zipCheckedStream struct {
	ctx        context.Context
	compressed *zipCompressedStream
	reader     io.ReadCloser
	record     zipRecord
	crc        hash.Hash32
	n          int64
	terminal   error
	closed     bool
}

func openZIPRecord(ctx context.Context, a ArchiveSnapshot, r zipRecord) *zipCheckedStream {
	compressed := &zipCompressedStream{source: bufio.NewReaderSize(io.NewSectionReader(zipContextReaderAt{ctx, a}, r.data, r.compressed), 32768)}
	var reader io.ReadCloser = io.NopCloser(compressed)
	if r.method == 8 {
		reader = flate.NewReader(compressed)
	}
	return &zipCheckedStream{ctx: ctx, compressed: compressed, reader: reader, record: r, crc: crc32.NewIEEE()}
}
func (r *zipCheckedStream) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	if r.terminal != nil {
		return 0, r.terminal
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > r.record.size-r.n+1 {
		p = p[:int(r.record.size-r.n+1)]
	}
	n, err := r.reader.Read(p)
	r.n += int64(n)
	_, _ = r.crc.Write(p[:n])
	if r.n > r.record.size {
		r.terminal = unsafeZIP("ZIP expansion exceeds declared size")
		return n, r.terminal
	}
	if err == io.EOF {
		if r.n != r.record.size || r.crc.Sum32() != r.record.crc || r.compressed.n != r.record.compressed {
			err = unsafeZIP("ZIP expanded size/CRC/compressed extent disagree")
		}
		r.terminal = err
	} else if err != nil {
		var corrupt flate.CorruptInputError
		if errors.As(err, &corrupt) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = errors.Join(unsafeZIP("invalid ZIP compressed stream"), err)
		}
		r.terminal = err
	}
	if cancel := r.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}
func (r *zipCheckedStream) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	err := r.reader.Close()
	if r.terminal != nil && r.terminal != io.EOF {
		err = errors.Join(err, r.terminal)
	}
	return err
}
