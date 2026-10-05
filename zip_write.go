// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"archive/zip"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"slices"
)

type ZIPOptions struct {
	DisplayDirectory string
	// Method accepts zip.Store or zip.Deflate. CompressionLevel is a flate
	// level, including DefaultCompression; zero selects NoCompression.
	Method           uint16
	CompressionLevel int
}
type ZIPWriteResult struct {
	PackageID PackageID
	HEAD      HEAD
	// ArtifactDigest hashes container bytes; it is NEVER a Version subject.
	ArtifactDigest ContentID
	Bytes          int64
}

// WriteZIP streams a single-wrapper ZIP into caller-isolated pending output.
// It validates the whole source/history before any write, preserves raw bytes
// and empty folders, closes ZIP framing, checks source stability and closes its
// observation. On failure it returns no artifact; discard pending output.
// It neither closes the supplied writer nor publishes/acknowledges a Host
// destination. A Host must validate/seal/publish that artifact separately.
func WriteZIP(ctx context.Context, source SnapshotSource, pending io.Writer, options ZIPOptions, l Limits, support CapabilitySupport) (out ZIPWriteResult, err error) {
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if source == nil || pending == nil {
		return out, schemaError("missing ZIP source/pending writer")
	}
	if err = ValidateComponent(options.DisplayDirectory); err != nil {
		return out, err
	}
	if options.Method != zip.Store && options.Method != zip.Deflate {
		return out, unsafeZIP("ZIP writer method unsupported")
	}
	if options.CompressionLevel < flate.HuffmanOnly || options.CompressionLevel > flate.BestCompression {
		return out, unsafeZIP("ZIP writer compression level unsupported")
	}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("missing ZIP source observation")
	}
	defer func() {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		if err != nil {
			out = ZIPWriteResult{}
		}
	}()
	h, err := validateDirectoryTree(ctx, snapshot, l, support)
	if err != nil {
		return out, err
	}
	wrapped := make([]TreeEntry, 0, len(h.Root.Entries)+1)
	wrapped = append(wrapped, TreeEntry{Path: options.DisplayDirectory, Kind: "directory"})
	for _, e := range h.Root.Entries {
		e.Path = options.DisplayDirectory + "/" + e.Path
		if len(e.Path) > 65535 {
			return out, protocolError(ReasonResourceLimit, "ZIP writer name length")
		}
		wrapped = append(wrapped, e)
	}
	if _, err = preflightTree(ctx, wrapped, l, false); err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	hash := sha256.New()
	counter := &zipArtifactWriter{ctx: ctx, writer: io.MultiWriter(pending, hash), max: l.MaxTotalBytes}
	writer := zip.NewWriter(counter)
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, writer.Close())
		}
	}()
	writer.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, options.CompressionLevel) })
	writer.RegisterCompressor(zip.Store, func(w io.Writer) (io.WriteCloser, error) { return zipStoreWriter{w}, nil })
	// All paths are planned before writer creation; order is presentation only.
	entries := slices.Clone(h.Root.Entries)
	headers := make([]*zip.FileHeader, 0, len(entries)+1)
	for n := -1; n < len(entries); n++ {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		e := TreeEntry{Kind: "directory"}
		name := options.DisplayDirectory
		if n >= 0 {
			e = entries[n]
			name += "/" + e.Path
		}
		if e.Kind == "directory" {
			name += "/"
		}
		header := &zip.FileHeader{Name: name, Method: options.Method, Flags: 0x800}
		if e.Kind == "directory" {
			header.SetMode(0700 | fs.ModeDir)
		} else {
			header.SetMode(0600)
		}
		w, createErr := writer.CreateHeader(header)
		if createErr != nil {
			return out, createErr
		}
		headers = append(headers, header)
		if e.Kind == "directory" {
			continue
		}
		r, openErr := snapshot.Open(ctx, e.Path)
		if openErr != nil {
			if r != nil {
				openErr = errors.Join(openErr, r.Close())
			}
			return out, openErr
		}
		if r == nil {
			return out, schemaError("missing ZIP writer source stream")
		}
		count, copyErr := io.Copy(w, io.LimitReader(contextReader{ctx, r}, e.Size+1))
		copyErr = errors.Join(copyErr, r.Close())
		if copyErr != nil {
			return out, copyErr
		}
		if count != e.Size {
			return out, ErrUnstableWorkingTree
		}
	}
	closed = true
	if err = writer.Close(); err != nil {
		return out, err
	}
	for _, h := range headers {
		if h.UncompressedSize64 != 0 && (h.CompressedSize64 == 0 || float64(h.UncompressedSize64) > float64(h.CompressedSize64)*l.MaxCompressionRatio) {
			return out, protocolError(ReasonResourceLimit, "ZIP writer compression ratio policy")
		}
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	err = snapshot.Close()
	snapshot = nil
	if err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	return ZIPWriteResult{h.Root.Package.PackageID, h.Root.HEAD, ContentID("sha256:" + hex.EncodeToString(hash.Sum(nil))), counter.n}, nil
}

type zipArtifactWriter struct {
	ctx    context.Context
	writer io.Writer
	n, max int64
}

type zipStoreWriter struct{ io.Writer }

func (zipStoreWriter) Close() error { return nil }

func (w *zipArtifactWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.max-w.n {
		return 0, protocolError(ReasonResourceLimit, "ZIP artifact output byte policy")
	}
	n, err := w.writer.Write(p)
	w.n += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if cancel := w.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}
