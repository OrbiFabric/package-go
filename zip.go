// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"slices"
	"sync"
)

// ArchiveSource selects one immutable, Host-authorized artifact observation.
// It performs no discovery or network fallback. ReadAt and stability checks
// must honor ctx, including blocking Host I/O; callers own snapshot Close.
type ArchiveSource interface {
	BeginArchive(context.Context) (ArchiveSnapshot, error)
}
type ArchiveSnapshot interface {
	Size() int64
	ReadAt(context.Context, []byte, int64) (int, error)
	CheckStable(context.Context) error
	Close() error
}

type zipSource struct {
	source ArchiveSource
	limits Limits
}

// NewZIPSource exposes a wrapped/unwrapped ZIP v1 as the same Package tree as
// Directory. BeginSnapshot preflights all central/local records and paths,
// including implicit parents, before exposing any stream or destination write.
// Names come only from raw UTF-8 entry names, never Unicode-extra overrides.
func NewZIPSource(source ArchiveSource, l Limits) (SnapshotSource, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if source == nil {
		return nil, schemaError("missing ZIP archive source")
	}
	return &zipSource{source, l}, nil
}
func (s *zipSource) BeginSnapshot(ctx context.Context) (TreeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	archive, err := s.source.BeginArchive(ctx)
	if err != nil {
		if archive != nil {
			err = errors.Join(err, archive.Close())
		}
		return nil, err
	}
	if archive == nil {
		return nil, schemaError("missing ZIP archive observation")
	}
	plan, err := preflightZIP(ctx, archive, s.limits)
	if err == nil {
		err = archive.CheckStable(ctx)
	}
	if err != nil {
		return nil, errors.Join(err, archive.Close())
	}
	return &zipTreeSnapshot{archive: archive, plan: plan}, nil
}

type zipTreeSnapshot struct {
	mu      sync.Mutex
	archive ArchiveSnapshot
	plan    zipPlan
	active  int
	closed  bool
}

func (s *zipTreeSnapshot) List(ctx context.Context, max int) ([]TreeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, fs.ErrClosed
	}
	if max <= 0 || len(s.plan.entries) > max {
		return nil, protocolError(ReasonResourceLimit, "ZIP tree entry policy")
	}
	return slices.Clone(s.plan.entries), nil
}
func (s *zipTreeSnapshot) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, fs.ErrClosed
	}
	record, ok := s.plan.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	stream := openZIPRecord(ctx, s.archive, record)
	s.active++
	return &zipOwnedStream{ReadCloser: stream, snapshot: s}, nil
}
func (s *zipTreeSnapshot) CheckStable(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return fs.ErrClosed
	}
	if s.active != 0 {
		return ErrUnstableWorkingTree
	}
	return s.archive.CheckStable(ctx)
}
func (s *zipTreeSnapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.active != 0 {
		return errors.New("ZIP observation has unclosed streams")
	}
	s.closed = true
	return s.archive.Close()
}

type zipOwnedStream struct {
	io.ReadCloser
	snapshot *zipTreeSnapshot
	closed   bool
}

func (s *zipOwnedStream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.ReadCloser.Close()
	s.snapshot.mu.Lock()
	s.snapshot.active--
	s.snapshot.mu.Unlock()
	return err
}
