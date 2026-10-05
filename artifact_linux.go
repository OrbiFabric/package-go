// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packagego

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type nativeArtifactTransaction struct {
	mu                                      sync.Mutex
	ctx                                     context.Context
	parent, file                            *os.File
	parentPath, pending, destination        string
	parentStamp, stamp                      directoryStamp
	digest                                  [32]byte
	l                                       Limits
	n                                       int64
	writeError                              error
	writerClosed, sealed, published, closed bool
}

func beginNativeArtifact(ctx context.Context, destination string, l Limits) (ArtifactTransaction, error) {
	parentPath, name := filepath.Dir(destination), filepath.Base(destination)
	parent, err := openAbsoluteDirectory(ctx, parentPath)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (ArtifactTransaction, error) { return nil, errors.Join(err, parent.Close()) }
	probe, err := openAt(parent, name, directoryPathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		return fail(errors.Join(os.ErrExist, probe.Close()))
	}
	if !errors.Is(err, syscall.ENOENT) {
		return fail(err)
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return fail(err)
	}
	pending := ".package-artifact-pending-" + hex.EncodeToString(random[:])
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	file, err := openAt(parent, pending, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fail(err)
	}
	stamp, err := stampDirectoryFile(parent)
	if err != nil {
		return fail(errors.Join(err, file.Close(), unlinkDirectoryAt(parent, pending, false)))
	}
	return &nativeArtifactTransaction{ctx: ctx, parent: parent, file: file, parentPath: parentPath, pending: pending, destination: name, parentStamp: stamp, l: l}, nil
}
func (t *nativeArtifactTransaction) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.writerClosed {
		return 0, os.ErrClosed
	}
	if t.writeError != nil {
		return 0, t.writeError
	}
	if err := t.ctx.Err(); err != nil {
		t.writeError = err
		return 0, err
	}
	if int64(len(p)) > t.l.MaxTotalBytes-t.n {
		t.writeError = protocolError(ReasonResourceLimit, "pending artifact byte policy")
		return 0, t.writeError
	}
	n, err := t.file.Write(p)
	t.n += int64(n)
	if cancel := t.ctx.Err(); cancel != nil {
		err = errors.Join(err, cancel)
	}
	t.writeError = err
	return n, err
}
func (t *nativeArtifactTransaction) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writerClosed {
		return t.writeError
	}
	t.writerClosed = true
	var stampErr error
	t.stamp, stampErr = stampDirectoryFile(t.file)
	err := errors.Join(stampErr, t.file.Sync(), t.file.Close())
	t.writeError = errors.Join(t.writeError, err)
	return t.writeError
}
func (t *nativeArtifactTransaction) Seal(ctx context.Context) (ArchiveSnapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.closed || t.sealed || !t.writerClosed {
		return nil, os.ErrClosed
	}
	if t.writeError != nil {
		return nil, t.writeError
	}
	if err := t.parent.Sync(); err != nil {
		return nil, err
	}
	s, err := openNativeArtifactSnapshot(ctx, t.parent, t.parentPath, t.pending, t.l)
	if err != nil {
		return nil, err
	}
	if s.stamp != t.stamp || s.stamp.Size != t.n {
		return nil, errors.Join(ErrUnstableWorkingTree, s.Close())
	}
	t.digest = s.digest
	t.sealed = true
	return s, nil
}
func (t *nativeArtifactTransaction) Publish(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.closed || !t.sealed || t.published {
		return os.ErrClosed
	}
	current, err := openAbsoluteDirectory(ctx, t.parentPath)
	if err != nil {
		return err
	}
	parentStamp, err := stampDirectoryFile(current)
	err = errors.Join(err, current.Close())
	if err != nil {
		return err
	}
	if parentStamp.Device != t.parentStamp.Device || parentStamp.Inode != t.parentStamp.Inode {
		return ErrUnstableWorkingTree
	}
	s, err := openNativeArtifactSnapshot(ctx, t.parent, t.parentPath, t.pending, t.l)
	if err != nil {
		return err
	}
	if s.stamp != t.stamp || s.digest != t.digest {
		return errors.Join(ErrUnstableWorkingTree, s.Close())
	}
	if err = s.Close(); err != nil {
		return err
	}
	if err = renameDirectoryNoReplace(t.parent, t.pending, t.destination); err != nil {
		return err
	}
	t.published = true
	if err = t.parent.Sync(); err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	installed, err := openAt(t.parent, t.destination, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	actual, err := stampDirectoryFile(installed)
	err = errors.Join(err, installed.Close())
	if actual.Device != t.stamp.Device || actual.Inode != t.stamp.Inode || actual.Mode != t.stamp.Mode || actual.Size != t.stamp.Size {
		err = errors.Join(err, ErrUnstableWorkingTree)
	}
	if cancel := ctx.Err(); cancel != nil {
		err = errors.Join(err, cancel)
	}
	if err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	return nil
}
func (t *nativeArtifactTransaction) Abort(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	var err error
	if !t.writerClosed {
		var stampErr error
		t.stamp, stampErr = stampDirectoryFile(t.file)
		err = errors.Join(stampErr, t.file.Close())
		t.writerClosed = true
	}
	if !t.published {
		probe, openErr := openAt(t.parent, t.pending, directoryPathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			err = errors.Join(err, ErrPublicationUncertain, openErr)
		} else {
			stamp, statErr := stampDirectoryFile(probe)
			err = errors.Join(err, statErr, probe.Close())
			if statErr == nil && stamp.Device == t.stamp.Device && stamp.Inode == t.stamp.Inode {
				err = errors.Join(err, unlinkDirectoryAt(t.parent, t.pending, false))
			} else {
				err = errors.Join(err, ErrUnstableWorkingTree)
			}
		}
	}
	t.closed = true
	return errors.Join(err, t.parent.Close())
}

type nativeArtifactSnapshot struct {
	mu               sync.Mutex
	file, parent     *os.File
	parentPath, name string
	stamp            directoryStamp
	digest           [32]byte
	l                Limits
	closed           bool
}

func openNativeArtifactSnapshot(ctx context.Context, parent *os.File, parentPath, name string, l Limits) (*nativeArtifactSnapshot, error) {
	anchor, err := openAt(parent, ".", directoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	file, err := openAt(anchor, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(err, anchor.Close())
	}
	s := &nativeArtifactSnapshot{file: file, parent: anchor, parentPath: parentPath, name: name, l: l}
	stamp, err := stampDirectoryFile(file)
	if err == nil && stamp.Mode&syscall.S_IFMT != syscall.S_IFREG {
		err = protocolError(ReasonInvalidPath, "artifact is not regular")
	}
	if err == nil && (stamp.Size < 0 || stamp.Size > l.MaxTotalBytes || stamp.Size == math.MaxInt64) {
		err = protocolError(ReasonResourceLimit, "artifact input byte policy")
	}
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	s.stamp = stamp
	s.digest, err = s.hash(ctx)
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	after, err := stampDirectoryFile(file)
	if err != nil || after != stamp {
		return nil, errors.Join(err, ErrUnstableWorkingTree, s.Close())
	}
	return s, nil
}

func beginNativeArchiveInput(ctx context.Context, path string, l Limits) (ArchiveSnapshot, error) {
	parentPath, name := filepath.Dir(path), filepath.Base(path)
	parent, err := openAbsoluteDirectory(ctx, parentPath)
	if err != nil {
		return nil, err
	}
	s, err := openNativeArtifactSnapshot(ctx, parent, parentPath, name, l)
	err = errors.Join(err, parent.Close())
	if err != nil {
		if s != nil {
			err = errors.Join(err, s.Close())
		}
		return nil, err
	}
	return s, nil
}
func (s *nativeArtifactSnapshot) Size() int64 { return s.stamp.Size }
func (s *nativeArtifactSnapshot) ReadAt(ctx context.Context, p []byte, offset int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed {
		return 0, os.ErrClosed
	}
	n, err := s.file.ReadAt(p, offset)
	if cancel := ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}
func (s *nativeArtifactSnapshot) hash(ctx context.Context) (digest [32]byte, err error) {
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(contextReader{ctx, s.file}, s.stamp.Size+1))
	if err != nil {
		return digest, err
	}
	if n != s.stamp.Size {
		return digest, ErrUnstableWorkingTree
	}
	copy(digest[:], hash.Sum(nil))
	_, err = s.file.Seek(0, io.SeekStart)
	return digest, err
}
func (s *nativeArtifactSnapshot) CheckStable(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return os.ErrClosed
	}
	current, err := openAbsoluteDirectory(ctx, s.parentPath)
	if err != nil {
		return errors.Join(ErrUnstableWorkingTree, err)
	}
	a, err := stampDirectoryFile(current)
	b, statErr := stampDirectoryFile(s.parent)
	err = errors.Join(err, statErr, current.Close())
	if err != nil {
		return err
	}
	if a.Device != b.Device || a.Inode != b.Inode {
		return ErrUnstableWorkingTree
	}
	probe, err := openAt(s.parent, s.name, directoryPathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrUnstableWorkingTree, err)
	}
	stamp, err := stampDirectoryFile(probe)
	err = errors.Join(err, probe.Close())
	if err != nil {
		return err
	}
	if stamp != s.stamp {
		return ErrUnstableWorkingTree
	}
	digest, err := s.hash(ctx)
	if err != nil {
		return err
	}
	after, err := stampDirectoryFile(s.file)
	if err != nil {
		return err
	}
	if digest != s.digest || after != s.stamp {
		return ErrUnstableWorkingTree
	}
	return nil
}
func (s *nativeArtifactSnapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.file.Close(), s.parent.Close())
}
