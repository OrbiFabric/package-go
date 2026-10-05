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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const directoryOpenFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
const directoryPathOnly = 0x200000 // Linux O_PATH: inspect kind without opening a device/FIFO for I/O.

// Every component is resolved relative to a held directory descriptor. Never
// replace this with Lstat followed by path-based Open or ordinary Rename.
func openAbsoluteDirectory(ctx context.Context, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		return nil, protocolError(ReasonInvalidPath, "absolute directory required")
	}
	fd, err := syscall.Open("/", directoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "directory")
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if component == "" {
			continue
		}
		if err = ctx.Err(); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		next, openErr := openAt(f, component, directoryOpenFlags, 0)
		closeErr := f.Close()
		if openErr != nil || closeErr != nil {
			if next != nil {
				closeErr = errors.Join(closeErr, next.Close())
			}
			return nil, errors.Join(openErr, closeErr)
		}
		f = next
	}
	return f, nil
}
func openAt(parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(parent.Fd()), name, flags, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "directory-entry"), nil
}
func relativeDirectoryParent(ctx context.Context, root *os.File, path string) (*os.File, string, error) {
	parts := strings.Split(path, "/")
	for _, component := range parts {
		if err := ValidateComponent(component); err != nil {
			return nil, "", err
		}
	}
	f, err := openAt(root, ".", directoryOpenFlags, 0)
	if err != nil {
		return nil, "", err
	}
	for _, component := range parts[:len(parts)-1] {
		if err = ctx.Err(); err != nil {
			return nil, "", errors.Join(err, f.Close())
		}
		next, openErr := openAt(f, component, directoryOpenFlags, 0)
		closeErr := f.Close()
		if openErr != nil || closeErr != nil {
			if next != nil {
				closeErr = errors.Join(closeErr, next.Close())
			}
			return nil, "", errors.Join(openErr, closeErr)
		}
		f = next
	}
	return f, parts[len(parts)-1], nil
}

type directoryStamp struct {
	Device, Inode     uint64
	Mode              uint32
	Size              int64
	Modified, Changed syscall.Timespec
}

func stampDirectoryFile(f *os.File) (directoryStamp, error) {
	var s syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &s); err != nil {
		return directoryStamp{}, err
	}
	return directoryStamp{uint64(s.Dev), uint64(s.Ino), s.Mode, s.Size, s.Mtim, s.Ctim}, nil
}

type nativeDirectorySnapshot struct {
	mu      sync.Mutex
	root    *os.File
	path    string
	limits  Limits
	stamps  map[string]directoryStamp
	entries []TreeEntry
	digests map[string][32]byte
	active  int
	closed  bool
}

func beginNativeDirectory(ctx context.Context, path string, l Limits) (TreeSnapshot, error) {
	root, err := openAbsoluteDirectory(ctx, path)
	if err != nil {
		return nil, err
	}
	return &nativeDirectorySnapshot{root: root, path: path, limits: l, digests: map[string][32]byte{}}, nil
}

func enumerateDirectory(ctx context.Context, root *os.File, l Limits, max int) (entries []TreeEntry, stamps map[string]directoryStamp, err error) {
	stamps = map[string]directoryStamp{}
	stamps[""], err = stampDirectoryFile(root)
	if err != nil {
		return nil, nil, err
	}
	var walk func(*os.File, string, int) error
	walk = func(parent *os.File, prefix string, depth int) (err error) {
		// Separate open-file description: directory offsets are never shared
		// with the snapshot anchor or subsequent enumeration.
		dir, err := openAt(parent, ".", directoryOpenFlags, 0)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, dir.Close()) }()
		for {
			if err = ctx.Err(); err != nil {
				return err
			}
			batch, readErr := dir.Readdirnames(min(128, max-len(entries)+1))
			for _, name := range batch {
				path := prefix + name
				if len(entries) >= max || len(path) > l.MaxPathBytes || depth > l.MaxTreeDepth {
					return protocolError(ReasonResourceLimit, "directory enumeration policy")
				}
				// Metadata-only descriptors avoid special-file I/O during listing.
				// O_PATH|NOFOLLOW opens a symlink itself; Fstat rejects its kind.
				child, openErr := openAt(parent, name, directoryPathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
				if errors.Is(openErr, syscall.ELOOP) {
					return protocolError(ReasonInvalidPath, "directory tree contains a symbolic link")
				}
				if openErr != nil {
					return openErr
				}
				stamp, statErr := stampDirectoryFile(child)
				if statErr != nil {
					return errors.Join(statErr, child.Close())
				}
				kind, size := "file", stamp.Size
				switch stamp.Mode & syscall.S_IFMT {
				case syscall.S_IFDIR:
					kind, size = "directory", 0
				case syscall.S_IFREG:
				default:
					return errors.Join(protocolError(ReasonInvalidPath, "directory tree contains a special file"), child.Close())
				}
				entries = append(entries, TreeEntry{path, kind, size})
				stamps[path] = stamp
				if kind == "directory" {
					statErr = walk(child, path+"/", depth+1)
				}
				if closeErr := child.Close(); statErr != nil || closeErr != nil {
					return errors.Join(statErr, closeErr)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	}
	err = walk(root, "", 1)
	slices.SortFunc(entries, func(a, b TreeEntry) int { return strings.Compare(a.Path, b.Path) })
	return entries, stamps, err
}
func (s *nativeDirectorySnapshot) List(ctx context.Context, maxEntries int) ([]TreeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if maxEntries <= 0 {
		return nil, protocolError(ReasonResourceLimit, "invalid directory entry limit")
	}
	entries, stamps, err := enumerateDirectory(ctx, s.root, s.limits, min(maxEntries, s.limits.MaxEntries))
	if err != nil {
		return nil, err
	}
	if s.stamps == nil {
		s.stamps, s.entries = stamps, entries
	} else if !reflect.DeepEqual(stamps, s.stamps) {
		return nil, ErrUnstableWorkingTree
	}
	return slices.Clone(entries), nil
}
func (s *nativeDirectorySnapshot) openObserved(ctx context.Context, path string) (*os.File, directoryStamp, error) {
	stamp, exists := s.stamps[path]
	if !exists {
		return nil, directoryStamp{}, os.ErrNotExist
	}
	if stamp.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, directoryStamp{}, protocolError(ReasonInvalidPath, "directory stream is not regular")
	}
	if stamp.Size < 0 || stamp.Size > s.limits.MaxFileBytes || stamp.Size > s.limits.MaxTotalBytes {
		return nil, directoryStamp{}, protocolError(ReasonResourceLimit, "directory stream byte policy")
	}
	parent, name, err := relativeDirectoryParent(ctx, s.root, path)
	if err != nil {
		return nil, directoryStamp{}, err
	}
	f, err := openAt(parent, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	err = errors.Join(err, parent.Close())
	if err != nil {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		return nil, directoryStamp{}, err
	}
	actual, err := stampDirectoryFile(f)
	if err == nil && actual != stamp {
		err = ErrUnstableWorkingTree
	}
	if err != nil {
		return nil, directoryStamp{}, errors.Join(err, f.Close())
	}
	return f, stamp, nil
}
func (s *nativeDirectorySnapshot) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, os.ErrClosed
	}
	if s.stamps == nil {
		return nil, schemaError("directory must be listed before streams are opened")
	}
	f, stamp, err := s.openObserved(ctx, path)
	if err != nil {
		return nil, err
	}
	s.active++
	return &observedDirectoryStream{file: f, snapshot: s, ctx: ctx, path: path, stamp: stamp, hash: sha256.New()}, nil
}
func (s *nativeDirectorySnapshot) CheckStable(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return os.ErrClosed
	}
	if s.active != 0 {
		return ErrUnstableWorkingTree
	}
	if s.stamps == nil {
		return schemaError("directory observation was not enumerated")
	}
	// A moved/replaced Root or symlink substitution must not be confused with
	// the still-readable, descriptor-anchored old Root.
	current, err := openAbsoluteDirectory(ctx, s.path)
	if err != nil {
		return errors.Join(ErrUnstableWorkingTree, err)
	}
	stamp, err := stampDirectoryFile(current)
	err = errors.Join(err, current.Close())
	if err != nil {
		return err
	}
	if stamp != s.stamps[""] {
		return ErrUnstableWorkingTree
	}
	check := func() error {
		_, stamps, err := enumerateDirectory(ctx, s.root, s.limits, s.limits.MaxEntries)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(stamps, s.stamps) {
			return ErrUnstableWorkingTree
		}
		return nil
	}
	if err = check(); err != nil {
		return err
	}
	for path, expected := range s.digests {
		f, stamp, err := s.openObserved(ctx, path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(contextReader{ctx, f}, stamp.Size+1))
		actual, statErr := stampDirectoryFile(f)
		readErr = errors.Join(readErr, statErr, f.Close())
		if readErr != nil {
			return readErr
		}
		var digest [32]byte
		copy(digest[:], hash.Sum(nil))
		if n != stamp.Size || digest != expected || actual != stamp {
			return ErrUnstableWorkingTree
		}
	}
	return check()
}
func (s *nativeDirectorySnapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.active != 0 {
		return errors.Join(ErrUnstableWorkingTree, errors.New("directory observation has unclosed streams"))
	}
	s.closed = true
	return s.root.Close()
}

type observedDirectoryStream struct {
	file     *os.File
	snapshot *nativeDirectorySnapshot
	ctx      context.Context
	path     string
	stamp    directoryStamp
	hash     interface {
		io.Writer
		Sum([]byte) []byte
	}
	n           int64
	eof, closed bool
}

func (r *observedDirectoryStream) Read(p []byte) (int, error) {
	if r.closed {
		return 0, os.ErrClosed
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.file.Read(p)
	_, _ = r.hash.Write(p[:n])
	r.n += int64(n)
	if err == io.EOF {
		r.eof = true
	}
	if r.n > r.stamp.Size {
		return n, ErrUnstableWorkingTree
	}
	if cancel := r.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}
func (r *observedDirectoryStream) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	actual, err := stampDirectoryFile(r.file)
	err = errors.Join(err, r.file.Close())
	s := r.snapshot
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if actual != r.stamp {
		err = errors.Join(err, ErrUnstableWorkingTree)
	}
	if r.eof && r.n == r.stamp.Size && err == nil {
		var digest [32]byte
		copy(digest[:], r.hash.Sum(nil))
		if previous, exists := s.digests[r.path]; exists && previous != digest {
			return ErrUnstableWorkingTree
		}
		s.digests[r.path] = digest
	}
	return err
}

type nativeDirectoryTransaction struct {
	mu                                   sync.Mutex
	parent, root                         *os.File
	parentPath, destination, pending     string
	parentStamp                          directoryStamp
	observation                          *nativeDirectorySnapshot
	paths                                []TreeEntry
	limits                               Limits
	total                                int64
	active                               int
	sealed, attempted, published, closed bool
}

func beginNativePublication(ctx context.Context, destination string, l Limits) (DirectoryTransaction, error) {
	parentPath, name := filepath.Dir(destination), filepath.Base(destination)
	parent, err := openAbsoluteDirectory(ctx, parentPath)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (DirectoryTransaction, error) { return nil, errors.Join(err, parent.Close()) }
	// Atomic NOREPLACE below is authoritative; this is only an early check.
	probe, probeErr := openAt(parent, name, directoryPathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if probeErr == nil {
		return fail(errors.Join(os.ErrExist, probe.Close()))
	}
	if !errors.Is(probeErr, syscall.ENOENT) {
		return fail(probeErr)
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return fail(err)
	}
	pending := ".package-pending-" + hex.EncodeToString(random[:])
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = syscall.Mkdirat(int(parent.Fd()), pending, 0700); err != nil {
		return fail(err)
	}
	root, err := openAt(parent, pending, directoryOpenFlags, 0)
	if err != nil {
		return fail(errors.Join(err, unlinkDirectoryAt(parent, pending, true)))
	}
	stamp, err := stampDirectoryFile(parent)
	if err != nil {
		return fail(errors.Join(err, root.Close(), unlinkDirectoryAt(parent, pending, true)))
	}
	return &nativeDirectoryTransaction{parent: parent, root: root, parentPath: parentPath, parentStamp: stamp, destination: name, pending: pending, limits: l}, nil
}
func (t *nativeDirectoryTransaction) checkPathPolicy(path string) error {
	if len(t.paths) >= t.limits.MaxEntries || len(path) > t.limits.MaxPathBytes || strings.Count(path, "/")+1 > t.limits.MaxTreeDepth {
		return protocolError(ReasonResourceLimit, "pending directory path policy")
	}
	return nil
}
func (t *nativeDirectoryTransaction) Mkdir(ctx context.Context, path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.sealed {
		return os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.checkPathPolicy(path); err != nil {
		return err
	}
	parent, name, err := relativeDirectoryParent(ctx, t.root, path)
	if err != nil {
		return err
	}
	err = syscall.Mkdirat(int(parent.Fd()), name, 0700)
	if err == nil {
		t.paths = append(t.paths, TreeEntry{Path: path, Kind: "directory"})
	}
	return errors.Join(err, parent.Close())
}
func (t *nativeDirectoryTransaction) Create(ctx context.Context, path string) (io.WriteCloser, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.sealed {
		return nil, os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := t.checkPathPolicy(path); err != nil {
		return nil, err
	}
	parent, name, err := relativeDirectoryParent(ctx, t.root, path)
	if err != nil {
		return nil, err
	}
	f, err := openAt(parent, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err == nil {
		t.paths = append(t.paths, TreeEntry{Path: path, Kind: "file"})
	}
	err = errors.Join(err, parent.Close())
	if err != nil {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		return nil, err
	}
	t.active++
	return &pendingDirectoryStream{file: f, ctx: ctx, tx: t}, nil
}

type pendingDirectoryStream struct {
	file   *os.File
	ctx    context.Context
	tx     *nativeDirectoryTransaction
	closed bool
	n      int64
}

func (w *pendingDirectoryStream) Write(p []byte) (int, error) {
	if w.closed {
		return 0, os.ErrClosed
	}
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	w.tx.mu.Lock()
	if int64(len(p)) > w.tx.limits.MaxFileBytes-w.n || int64(len(p)) > w.tx.limits.MaxTotalBytes-w.tx.total {
		w.tx.mu.Unlock()
		return 0, protocolError(ReasonResourceLimit, "pending directory byte policy")
	}
	n, err := w.file.Write(p)
	w.n += int64(n)
	w.tx.total += int64(n)
	w.tx.mu.Unlock()
	if cancel := w.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}
func (w *pendingDirectoryStream) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	err := errors.Join(w.file.Sync(), w.file.Close())
	w.tx.mu.Lock()
	w.tx.active--
	w.tx.mu.Unlock()
	return err
}
func (t *nativeDirectoryTransaction) Seal(ctx context.Context) (TreeSnapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.sealed {
		return nil, os.ErrClosed
	}
	if t.active != 0 {
		return nil, errors.New("pending directory has unclosed writers")
	}
	// Flush directories from children to parents after all regular files.
	for i := len(t.paths) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := t.paths[i]
		if e.Kind != "directory" {
			continue
		}
		parent, name, err := relativeDirectoryParent(ctx, t.root, e.Path)
		if err != nil {
			return nil, err
		}
		dir, err := openAt(parent, name, directoryOpenFlags, 0)
		err = errors.Join(err, parent.Close())
		if dir != nil {
			err = errors.Join(err, dir.Sync(), dir.Close())
		}
		if err != nil {
			return nil, err
		}
	}
	if err := t.root.Sync(); err != nil {
		return nil, err
	}
	if err := t.parent.Sync(); err != nil {
		return nil, err
	}
	t.sealed = true
	s, err := beginNativeDirectory(ctx, filepath.Join(t.parentPath, t.pending), t.limits)
	if err != nil {
		return nil, err
	}
	t.observation = s.(*nativeDirectorySnapshot)
	return s, nil
}

func (t *nativeDirectoryTransaction) recheckSealed(ctx context.Context) error {
	observed := t.observation
	if observed == nil {
		return schemaError("missing sealed directory observation")
	}
	observed.mu.Lock()
	if observed.active != 0 {
		observed.mu.Unlock()
		return ErrUnstableWorkingTree
	}
	root, err := openAt(t.root, ".", directoryOpenFlags, 0)
	if err != nil {
		observed.mu.Unlock()
		return err
	}
	// Reopen a descriptor, retaining the validated stamps/digests even after
	// the SDK has closed its pending observation. Metadata is an early-change
	// guard; the fully read raw file digests are checked again before rename.
	stamps := make(map[string]directoryStamp, len(observed.stamps))
	for p, s := range observed.stamps {
		stamps[p] = s
	}
	digests := make(map[string][32]byte, len(observed.digests))
	for p, d := range observed.digests {
		digests[p] = d
	}
	observed.mu.Unlock()
	check := &nativeDirectorySnapshot{root: root, path: filepath.Join(t.parentPath, t.pending), limits: t.limits, stamps: stamps, digests: digests}
	if len(stamps) == 0 {
		_, err = check.List(ctx, t.limits.MaxEntries)
	}
	if err == nil {
		err = check.CheckStable(ctx)
	}
	return errors.Join(err, check.Close())
}
func (t *nativeDirectoryTransaction) Publish(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.sealed || t.attempted {
		return os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.recheckSealed(ctx); err != nil {
		return err
	}
	current, err := openAbsoluteDirectory(ctx, t.parentPath)
	if err != nil {
		return err
	}
	stamp, err := stampDirectoryFile(current)
	err = errors.Join(err, current.Close())
	if err != nil {
		return err
	}
	if stamp.Device != t.parentStamp.Device || stamp.Inode != t.parentStamp.Inode {
		return ErrUnstableWorkingTree
	}
	probe, err := openAt(t.parent, t.pending, directoryOpenFlags, 0)
	if err != nil {
		return err
	}
	a, err := stampDirectoryFile(probe)
	b, statErr := stampDirectoryFile(t.root)
	err = errors.Join(err, statErr, probe.Close())
	if err != nil {
		return err
	}
	if a != b {
		return ErrUnstableWorkingTree
	}
	t.attempted = true
	if err = renameDirectoryNoReplace(t.parent, t.pending, t.destination); err != nil {
		return err
	}
	t.published = true
	if err = t.parent.Sync(); err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	if err = ctx.Err(); err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	// Read back the installed inode; no path-based payload read or overwrite.
	installed, err := openAt(t.parent, t.destination, directoryOpenFlags, 0)
	if err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	actual, err := stampDirectoryFile(installed)
	err = errors.Join(err, installed.Close())
	// rename changes ctime: only identity, type and size are acknowledged.
	if actual.Device != b.Device || actual.Inode != b.Inode || actual.Mode != b.Mode || actual.Size != b.Size {
		err = errors.Join(err, ErrUnstableWorkingTree)
	}
	if err != nil {
		return errors.Join(ErrPublicationUncertain, err)
	}
	return nil
}
func (t *nativeDirectoryTransaction) Abort(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	if t.active != 0 {
		return errors.New("cannot abort pending directory with open writers")
	}
	var err error
	if !t.published {
		// Establish that the anchor is still named pending BEFORE removing any
		// child. A remote/uncertain rename may move it despite returning error.
		probe, openErr := openAt(t.parent, t.pending, directoryOpenFlags, 0)
		if openErr != nil {
			t.closed = true
			return errors.Join(ErrPublicationUncertain, openErr, t.root.Close(), t.parent.Close())
		}
		a, statErr := stampDirectoryFile(probe)
		b, rootErr := stampDirectoryFile(t.root)
		err = errors.Join(statErr, rootErr, probe.Close())
		if err != nil || a.Device != b.Device || a.Inode != b.Inode {
			t.closed = true
			return errors.Join(err, ErrUnstableWorkingTree, t.root.Close(), t.parent.Close())
		}
		for i := len(t.paths) - 1; i >= 0; i-- {
			e := t.paths[i]
			parent, name, openErr := relativeDirectoryParent(ctx, t.root, e.Path)
			if openErr != nil {
				err = errors.Join(err, openErr)
				continue
			}
			err = errors.Join(err, unlinkDirectoryAt(parent, name, e.Kind == "directory"), parent.Close())
		}
		// Recheck the entry before removing the empty pending directory itself.
		probe, openErr = openAt(t.parent, t.pending, directoryOpenFlags, 0)
		if openErr == nil {
			a, statErr := stampDirectoryFile(probe)
			b, rootErr := stampDirectoryFile(t.root)
			err = errors.Join(err, statErr, rootErr, probe.Close())
			if statErr == nil && rootErr == nil && a.Device == b.Device && a.Inode == b.Inode {
				err = errors.Join(err, unlinkDirectoryAt(t.parent, t.pending, true))
			} else {
				err = errors.Join(err, ErrUnstableWorkingTree)
			}
		} else {
			err = errors.Join(err, openErr)
		}
	}
	t.closed = true
	return errors.Join(err, t.root.Close(), t.parent.Close())
}

func unlinkDirectoryAt(parent *os.File, name string, directory bool) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	flags := uintptr(0)
	if directory {
		flags = 0x200
	} // AT_REMOVEDIR
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, parent.Fd(), uintptr(unsafe.Pointer(p)), flags)
	runtime.KeepAlive(p)
	if errno != 0 {
		return errno
	}
	return nil
}
func renameDirectoryNoReplace(parent *os.File, old, new string) error {
	// Linux UAPI asm/unistd_64.h (amd64); asm-generic/unistd.h (arm64,
	// riscv64, loong64). Other architectures fail explicitly, never overwrite.
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 316
	case "arm64", "riscv64", "loong64":
		number = 276
	default:
		return ErrDirectoryPlatformUnsupported
	}
	a, err := syscall.BytePtrFromString(old)
	if err != nil {
		return err
	}
	b, err := syscall.BytePtrFromString(new)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(number, parent.Fd(), uintptr(unsafe.Pointer(a)), parent.Fd(), uintptr(unsafe.Pointer(b)), 1, 0) // RENAME_NOREPLACE
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	if errno != 0 {
		return errno
	}
	return nil
}
