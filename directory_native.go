// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"path/filepath"
	"strings"
)

type directorySource struct {
	root   string
	limits Limits
}
type directoryHost struct {
	destination string
	limits      Limits
}

// NewDirectorySource selects exactly one Host-authorized absolute Root. It
// performs no discovery, ancestor search or authority inference. Native Linux
// snapshots reject links in every component, bound enumeration and detect
// changes using descriptor metadata plus hashes of every fully read file.
// Other platforms explicitly return ErrDirectoryPlatformUnsupported; Hosts
// may supply their own safe SnapshotSource instead.
func NewDirectorySource(authorizedRoot string, l Limits) (SnapshotSource, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(authorizedRoot) || strings.ContainsRune(authorizedRoot, 0) {
		return nil, protocolError(ReasonInvalidPath, "Directory Root must be an explicit absolute path")
	}
	return &directorySource{filepath.Clean(authorizedRoot), l}, nil
}
func (s *directorySource) BeginSnapshot(ctx context.Context) (TreeSnapshot, error) {
	return beginNativeDirectory(ctx, s.root, s.limits)
}

// NewDirectoryHost selects one absolute destination. Native Linux publication
// uses a private sibling staging directory, fsync and renameat2 NOREPLACE.
// Unsupported kernel/filesystem/platform operations fail without fallback to
// replacement rename. The Host authorizes the parent directory and excludes
// hostile writers from pending output until its acknowledgement.
func NewDirectoryHost(destination string, l Limits) (DirectoryHost, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(destination) || strings.ContainsRune(destination, 0) {
		return nil, protocolError(ReasonInvalidPath, "Directory destination must be an explicit absolute path")
	}
	destination = filepath.Clean(destination)
	if destination == filepath.Dir(destination) {
		return nil, protocolError(ReasonInvalidPath, "cannot publish over filesystem root")
	}
	return &directoryHost{destination, l}, nil
}
func (h *directoryHost) BeginDirectory(ctx context.Context) (DirectoryTransaction, error) {
	return beginNativePublication(ctx, h.destination, h.limits)
}

func checkNativeDirectorySeparation(source SnapshotSource, host DirectoryHost) error {
	s, ok := source.(*directorySource)
	if !ok {
		return nil
	}
	h, ok := host.(*directoryHost)
	if !ok {
		return nil
	}
	rel, err := filepath.Rel(s.root, h.destination)
	if err != nil {
		return err
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return protocolError(ReasonInvalidPath, "directory publication destination lies inside source Root")
	}
	return nil
}
