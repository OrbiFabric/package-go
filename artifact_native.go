// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"path/filepath"
	"strings"
)

type artifactHost struct {
	destination string
	limits      Limits
}

type fileArchiveSource struct {
	path   string
	limits Limits
}

// NewFileArchiveSource selects one explicit Host-authorized absolute artifact.
// Native Linux anchors every component, reads a regular file without following
// links, bounds bytes and verifies descriptor metadata/full artifact stability.
// It performs no recursive discovery or format/legacy dispatch.
func NewFileArchiveSource(authorizedPath string, l Limits) (ArchiveSource, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(authorizedPath) || strings.ContainsRune(authorizedPath, 0) {
		return nil, protocolError(ReasonInvalidPath, "archive input must be an explicit absolute path")
	}
	return &fileArchiveSource{filepath.Clean(authorizedPath), l}, nil
}
func (s *fileArchiveSource) BeginArchive(ctx context.Context) (ArchiveSnapshot, error) {
	return beginNativeArchiveInput(ctx, s.path, s.limits)
}

// NewArtifactHost supplies native Linux external pending/no-overwrite artifact
// publication. Other platforms fail explicitly and can supply their own Host.
func NewArtifactHost(destination string, l Limits) (ArtifactHost, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(destination) || strings.ContainsRune(destination, 0) {
		return nil, protocolError(ReasonInvalidPath, "artifact destination must be absolute")
	}
	destination = filepath.Clean(destination)
	if destination == filepath.Dir(destination) {
		return nil, protocolError(ReasonInvalidPath, "cannot publish over filesystem root")
	}
	return &artifactHost{destination, l}, nil
}
func (h *artifactHost) BeginArtifact(ctx context.Context) (ArtifactTransaction, error) {
	return beginNativeArtifact(ctx, h.destination, h.limits)
}
func checkNativeArtifactSeparation(source SnapshotSource, host ArtifactHost) error {
	s, ok := source.(*directorySource)
	if !ok {
		return nil
	}
	h, ok := host.(*artifactHost)
	if !ok {
		return nil
	}
	rel, err := filepath.Rel(s.root, h.destination)
	if err != nil {
		return err
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return protocolError(ReasonInvalidPath, "artifact destination lies inside source Root")
	}
	return nil
}
