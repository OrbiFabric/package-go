// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package packagego

import "context"

func beginNativeArtifact(context.Context, string, Limits) (ArtifactTransaction, error) {
	return nil, ErrDirectoryPlatformUnsupported
}
func beginNativeArchiveInput(context.Context, string, Limits) (ArchiveSnapshot, error) {
	return nil, ErrDirectoryPlatformUnsupported
}
