// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package packagego

import "context"

func beginNativeDirectory(context.Context, string, Limits) (TreeSnapshot, error) {
	return nil, ErrDirectoryPlatformUnsupported
}
func beginNativePublication(context.Context, string, Limits) (DirectoryTransaction, error) {
	return nil, ErrDirectoryPlatformUnsupported
}
