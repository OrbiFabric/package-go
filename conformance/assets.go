// SPDX-License-Identifier: Apache-2.0
// Package conformance exposes read-only frozen shared inputs for SDK runners.
// Loading or checking assets is not implementation conformance certification.
package conformance

import (
	"github.com/orbifabric/package-go/internal/specassets"
	"io/fs"
)

const SpecCommit = specassets.Commit

func Assets() fs.FS       { return specassets.FS() }
func VerifyAssets() error { return specassets.Verify() }
