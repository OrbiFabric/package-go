// SPDX-License-Identifier: Apache-2.0
// Package specassets holds verbatim machine assets from the frozen public spec.
// This snapshot is reference input, never a second source of protocol authority.
package specassets

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
)

const Commit = "181f9c2048b7cad346044a6fa4a15096166e83d4"

//go:embed data checksums.json
var snapshot embed.FS

func FS() fs.FS { f, _ := fs.Sub(snapshot, "data"); return f }

// Verify checks every pinned asset and rejects additional machine input files.
func Verify() error {
	b, err := snapshot.ReadFile("checksums.json")
	if err != nil {
		return err
	}
	var lock struct {
		Authority string            `json:"authority"`
		SHA256    map[string]string `json:"sha256"`
	}
	if err = json.Unmarshal(b, &lock); err != nil {
		return err
	}
	if lock.Authority != Commit {
		return fmt.Errorf("asset authority mismatch")
	}
	f := FS()
	count := 0
	err = fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || p == "LICENSE" || p == "NOTICE" {
			return nil
		}
		want, ok := lock.SHA256[p]
		if !ok {
			return fmt.Errorf("unpinned asset %s", p)
		}
		b, err := fs.ReadFile(f, p)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != want {
			return fmt.Errorf("asset digest mismatch: %s", p)
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count != len(lock.SHA256) {
		return fmt.Errorf("missing pinned asset")
	}
	return nil
}
