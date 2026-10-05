// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packagego_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

func TestZIPActualDirectoryEquivalentRoundTrips(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	for _, name := range []string{"minimal-valid", "complete-history", "dirty-working-tree", "moved-file", "unknown-optional-extension"} {
		t.Run(name, func(t *testing.T) {
			root, _ := directoryFixture(t, name)
			if err := os.MkdirAll(filepath.Join(root, "empty", "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			beforeEntries, before := readDirectoryBytes(t, root)
			for _, method := range []uint16{zip.Store, zip.Deflate} {
				var pending bytes.Buffer
				written, err := pkg.WriteZIP(ctx, nativeDirectorySource(t, root), &pending, pkg.ZIPOptions{DisplayDirectory: "Presentation", Method: method, CompressionLevel: flate.DefaultCompression}, l, support)
				if err != nil {
					t.Fatal(err)
				}
				artifact := filepath.Join(t.TempDir(), "artifact.zip")
				if err = os.WriteFile(artifact, pending.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				artifactBytes, err := os.ReadFile(artifact)
				if err != nil || len(artifactBytes) != int(written.Bytes) {
					t.Fatal(err)
				}
				destination := filepath.Join(t.TempDir(), "restored")
				out, err := pkg.PublishDirectory(ctx, zipSource(t, artifactBytes, l), nativeDirectoryHost(t, destination), l, support)
				if err != nil || out.PackageID != written.PackageID || out.HEAD != written.HEAD {
					t.Fatal(out, written, err)
				}
				afterEntries, after := readDirectoryBytes(t, destination)
				if !slices.Equal(beforeEntries, afterEntries) || !reflect.DeepEqual(before, after) {
					t.Fatal("Directory -> persisted ZIP -> Directory differs")
				}
			}
		})
	}
}

func TestZIPUnsafePreflightNeverBeginsOutputAndCRCFailureNeverPublishes(t *testing.T) {
	for _, name := range []string{"zip-traversal", "zip-duplicate", "late-working-crc", "object-crc"} {
		t.Run(name, func(t *testing.T) {
			var b []byte
			if name == "late-working-crc" || name == "object-crc" {
				b = writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Store, false)
				for _, r := range locateZIP(t, b) {
					if name == "late-working-crc" && r.name == "hello.txt" || name == "object-crc" && strings.HasPrefix(r.name, ".packtell/objects/sha256/") && !strings.HasSuffix(r.name, "/") {
						binary.LittleEndian.PutUint32(b[r.central+16:], 0)
						binary.LittleEndian.PutUint32(b[r.data+int(r.compressed)+4:], 0)
					}
				}
			} else {
				b, _ = zipFixture(t, name)
			}
			parent := t.TempDir()
			destination := filepath.Join(parent, "output")
			began := false
			host := &hookedDirectoryHost{host: nativeDirectoryHost(t, destination), hook: func(phase string, _ pkg.DirectoryTransaction) error {
				if phase == "begin" {
					began = true
				}
				return nil
			}}
			out, err := pkg.PublishDirectory(context.Background(), zipSource(t, b, pkg.DefaultLimits()), host, pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || out != (pkg.DirectoryPublication{}) {
				t.Fatal(out, err)
			}
			assertNoDirectoryOutput(t, parent, destination)
			if name == "late-working-crc" {
				if !began {
					t.Fatal("test did not exercise pending extraction")
				}
				requireCode(t, err, pkg.ReasonUnsafeArchive)
			} else if began {
				t.Fatal("unsafe ZIP started destination transaction")
			}
			if name == "object-crc" {
				requireCode(t, err, pkg.ReasonUnsafeArchive)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	parent := t.TempDir()
	destination := filepath.Join(parent, "output")
	b, _ := zipFixture(t, "zip-wrapped")
	out, err := pkg.PublishDirectory(ctx, zipSource(t, b, pkg.DefaultLimits()), nativeDirectoryHost(t, destination), pkg.DefaultLimits(), supportAllVocabulary())
	if !errors.Is(err, context.Canceled) || out != (pkg.DirectoryPublication{}) {
		t.Fatal(out, err)
	}
	assertNoDirectoryOutput(t, parent, destination)
}
