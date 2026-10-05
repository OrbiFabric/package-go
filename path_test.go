// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"context"
	pkg "github.com/orbifabric/package-go"
	"strings"
	"testing"
)

func TestPortablePathRulesAndCollisionOrder(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	for _, name := range []string{"CON", "con.txt", "PRN", "aux.log", "nul", "conin$.x", "CONOUT$", "COM1", "com9.bin", "LPT1", "lpt9.txt", "COM¹", "LPT².x", "com³.txt", "COM1 .txt", "trailing.", "trailing ", "a:b", "a?b", "a|b", "a*b", "a<b", "a>b", `a"b`, "a\x00b", "a\x1fb", "a\x7fb", strings.Repeat("😀", 128), "e\u0301"} {
		requireCode(t, pkg.ValidateComponent(name), pkg.ReasonInvalidPath)
	}
	for _, name := range []string{"é.txt", "COM0", "COM10", "LPT0", "folder", ".packtell", strings.Repeat("😀", 127) + "a", "CONsole.txt"} {
		if err := pkg.ValidateComponent(name); err != nil {
			t.Fatalf("valid %q: %v", name, err)
		}
	}
	for _, path := range []string{"../outside", "a/../b", "a/./b", "a//b", "/absolute", "C:/file", `C:\file`, `\\server\file`, `a\b`} {
		_, err := pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: path, Kind: "file"}}, l)
		requireCode(t, err, pkg.ReasonPathTraversal)
	}
	for _, kind := range []string{"symlink", "junction", "fifo", "socket", "device", "special"} {
		_, err := pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "node", Kind: kind}}, l)
		requireCode(t, err, pkg.ReasonInvalidPath)
	}
	for _, paths := range [][]string{{"A/a.txt", "a/b.txt"}, {"Straße", "STRASSE"}, {"Σ", "ς"}, {"K.txt", "k.txt"}, {"\U00010d50.txt", "\U00010d70.txt"}} {
		entries := []pkg.TreeEntry{}
		for _, p := range paths {
			entries = append(entries, pkg.TreeEntry{Path: p, Kind: "file"})
		}
		_, err := pkg.PreflightTree(ctx, entries, l)
		requireCode(t, err, pkg.ReasonCaseConflict)
	}
	_, err := pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "e\u0301.txt", Kind: "file"}, {Path: "é.txt", Kind: "file"}, {Path: "A", Kind: "file"}, {Path: "a", Kind: "file"}, {Path: "CON", Kind: "file"}}, l)
	requireCode(t, err, pkg.ReasonUnicodeNormalizationConflict)
	_, err = pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "A", Kind: "file"}, {Path: "a", Kind: "file"}, {Path: "CON", Kind: "file"}}, l)
	requireCode(t, err, pkg.ReasonCaseConflict)
	for _, p := range []string{".PACKTELL/file", ".PackTell"} {
		_, err := pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: p, Kind: "file"}}, l)
		requireCode(t, err, pkg.ReasonCaseConflict)
	}
	for _, entries := range [][]pkg.TreeEntry{{{Path: "a", Kind: "file"}, {Path: "a/b", Kind: "file"}}, {{Path: "a", Kind: "file"}, {Path: "a", Kind: "file"}}, {{Path: "a/", Kind: "directory"}, {Path: "a", Kind: "file"}}} {
		_, err := pkg.PreflightTree(ctx, entries, l)
		requireCode(t, err, pkg.ReasonInvalidPath)
	}
	nodes, err := pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "folder/.packtell/file", Kind: "file"}, {Path: "empty/", Kind: "directory"}}, l)
	if err != nil || len(nodes) != 4 {
		t.Fatalf("implicit/nested/empty dirs: %#v %v", nodes, err)
	}
	small := l
	small.MaxEntries = 1
	_, err = pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "a/b", Kind: "file"}}, small)
	requireCode(t, err, pkg.ReasonResourceLimit)
	small = l
	small.MaxTreeDepth = 1
	_, err = pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "a/b", Kind: "file"}}, small)
	requireCode(t, err, pkg.ReasonResourceLimit)
	small = l
	small.MaxPathBytes = 3
	_, err = pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "long", Kind: "file"}}, small)
	requireCode(t, err, pkg.ReasonResourceLimit)
	small = l
	small.MaxTotalBytes = 3
	_, err = pkg.PreflightTree(ctx, []pkg.TreeEntry{{Path: "a", Kind: "file", Size: 2}, {Path: "b", Kind: "file", Size: 2}}, small)
	requireCode(t, err, pkg.ReasonResourceLimit)
}
func TestManifestDerivedPathsAndSafety(t *testing.T) {
	m := manifest(t, "moved-file")
	paths, err := m.Paths(context.Background(), pkg.DefaultLimits())
	if err != nil || paths[pkg.UUID(fileID)] != "folder/hello.txt" || paths[pkg.UUID(folderID)] != "folder" {
		t.Fatalf("%v %v", paths, err)
	}
	m.Entries[0].Name = "CON.txt"
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidPath)
	m = manifest(t, "core-minimal")
	second := m.Entries[0]
	second.FileID = "019a0000-0000-7000-8000-000000000010"
	second.Name = "HELLO.TXT"
	m.Entries = append(m.Entries, second)
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonCaseConflict)
	m = manifest(t, "core-minimal")
	m.Entries[0].Name = ".packtell"
	requireCode(t, m.Validate(context.Background(), pkg.DefaultLimits()), pkg.ReasonInvalidPath)
}
func FuzzPortableTreePaths(f *testing.F) {
	for _, seed := range []string{"hello.txt", "../escape", "A/a", "Straße", "e\u0301", ".PACKTELL", "CON", "😀"} {
		f.Add(seed, seed)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		l := pkg.DefaultLimits()
		l.MaxPathBytes = 1024
		l.MaxTreeDepth = 32
		l.MaxEntries = 100
		entries := []pkg.TreeEntry{{Path: a, Kind: "file"}, {Path: b, Kind: "file"}}
		nodes, err := pkg.PreflightTree(context.Background(), entries, l)
		if err == nil {
			for _, e := range nodes {
				for _, name := range strings.Split(e.Path, "/") {
					if err := pkg.ValidateComponent(name); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	})
}
