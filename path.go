// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/orbifabric/package-go/internal/unicode16"
)

// PathCollisionKey implements the exact Unicode16 NFC(full-fold(NFC(name)))
// rule. It is never a replacement name or a portable entity identity.
func PathCollisionKey(name string) string { return unicode16.CollisionKey(name) }
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func ValidateComponent(name string) error {
	if !utf8.ValidString(name) || name == "" {
		return protocolError(ReasonInvalidPath, "invalid UTF-8 or empty component")
	}
	if name == "." || name == ".." {
		return protocolError(ReasonPathTraversal, "relative path traversal component")
	}
	if strings.ContainsAny(name, `/\<>:"|?*`) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return protocolError(ReasonInvalidPath, "nonportable component")
	}
	units := 0
	for _, r := range name {
		if r < 32 || r == 127 {
			return protocolError(ReasonInvalidPath, "path control character")
		}
		units++
		if r > 0xffff {
			units++
		}
	}
	if units > 255 {
		return protocolError(ReasonInvalidPath, "component exceeds UTF-16 limit")
	}
	if unicode16.NFC(name) != name {
		return protocolError(ReasonInvalidPath, "authority component is not Unicode16 NFC")
	}
	base := asciiLower(strings.TrimRight(strings.SplitN(name, ".", 2)[0], " "))
	if base == "con" || base == "prn" || base == "aux" || base == "nul" || base == "conin$" || base == "conout$" {
		return protocolError(ReasonInvalidPath, "Windows reserved basename")
	}
	for _, prefix := range []string{"com", "lpt"} {
		if strings.HasPrefix(base, prefix) {
			n := strings.TrimPrefix(base, prefix)
			if len([]rune(n)) == 1 && strings.ContainsRune("123456789¹²³", []rune(n)[0]) {
				return protocolError(ReasonInvalidPath, "Windows reserved device basename")
			}
		}
	}
	return nil
}

// PreflightTree checks the entire input (including implicit parents) without
// opening any stream. Returned paths have no trailing slash and are sorted.
// NFC collisions precede full-fold collisions and individual name rejection.
func PreflightTree(ctx context.Context, entries []TreeEntry, l Limits) ([]TreeEntry, error) {
	return preflightTree(ctx, entries, l, true)
}

// Archive wrappers are outside Package Root. Their display names do not own
// the reserved control namespace; the stripped logical Root still does.
func preflightTree(ctx context.Context, entries []TreeEntry, l Limits, reserveRootControl bool) ([]TreeEntry, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(entries) > l.MaxEntries {
		return nil, protocolError(ReasonResourceLimit, "tree entry limit")
	}
	nodes := map[string]TreeEntry{}
	explicit := map[string]bool{}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(e.Path) > l.MaxPathBytes {
			return nil, protocolError(ReasonResourceLimit, "path byte limit")
		}
		p := e.Path
		if strings.HasPrefix(p, "/") {
			return nil, protocolError(ReasonPathTraversal, "absolute tree path")
		}
		if e.Kind == "directory" {
			p = strings.TrimSuffix(p, "/")
		} else if e.Kind != "file" {
			return nil, protocolError(ReasonInvalidPath, "tree contains a link/junction/special file")
		}
		if !utf8.ValidString(p) || p == "" {
			return nil, protocolError(ReasonInvalidPath, "invalid tree path")
		}
		if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
			return nil, protocolError(ReasonPathTraversal, "absolute/UNC/backslash path")
		}
		if len(p) >= 2 && p[1] == ':' {
			return nil, protocolError(ReasonPathTraversal, "drive path")
		}
		parts := strings.Split(p, "/")
		if len(parts) > l.MaxTreeDepth {
			return nil, protocolError(ReasonResourceLimit, "tree depth limit")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return nil, protocolError(ReasonPathTraversal, "empty/traversal path component")
			}
		}
		if explicit[p] {
			return nil, protocolError(ReasonInvalidPath, "duplicate tree path")
		}
		explicit[p] = true
		if old, ok := nodes[p]; ok && old.Kind != e.Kind {
			return nil, protocolError(ReasonInvalidPath, "file/directory path conflict")
		}
		e.Path = p
		nodes[p] = e
		if len(nodes) > l.MaxEntries {
			return nil, protocolError(ReasonResourceLimit, "implicit parent entry limit")
		}
		parent := p
		for strings.Contains(parent, "/") {
			parent = parent[:strings.LastIndexByte(parent, '/')]
			if old, ok := nodes[parent]; ok {
				if old.Kind != "directory" {
					return nil, protocolError(ReasonInvalidPath, "file used as a parent")
				}
			} else {
				nodes[parent] = TreeEntry{Path: parent, Kind: "directory"}
			}
			if len(nodes) > l.MaxEntries {
				return nil, protocolError(ReasonResourceLimit, "implicit parent entry limit")
			}
		}
	}
	paths := sortedTreePaths(nodes)
	nfc := map[string]string{}
	for _, p := range paths {
		key := unicode16.NFC(p)
		if prior, ok := nfc[key]; ok && prior != p {
			return nil, protocolError(ReasonUnicodeNormalizationConflict, "tree NFC collision")
		}
		nfc[key] = p
	}
	folded := map[string]string{}
	for _, p := range paths {
		key := PathCollisionKey(p)
		if prior, ok := folded[key]; ok && prior != p {
			return nil, protocolError(ReasonCaseConflict, "tree full-fold collision")
		}
		folded[key] = p
	}
	out := make([]TreeEntry, 0, len(nodes))
	var total int64
	for _, p := range paths {
		parts := strings.Split(p, "/")
		for _, part := range parts {
			if err := ValidateComponent(part); err != nil {
				return nil, err
			}
		}
		if reserveRootControl && parts[0] != ".packtell" && PathCollisionKey(parts[0]) == ".packtell" {
			return nil, protocolError(ReasonCaseConflict, "reserved Root control alias")
		}
		e := nodes[p]
		if e.Kind == "file" {
			if e.Size < 0 || e.Size > MaxProtocolInteger {
				return nil, schemaError("invalid tree file size")
			}
			if e.Size > l.MaxFileBytes || e.Size > l.MaxTotalBytes-total {
				return nil, protocolError(ReasonResourceLimit, "tree byte budget")
			}
			total += e.Size
		} else if e.Size != 0 {
			return nil, schemaError("directory carries file size")
		}
		out = append(out, e)
	}
	return out, nil
}
