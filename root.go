// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"errors"
	"strings"
)

// ErrUnstableWorkingTree is a Host observation failure, not historical content
// corruption. An unstable scan yields UNREADABLE and never a valid proposal.
var ErrUnstableWorkingTree = errors.New("working tree changed during stable scan")

type RootInspection struct {
	Recognition  Recognition
	Format       Format
	Package      Package
	HEAD         HEAD
	Entries      []TreeEntry
	HeadVersion  *Version
	HeadManifest *Manifest
}

// ReadRoot inspects only the caller-designated Root. No recursive discovery,
// alternate layout, filesystem ancestor search, DB or network is consulted.
// It checks control topology and HEAD model; linear history/object/Complete/
// signature verification remain separate operations. Use a Host snapshot to
// bind this inspection and a Working Tree scan to one stable observation.
func ReadRoot(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport) (RootInspection, error) {
	out := RootInspection{}
	if err := l.Validate(); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if source == nil {
		return out, schemaError("missing Root reader")
	}
	raw, err := source.List(ctx, l.MaxEntries)
	if err != nil {
		return out, err
	}
	entries, preflightErr := PreflightTree(ctx, raw, l)
	// Compute safety first. Only the exact known-safe control marker may be read
	// to label recognition; no unsafe or payload path is ever opened on failure.
	marker := false
	safeControl := true
	for _, e := range raw {
		p := strings.TrimSuffix(e.Path, "/")
		if p == ".packtell" && e.Kind != "directory" {
			safeControl = false
		}
		if e.Path == ".packtell/format.json" && e.Kind == "file" {
			marker = true
		}
	}
	if preflightErr != nil {
		if marker && safeControl {
			if r, e := source.Open(ctx, ".packtell/format.json"); e == nil && r != nil {
				_, out.Recognition, _ = ReadFormat(ctx, r, l, support)
				_ = r.Close()
			}
		}
		return out, preflightErr
	}
	out.Entries = entries
	nodes := map[string]TreeEntry{}
	for _, e := range entries {
		nodes[e.Path] = e
	}
	if err = validateControlJSONBudget(entries, l); err != nil {
		return out, err
	}
	e, present := nodes[".packtell/format.json"]
	if !present || e.Kind != "file" {
		out.Recognition = NotPackage
		return out, protocolError(ReasonNotPackage, "Root discriminator is absent")
	}
	b, err := readRootBytes(ctx, source, nodes, ".packtell/format.json", l.MaxJSONBytes)
	if err != nil {
		return out, err
	}
	out.Format, out.Recognition, err = ReadFormat(ctx, bytes.NewReader(b), l, support)
	if err != nil {
		return out, err
	}
	if err = validateControlTree(nodes, out.Format); err != nil {
		return out, err
	}
	b, err = readRootBytes(ctx, source, nodes, ".packtell/package.json", l.MaxJSONBytes)
	if err != nil {
		return out, err
	}
	out.Package, err = ReadPackage(ctx, bytes.NewReader(b), l)
	if err != nil {
		return out, err
	}
	// HEAD parsing itself uses its exact 37-byte maximum and INVALID_HEAD reason.
	r, err := source.Open(ctx, ".packtell/HEAD")
	if err != nil {
		return out, err
	}
	if r == nil {
		return out, schemaError("missing HEAD stream")
	}
	out.HEAD, err = ReadHEAD(ctx, r)
	closeErr := r.Close()
	if err != nil {
		return out, err
	}
	if closeErr != nil {
		return out, closeErr
	}
	versions := 0
	for _, e := range entries {
		if e.Kind == "directory" && strings.HasPrefix(e.Path, ".packtell/versions/") && strings.Count(e.Path, "/") == 2 {
			versions++
		}
	}
	if out.HEAD == UnbornHEAD {
		if versions != 0 {
			return out, protocolError(ReasonNonLinearHistory, "unborn HEAD has committed Versions")
		}
		return out, nil
	}
	dir := ".packtell/versions/" + string(out.HEAD)
	if _, ok := nodes[dir]; !ok {
		return out, protocolError(ReasonMissingParent, "HEAD Version is absent")
	}
	b, err = readRootBytes(ctx, source, nodes, dir+"/version.json", l.MaxJSONBytes)
	if err != nil {
		return out, err
	}
	v, err := ReadVersion(ctx, bytes.NewReader(b), l, support)
	if err != nil {
		return out, err
	}
	b, err = readRootBytes(ctx, source, nodes, dir+"/manifest.json", l.MaxJSONBytes)
	if err != nil {
		return out, err
	}
	m, err := ReadManifest(ctx, bytes.NewReader(b), l)
	if err != nil {
		return out, err
	}
	if v.PackageID != out.Package.PackageID || m.PackageID != out.Package.PackageID || v.VersionID != VersionID(out.HEAD) || m.VersionID != VersionID(out.HEAD) {
		return out, schemaError("HEAD document/path/Package IDs disagree")
	}
	if _, err = m.Paths(ctx, l); err != nil {
		return out, err
	}
	out.HeadVersion = &v
	out.HeadManifest = &m
	return out, nil
}

func readRootBytes(ctx context.Context, source TreeReader, nodes map[string]TreeEntry, path string, max int64) ([]byte, error) {
	e, ok := nodes[path]
	if !ok || e.Kind != "file" {
		return nil, schemaError("missing control file")
	}
	if e.Size > max {
		return nil, protocolError(ReasonResourceLimit, "control file exceeds input policy")
	}
	r, err := source.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, schemaError("missing control stream")
	}
	b, readErr := ReadBounded(ctx, r, max)
	closeErr := r.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(b)) != e.Size {
		return nil, ErrUnstableWorkingTree
	}
	return b, nil
}

func validateControlTree(nodes map[string]TreeEntry, f Format) error {
	for _, p := range []string{".packtell/format.json", ".packtell/package.json", ".packtell/HEAD"} {
		e, ok := nodes[p]
		if !ok || e.Kind != "file" {
			return schemaError("missing Core control file")
		}
	}
	for _, p := range []string{".packtell", ".packtell/versions", ".packtell/objects/sha256"} {
		e, ok := nodes[p]
		if !ok || e.Kind != "directory" {
			return schemaError("missing Core control directory")
		}
	}
	declared := map[string]bool{}
	for _, d := range f.Extensions {
		declared[d.Namespace] = true
		if e, ok := nodes[".packtell/extensions/"+d.Namespace]; !ok || e.Kind != "directory" {
			return schemaError("declared extension namespace is absent")
		}
	}
	for p, e := range nodes {
		if p != ".packtell" && !strings.HasPrefix(p, ".packtell/") {
			continue
		}
		if !allowedControl(p, e.Kind, declared) {
			return schemaError("unknown or invalid control path")
		}
		if e.Kind == "directory" && strings.HasPrefix(p, ".packtell/versions/") && strings.Count(p, "/") == 2 {
			for _, file := range []string{"version.json", "manifest.json"} {
				if item, ok := nodes[p+"/"+file]; !ok || item.Kind != "file" {
					return schemaError("Version directory is incomplete")
				}
			}
		}
	}
	return nil
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validUUID(s string) bool { return UUID(s).Validate() == nil }
func allowedControl(p, kind string, declared map[string]bool) bool {
	dirs := map[string]bool{".packtell": true, ".packtell/versions": true, ".packtell/objects": true, ".packtell/objects/sha256": true, ".packtell/metadata": true, ".packtell/history": true, ".packtell/verification": true, ".packtell/verification/versions": true, ".packtell/evidence": true, ".packtell/evidence/deliveries": true, ".packtell/evidence/objects": true, ".packtell/extensions": true}
	files := map[string]bool{".packtell/format.json": true, ".packtell/package.json": true, ".packtell/HEAD": true, ".packtell/metadata/package.json": true, ".packtell/metadata/notes.json": true, ".packtell/metadata/tags.json": true, ".packtell/metadata/provenance.json": true, ".packtell/history/events.ndjson": true}
	if dirs[p] {
		return kind == "directory"
	}
	if files[p] {
		return kind == "file"
	}
	parts := strings.Split(p, "/")
	if len(parts) >= 3 && parts[1] == "extensions" {
		if !declared[parts[2]] {
			return false
		}
		return len(parts) > 3 || kind == "directory"
	}
	if len(parts) >= 3 && parts[1] == "versions" && validUUID(parts[2]) {
		return len(parts) == 3 && kind == "directory" || len(parts) == 4 && kind == "file" && (parts[3] == "version.json" || parts[3] == "manifest.json")
	}
	if len(parts) >= 4 && parts[1] == "objects" && parts[2] == "sha256" {
		prefix := parts[3]
		if len(prefix) != 2 || !validDigest(prefix+strings.Repeat("0", 62)) {
			return false
		}
		return len(parts) == 4 && kind == "directory" || len(parts) == 5 && kind == "file" && validDigest(parts[4]) && strings.HasPrefix(parts[4], prefix)
	}
	if len(parts) >= 4 && parts[1] == "verification" && parts[2] == "versions" && validUUID(parts[3]) {
		return len(parts) == 4 && kind == "directory" || len(parts) == 5 && kind == "file" && strings.HasSuffix(parts[4], ".json") && validUUID(strings.TrimSuffix(parts[4], ".json"))
	}
	if len(parts) >= 4 && parts[1] == "evidence" && parts[2] == "deliveries" && validUUID(parts[3]) {
		return len(parts) == 4 && kind == "directory" || len(parts) == 5 && kind == "file" && parts[4] == "delivery.json"
	}
	if len(parts) == 4 && parts[1] == "evidence" && parts[2] == "objects" && kind == "file" {
		return strings.HasSuffix(parts[3], ".json") && validUUID(strings.TrimSuffix(parts[3], ".json"))
	}
	return false
}

func validateControlJSONBudget(entries []TreeEntry, l Limits) error {
	var total int64
	for _, entry := range entries {
		if entry.Kind == "file" && (controlJSONPath(entry.Path) || entry.Path == ".packtell/history/events.ndjson") {
			if entry.Size > l.MaxTotalJSONBytes-total {
				return protocolError(ReasonResourceLimit, "aggregate control JSON byte budget")
			}
			total += entry.Size
		}
	}
	return nil
}

func controlJSONPath(path string) bool {
	return strings.HasPrefix(path, ".packtell/") && strings.HasSuffix(path, ".json") && !strings.HasPrefix(path, ".packtell/extensions/")
}
