// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"slices"
	"strings"
)

type CommittedVersion struct {
	Version  Version
	Manifest Manifest
}

// History is ordered by actual parent lineage, oldest first, never inferred
// from UUID timestamps, filesystem order or ordinal sorting.
type History struct {
	Root     RootInspection
	Versions []CommittedVersion
	Contents []ContentObjectRef
}
type ContentObjectRef struct {
	ContentID ContentID `json:"content_id"`
	Size      int64     `json:"size"`
}

func (ref ContentObjectRef) ObjectPath() (string, error) {
	if err := ref.ContentID.Validate(); err != nil {
		return "", err
	}
	digest := string(ref.ContentID)[7:]
	return ".packtell/objects/sha256/" + digest[:2] + "/" + digest, nil
}

// ReadHistory validates every committed Version and the unique HEAD chain. It
// never uses Working Tree bytes, product indexes or a remote content resolver.
// Callers use a stable Host observation when coupling this to other operations.
func ReadHistory(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport) (History, error) {
	root, err := ReadRoot(ctx, source, l, support)
	if err != nil {
		return History{}, err
	}
	return readHistory(ctx, source, root, l, support)
}
func readHistory(ctx context.Context, source TreeReader, root RootInspection, l Limits, support CapabilitySupport) (History, error) {
	out := History{Root: root, Versions: []CommittedVersion{}, Contents: []ContentObjectRef{}}
	nodes := map[string]TreeEntry{}
	for _, e := range root.Entries {
		nodes[e.Path] = e
	}
	all := map[VersionID]CommittedVersion{}
	for _, e := range root.Entries {
		if e.Kind != "directory" || !strings.HasPrefix(e.Path, ".packtell/versions/") || strings.Count(e.Path, "/") != 2 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return History{}, err
		}
		id := VersionID(strings.TrimPrefix(e.Path, ".packtell/versions/"))
		b, err := readRootBytes(ctx, source, nodes, e.Path+"/version.json", l.MaxJSONBytes)
		if err != nil {
			return History{}, err
		}
		v, err := ReadVersion(ctx, bytes.NewReader(b), l, support)
		if err != nil {
			return History{}, err
		}
		b, err = readRootBytes(ctx, source, nodes, e.Path+"/manifest.json", l.MaxJSONBytes)
		if err != nil {
			return History{}, err
		}
		m, err := ReadManifest(ctx, bytes.NewReader(b), l)
		if err != nil {
			return History{}, err
		}
		if v.VersionID != id || m.VersionID != id || v.PackageID != root.Package.PackageID || m.PackageID != root.Package.PackageID {
			return History{}, schemaError("historical document/path/Package IDs disagree")
		}
		for _, capability := range v.RequiredCapabilities {
			if !slices.Contains(root.Format.RequiredCapabilities, capability) {
				return History{}, schemaError("current format omits historical required capability")
			}
		}
		if _, err = m.Paths(ctx, l); err != nil {
			return History{}, err
		}
		all[id] = CommittedVersion{v, m}
	}
	if root.HEAD == UnbornHEAD {
		if len(all) != 0 {
			return History{}, protocolError(ReasonNonLinearHistory, "unborn history is not empty")
		}
		return out, nil
	}
	id := VersionID(root.HEAD)
	seen := map[VersionID]bool{}
	reverse := []CommittedVersion{}
	for {
		if err := ctx.Err(); err != nil {
			return History{}, err
		}
		if seen[id] {
			return History{}, protocolError(ReasonNonLinearHistory, "committed parent cycle")
		}
		seen[id] = true
		record, ok := all[id]
		if !ok {
			return History{}, protocolError(ReasonMissingParent, "committed parent is absent")
		}
		reverse = append(reverse, record)
		parent := record.Version.ParentVersionID
		if parent == nil {
			if record.Version.Ordinal != 1 {
				return History{}, protocolError(ReasonNonLinearHistory, "root ordinal is not one")
			}
			break
		}
		prior, ok := all[*parent]
		if !ok {
			return History{}, protocolError(ReasonMissingParent, "committed parent is absent")
		}
		if prior.Version.Ordinal >= MaxProtocolInteger || record.Version.Ordinal != prior.Version.Ordinal+1 {
			return History{}, protocolError(ReasonNonLinearHistory, "ordinal does not continue parent")
		}
		id = *parent
	}
	if len(seen) != len(all) {
		return History{}, protocolError(ReasonNonLinearHistory, "HEAD chain leaves detached or multiple-root Versions")
	}
	inventory, err := NewIdentityInventory(root.Package.PackageID)
	if err != nil {
		return History{}, err
	}
	sizes := map[ContentID]int64{}
	for n := len(reverse) - 1; n >= 0; n-- {
		record := reverse[n]
		if err = inventory.Observe(ctx, record.Manifest, l); err != nil {
			return History{}, err
		}
		out.Versions = append(out.Versions, record)
		for _, e := range record.Manifest.Entries {
			if e.Kind != "file" {
				continue
			}
			if size, known := sizes[e.ContentID]; known && size != e.Size {
				return History{}, schemaError("historical ContentID has unequal sizes")
			}
			if _, known := sizes[e.ContentID]; !known && len(sizes) >= l.MaxEntries {
				return History{}, protocolError(ReasonResourceLimit, "historical distinct content count")
			}
			sizes[e.ContentID] = e.Size
		}
	}
	for id, size := range sizes {
		out.Contents = append(out.Contents, ContentObjectRef{id, size})
	}
	slices.SortFunc(out.Contents, func(a, b ContentObjectRef) int { return strings.Compare(string(a.ContentID), string(b.ContentID)) })
	return out, nil
}

// KnownIDs includes Package/Version/entry identities, including removed entries.
// Portable-memory and evidence identities must additionally be reserved by their
// respective later-stage operations; this is not a full Package ID inventory.
func (h History) KnownIDs() []UUID {
	ids := map[UUID]bool{UUID(h.Root.Package.PackageID): true}
	for _, v := range h.Versions {
		ids[UUID(v.Version.VersionID)] = true
		for _, e := range v.Manifest.Entries {
			ids[e.ID()] = true
		}
	}
	out := make([]UUID, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
