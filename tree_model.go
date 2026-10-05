// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"
)

func copyParent(parent *FolderID) *FolderID {
	if parent == nil {
		return nil
	}
	id := *parent
	return &id
}
func NewFileEntry(ctx context.Context, g *IDGenerator, at time.Time, parent *FolderID, name string, content ContentID, size int64) (Entry, error) {
	id, err := g.Generate(ctx, at)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Kind: "file", FileID: FileID(id), ParentFolderID: copyParent(parent), Name: name, ContentID: content, Size: size}
	return e, e.Validate()
}
func NewFolderEntry(ctx context.Context, g *IDGenerator, at time.Time, parent *FolderID, name string) (Entry, error) {
	id, err := g.Generate(ctx, at)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Kind: "folder", FolderID: FolderID(id), ParentFolderID: copyParent(parent), Name: name}
	return e, e.Validate()
}

// SortEntries establishes the single UUID-text order across both entry kinds.
func SortEntries(entries []Entry) {
	slices.SortFunc(entries, func(a, b Entry) int {
		if a.ID() < b.ID() {
			return -1
		}
		if a.ID() > b.ID() {
			return 1
		}
		return 0
	})
}

// clone creates independent proposal data, including unknown optional JSON.
// These operations perform no writes and do not mutate a committed manifest.
// A proposal retains source VersionID solely as a reference; publication must
// assign a new VersionID and preserve history through the Version commit API.
func (m Manifest) clone(ctx context.Context, l Limits) (Manifest, error) {
	if err := m.Validate(ctx, l); err != nil {
		return Manifest{}, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, err
	}
	return ReadManifest(ctx, bytes.NewReader(b), l)
}
func (m Manifest) WithPlacement(ctx context.Context, id UUID, parent *FolderID, name string, l Limits) (Manifest, error) {
	out, err := m.clone(ctx, l)
	if err != nil {
		return Manifest{}, err
	}
	found := false
	for i := range out.Entries {
		if out.Entries[i].ID() == id {
			out.Entries[i].ParentFolderID = copyParent(parent)
			out.Entries[i].Name = name
			found = true
			break
		}
	}
	if !found {
		return Manifest{}, schemaError("placement target is absent")
	}
	if err = out.Validate(ctx, l); err != nil {
		return Manifest{}, err
	}
	return out, nil
}
func (m Manifest) WithContent(ctx context.Context, id FileID, content ContentID, size int64, l Limits) (Manifest, error) {
	out, err := m.clone(ctx, l)
	if err != nil {
		return Manifest{}, err
	}
	found := false
	for i := range out.Entries {
		if out.Entries[i].Kind == "file" && out.Entries[i].FileID == id {
			out.Entries[i].ContentID = content
			out.Entries[i].Size = size
			found = true
			break
		}
	}
	if !found {
		return Manifest{}, schemaError("content target is absent")
	}
	if err = out.Validate(ctx, l); err != nil {
		return Manifest{}, err
	}
	return out, nil
}

// CopyFile allocates a new FileID while retaining the whole-file ContentID.
// The generator must also be seeded with removed historical IDs by the Host.
func (m Manifest) CopyFile(ctx context.Context, g *IDGenerator, at time.Time, id FileID, parent *FolderID, name string, l Limits) (Manifest, error) {
	out, err := m.clone(ctx, l)
	if err != nil {
		return Manifest{}, err
	}
	used := []UUID{UUID(m.PackageID), UUID(m.VersionID)}
	for _, e := range m.Entries {
		used = append(used, e.ID())
	}
	if err = g.Reserve(used...); err != nil {
		return Manifest{}, err
	}
	for _, e := range out.Entries {
		if e.Kind == "file" && e.FileID == id {
			newID, err := g.Generate(ctx, at)
			if err != nil {
				return Manifest{}, err
			}
			e.FileID = FileID(newID)
			e.ParentFolderID = copyParent(parent)
			e.Name = name
			out.Entries = append(out.Entries, e)
			SortEntries(out.Entries)
			if err = out.Validate(ctx, l); err != nil {
				return Manifest{}, err
			}
			return out, nil
		}
	}
	return Manifest{}, schemaError("copy source is absent")
}

// IdentityInventory enforces cross-Version entry-kind continuity. It retains
// removed identities; it is a validation aid, never Version/history authority.
// Use one instance per Package while validating its committed manifest chain.
// Hosts serialize access; no concurrent observation is implied.
type IdentityInventory struct {
	packageID PackageID
	kinds     map[UUID]string
}

func NewIdentityInventory(packageID PackageID) (*IdentityInventory, error) {
	if err := UUID(packageID).Validate(); err != nil {
		return nil, err
	}
	return &IdentityInventory{packageID: packageID, kinds: map[UUID]string{}}, nil
}
func (i *IdentityInventory) Observe(ctx context.Context, m Manifest, l Limits) error {
	if err := m.Validate(ctx, l); err != nil {
		return err
	}
	if m.PackageID != i.packageID {
		return schemaError("cross-Package manifest")
	}
	for _, e := range m.Entries {
		if kind, ok := i.kinds[e.ID()]; ok && kind != e.Kind {
			return schemaError("historical entity ID changed kind")
		}
	}
	for _, e := range m.Entries {
		i.kinds[e.ID()] = e.Kind
	}
	return nil
}
