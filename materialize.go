// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"sort"
)

type MaterializationEntry struct {
	Path      string
	Kind      string
	ID        UUID
	ContentID ContentID
	Size      int64
}
type MaterializationPlan struct {
	PackageID PackageID
	VersionID VersionID
	Entries   []MaterializationEntry
}

// PayloadWriter receives only preflighted relative paths in caller-isolated
// pending output. It must not overwrite existing published data, follow links,
// use hardlinks as historical backing, or publish the output on its own.
// On any SDK error the caller discards this pending output. All operations,
// streams and closes must honor cancellation and durable Host error semantics.
type PayloadWriter interface {
	Mkdir(ctx context.Context, relativePath string) error
	Create(ctx context.Context, relativePath string) (io.WriteCloser, error)
}

func PlanMaterializeVersion(ctx context.Context, source TreeReader, id VersionID, l Limits, support CapabilitySupport) (MaterializationPlan, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return MaterializationPlan{}, err
	}
	return planMaterialize(ctx, h, id, l)
}
func planMaterialize(ctx context.Context, h History, id VersionID, l Limits) (MaterializationPlan, error) {
	if err := UUID(id).Validate(); err != nil {
		return MaterializationPlan{}, err
	}
	for _, record := range h.Versions {
		if record.Version.VersionID == id {
			paths, err := record.Manifest.Paths(ctx, l)
			if err != nil {
				return MaterializationPlan{}, err
			}
			plan := MaterializationPlan{PackageID: h.Root.Package.PackageID, VersionID: id, Entries: []MaterializationEntry{}}
			raw := []TreeEntry{}
			for _, e := range record.Manifest.Entries {
				kind := "file"
				if e.Kind == "folder" {
					kind = "directory"
				}
				path := paths[e.ID()]
				plan.Entries = append(plan.Entries, MaterializationEntry{path, kind, e.ID(), e.ContentID, e.Size})
				raw = append(raw, TreeEntry{Path: path, Kind: kind, Size: e.Size})
			}
			if _, err = PreflightTree(ctx, raw, l); err != nil {
				return MaterializationPlan{}, err
			}
			sort.Slice(plan.Entries, func(i, j int) bool { return plan.Entries[i].Path < plan.Entries[j].Path })
			return plan, nil
		}
	}
	return MaterializationPlan{}, protocolError(ReasonMissingParent, "requested historical Version is absent")
}

// MaterializeVersionPayload reconstructs one committed logical tree offline,
// including explicit empty folders, using only committed object paths. It does
// not publish a Package container, move HEAD, fetch content, sign or modify DBs.
func MaterializeVersionPayload(ctx context.Context, source TreeReader, id VersionID, pending PayloadWriter, l Limits, support CapabilitySupport) error {
	if pending == nil {
		return schemaError("missing pending payload writer")
	}
	plan, err := PlanMaterializeVersion(ctx, source, id, l, support)
	if err != nil {
		return err
	}
	for _, entry := range plan.Entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		if entry.Kind == "directory" {
			if err = pending.Mkdir(ctx, entry.Path); err != nil {
				return err
			}
			continue
		}
		ref := ContentObjectRef{entry.ContentID, entry.Size}
		path, err := ref.ObjectPath()
		if err != nil {
			return err
		}
		r, err := source.Open(ctx, path)
		if err != nil {
			if r != nil {
				_ = r.Close()
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, fs.ErrNotExist) {
				return protocolError(ReasonMissingObject, "historical object is unavailable")
			}
			return err
		}
		if r == nil {
			return protocolError(ReasonMissingObject, "historical object is unavailable")
		}
		w, err := pending.Create(ctx, entry.Path)
		if err != nil {
			_ = r.Close()
			return err
		}
		if w == nil {
			_ = r.Close()
			return schemaError("missing pending output stream")
		}
		copyErr := CopyVerifiedContent(ctx, w, r, entry.ContentID, entry.Size, l)
		readCloseErr := r.Close()
		writeCloseErr := w.Close()
		if copyErr != nil {
			return copyErr
		}
		if readCloseErr != nil {
			return readCloseErr
		}
		if writeCloseErr != nil {
			return writeCloseErr
		}
	}
	return ctx.Err()
}
