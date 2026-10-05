// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strings"
)

// SnapshotSource isolates one explicitly designated Root. A Host may implement
// a read lock or detect concurrent changes, but must not silently provide mixed
// generation bytes. Filesystem metadata/inodes are Host stability hints only.
// They never enter portable identities or logical diff equality.
type SnapshotSource interface {
	BeginSnapshot(ctx context.Context) (TreeSnapshot, error)
}
type TreeSnapshot interface {
	TreeReader
	CheckStable(ctx context.Context) error
	Close() error
}

type WorkingEntry struct {
	Path      string
	Kind      string
	ID        UUID
	ContentID ContentID
	Size      int64
}
type ChangeType string

const (
	ChangeAdded   ChangeType = "ADDED"
	ChangeRemoved ChangeType = "REMOVED"
	ChangePath    ChangeType = "PATH_CHANGED"
	ChangeContent ChangeType = "CONTENT_CHANGED"
)

type Change struct {
	Type          ChangeType
	ID            UUID
	BeforePath    string
	AfterPath     string
	BeforeContent ContentID
	AfterContent  ContentID
}
type WorkingScan struct {
	Root    RootInspection
	State   WorkingState
	Entries []WorkingEntry
	Changes []Change
}

// Scan checks safe Root/control paths, reads stable raw payload bytes and diffs
// against HEAD inside Host observation isolation. tracking is explicit Host
// identity proof, keyed by current path; equal bytes never prove rename/copy.
// No new IDs or committed Versions are created; unknown additions retain no ID.
// Errors discard the entire proposed scan and yield UNREADABLE. Historical
// committed integrity/signature/history results are untouched by this operation.
func Scan(ctx context.Context, source SnapshotSource, l Limits, support CapabilitySupport, tracking map[string]UUID) (out WorkingScan, err error) {
	out.State = WorkingUnreadable
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if source == nil {
		return out, schemaError("missing snapshot source")
	}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("Host returned no snapshot")
	}
	defer func() {
		stableErr := snapshot.CheckStable(ctx)
		closeErr := snapshot.Close()
		if stableErr != nil {
			err = stableErr
		}
		if err == nil {
			err = closeErr
		}
		if err != nil {
			out.State = WorkingUnreadable
			out.Entries = nil
			out.Changes = nil
		}
	}()
	out.Root, err = ReadRoot(ctx, snapshot, l, support)
	if err != nil {
		return out, err
	}
	var total int64
	for _, e := range out.Root.Entries {
		if e.Path == ".packtell" || strings.HasPrefix(e.Path, ".packtell/") {
			continue
		}
		if err = ctx.Err(); err != nil {
			return out, err
		}
		entry := WorkingEntry{Path: e.Path, Kind: e.Kind, Size: e.Size}
		if e.Kind == "file" {
			if e.Size > l.MaxFileBytes || e.Size > l.MaxTotalBytes-total {
				return out, protocolError(ReasonResourceLimit, "Working Tree bytes exceed policy")
			}
			total += e.Size
			r, openErr := snapshot.Open(ctx, e.Path)
			if openErr != nil {
				return out, openErr
			}
			if r == nil {
				return out, schemaError("missing payload stream")
			}
			h := sha256.New()
			n, readErr := io.Copy(h, io.LimitReader(contextReader{ctx, r}, e.Size+1))
			closeErr := r.Close()
			if readErr != nil {
				return out, readErr
			}
			if closeErr != nil {
				return out, closeErr
			}
			if n != e.Size {
				return out, ErrUnstableWorkingTree
			}
			entry.ContentID = ContentID("sha256:" + hex.EncodeToString(h.Sum(nil)))
		}
		out.Entries = append(out.Entries, entry)
	}
	if err = assignContinuity(ctx, out.Root.HeadManifest, out.Entries, tracking, l); err != nil {
		return out, err
	}
	out.Changes, err = diff(ctx, out.Root.HeadManifest, out.Entries, l)
	if err != nil {
		return out, err
	}
	if out.Root.HEAD == UnbornHEAD {
		out.State = WorkingUnborn
	} else if len(out.Changes) == 0 {
		out.State = WorkingClean
	} else {
		out.State = WorkingDirty
	}
	return out, nil
}

func assignContinuity(ctx context.Context, head *Manifest, current []WorkingEntry, tracking map[string]UUID, l Limits) error {
	prior := map[string]Entry{}
	kinds := map[UUID]string{}
	if head != nil {
		paths, err := head.Paths(ctx, l)
		if err != nil {
			return err
		}
		for _, e := range head.Entries {
			prior[paths[e.ID()]] = e
			kinds[e.ID()] = e.Kind
		}
	}
	seenIDs := map[UUID]bool{}
	seenPaths := map[string]bool{}
	for i, e := range current {
		seenPaths[e.Path] = true
		id, tracked := tracking[e.Path]
		if tracked {
			if err := id.Validate(); err != nil {
				return err
			}
			if kind, known := kinds[id]; known && kind != logicalKind(e.Kind) {
				return schemaError("Host identity proof changes historical entry kind")
			}
		} else if old, ok := prior[e.Path]; ok && old.Kind == logicalKind(e.Kind) {
			id = old.ID()
		}
		if id != "" {
			if seenIDs[id] {
				return schemaError("ambiguous duplicate Host identity proof")
			}
			seenIDs[id] = true
		}
		current[i].ID = id
	}
	for p := range tracking {
		if !seenPaths[p] {
			return schemaError("Host identity proof references absent payload path")
		}
	}
	return nil
}

// Diff reports ID-matched path and content differences independently. Working
// entries with no identity continuity are additions; unmatched HEAD IDs are
// removals, even when their bytes are equal. Current IDs do not commit history.
func Diff(ctx context.Context, head Manifest, current []WorkingEntry, l Limits) ([]Change, error) {
	return diff(ctx, &head, current, l)
}
func diff(ctx context.Context, head *Manifest, current []WorkingEntry, l Limits) ([]Change, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(current) > l.MaxEntries {
		return nil, protocolError(ReasonResourceLimit, "working entry limit")
	}
	raw := make([]TreeEntry, 0, len(current))
	seenID := map[UUID]bool{}
	sizes := map[ContentID]int64{}
	for _, e := range current {
		raw = append(raw, TreeEntry{Path: e.Path, Kind: e.Kind, Size: e.Size})
		if e.ID != "" {
			if err := e.ID.Validate(); err != nil {
				return nil, err
			}
			if seenID[e.ID] {
				return nil, schemaError("duplicate working entity identity")
			}
			seenID[e.ID] = true
		}
		if e.Kind == "file" {
			if err := e.ContentID.Validate(); err != nil {
				return nil, err
			}
			if size, ok := sizes[e.ContentID]; ok && size != e.Size {
				return nil, schemaError("working ContentID has unequal sizes")
			}
			sizes[e.ContentID] = e.Size
		} else if e.ContentID != "" {
			return nil, schemaError("working folder carries content identity")
		}
	}
	nodes, err := PreflightTree(ctx, raw, l)
	if err != nil {
		return nil, err
	}
	if len(nodes) != len(current) {
		return nil, schemaError("working snapshot omits parent directories")
	}
	before := map[UUID]Entry{}
	paths := map[UUID]string{}
	if head != nil {
		var err error
		paths, err = head.Paths(ctx, l)
		if err != nil {
			return nil, err
		}
		for _, e := range head.Entries {
			before[e.ID()] = e
		}
	}
	changes := []Change{}
	matched := map[UUID]bool{}
	for _, e := range current {
		if e.Path == ".packtell" || strings.HasPrefix(e.Path, ".packtell/") {
			return nil, protocolError(ReasonInvalidPath, "control data is not Working Tree payload")
		}
		old, known := before[e.ID]
		if !known || e.ID == "" {
			changes = append(changes, Change{Type: ChangeAdded, ID: e.ID, AfterPath: e.Path, AfterContent: e.ContentID})
			continue
		}
		if old.Kind != logicalKind(e.Kind) {
			return nil, schemaError("working identity changed kind")
		}
		matched[e.ID] = true
		if paths[e.ID] != e.Path {
			changes = append(changes, Change{Type: ChangePath, ID: e.ID, BeforePath: paths[e.ID], AfterPath: e.Path})
		}
		if e.Kind == "file" && (old.ContentID != e.ContentID || old.Size != e.Size) {
			changes = append(changes, Change{Type: ChangeContent, ID: e.ID, BeforePath: paths[e.ID], AfterPath: e.Path, BeforeContent: old.ContentID, AfterContent: e.ContentID})
		}
	}
	for id, e := range before {
		if !matched[id] {
			changes = append(changes, Change{Type: ChangeRemoved, ID: id, BeforePath: paths[id], BeforeContent: e.ContentID})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.BeforePath != b.BeforePath {
			return a.BeforePath < b.BeforePath
		}
		return a.AfterPath < b.AfterPath
	})
	return changes, nil
}

func logicalKind(kind string) string {
	if kind == "directory" {
		return "folder"
	}
	return kind
}
