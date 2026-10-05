// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
)

// DirectoryHost authorizes one destination. BeginDirectory creates isolated
// pending output outside both destination and source. Existing destinations,
// including empty directories and links, must never be overwritten. Locks and
// recovery records belong outside the portable tree.
type DirectoryHost interface {
	BeginDirectory(context.Context) (DirectoryTransaction, error)
}

// DirectoryTransaction writes independent regular-file bytes. Seal durably
// closes writes and supplies an immutable observation of pending output.
// Publish atomically installs that exact tree without replacement, or uses
// Host isolation/recovery on platforms lacking that operation. Its nil result
// acknowledges durable publication. Abort removes only unpublished pending
// output; after a failed/uncertain Publish it must never remove a destination.
type DirectoryTransaction interface {
	PayloadWriter
	Seal(context.Context) (TreeSnapshot, error)
	Publish(context.Context) error
	Abort(context.Context) error
}

// ErrPublicationUncertain means publication may have occurred but its durable
// acknowledgement failed. Callers inspect/recover through their Host; they
// must not report success or automatically retry over an existing destination.
var ErrPublicationUncertain = errors.New("directory publication acknowledgement uncertain")
var ErrDirectoryPlatformUnsupported = errors.New("native safe directory operations unsupported on this platform")

type DirectoryPublication struct {
	PackageID PackageID
	HEAD      HEAD
	Entries   int
}

// PublishDirectory preserves every byte of one stable Package tree, including
// dirty Working Tree, unknown optional fields/extensions and empty folders.
// It validates committed history, all objects, portable memory and embedded
// presence before no-overwrite publication. Signature/evidence mathematics is
// independent: invalid attestations are retained, never silently removed.
// This operation does not claim a conformance level or emit a FULL verdict.
func PublishDirectory(ctx context.Context, source SnapshotSource, host DirectoryHost, l Limits, support CapabilitySupport) (out DirectoryPublication, err error) {
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if source == nil || host == nil {
		return out, schemaError("missing directory source/Host")
	}
	if err = checkNativeDirectorySeparation(source, host); err != nil {
		return out, err
	}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("missing directory snapshot")
	}
	defer func() {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		if err != nil {
			out = DirectoryPublication{}
		}
	}()
	h, err := validateDirectoryTree(ctx, snapshot, l, support)
	if err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	tx, err := host.BeginDirectory(ctx)
	if err != nil {
		if tx != nil {
			err = errors.Join(err, tx.Abort(context.WithoutCancel(ctx)))
		}
		return out, err
	}
	if tx == nil {
		return out, schemaError("missing directory transaction")
	}
	published := false
	defer func() {
		abortErr := tx.Abort(context.WithoutCancel(ctx))
		if published && abortErr != nil {
			abortErr = errors.Join(ErrPublicationUncertain, abortErr)
		}
		err = errors.Join(err, abortErr)
	}()
	digests := make(map[string][32]byte)
	// Preflight already sorted parents before children. HEAD is written last
	// even though all these writes remain invisible pending output.
	entries := slices.Clone(h.Root.Entries)
	slices.SortStableFunc(entries, func(a, b TreeEntry) int {
		if a.Path == b.Path {
			return 0
		}
		if a.Path == ".packtell/HEAD" {
			return 1
		}
		if b.Path == ".packtell/HEAD" {
			return -1
		}
		return 0
	})
	for _, e := range entries {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		if e.Kind == "directory" {
			if err = tx.Mkdir(ctx, e.Path); err != nil {
				return out, err
			}
			continue
		}
		digest, copyErr := copyDirectoryFile(ctx, snapshot, tx, e)
		if copyErr != nil {
			return out, copyErr
		}
		digests[e.Path] = digest
	}
	pending, err := tx.Seal(ctx)
	if err != nil {
		if pending != nil {
			err = errors.Join(err, pending.Close())
		}
		return out, err
	}
	if pending == nil {
		return out, schemaError("missing sealed directory observation")
	}
	err = checkDirectoryCopy(ctx, pending, h, digests, l, support)
	err = errors.Join(err, pending.Close())
	if err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	err = snapshot.Close()
	snapshot = nil
	if err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = tx.Publish(ctx); err != nil {
		return out, err
	}
	published = true
	if err = ctx.Err(); err != nil {
		return out, errors.Join(ErrPublicationUncertain, err)
	}
	return DirectoryPublication{h.Root.Package.PackageID, h.Root.HEAD, len(h.Root.Entries)}, nil
}

func validateDirectoryTree(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport) (History, error) {
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return History{}, err
	}
	content, err := verifyCommittedContent(ctx, source, h, l)
	if err != nil {
		return History{}, err
	}
	if len(content.Missing) != 0 {
		return History{}, protocolError(ReasonMissingObject, "directory requires all historical and extra object bytes")
	}
	if len(content.Invalid) != 0 {
		return History{}, protocolError(ReasonObjectHashMismatch, "directory object validation failed")
	}
	memory, err := readPortableMemory(ctx, source, h, l)
	if err != nil {
		return History{}, err
	}
	complete := containsText(h.Root.Format.Profiles, ProfileComplete)
	for _, v := range h.Versions {
		complete = complete || containsText(v.Version.Profiles, ProfileComplete)
	}
	if complete && len(memory.MissingPaths) != 0 {
		return History{}, protocolError(ReasonInvalidMetadata, "Complete directory requires portable memory files")
	}
	evidence, err := verifyEvidence(ctx, source, h, memory, l, support, nil)
	if err != nil {
		return History{}, err
	}
	if len(evidence.MissingEmbedded) != 0 {
		return History{}, protocolError(ReasonInvalidEvidence, "declared embedded evidence absent")
	}
	return h, nil
}

func copyDirectoryFile(ctx context.Context, source TreeReader, output PayloadWriter, e TreeEntry) (digest [32]byte, err error) {
	r, err := source.Open(ctx, e.Path)
	if err != nil {
		if r != nil {
			err = errors.Join(err, r.Close())
		}
		return digest, err
	}
	if r == nil {
		return digest, schemaError("missing directory input stream")
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	w, err := output.Create(ctx, e.Path)
	if err != nil {
		if w != nil {
			err = errors.Join(err, w.Close())
		}
		return digest, err
	}
	if w == nil {
		return digest, schemaError("missing pending directory writer")
	}
	defer func() { err = errors.Join(err, w.Close()) }()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hash), io.LimitReader(contextReader{ctx, r}, e.Size+1))
	if err != nil {
		return digest, err
	}
	if n != e.Size {
		return digest, ErrUnstableWorkingTree
	}
	copy(digest[:], hash.Sum(nil))
	return digest, ctx.Err()
}

func checkDirectoryCopy(ctx context.Context, pending TreeSnapshot, original History, digests map[string][32]byte, l Limits, support CapabilitySupport) error {
	h, err := validateDirectoryTree(ctx, pending, l, support)
	if err != nil {
		return err
	}
	if !slices.Equal(h.Root.Entries, original.Root.Entries) {
		return ErrUnstableWorkingTree
	}
	// Check raw bytes too: logical subject equality alone would lose dirty
	// payload, opaque extensions, JSON spelling or optional unsigned facts.
	for _, e := range h.Root.Entries {
		if e.Kind != "file" {
			continue
		}
		r, err := pending.Open(ctx, e.Path)
		if err != nil {
			if r != nil {
				err = errors.Join(err, r.Close())
			}
			return err
		}
		if r == nil {
			return schemaError("missing pending read-back stream")
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(contextReader{ctx, r}, e.Size+1))
		readErr = errors.Join(readErr, r.Close())
		if readErr != nil {
			return readErr
		}
		var digest [32]byte
		copy(digest[:], hash.Sum(nil))
		if n != e.Size || digest != digests[e.Path] {
			return ErrUnstableWorkingTree
		}
	}
	return pending.CheckStable(ctx)
}
