// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
)

// ArtifactHost authorizes a single no-overwrite destination. Pending artifacts
// and recovery records stay outside portable/source/final output trees.
type ArtifactHost interface {
	BeginArtifact(context.Context) (ArtifactTransaction, error)
}

// ArtifactTransaction owns a context-aware pending writer. Close durably ends
// writes; Seal returns an immutable read-back. Publish acknowledges durable
// no-overwrite installation. Abort removes only unpublished pending bytes.
type ArtifactTransaction interface {
	io.WriteCloser
	Seal(context.Context) (ArchiveSnapshot, error)
	Publish(context.Context) error
	Abort(context.Context) error
}

// ExecuteTransferZIP hydrates into an external temporary Directory transaction,
// writes a single-wrapper artifact, validates its actual hash and decoded raw
// tree/Complete proof, then publishes through ArtifactHost. The temporary tree
// is never published and is removed before final publication. No source change,
// permanent content cache, implicit Resolver or credential client is involved.
func ExecuteTransferZIP(ctx context.Context, plan TransferPlan, staging DirectoryHost, host ArtifactHost, resolver ContentResolver, options ZIPOptions) (out TransferResult, err error) {
	p := plan.state
	if p == nil || staging == nil || host == nil {
		return out, schemaError("ZIP transfer requires plan/staging/artifact Hosts")
	}
	if err = validateZIPOptions(options); err != nil {
		return out, err
	}
	wrapped := make([]TreeEntry, 0, len(p.summary.Entries)+1)
	wrapped = append(wrapped, TreeEntry{Path: options.DisplayDirectory, Kind: "directory"})
	for _, e := range p.summary.Entries {
		e.Path = options.DisplayDirectory + "/" + e.Path
		wrapped = append(wrapped, e)
	}
	if _, err = preflightTree(ctx, wrapped, p.l, false); err != nil {
		return out, err
	}
	if err = checkNativeDirectorySeparation(p.source, staging); err != nil {
		return out, err
	}
	if err = checkNativeArtifactSeparation(p.source, host); err != nil {
		return out, err
	}
	source, h, err := reopenTransfer(ctx, p)
	if err != nil {
		return out, err
	}
	defer func() {
		if source != nil {
			err = errors.Join(err, source.Close())
		}
		if err != nil {
			out = TransferResult{}
		}
	}()
	stage, err := stageTransfer(ctx, p, source, h, staging, resolver)
	if err != nil {
		return out, err
	}
	defer func() {
		if stage.snapshot != nil {
			err = errors.Join(err, stage.snapshot.Close())
		}
		if stage.tx != nil {
			err = errors.Join(err, stage.tx.Abort(context.WithoutCancel(ctx)))
		}
	}()
	tx, err := host.BeginArtifact(ctx)
	if err != nil {
		if tx != nil {
			err = errors.Join(err, tx.Abort(context.WithoutCancel(ctx)))
		}
		return out, err
	}
	if tx == nil {
		return out, schemaError("missing artifact transaction")
	}
	published := false
	writerClosed := false
	defer func() {
		if !writerClosed {
			err = errors.Join(err, tx.Close())
		}
		cleanup := tx.Abort(context.WithoutCancel(ctx))
		if published && cleanup != nil {
			cleanup = errors.Join(ErrPublicationUncertain, cleanup)
		}
		err = errors.Join(err, cleanup)
	}()
	written, err := WriteZIP(ctx, borrowedTransferTree{stage.snapshot}, tx, options, p.l, p.support)
	closeErr := tx.Close()
	writerClosed = true
	err = errors.Join(err, closeErr)
	if err != nil {
		return out, err
	}
	archive, err := tx.Seal(ctx)
	if err != nil {
		if archive != nil {
			err = errors.Join(err, archive.Close())
		}
		return out, err
	}
	if archive == nil {
		return out, schemaError("missing sealed ZIP artifact")
	}
	proof, err := verifyTransferArtifact(ctx, archive, written, p, stage.snapshot)
	err = errors.Join(err, archive.Close())
	if err != nil {
		return out, err
	}
	if err = stage.snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	err = stage.snapshot.Close()
	stage.snapshot = nil
	if err != nil {
		return out, err
	}
	err = stage.tx.Abort(context.WithoutCancel(ctx))
	stage.tx = nil
	if err != nil {
		return out, err
	}
	if err = source.CheckStable(ctx); err != nil {
		return out, err
	}
	err = source.Close()
	source = nil
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
	return TransferResult{PackageID: p.summary.PackageID, HEAD: p.summary.HEAD, Input: cloneTransferProof(p.summary.Input), Output: cloneTransferProof(proof), Hydrated: slices.Clone(stage.hydrated), ArtifactDigest: written.ArtifactDigest, ArtifactBytes: written.Bytes}, nil
}

type borrowedTransferTree struct{ TreeSnapshot }

func (s borrowedTransferTree) BeginSnapshot(context.Context) (TreeSnapshot, error) {
	return borrowedTransferSnapshot{s.TreeSnapshot}, nil
}

type borrowedTransferSnapshot struct{ TreeSnapshot }

func (borrowedTransferSnapshot) Close() error { return nil }

type borrowedTransferArchive struct{ ArchiveSnapshot }

func (s borrowedTransferArchive) BeginArchive(context.Context) (ArchiveSnapshot, error) {
	return s, nil
}
func (borrowedTransferArchive) Close() error { return nil }

func verifyTransferArtifact(ctx context.Context, archive ArchiveSnapshot, written ZIPWriteResult, p *transferPlan, staged TreeSnapshot) (proof TransferProof, err error) {
	if archive.Size() != written.Bytes {
		return proof, ErrUnstableWorkingTree
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(zipContextReaderAt{ctx, archive}, 0, written.Bytes))
	if err != nil {
		return proof, err
	}
	if n != written.Bytes || ContentID("sha256:"+hex.EncodeToString(hash.Sum(nil))) != written.ArtifactDigest {
		return proof, ErrUnstableWorkingTree
	}
	codec, err := NewZIPSource(borrowedTransferArchive{archive}, p.l)
	if err != nil {
		return proof, err
	}
	tree, err := codec.BeginSnapshot(ctx)
	if err != nil {
		return proof, err
	}
	defer func() { err = errors.Join(err, tree.Close()) }()
	h, proof, err := inspectTransfer(ctx, tree, p.l, p.support)
	if err != nil {
		return proof, err
	}
	if proof.HistoryCompleteness != HistoryFull {
		return proof, protocolError(ReasonMissingObject, "actual ZIP output is not self-contained")
	}
	if !slices.Equal(h.Root.Entries, p.summary.Entries) {
		return proof, ErrUnstableWorkingTree
	}
	for _, e := range h.Root.Entries {
		if e.Kind != "file" {
			continue
		}
		want, readErr := hashTransferFile(ctx, staged, e)
		if readErr != nil {
			return proof, readErr
		}
		got, readErr := hashTransferFile(ctx, tree, e)
		if readErr != nil {
			return proof, readErr
		}
		if got != want {
			return proof, ErrUnstableWorkingTree
		}
	}
	if err = tree.CheckStable(ctx); err != nil {
		return proof, err
	}
	return proof, archive.CheckStable(ctx)
}
