// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
)

type TransferResult struct {
	PackageID      PackageID
	HEAD           HEAD
	Input          TransferProof
	Output         TransferProof
	Hydrated       []ContentID
	ArtifactDigest ContentID
	ArtifactBytes  int64
}
type stagedTransfer struct {
	tx       DirectoryTransaction
	snapshot TreeSnapshot
	proof    TransferProof
	hydrated []ContentID
}

// ExecuteTransferDirectory consumes a sealed import/export plan. A Resolver is
// called only for explicitly missing planned objects, exactly once per ID.
// Source bytes are never modified. Output FULL is proved offline from the
// actual sealed output; Input retains the original offline observation.
func ExecuteTransferDirectory(ctx context.Context, plan TransferPlan, host DirectoryHost, resolver ContentResolver) (out TransferResult, err error) {
	p := plan.state
	if p == nil || host == nil {
		return out, schemaError("missing transfer plan/destination Host")
	}
	if err = checkNativeDirectorySeparation(p.source, host); err != nil {
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
	stage, err := stageTransfer(ctx, p, source, h, host, resolver)
	if err != nil {
		return out, err
	}
	published := false
	defer func() {
		cleanup := stage.tx.Abort(context.WithoutCancel(ctx))
		if published && cleanup != nil {
			cleanup = errors.Join(ErrPublicationUncertain, cleanup)
		}
		err = errors.Join(err, cleanup)
	}()
	err = stage.snapshot.Close()
	stage.snapshot = nil
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
	if err = stage.tx.Publish(ctx); err != nil {
		return out, err
	}
	published = true
	if err = ctx.Err(); err != nil {
		return out, errors.Join(ErrPublicationUncertain, err)
	}
	return TransferResult{PackageID: p.summary.PackageID, HEAD: p.summary.HEAD, Input: cloneTransferProof(p.summary.Input), Output: cloneTransferProof(stage.proof), Hydrated: slices.Clone(stage.hydrated)}, nil
}

func reopenTransfer(ctx context.Context, p *transferPlan) (out TreeSnapshot, h History, err error) {
	if err = ctx.Err(); err != nil {
		return nil, h, err
	}
	s, err := p.source.BeginSnapshot(ctx)
	if err != nil {
		if s != nil {
			err = errors.Join(err, s.Close())
		}
		return nil, h, err
	}
	if s == nil {
		return nil, h, schemaError("missing execution observation")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
			out = nil
		}
	}()
	root, err := ReadRoot(ctx, s, p.l, p.support)
	if err != nil {
		return nil, h, err
	}
	if err = CheckExpectedHEAD(p.summary.HEAD, root.HEAD); err != nil {
		return nil, h, err
	}
	var proof TransferProof
	h, proof, err = inspectTransfer(ctx, s, p.l, p.support)
	if err != nil {
		return nil, h, err
	}
	if !equalTransferProof(proof, p.summary.Input) {
		return nil, h, ErrTransferDrift
	}
	missing := map[ContentID]bool{}
	for _, id := range proof.MissingObjects {
		missing[id] = true
	}
	_, fingerprint, err := fingerprintTransfer(ctx, s, h.Root.Entries, missing, p.l)
	if err != nil {
		return nil, h, err
	}
	if fingerprint != p.fingerprint {
		return nil, h, ErrTransferDrift
	}
	if err = approveTransferFacts(ctx, p.facts, s, h.Root, p.summary, p.l); err != nil {
		return nil, h, err
	}
	if err = s.CheckStable(ctx); err != nil {
		return nil, h, err
	}
	return s, h, nil
}
func equalTransferProof(a, b TransferProof) bool {
	return a.CommittedIntegrity == b.CommittedIntegrity && a.HistoryCompleteness == b.HistoryCompleteness && slices.Equal(a.MissingObjects, b.MissingObjects) && slices.Equal(a.MissingMemory, b.MissingMemory) && slices.Equal(a.MissingEmbedded, b.MissingEmbedded)
}

func stageTransfer(ctx context.Context, p *transferPlan, source TreeSnapshot, h History, host DirectoryHost, resolver ContentResolver) (out stagedTransfer, err error) {
	if len(p.summary.Input.MissingObjects) != 0 && resolver == nil {
		return out, protocolError(ReasonMissingObject, "explicit hydration requires a Host Resolver")
	}
	tx, err := host.BeginDirectory(ctx)
	if err != nil {
		if tx != nil {
			err = errors.Join(err, tx.Abort(context.WithoutCancel(ctx)))
		}
		return out, err
	}
	if tx == nil {
		return out, schemaError("missing transfer transaction")
	}
	var pending TreeSnapshot
	defer func() {
		if err != nil {
			if pending != nil {
				err = errors.Join(err, pending.Close())
			}
			err = errors.Join(err, tx.Abort(context.WithoutCancel(ctx)))
			out = stagedTransfer{}
		}
	}()
	requests := map[string]PlannedContent{}
	for _, r := range p.summary.Contents {
		if r.Resolve {
			path, _ := (ContentObjectRef{r.ContentID, r.Size}).ObjectPath()
			requests[path] = r
		}
	}
	digests := map[string][32]byte{}
	hydrated := []ContentID{}
	entries := slices.Clone(p.summary.Entries)
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
		if request, resolve := requests[e.Path]; resolve {
			if err = hydrateTransferObject(ctx, tx, e.Path, request, resolver, p.l); err != nil {
				return out, err
			}
			var digest [32]byte
			raw, _ := hex.DecodeString(string(request.ContentID)[7:])
			copy(digest[:], raw)
			digests[e.Path] = digest
			hydrated = append(hydrated, request.ContentID)
		} else {
			digest, copyErr := copyDirectoryFile(ctx, source, tx, e)
			if copyErr != nil {
				return out, copyErr
			}
			if digest != p.files[e.Path] {
				return out, ErrTransferDrift
			}
			digests[e.Path] = digest
		}
	}
	pending, err = tx.Seal(ctx)
	if err != nil {
		return out, err
	}
	if pending == nil {
		return out, schemaError("missing sealed transfer tree")
	}
	// Prospective entries differ only by explicitly hydrated objects and their
	// implicit parent directories; every other raw file must match the plan.
	expected := h
	expected.Root.Entries = slices.Clone(p.summary.Entries)
	if err = checkDirectoryCopy(ctx, pending, expected, digests, p.l, p.support); err != nil {
		return out, err
	}
	_, proof, err := inspectTransfer(ctx, pending, p.l, p.support)
	if err != nil {
		return out, err
	}
	if proof.HistoryCompleteness != HistoryFull {
		return out, protocolError(ReasonMissingObject, "actual transfer output is not self-contained")
	}
	if err = pending.CheckStable(ctx); err != nil {
		return out, err
	}
	return stagedTransfer{tx, pending, proof, hydrated}, nil
}

func hydrateTransferObject(ctx context.Context, output PayloadWriter, path string, request PlannedContent, resolver ContentResolver, l Limits) (err error) {
	resolved, err := resolver.Resolve(ctx, ContentRequest{request.ContentID, request.Size, request.ExpectedRevision})
	if err != nil {
		if resolved.Reader != nil {
			err = errors.Join(err, resolved.Reader.Close())
		}
		return err
	}
	if resolved.Reader == nil {
		return schemaError("Resolver returned no content stream")
	}
	reader := resolved.Reader
	defer func() {
		if reader != nil {
			err = errors.Join(err, reader.Close())
		}
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	if request.ExpectedRevision != "" && (resolved.Revision != request.ExpectedRevision || resolved.CheckStable == nil) {
		return ErrContentRevisionMismatch
	}
	w, err := output.Create(ctx, path)
	if err != nil {
		if w != nil {
			err = errors.Join(err, w.Close())
		}
		return err
	}
	if w == nil {
		return schemaError("missing hydration pending writer")
	}
	err = CopyVerifiedContent(ctx, w, reader, request.ContentID, request.Size, l)
	err = errors.Join(err, w.Close(), reader.Close())
	reader = nil
	if err != nil {
		return err
	}
	if resolved.CheckStable != nil {
		if err = resolved.CheckStable(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}
