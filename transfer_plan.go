// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
)

var ErrTransferDrift = errors.New("source changed since transfer planning")
var ErrContentRevisionMismatch = errors.New("resolved content revision disagrees with selected revision")

// TransferProof couples actual history/path/schema/capability/object/memory/
// embedded-presence checks. FULL is never inferred from a profile label or
// object coverage alone. Signature mathematics/trust remains independent.
type TransferProof struct {
	CommittedIntegrity  IntegrityState
	HistoryCompleteness CompletenessState
	MissingObjects      []ContentID
	MissingMemory       []string
	MissingEmbedded     []EvidenceID
}
type PlannedContent struct {
	ContentID        ContentID
	Size             int64
	Resolve          bool
	ExpectedRevision string
}
type TransferSummary struct {
	Intent    string
	PackageID PackageID
	HEAD      HEAD
	Versions  []VersionID
	Contents  []PlannedContent
	Entries   []TreeEntry
	Input     TransferProof
}

// TransferFacts is a Host approval view, not portable serialization. Documents
// contains exact control JSON/NDJSON bytes; Entries inventories the entire
// selected output, including opaque extensions. Host selection must affirm
// privacy-safe facts/opaque bytes through its authorized source. A schema pass
// is not redaction. Approval cannot mutate the private transfer plan.
type TransferFacts struct {
	Intent    string
	PackageID PackageID
	HEAD      HEAD
	Documents map[string][]byte
	Entries   []TreeEntry
}
type TransferFactPolicy interface {
	ApproveTransfer(context.Context, TransferFacts) error
}
type TransferOptions struct {
	// Revisions are transient Host pins, never inserted into portable files.
	ExpectedRevisions map[ContentID]string
	Facts             TransferFactPolicy
}

// TransferPlan is sealed SDK state. Summary returns an owned review copy;
// editing it cannot alter execution. Plans authorize no network or publication.
type TransferPlan struct{ state *transferPlan }
type transferPlan struct {
	source      SnapshotSource
	l           Limits
	support     CapabilitySupport
	summary     TransferSummary
	files       map[string][32]byte
	fingerprint [32]byte
	facts       TransferFactPolicy
}

func cloneTransferProof(p TransferProof) TransferProof {
	p.MissingObjects = slices.Clone(p.MissingObjects)
	p.MissingMemory = slices.Clone(p.MissingMemory)
	p.MissingEmbedded = slices.Clone(p.MissingEmbedded)
	return p
}
func (p TransferPlan) Summary() TransferSummary {
	if p.state == nil {
		return TransferSummary{}
	}
	s := p.state.summary
	s.Versions = slices.Clone(s.Versions)
	s.Contents = slices.Clone(s.Contents)
	s.Entries = slices.Clone(s.Entries)
	s.Input = cloneTransferProof(s.Input)
	return s
}

// PlanExport rejects known-invalid signatures/evidence as well as invalid
// history/objects. It never repairs a negative input or requires identity trust.
func PlanExport(ctx context.Context, source SnapshotSource, l Limits, support CapabilitySupport, options TransferOptions) (TransferPlan, error) {
	return planTransfer(ctx, "export", source, l, support, options)
}
func PlanImport(ctx context.Context, source SnapshotSource, l Limits, support CapabilitySupport, options TransferOptions) (TransferPlan, error) {
	return planTransfer(ctx, "import", source, l, support, options)
}

func planTransfer(ctx context.Context, intent string, source SnapshotSource, l Limits, support CapabilitySupport, options TransferOptions) (out TransferPlan, err error) {
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if source == nil || options.Facts == nil {
		return out, schemaError("transfer requires source and Host fact selection")
	}
	if len(options.ExpectedRevisions) > l.MaxEntries {
		return out, protocolError(ReasonResourceLimit, "transfer revision inventory")
	}
	support = CapabilitySupport{Capabilities: slices.Clone(support.Capabilities), Profiles: slices.Clone(support.Profiles)}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("missing transfer observation")
	}
	defer func() {
		err = errors.Join(err, snapshot.Close())
		if err != nil {
			out = TransferPlan{}
		}
	}()
	h, proof, err := inspectTransfer(ctx, snapshot, l, support)
	if err != nil {
		return out, err
	}
	if proof.HistoryCompleteness == HistoryInvalid {
		return out, protocolError(ReasonObjectHashMismatch, "invalid source objects cannot be silently replaced")
	}
	if len(proof.MissingMemory) != 0 {
		return out, protocolError(ReasonInvalidMetadata, "Complete source needs explicit portable memory repair before transfer")
	}
	if len(proof.MissingEmbedded) != 0 {
		return out, protocolError(ReasonInvalidEvidence, "declared embedded evidence absent")
	}
	refs := transferContentRefs(h)
	missing := map[ContentID]bool{}
	for _, id := range proof.MissingObjects {
		missing[id] = true
	}
	summary := TransferSummary{Intent: intent, PackageID: h.Root.Package.PackageID, HEAD: h.Root.HEAD, Input: cloneTransferProof(proof)}
	known := map[ContentID]bool{}
	proposed := slices.Clone(h.Root.Entries)
	for _, ref := range refs {
		known[ref.ContentID] = true
		summary.Contents = append(summary.Contents, PlannedContent{ref.ContentID, ref.Size, missing[ref.ContentID], options.ExpectedRevisions[ref.ContentID]})
		if !missing[ref.ContentID] {
			continue
		}
		path, _ := ref.ObjectPath()
		found := false
		for i, e := range proposed {
			if e.Path == path {
				proposed[i].Size = ref.Size
				found = true
				break
			}
		}
		if !found {
			proposed = append(proposed, TreeEntry{path, "file", ref.Size})
		}
	}
	for id := range options.ExpectedRevisions {
		if !known[id] {
			return out, schemaError("revision pin is not actual historical/extra content")
		}
	}
	summary.Entries, err = PreflightTree(ctx, proposed, l)
	if err != nil {
		return out, err
	}
	for _, v := range h.Versions {
		summary.Versions = append(summary.Versions, v.Version.VersionID)
	}
	files, fingerprint, err := fingerprintTransfer(ctx, snapshot, h.Root.Entries, missing, l)
	if err != nil {
		return out, err
	}
	if err = approveTransferFacts(ctx, options.Facts, snapshot, h.Root, summary, l); err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	return TransferPlan{&transferPlan{source, l, support, summary, files, fingerprint, options.Facts}}, nil
}

func inspectTransfer(ctx context.Context, source TreeReader, l Limits, support CapabilitySupport) (History, TransferProof, error) {
	p := TransferProof{CommittedIntegrity: IntegrityNotChecked, HistoryCompleteness: HistoryNotChecked}
	h, err := ReadHistory(ctx, source, l, support)
	if err != nil {
		return History{}, p, err
	}
	if err = validateAttestationDeclarations(ctx, source, h, l, support); err != nil {
		return History{}, p, err
	}
	memory, err := readPortableMemory(ctx, source, h, l)
	if err != nil {
		return History{}, p, err
	}
	content, err := verifyCommittedContent(ctx, source, h, l)
	if err != nil {
		return History{}, p, err
	}
	evidence, err := verifyEvidence(ctx, source, h, memory, l, support, nil)
	if err != nil {
		return History{}, p, err
	}
	if err = validateWriteAttestations(ctx, source, h, evidence, l, support); err != nil {
		return History{}, p, err
	}
	p.CommittedIntegrity = content.Integrity
	p.MissingObjects = slices.Clone(content.Missing)
	p.MissingEmbedded = slices.Clone(evidence.MissingEmbedded)
	complete := containsText(h.Root.Format.Profiles, ProfileComplete)
	for _, v := range h.Versions {
		complete = complete || containsText(v.Version.Profiles, ProfileComplete)
	}
	if complete {
		p.MissingMemory = slices.Clone(memory.MissingPaths)
	}
	p.HistoryCompleteness = HistoryFull
	if len(content.Invalid) != 0 {
		p.HistoryCompleteness = HistoryInvalid
	} else if len(p.MissingObjects) != 0 || len(p.MissingMemory) != 0 || len(p.MissingEmbedded) != 0 {
		p.HistoryCompleteness = HistoryNotFull
	} else if evidence.State == EvidenceNotChecked {
		p.HistoryCompleteness = HistoryNotChecked
	}
	return h, p, nil
}
func transferContentRefs(h History) []ContentObjectRef {
	refs := map[ContentID]ContentObjectRef{}
	for _, r := range h.Contents {
		refs[r.ContentID] = r
	}
	for _, e := range h.Root.Entries {
		if e.Kind == "file" && strings.HasPrefix(e.Path, ".packtell/objects/sha256/") {
			id := ContentID("sha256:" + e.Path[strings.LastIndexByte(e.Path, '/')+1:])
			if _, ok := refs[id]; !ok {
				refs[id] = ContentObjectRef{id, e.Size}
			}
		}
	}
	ordered := make([]ContentObjectRef, 0, len(refs))
	for _, r := range refs {
		ordered = append(ordered, r)
	}
	sortContentRefs(ordered)
	return ordered
}
func fingerprintTransfer(ctx context.Context, source TreeReader, entries []TreeEntry, missing map[ContentID]bool, l Limits) (map[string][32]byte, [32]byte, error) {
	files := map[string][32]byte{}
	hash := sha256.New()
	_, _ = io.WriteString(hash, "orbifabric.sdk.transfer-observation.v1\n")
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, [32]byte{}, err
		}
		var scalar [8]byte
		binary.BigEndian.PutUint64(scalar[:], uint64(len(e.Path)))
		_, _ = hash.Write(scalar[:])
		_, _ = io.WriteString(hash, e.Path)
		_, _ = io.WriteString(hash, e.Kind+"\x00")
		binary.BigEndian.PutUint64(scalar[:], uint64(e.Size))
		_, _ = hash.Write(scalar[:])
		if e.Kind != "file" {
			continue
		}
		id := ContentID("")
		if strings.HasPrefix(e.Path, ".packtell/objects/sha256/") {
			id = ContentID("sha256:" + e.Path[strings.LastIndexByte(e.Path, '/')+1:])
		}
		if missing[id] {
			_, _ = hash.Write([]byte{0})
			continue
		}
		digest, err := hashTransferFile(ctx, source, e)
		if err != nil {
			return nil, [32]byte{}, err
		}
		files[e.Path] = digest
		_, _ = hash.Write([]byte{1})
		_, _ = hash.Write(digest[:])
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return files, digest, nil
}
func hashTransferFile(ctx context.Context, source TreeReader, e TreeEntry) (digest [32]byte, err error) {
	r, err := source.Open(ctx, e.Path)
	if err != nil {
		if r != nil {
			err = errors.Join(err, r.Close())
		}
		return digest, err
	}
	if r == nil {
		return digest, schemaError("missing transfer byte stream")
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(contextReader{ctx, r}, e.Size+1))
	err = errors.Join(readErr, r.Close())
	if err != nil {
		return digest, err
	}
	if n != e.Size {
		return digest, ErrUnstableWorkingTree
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
func approveTransferFacts(ctx context.Context, policy TransferFactPolicy, source TreeReader, root RootInspection, summary TransferSummary, l Limits) error {
	if policy == nil {
		return schemaError("missing Host transfer fact selection")
	}
	nodes := map[string]TreeEntry{}
	for _, e := range root.Entries {
		nodes[e.Path] = e
	}
	documents := map[string][]byte{}
	for _, e := range root.Entries {
		if e.Kind == "file" && (controlJSONPath(e.Path) || e.Path == ".packtell/history/events.ndjson") {
			max := l.MaxJSONBytes
			if e.Path == ".packtell/history/events.ndjson" {
				max = l.MaxTotalJSONBytes
			}
			b, err := readRootBytes(ctx, source, nodes, e.Path, max)
			if err != nil {
				return err
			}
			documents[e.Path] = bytes.Clone(b)
		}
	}
	if err := policy.ApproveTransfer(ctx, TransferFacts{summary.Intent, summary.PackageID, summary.HEAD, documents, slices.Clone(summary.Entries)}); err != nil {
		return err
	}
	return ctx.Err()
}
