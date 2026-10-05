// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// CommitHost owns authorization, reader/writer isolation and crash recovery.
// BeginCommit must keep incomplete output hidden until HEAD-last publication.
// Pending files and journals stay outside the portable tree. The SDK owns all
// protocol fields/serialization, object hashes and expected-HEAD semantics.
type CommitHost interface {
	BeginCommit(ctx context.Context) (CommitTransaction, error)
}
type CommitTransaction interface {
	HEADTransaction
	TreeReader
	CheckStable(ctx context.Context) error
	// StageObject returns an isolated pending stream. A successful Close makes
	// its bytes durable but not published; the SDK verifies bytes before closing.
	StageObject(ctx context.Context, ref ContentObjectRef) (io.WriteCloser, error)
	// StageVersion stages exactly the two SDK-produced documents, never replaces
	// a committed Version, and makes them durable without publishing the proposal.
	StageVersion(ctx context.Context, id VersionID, versionJSON, manifestJSON []byte) error
	// Abort removes only pending output. It must never delete published Versions
	// or prior objects, even if publication returned an uncertain Host error.
	Abort(ctx context.Context) error
}

type CommitRequest struct {
	ExpectedHEAD   HEAD
	At             time.Time
	SealedMetadata SealedMetadata
	Label          *string
	Tracking       map[string]UUID
	// ReservedIDs are additional non-entry portable identities (memory/evidence).
	// The SDK already reserves historical entities and portable-memory IDs.
	ReservedIDs   []UUID
	VersionExtra  map[string]any
	ManifestExtra map[string]any
}

type borrowedSnapshotSource struct{ tx CommitTransaction }
type borrowedSnapshot struct{ CommitTransaction }

func (s borrowedSnapshotSource) BeginSnapshot(context.Context) (TreeSnapshot, error) {
	return borrowedSnapshot{s.tx}, nil
}
func (borrowedSnapshot) Close() error { return nil } // outer transaction owns isolation

// NextOrdinal never wraps the protocol integer domain. Zero represents only
// the absence of a parent; a committed parent must have a positive ordinal.
func NextOrdinal(parent int64) (int64, error) {
	if parent < 0 || parent > MaxProtocolInteger {
		return 0, schemaError("invalid parent ordinal")
	}
	if parent == MaxProtocolInteger {
		return 0, protocolError(ReasonResourceLimit, "maximum ordinal reached; commit stopped")
	}
	return parent + 1, nil
}

// Commit creates an unsigned Version from stable Working Tree bytes. It does
// not require a signer/container/network. The Host isolates compare, scan and
// writes, makes all objects/documents durable, then publishes HEAD last. Any
// error returns no success artifact; callers read back authority to resolve an
// uncertain publication/close failure rather than retrying with a new parent.
func Commit(ctx context.Context, host CommitHost, request CommitRequest, l Limits, support CapabilitySupport) (out CommittedVersion, err error) {
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = request.ExpectedHEAD.Validate(); err != nil {
		return out, err
	}
	if _, err = Timestamp(request.At); err != nil {
		return out, err
	}
	if host == nil {
		return out, schemaError("missing commit Host")
	}
	if err = validateCommitFacts(ctx, request, l); err != nil {
		return out, err
	}
	tx, err := host.BeginCommit(ctx)
	if err != nil {
		return out, err
	}
	if tx == nil {
		return out, schemaError("Host returned no commit transaction")
	}
	published := false
	defer func() {
		if !published {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			abortErr := tx.Abort(cleanup)
			cancel()
			if abortErr != nil {
				err = errors.Join(err, abortErr)
			}
		}
		closeErr := tx.Close()
		if closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		if err != nil {
			out = CommittedVersion{}
		}
	}()
	actual, err := tx.ReadHEAD(ctx)
	if err != nil {
		return out, err
	}
	if err = CheckExpectedHEAD(request.ExpectedHEAD, actual); err != nil {
		return out, err
	}
	history, err := ReadHistory(ctx, tx, l, support)
	if err != nil {
		return out, err
	}
	if err = CheckExpectedHEAD(request.ExpectedHEAD, history.Root.HEAD); err != nil {
		return out, err
	}
	memory, err := readPortableMemory(ctx, tx, history, l)
	if err != nil {
		return out, err
	}
	request.ReservedIDs = append(append([]UUID{}, request.ReservedIDs...), memory.KnownIDs()...)
	coverage, err := verifyCommittedContent(ctx, tx, history, l)
	if err != nil {
		return out, err
	}
	if coverage.HistoryCompleteness == HistoryInvalid {
		return out, protocolError(ReasonObjectHashMismatch, "existing object store is invalid")
	}
	if coverage.Integrity != IntegrityValid || coverage.HistoryCompleteness == HistoryNotFull {
		return out, protocolError(ReasonMissingObject, "existing committed objects are unavailable")
	}
	scan, err := Scan(ctx, borrowedSnapshotSource{tx}, l, support, request.Tracking)
	if err != nil {
		return out, err
	}
	if err = CheckExpectedHEAD(request.ExpectedHEAD, scan.Root.HEAD); err != nil {
		return out, err
	}
	record, paths, err := prepareCommit(ctx, history, scan, request, l, support)
	if err != nil {
		return out, err
	}
	existing := map[ContentID]int64{}
	for _, ref := range history.Contents {
		existing[ref.ContentID] = ref.Size
	}

	for _, entry := range history.Root.Entries {
		if entry.Kind == "file" && strings.HasPrefix(entry.Path, ".packtell/objects/sha256/") {
			parts := strings.Split(entry.Path, "/")
			existing[ContentID("sha256:"+parts[4])] = entry.Size
		}
	}
	versionBytes, err := json.Marshal(record.Version)
	if err != nil {
		return out, err
	}
	manifestBytes, err := json.Marshal(record.Manifest)
	if err != nil {
		return out, err
	}
	if int64(len(versionBytes)) > l.MaxJSONBytes || int64(len(manifestBytes)) > l.MaxJSONBytes {
		return out, protocolError(ReasonResourceLimit, "commit documents exceed JSON policy")
	}
	proposed := append([]TreeEntry{}, history.Root.Entries...)
	for i := range proposed {
		if proposed[i].Path == ".packtell/HEAD" {
			proposed[i].Size = 37
		}
	}
	dir := ".packtell/versions/" + string(record.Version.VersionID)
	proposed = append(proposed, TreeEntry{Path: dir, Kind: "directory"}, TreeEntry{Path: dir + "/version.json", Kind: "file", Size: int64(len(versionBytes))}, TreeEntry{Path: dir + "/manifest.json", Kind: "file", Size: int64(len(manifestBytes))})
	newObjects := map[ContentID]bool{}
	for _, entry := range record.Manifest.Entries {
		if entry.Kind == "file" {
			if _, known := existing[entry.ContentID]; !known && !newObjects[entry.ContentID] {
				newObjects[entry.ContentID] = true
				path, _ := (ContentObjectRef{entry.ContentID, entry.Size}).ObjectPath()
				proposed = append(proposed, TreeEntry{Path: path, Kind: "file", Size: entry.Size})
			}
		}
	}
	if _, err = PreflightTree(ctx, proposed, l); err != nil {
		return out, err
	}
	if err = validateControlJSONBudget(proposed, l); err != nil {
		return out, err
	}
	staged := map[ContentID]bool{}
	for _, e := range record.Manifest.Entries {
		if e.Kind != "file" {
			continue
		}
		if size, known := existing[e.ContentID]; known {
			if size != e.Size {
				return out, schemaError("new manifest changes historical ContentID size")
			}
			continue
		}
		if staged[e.ContentID] {
			continue
		}
		staged[e.ContentID] = true
		if err = stageWorkingObject(ctx, tx, paths[e.ID()], ContentObjectRef{e.ContentID, e.Size}, l); err != nil {
			return out, err
		}
	}
	if err = tx.CheckStable(ctx); err != nil {
		return out, err
	}
	if err = tx.StageVersion(ctx, record.Version.VersionID, versionBytes, manifestBytes); err != nil {
		return out, err
	}
	if err = tx.CheckStable(ctx); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	actual, err = tx.ReadHEAD(ctx)
	if err != nil {
		return out, err
	}
	if err = CheckExpectedHEAD(request.ExpectedHEAD, actual); err != nil {
		return out, err
	}
	if err = tx.PublishHEAD(ctx, HEAD(record.Version.VersionID)); err != nil {
		return out, err
	}
	published = true
	actual, err = tx.ReadHEAD(ctx)
	if err != nil {
		return out, err
	}
	if err = CheckExpectedHEAD(HEAD(record.Version.VersionID), actual); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	return record, nil
}
func stageWorkingObject(ctx context.Context, tx CommitTransaction, path string, ref ContentObjectRef, l Limits) error {
	r, err := tx.Open(ctx, path)
	if err != nil {
		if r != nil {
			_ = r.Close()
		}
		return err
	}
	if r == nil {
		return schemaError("missing stable working stream")
	}
	w, err := tx.StageObject(ctx, ref)
	if err != nil {
		_ = r.Close()
		if w != nil {
			_ = w.Close()
		}
		return err
	}
	if w == nil {
		_ = r.Close()
		return schemaError("missing pending object stream")
	}
	copyErr := CopyVerifiedContent(ctx, w, r, ref.ContentID, ref.Size, l)
	readCloseErr := r.Close()
	writeCloseErr := w.Close()
	return errors.Join(copyErr, readCloseErr, writeCloseErr)
}
func prepareCommit(ctx context.Context, h History, scan WorkingScan, r CommitRequest, l Limits, support CapabilitySupport) (CommittedVersion, map[UUID]string, error) {
	old := map[UUID]Entry{}
	nonEntries := map[UUID]bool{UUID(h.Root.Package.PackageID): true}
	for _, v := range h.Versions {
		nonEntries[UUID(v.Version.VersionID)] = true
		for _, e := range v.Manifest.Entries {
			old[e.ID()] = e
		}
	}
	for _, id := range r.ReservedIDs {
		if err := id.Validate(); err != nil {
			return CommittedVersion{}, nil, err
		}
		if _, entry := old[id]; !entry {
			nonEntries[id] = true
		}
	}
	ids := append(h.KnownIDs(), r.ReservedIDs...)
	// Existing envelope/delivery IDs are already explicit in control paths.
	for _, entry := range h.Root.Entries {
		if !strings.HasPrefix(entry.Path, ".packtell/verification/") && !strings.HasPrefix(entry.Path, ".packtell/evidence/") {
			continue
		}
		for _, part := range strings.Split(entry.Path, "/") {
			part = strings.TrimSuffix(part, ".json")
			if validUUID(part) {
				id := UUID(part)
				ids = append(ids, id)
				if _, entryID := old[id]; !entryID {
					nonEntries[id] = true
				}
			}
		}
	}
	for _, e := range scan.Entries {
		if e.ID != "" {
			if nonEntries[e.ID] {
				return CommittedVersion{}, nil, schemaError("working identity reuses a non-entry protocol ID")
			}
			if prior, known := old[e.ID]; known && prior.Kind != logicalKind(e.Kind) {
				return CommittedVersion{}, nil, schemaError("working identity changes historical kind")
			}
			ids = append(ids, e.ID)
		}
	}
	gen, err := NewIDGenerator(nil, ids)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	byPath := map[string]WorkingEntry{}
	for _, entry := range scan.Entries {
		if entry.ID == "" {
			entry.ID, err = gen.Generate(ctx, r.At)
			if err != nil {
				return CommittedVersion{}, nil, err
			}
		}
		byPath[entry.Path] = entry
	}
	id, err := gen.Generate(ctx, r.At)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	created, err := Timestamp(r.At)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	var parent *VersionID
	parentOrdinal := int64(0)
	if len(h.Versions) > 0 {
		last := h.Versions[len(h.Versions)-1].Version
		p := last.VersionID
		parent = &p
		parentOrdinal = last.Ordinal
	}
	ordinal, err := NextOrdinal(parentOrdinal)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	f := h.Root.Format
	version := Version{Schema: "orbifabric.package.version.v2", PackageID: h.Root.Package.PackageID, VersionID: VersionID(id), ParentVersionID: parent, Ordinal: ordinal, CreatedAt: created, Protocol: f.Protocol, ProtocolVersion: f.ProtocolVersion, TreeProfile: f.TreeProfile, Profiles: f.Profiles, RequiredCapabilities: f.RequiredCapabilities, OptionalCapabilities: f.OptionalCapabilities, SealedMetadata: r.SealedMetadata, Label: r.Label, Extra: r.VersionExtra}
	manifest := Manifest{Schema: "orbifabric.package.manifest.v2", PackageID: h.Root.Package.PackageID, VersionID: VersionID(id), Entries: []Entry{}, Extra: map[string]any{}}
	if h.Root.HeadManifest != nil {
		for key, value := range h.Root.HeadManifest.Extra {
			manifest.Extra[key] = value
		}
	}
	for key, value := range r.ManifestExtra {
		manifest.Extra[key] = value
	}
	paths := map[UUID]string{}
	for _, working := range byPath {
		e := old[working.ID]
		e.Kind = logicalKind(working.Kind)
		e.FileID = ""
		e.FolderID = ""
		e.Name = working.Path[strings.LastIndexByte(working.Path, '/')+1:]
		e.ParentFolderID = nil
		e.ContentID = ""
		e.Size = 0
		if index := strings.LastIndexByte(working.Path, '/'); index >= 0 {
			folder, ok := byPath[working.Path[:index]]
			if !ok || folder.Kind != "directory" {
				return CommittedVersion{}, nil, schemaError("working parent is absent")
			}
			p := FolderID(folder.ID)
			e.ParentFolderID = &p
		}
		if e.Kind == "file" {
			e.FileID = FileID(working.ID)
			e.ContentID = working.ContentID
			e.Size = working.Size
		} else {
			e.FolderID = FolderID(working.ID)
		}
		manifest.Entries = append(manifest.Entries, e)
		paths[e.ID()] = working.Path
	}
	SortEntries(manifest.Entries)
	if err = manifest.Validate(ctx, l); err != nil {
		return CommittedVersion{}, nil, err
	}
	inventory, _ := NewIdentityInventory(h.Root.Package.PackageID)
	for _, v := range h.Versions {
		if err = inventory.Observe(ctx, v.Manifest, l); err != nil {
			return CommittedVersion{}, nil, err
		}
	}
	if err = inventory.Observe(ctx, manifest, l); err != nil {
		return CommittedVersion{}, nil, err
	}
	b, err := json.Marshal(version)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	version, err = ReadVersion(ctx, bytes.NewReader(b), l, support)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	b, err = json.Marshal(manifest)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	manifest, err = ReadManifest(ctx, bytes.NewReader(b), l)
	if err != nil {
		return CommittedVersion{}, nil, err
	}
	return CommittedVersion{version, manifest}, paths, nil
}
func validateCommitFacts(ctx context.Context, r CommitRequest, l Limits) error {
	if !utf8.ValidString(r.SealedMetadata.Title) || (r.SealedMetadata.Description != nil && !utf8.ValidString(*r.SealedMetadata.Description)) || (r.Label != nil && !utf8.ValidString(*r.Label)) {
		return schemaError("invalid UTF-8 commit text")
	}
	if int64(len(r.SealedMetadata.Title)) > l.MaxJSONBytes || (r.SealedMetadata.Description != nil && int64(len(*r.SealedMetadata.Description)) > l.MaxJSONBytes) || (r.Label != nil && int64(len(*r.Label)) > l.MaxJSONBytes) {
		return protocolError(ReasonResourceLimit, "sealed title exceeds JSON policy")
	}
	for _, v := range []any{r.SealedMetadata.Extra, r.SealedMetadata.Extensions, r.VersionExtra, r.ManifestExtra} {
		if err := validateOptionalValue(ctx, v, l, 0); err != nil {
			return err
		}
	}
	return nil
}
