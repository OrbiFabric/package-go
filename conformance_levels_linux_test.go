// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packagego_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

type sharedManifest struct {
	Levels   []string `json:"levels"`
	Fixtures []struct {
		ID     string   `json:"id"`
		Levels []string `json:"levels"`
		SHA256 string   `json:"sha256"`
	} `json:"fixtures"`
	WriterOperations []struct {
		ID                string         `json:"id"`
		ExpectedHEAD      pkg.HEAD       `json:"expected_head"`
		ActualHEAD        pkg.HEAD       `json:"actual_head"`
		ExpectedReason    pkg.ReasonCode `json:"expected_reason"`
		PublishedVersions int            `json:"published_versions"`
		Parent            pkg.VersionID  `json:"parent"`
		Ordinal           int64          `json:"ordinal"`
		ExpectedParent    pkg.VersionID  `json:"expected_parent"`
		ExpectedOrdinal   int64          `json:"expected_ordinal"`
	} `json:"writer_operations"`
}

func sharedLevelManifest(t *testing.T) sharedManifest {
	t.Helper()
	b, err := fs.ReadFile(conformance.Assets(), "conformance/manifest.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var m sharedManifest
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Levels) != 7 || len(m.Fixtures) != 30 || len(m.WriterOperations) != 2 {
		t.Fatal("authority inventory", m)
	}
	return m
}

type sharedCaseRecord struct {
	Level                  string         `json:"level"`
	Fixture                string         `json:"fixture"`
	FixtureDigest          string         `json:"fixture_digest"`
	Expected               pkg.Result     `json:"expected"`
	Actual                 pkg.Result     `json:"actual"`
	Output                 *pkg.Result    `json:"output,omitempty"`
	Operation              string         `json:"operation"`
	OperationReason        pkg.ReasonCode `json:"operation_reason,omitempty"`
	DirectoryBegins        int            `json:"directory_begins"`
	PublishedDirectories   int            `json:"published_directories"`
	PublishedArtifacts     int            `json:"published_artifacts"`
	HistoricalRestores     int            `json:"historical_restores"`
	RawAndSubjectPreserved bool           `json:"raw_and_subject_preserved"`
	ZIPMethods             []string       `json:"zip_methods,omitempty"`
	Pass                   bool           `json:"comparison_pass"`
}
type sharedLevelReport struct {
	AuthorityAttribution string             `json:"authority_attribution"`
	SpecCommit           string             `json:"spec_commit"`
	ImplementationCommit string             `json:"implementation_commit"`
	WorkingTreeClean     bool               `json:"working_tree_clean"`
	Platform             string             `json:"platform"`
	Limits               pkg.Limits         `json:"resource_policy"`
	Comparison           string             `json:"comparison_rule"`
	Cases                []sharedCaseRecord `json:"cases"`
}

// These counters observe the real native Hosts; they do not emulate filesystem
// transactions or make publication claims from an in-memory writer.
type levelDirectoryHost struct {
	pkg.DirectoryHost
	begins, published int
}
type levelDirectoryTX struct {
	pkg.DirectoryTransaction
	host *levelDirectoryHost
}

func (h *levelDirectoryHost) BeginDirectory(ctx context.Context) (pkg.DirectoryTransaction, error) {
	h.begins++
	tx, err := h.DirectoryHost.BeginDirectory(ctx)
	if tx == nil {
		return nil, err
	}
	return &levelDirectoryTX{tx, h}, err
}
func (t *levelDirectoryTX) Publish(ctx context.Context) error {
	err := t.DirectoryTransaction.Publish(ctx)
	if err == nil {
		t.host.published++
	}
	return err
}

type levelArtifactHost struct {
	pkg.ArtifactHost
	published int
}
type levelArtifactTX struct {
	pkg.ArtifactTransaction
	host *levelArtifactHost
}

func (h *levelArtifactHost) BeginArtifact(ctx context.Context) (pkg.ArtifactTransaction, error) {
	tx, err := h.ArtifactHost.BeginArtifact(ctx)
	if tx == nil {
		return nil, err
	}
	return &levelArtifactTX{tx, h}, err
}
func (t *levelArtifactTX) Publish(ctx context.Context) error {
	err := t.ArtifactTransaction.Publish(ctx)
	if err == nil {
		t.host.published++
	}
	return err
}

func levelFixtureSource(t *testing.T, id string, l pkg.Limits) (pkg.SnapshotSource, pkg.Result, *memorySource) {
	t.Helper()
	b, err := fs.ReadFile(conformance.Assets(), "fixtures/"+id+".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input    struct{ Kind string }
		Expected pkg.Result
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Input.Kind == "zip" {
		b, _ := zipFixture(t, id)
		return zipSource(t, b, l), f.Expected, nil
	}
	virtual := treeFixture(t, id)
	// Unsafe arrays remain virtual and never reach filesystem materialization.
	if _, err = pkg.PreflightTree(context.Background(), virtual.entries, l); err != nil {
		return virtual, f.Expected, virtual
	}
	root, _ := directoryFixture(t, id)
	source, err := pkg.NewDirectorySource(root, l)
	if err != nil {
		t.Fatal(err)
	}
	return source, f.Expected, virtual
}
func levelRaw(t *testing.T, source pkg.SnapshotSource, l pkg.Limits) ([]pkg.TreeEntry, map[string][]byte) {
	t.Helper()
	s, err := source.BeginSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	entries, err := s.List(context.Background(), l.MaxEntries)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.Kind != "file" {
			continue
		}
		r, err := s.Open(context.Background(), e.Path)
		if err != nil {
			t.Fatal(err)
		}
		b, err := pkg.ReadBounded(context.Background(), r, l.MaxFileBytes)
		err = errors.Join(err, r.Close())
		if err != nil {
			t.Fatal(err)
		}
		files[e.Path] = b
	}
	if err = s.CheckStable(context.Background()); err != nil {
		t.Fatal(err)
	}
	return entries, files
}
func levelPreservation(t *testing.T, before, after pkg.SnapshotSource, l pkg.Limits, support pkg.CapabilitySupport) int {
	t.Helper()
	be, bf := levelRaw(t, before, l)
	ae, af := levelRaw(t, after, l)
	if !slices.Equal(be, ae) || !equalTransferBytes(bf, af) {
		t.Fatal("lossy raw tree round-trip")
	}
	ctx := context.Background()
	a, err := before.BeginSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	}()
	b, err := after.BeginSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()
	old, err := pkg.ReadHistory(ctx, a, l, support)
	if err != nil {
		t.Fatal(err)
	}
	current, err := pkg.ReadHistory(ctx, b, l, support)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Versions) != len(current.Versions) {
		t.Fatal("history loss")
	}
	for i, version := range old.Versions {
		_, want, err := pkg.DeriveVersionSubject(ctx, old.Root.Package, version.Version, version.Manifest, l, support)
		if err != nil {
			t.Fatal(err)
		}
		_, got, err := pkg.DeriveVersionSubject(ctx, current.Root.Package, current.Versions[i].Version, current.Versions[i].Manifest, l, support)
		if err != nil || got != want {
			t.Fatal("Version subject changed", got, want, err)
		}
		// Real independent restored files are produced from output objects only.
		payloadParent := t.TempDir()
		destination := filepath.Join(payloadParent, "historical-payload")
		tx, err := nativeDirectoryHost(t, destination).BeginDirectory(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = pkg.MaterializeVersionPayload(ctx, b, version.Version.VersionID, tx, l, support); err != nil {
			t.Fatal(err)
		}
		pending, err := tx.Seal(ctx)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := pkg.PlanMaterializeVersion(ctx, b, version.Version.VersionID, l, support)
		if err != nil {
			t.Fatal(err)
		}
		actualEntries, err := pending.List(ctx, l.MaxEntries)
		if err != nil {
			t.Fatal(err)
		}
		wanted := []pkg.TreeEntry{}
		for _, e := range plan.Entries {
			wanted = append(wanted, pkg.TreeEntry{Path: e.Path, Kind: e.Kind, Size: e.Size})
		}
		wanted, err = pkg.PreflightTree(ctx, wanted, l)
		if err != nil || !slices.Equal(actualEntries, wanted) {
			t.Fatal("restored files/empty folders", actualEntries, wanted, err)
		}
		pendingDirs, err := os.ReadDir(payloadParent)
		if err != nil || len(pendingDirs) != 1 || !strings.HasPrefix(pendingDirs[0].Name(), ".package-pending-") {
			t.Fatal("isolated actual restoration", pendingDirs, err)
		}
		for _, entry := range plan.Entries {
			if entry.Kind == "directory" {
				continue
			}
			r, err := pending.Open(ctx, entry.Path)
			if err != nil {
				t.Fatal(err)
			}
			err = pkg.CopyVerifiedContent(ctx, bytes.NewBuffer(nil), r, entry.ContentID, entry.Size, l)
			err = errors.Join(err, r.Close())
			if err != nil {
				t.Fatal("restored bytes", err)
			}
			info, err := os.Lstat(filepath.Join(payloadParent, pendingDirs[0].Name(), filepath.FromSlash(entry.Path)))
			if err != nil || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
				t.Fatal("restoration needs independent regular files", info, err)
			}
		}
		if err = errors.Join(pending.CheckStable(ctx), pending.Close(), tx.Abort(ctx)); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("payload restoration published an unrequested Package", err)
		}
	}
	if err = errors.Join(a.CheckStable(ctx), b.CheckStable(ctx)); err != nil {
		t.Fatal(err)
	}
	return len(old.Versions)
}

func TestS11SevenLevels(t *testing.T) {
	if err := conformance.VerifyAssets(); err != nil {
		t.Fatal(err)
	}
	m := sharedLevelManifest(t)
	l := conformancePolicy()
	ctx := context.Background()
	report := sharedLevelReport{AuthorityAttribution: "Expected fields are facts from the pinned package-spec CC BY 4.0 machine assets; SDK implementation/tests are Apache-2.0.", SpecCommit: conformance.SpecCommit, Platform: "linux", Limits: l, Comparison: "Match every frozen dimension except expected NOT_CHECKED; include all expected reasons. A passing rejection is not semantic success."}
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	report.ImplementationCommit = strings.TrimSpace(string(head))
	status, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		t.Fatal(err)
	}
	report.WorkingTreeClean = len(status) == 0
	for _, level := range m.Levels {
		t.Run(level, func(t *testing.T) {
			for _, row := range m.Fixtures {
				if !slices.Contains(row.Levels, level) {
					continue
				}
				t.Run(row.ID, func(t *testing.T) {
					r := sharedCaseRecord{Level: level, Fixture: row.ID, FixtureDigest: row.SHA256}
					defer func() {
						r.Pass = !t.Failed()
						report.Cases = append(report.Cases, r)
						b, _ := json.Marshal(r)
						t.Logf("S11_RECORD %s", b)
					}()
					source, want, virtual := levelFixtureSource(t, row.ID, l)
					r.Expected = want
					support := pkg.CompleteSupport()
					if strings.HasPrefix(level, "Core ") {
						support = pkg.CoreSupport()
					}
					observed, verifyErr := pkg.Verify(ctx, source, l, pkg.VerificationOptions{Support: support})
					r.Actual = observed.Result
					compareFrozenResult(t, observed.Result, want)
					if strings.HasSuffix(level, "Reader") || level == "Verifier" {
						r.Operation = "offline-read"
						if want.Structure == pkg.StructureValid && verifyErr != nil {
							t.Fatal(verifyErr)
						}
						return
					}
					// Every writer/codec entry point shares the same negative-input
					// validation. No alternate copying policy bypasses this gate.
					parent := t.TempDir()
					destination := filepath.Join(parent, "output")
					artifact := filepath.Join(parent, "output.zip")
					directory := &levelDirectoryHost{DirectoryHost: nativeDirectoryHost(t, destination)}
					ah, err := pkg.NewArtifactHost(artifact, l)
					if err != nil {
						t.Fatal(err)
					}
					archiveHost := &levelArtifactHost{ArtifactHost: ah}
					var plan pkg.TransferPlan
					var operationErr error
					if level != "Directory Codec" {
						plan, operationErr = pkg.PlanExport(ctx, source, l, support, testTransferOptions())
					}
					var output pkg.SnapshotSource
					var transfer pkg.TransferResult
					if level == "Directory Codec" {
						_, operationErr = pkg.PublishDirectory(ctx, source, directory, l, support)
						if operationErr == nil {
							output, err = pkg.NewDirectorySource(destination, l)
							if err != nil {
								t.Fatal(err)
							}
						}
					} else if operationErr == nil {
						if level == "ZIP Codec" {
							transfer, operationErr = pkg.ExecuteTransferZIP(ctx, plan, directory, archiveHost, nil, pkg.ZIPOptions{DisplayDirectory: "Shared Fixture", Method: zip.Deflate})
							if operationErr == nil {
								a, err := pkg.NewFileArchiveSource(artifact, l)
								if err != nil {
									t.Fatal(err)
								}
								output, err = pkg.NewZIPSource(a, l)
								if err != nil {
									t.Fatal(err)
								}
							}
						} else {
							transfer, operationErr = pkg.ExecuteTransferDirectory(ctx, plan, directory, nil)
							if operationErr == nil {
								output, err = pkg.NewDirectorySource(destination, l)
								if err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					r.DirectoryBegins = directory.begins
					r.PublishedDirectories = directory.published
					r.PublishedArtifacts = archiveHost.published
					negative := want.Recognition != pkg.Recognized || want.Structure != pkg.StructureValid || want.CommittedIntegrity == pkg.IntegrityUnavailable || want.CommittedIntegrity == pkg.IntegrityInvalid || want.HistoryCompleteness == pkg.HistoryInvalid || want.HistoryCompleteness == pkg.HistoryNotFull || want.Signature == pkg.SignatureInvalid || want.Evidence == pkg.EvidenceInvalid
					if negative {
						r.Operation = "rejected-before-publication"
						if operationErr == nil || directory.published != 0 || archiveHost.published != 0 {
							t.Fatal("negative input published", operationErr, r)
						}
						var p *pkg.ProtocolError
						if errors.As(operationErr, &p) {
							r.OperationReason = p.Code
						} else {
							t.Fatal("unexpected non-protocol rejection", operationErr)
						}
						assertNoDirectoryOutput(t, parent, destination)
						if _, err = os.Lstat(artifact); !errors.Is(err, fs.ErrNotExist) {
							t.Fatal("negative artifact appeared", err)
						}
						if directory.begins != 0 {
							t.Fatal("negative validation reached transaction", r)
						}
						if !reflect.DeepEqual(transfer, pkg.TransferResult{}) {
							t.Fatal("negative transfer returned success facts", transfer)
						}
						if level == "ZIP Codec" {
							var pending bytes.Buffer
							zipResult, err := pkg.WriteZIP(ctx, source, &pending, pkg.ZIPOptions{DisplayDirectory: "Shared Fixture", Method: zip.Store}, l, support)
							requireCode(t, err, r.OperationReason)
							if zipResult != (pkg.ZIPWriteResult{}) || pending.Len() != 0 {
								t.Fatal("bare ZIP writer accepted negative source", zipResult, pending.Len())
							}
						}
						if virtual != nil {
							for _, p := range virtual.opens {
								if strings.HasPrefix(p, "../") {
									t.Fatal("unsafe path opened", p)
								}
							}
						}
						return
					}
					if operationErr != nil || output == nil {
						t.Fatal(operationErr)
					}
					if level != "Directory Codec" && (transfer.PackageID != plan.Summary().PackageID || transfer.HEAD != plan.Summary().HEAD || transfer.Output.HistoryCompleteness != pkg.HistoryFull) {
						t.Fatal("publication result disagrees with actual output", transfer)
					}
					r.Operation = "lossless-published-round-trip"
					if level == "ZIP Codec" {
						if archiveHost.published != 1 || directory.published != 0 {
							t.Fatal("ZIP staging/final publication", r)
						}
					} else if directory.published != 1 || archiveHost.published != 0 {
						t.Fatal("Directory publication", r)
					}
					out, err := pkg.Verify(ctx, output, l, pkg.VerificationOptions{Support: support})
					if err != nil {
						t.Fatal(err)
					}
					r.Output = &out.Result
					compareFrozenResult(t, out.Result, want)
					r.HistoricalRestores = levelPreservation(t, source, output, l, support)
					r.RawAndSubjectPreserved = true
					if level == "ZIP Codec" {
						var pending bytes.Buffer
						store, err := pkg.WriteZIP(ctx, source, &pending, pkg.ZIPOptions{DisplayDirectory: "Alternate Wrapper", Method: zip.Store}, l, support)
						if err != nil || store.Bytes != int64(pending.Len()) {
							t.Fatal("STORE writer", store, err)
						}
						stored := zipSource(t, pending.Bytes(), l)
						view, err := pkg.Verify(ctx, stored, l, pkg.VerificationOptions{Support: support})
						if err != nil {
							t.Fatal(err)
						}
						compareFrozenResult(t, view.Result, want)
						r.HistoricalRestores += levelPreservation(t, source, stored, l, support)
						r.ZIPMethods = []string{"DEFLATE", "STORE"}
						if _, err = os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
							t.Fatal("temporary tree exposed", err)
						}
					}
				})
			}
		})
	}
	if len(report.Cases) != 136 {
		t.Fatal("missing level cases", len(report.Cases))
	}
	if path := os.Getenv("PACKAGE_GO_CONFORMANCE_REPORT"); path != "" {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestS11SharedWriterOperations(t *testing.T) {
	m := sharedLevelManifest(t)
	ctx := context.Background()
	l := conformancePolicy()
	for _, level := range []string{"Core Writer", "Complete Writer"} {
		t.Run(level, func(t *testing.T) {
			for _, op := range m.WriterOperations {
				t.Run(op.ID, func(t *testing.T) {
					support := pkg.CompleteSupport()
					baseline := "minimal-valid"
					if level == "Core Writer" {
						support = pkg.CoreSupport()
						baseline = "core-minimal"
					}
					if op.ID == "stale-head" {
						baseline = "complete-history"
						support = pkg.CompleteSupport()
					}
					s := treeFixture(t, baseline)
					before := map[string][]byte{}
					for p, b := range s.data {
						before[p] = bytes.Clone(b)
					}
					host := newCommitHost(s)
					if op.ID == "stale-head" {
						if pkg.HEAD(strings.TrimSuffix(string(s.data[".packtell/HEAD"]), "\n")) != op.ActualHEAD {
							t.Fatal("authority baseline does not match writer operation")
						}
						record, err := pkg.Commit(ctx, host, request(op.ExpectedHEAD), l, support)
						requireCode(t, err, op.ExpectedReason)
						if record.Version.VersionID != "" || !equalTransferBytes(before, s.data) || slices.Contains(host.operations, "publish") || slices.Contains(host.operations, "version-stage") || op.PublishedVersions != 0 {
							t.Fatal("stale operation changed authority", record, host.operations)
						}
						t.Logf("S11_WRITER level=%s operation=%s expected_reason=%s actual_reason=%s published_versions=0 old_raw_unchanged=true", level, op.ID, op.ExpectedReason, op.ExpectedReason)
					} else if op.ID == "linear-commit" {
						s.setFile("hello.txt", []byte("writer operation changed bytes\n"))
						record, err := pkg.Commit(ctx, host, request(pkg.HEAD(op.Parent)), l, support)
						if err != nil {
							t.Fatal(err)
						}
						if record.Version.ParentVersionID == nil || *record.Version.ParentVersionID != op.ExpectedParent || record.Version.Ordinal != op.ExpectedOrdinal || op.Ordinal != op.ExpectedOrdinal {
							t.Fatal("linear operation", record)
						}
						for p, b := range before {
							if strings.HasPrefix(p, ".packtell/") && p != ".packtell/HEAD" && !bytes.Equal(b, s.data[p]) {
								t.Fatal("old portable authority changed", p)
							}
						}
						if !reflect.DeepEqual(host.operations, []string{"begin", "object-stage", "object-close", "version-stage", "publish", "close"}) {
							t.Fatal("HEAD publication not last", host.operations)
						}
						view, err := pkg.Verify(ctx, s, l, pkg.VerificationOptions{Support: support, ProveCompleteness: true})
						if err != nil || view.Result.HistoryCompleteness != pkg.HistoryFull || view.Result.WorkingState != pkg.WorkingClean {
							t.Fatal(view, err)
						}
						t.Logf("S11_WRITER level=%s operation=%s actual_parent=%s actual_ordinal=%d published_versions=1 history_full=true", level, op.ID, *record.Version.ParentVersionID, record.Version.Ordinal)
					} else {
						t.Fatal("unhandled frozen writer operation", op.ID)
					}
				})
			}
		})
	}
}

func TestS11SharedCryptoAndInvariants(t *testing.T) {
	// Reuse the actual independent vector adapters inside this declared gate.
	t.Run("canonical-positive-negative-exact-bytes", TestCanonicalFrozenExactBytesAndDigests)
	t.Run("version-subject-exact-derivation", TestVersionSubjectFrozenExactDerivation)
	t.Run("signing-input-fixed-signature-and-trust", TestFrozenSigningInputSignatureAndIndependentTrust)
	t.Run("later-evidence-subject-signature-delivery-invariance", TestFrozenEvidenceAppendPreservesOriginalAuthorityAndSignatureBytes)
	b, err := fs.ReadFile(conformance.Assets(), "vectors/crypto.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Seed        string        `json:"seed_hex"`
		Public      string        `json:"public_key_base64url"`
		Fingerprint pkg.ContentID `json:"fingerprint"`
		Verify      bool          `json:"signature_verify"`
		Bad         string        `json:"bad_signature_fixture"`
		Invariants  []struct {
			Before        string        `json:"before"`
			After         string        `json:"after"`
			VersionID     pkg.VersionID `json:"package_version_id"`
			SubjectDigest pkg.ContentID `json:"subject_digest"`
			Unchanged     []string      `json:"unchanged"`
		} `json:"invariants"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Seed == "" || !v.Verify || v.Bad != "../fixtures/bad-signature.json" || len(v.Invariants) != 1 {
		t.Fatal("unhandled vector contract", v)
	}
	key := ed25519.NewKeyFromSeed(decodeHex(t, v.Seed))
	if base64.RawURLEncoding.EncodeToString(key[32:]) != v.Public || pkg.ContentIDForBytes(key[32:]) != v.Fingerprint {
		t.Fatal("frozen public key/fingerprint")
	}
	for _, invariant := range v.Invariants {
		before := treeFixture(t, strings.TrimSuffix(filepath.Base(invariant.Before), ".json"))
		after := treeFixture(t, strings.TrimSuffix(filepath.Base(invariant.After), ".json"))
		_, a, err := pkg.DeriveSubjectAt(context.Background(), before, invariant.VersionID, conformancePolicy(), pkg.CompleteSupport())
		if err != nil {
			t.Fatal(err)
		}
		_, b, err := pkg.DeriveSubjectAt(context.Background(), after, invariant.VersionID, conformancePolicy(), pkg.CompleteSupport())
		if err != nil || a != invariant.SubjectDigest || b != invariant.SubjectDigest {
			t.Fatal("frozen invariant subject", a, b, invariant.SubjectDigest, err)
		}
		for _, name := range invariant.Unchanged {
			switch name {
			case "version_subject": // Exact subject comparison above.
			case "version_signature":
				for p, bytesBefore := range before.data {
					if strings.HasPrefix(p, ".packtell/verification/versions/") && !bytes.Equal(bytesBefore, after.data[p]) {
						t.Fatal("signature changed", p)
					}
				}
			case "delivery_digest":
				next := map[pkg.DeliveryID]pkg.Delivery{}
				for _, d := range deliveriesFromSource(t, after) {
					next[d.DeliveryID] = d
				}
				for _, old := range deliveriesFromSource(t, before) {
					current, ok := next[old.DeliveryID]
					if !ok {
						t.Fatal("lost Delivery", old.DeliveryID)
					}
					a, err := pkg.DeliveryDigest(context.Background(), old, conformancePolicy())
					if err != nil {
						t.Fatal(err)
					}
					b, err := pkg.DeliveryDigest(context.Background(), current, conformancePolicy())
					if err != nil || a != b {
						t.Fatal("receipt-bound Delivery digest changed", a, b, err)
					}
				}
			default:
				t.Fatal("unhandled frozen invariant", name)
			}
		}
	}
	// Authority fixture pairs prove ID continuity with separate path/content facts.
	baseline, err := pkg.ReadRoot(context.Background(), treeFixture(t, "minimal-valid"), conformancePolicy(), pkg.CompleteSupport())
	if err != nil {
		t.Fatal(err)
	}
	prior := baseline.HeadManifest.Entries[0]
	oldPaths, err := baseline.HeadManifest.Paths(context.Background(), conformancePolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"renamed-file", "moved-file", "modified-file"} {
		root, err := pkg.ReadRoot(context.Background(), treeFixture(t, name), conformancePolicy(), pkg.CompleteSupport())
		if err != nil {
			t.Fatal(err)
		}
		paths, err := root.HeadManifest.Paths(context.Background(), conformancePolicy())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range root.HeadManifest.Entries {
			if e.Kind != "file" {
				continue
			}
			if e.FileID != prior.FileID {
				t.Fatal("fixture pair lost FileID", name)
			}
			found = true
			if name == "modified-file" {
				if paths[e.ID()] != oldPaths[prior.ID()] || e.ContentID == prior.ContentID {
					t.Fatal("modified pair", e)
				}
			} else if paths[e.ID()] == oldPaths[prior.ID()] || e.ContentID != prior.ContentID {
				t.Fatal("rename/move pair", e)
			}
		}
		if !found {
			t.Fatal("pair lost file", name)
		}
	}
}
