// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

type testArchiveSource struct {
	data                                          []byte
	beginError, checkError, closeError, readError error
	begins, checks, closes                        int
	readHook                                      func(int64)
}
type testArchiveSnapshot struct {
	source *testArchiveSource
	data   []byte
}

func (s *testArchiveSource) BeginArchive(ctx context.Context) (pkg.ArchiveSnapshot, error) {
	s.begins++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.beginError != nil {
		return nil, s.beginError
	}
	return &testArchiveSnapshot{s, bytes.Clone(s.data)}, nil
}
func (s *testArchiveSnapshot) Size() int64 { return int64(len(s.data)) }
func (s *testArchiveSnapshot) ReadAt(ctx context.Context, p []byte, offset int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.source.readHook != nil {
		s.source.readHook(offset)
	}
	if s.source.readError != nil {
		return 0, s.source.readError
	}
	return bytes.NewReader(s.data).ReadAt(p, offset)
}
func (s *testArchiveSnapshot) CheckStable(ctx context.Context) error {
	s.source.checks++
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.source.checkError
}
func (s *testArchiveSnapshot) Close() error { s.source.closes++; return s.source.closeError }
func zipFixture(t testing.TB, name string) ([]byte, pkg.Result) {
	t.Helper()
	raw, err := fs.ReadFile(conformance.Assets(), "fixtures/"+name+".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input struct {
			Bytes string `json:"bytes_base64"`
		}
		Expected pkg.Result
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(f.Input.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return b, f.Expected
}
func zipSource(t testing.TB, b []byte, l pkg.Limits) pkg.SnapshotSource {
	t.Helper()
	source, err := pkg.NewZIPSource(&testArchiveSource{data: b}, l)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
func readZIPTree(t testing.TB, b []byte, l pkg.Limits) ([]pkg.TreeEntry, map[string][]byte) {
	t.Helper()
	ctx := context.Background()
	s, err := zipSource(t, b, l).BeginSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := s.List(ctx, l.MaxEntries)
	if err != nil {
		t.Fatal(err)
	}
	data := map[string][]byte{}
	for _, e := range entries {
		if e.Kind != "file" {
			continue
		}
		r, err := s.Open(ctx, e.Path)
		if err != nil {
			t.Fatal(err)
		}
		data[e.Path], err = io.ReadAll(r)
		err = errors.Join(err, r.Close())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = s.CheckStable(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	return entries, data
}
func TestS09FrozenZIPReaders(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	var beforeEntries []pkg.TreeEntry
	var before map[string][]byte
	for _, name := range []string{"zip-wrapped", "zip-unwrapped", "zip-traversal", "zip-duplicate"} {
		t.Run(name, func(t *testing.T) {
			b, expected := zipFixture(t, name)
			s, err := zipSource(t, b, l).BeginSnapshot(ctx)
			if name == "zip-traversal" || name == "zip-duplicate" {
				if s != nil {
					_ = s.Close()
					t.Fatal("unsafe ZIP exposed a tree")
				}
				requireCode(t, err, expected.ReasonCodes[0])
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			h, err := pkg.ReadHistory(ctx, s, l, support)
			if err != nil || h.Root.Recognition != expected.Recognition || len(h.Versions) != 1 {
				t.Fatal(h, err)
			}
			content, err := pkg.VerifyCommittedContent(ctx, s, l, support)
			if err != nil || content.Integrity != expected.CommittedIntegrity || len(content.Missing) != 0 || len(content.Invalid) != 0 {
				t.Fatal(content, err)
			}
			memory, err := pkg.ReadPortableMemory(ctx, s, l, support)
			if err != nil || len(memory.MissingPaths) != 0 {
				t.Fatal(memory, err)
			}
			signatures, err := pkg.VerifySignatures(ctx, s, l, support, nil)
			if err != nil || signatures.State != expected.Signature || signatures.Identity != expected.Identity {
				t.Fatal(signatures, err)
			}
			evidence, err := pkg.VerifyEvidence(ctx, s, l, support, nil)
			if err != nil || evidence.State != expected.Evidence || evidence.Online != expected.Online {
				t.Fatal(evidence, err)
			}
			if err = s.CheckStable(ctx); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			scan, err := pkg.Scan(ctx, zipSource(t, b, l), l, support, nil)
			if err != nil || scan.State != expected.WorkingState {
				t.Fatal(scan, err)
			}
			entries, data := readZIPTree(t, b, l)
			if name == "zip-wrapped" {
				beforeEntries, before = entries, data
			} else if !slices.Equal(beforeEntries, entries) || !reflect.DeepEqual(before, data) {
				t.Fatal("wrapped/unwrapped trees differ")
			}
		})
	}
}

func writeFixtureZIP(t testing.TB, s *memorySource, wrapper string, method uint16, reverse bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entries := slices.Clone(s.entries)
	if reverse {
		slices.Reverse(entries)
	}
	for _, e := range entries {
		name := e.Path
		if wrapper != "" {
			name = wrapper + "/" + name
		}
		if e.Kind == "directory" && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		h := &zip.FileHeader{Name: name, Method: method, Flags: 0x800, Modified: time.Date(2020, 2, 3, 4, 5, 6, 0, time.UTC)}
		if e.Kind == "directory" {
			h.SetMode(fs.ModeDir | 0755)
		} else {
			h.SetMode(0644)
		}
		w, err := writer.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == "file" {
			if _, err = w.Write(s.data[e.Path]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestZIPWriterSubjectAndByteInvariance(t *testing.T) {
	ctx, l, support := context.Background(), pkg.DefaultLimits(), supportAllVocabulary()
	for _, fixture := range []string{"minimal-valid", "complete-history", "dirty-working-tree", "moved-file", "unknown-optional-extension", "later-evidence-append", "bad-signature"} {
		t.Run(fixture, func(t *testing.T) {
			source := treeFixture(t, fixture)
			source.entries = append(source.entries, pkg.TreeEntry{Path: "empty/nested", Kind: "directory"})
			wantEntries, err := pkg.PreflightTree(ctx, source.entries, l)
			if err != nil {
				t.Fatal(err)
			}
			history, err := pkg.ReadHistory(ctx, source, l, support)
			if err != nil {
				t.Fatal(err)
			}
			var priorArtifact pkg.ContentID
			for _, option := range []pkg.ZIPOptions{{DisplayDirectory: "Demo", Method: zip.Store}, {DisplayDirectory: "別名", Method: zip.Deflate, CompressionLevel: flate.BestCompression}, {DisplayDirectory: "Demo", Method: zip.Deflate, CompressionLevel: flate.BestSpeed}, {DisplayDirectory: ".PACKTELL", Method: zip.Store}} {
				var pending bytes.Buffer
				result, err := pkg.WriteZIP(ctx, source, &pending, option, l, support)
				if fixture == "bad-signature" {
					requireCode(t, err, pkg.ReasonBadSignature)
					if result != (pkg.ZIPWriteResult{}) || pending.Len() != 0 {
						t.Fatal("bad signature produced writer output", result, pending.Len())
					}
					view, err := pkg.Verify(ctx, source, l, pkg.VerificationOptions{Support: pkg.CompleteSupport()})
					if err != nil || view.Result.Signature != pkg.SignatureInvalid || view.Result.HistoryCompleteness != pkg.HistoryFull {
						t.Fatal("original independent proof changed", view, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(pending.Bytes())
				if result.ArtifactDigest != pkg.ContentID("sha256:"+hex.EncodeToString(hash[:])) || result.Bytes != int64(pending.Len()) || result.PackageID != history.Root.Package.PackageID || result.HEAD != history.Root.HEAD {
					t.Fatal(result)
				}
				if priorArtifact != "" && result.ArtifactDigest == priorArtifact {
					t.Fatal("container variants should differ in this test")
				}
				priorArtifact = result.ArtifactDigest
				entries, data := readZIPTree(t, pending.Bytes(), l)
				if !slices.Equal(entries, wantEntries) || !reflect.DeepEqual(data, source.data) {
					t.Fatal("writer lost bytes or empty folders")
				}
				s, err := zipSource(t, pending.Bytes(), l).BeginSnapshot(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, version := range history.Versions {
					_, want, err := pkg.DeriveSubjectAt(ctx, source, version.Version.VersionID, l, support)
					if err != nil {
						t.Fatal(err)
					}
					_, got, err := pkg.DeriveSubjectAt(ctx, s, version.Version.VersionID, l, support)
					if err != nil || want != got {
						t.Fatal(got, want, err)
					}
				}
				wantSignatures, err := pkg.VerifySignatures(ctx, source, l, support, nil)
				if err != nil {
					t.Fatal(err)
				}
				gotSignatures, err := pkg.VerifySignatures(ctx, s, l, support, nil)
				if err != nil || gotSignatures.State != wantSignatures.State || gotSignatures.Identity != wantSignatures.Identity || len(gotSignatures.Items) != len(wantSignatures.Items) {
					t.Fatal("codec changed signature dimension", gotSignatures, wantSignatures, err)
				}
				wantEvidence, err := pkg.VerifyEvidence(ctx, source, l, support, nil)
				if err != nil {
					t.Fatal(err)
				}
				gotEvidence, err := pkg.VerifyEvidence(ctx, s, l, support, nil)
				if err != nil || gotEvidence.State != wantEvidence.State || len(gotEvidence.Items) != len(wantEvidence.Items) || len(gotEvidence.Deliveries) != len(wantEvidence.Deliveries) {
					t.Fatal("codec changed evidence dimension", gotEvidence, wantEvidence, err)
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// Independent standard writer: reversed order/mtime/permissions and
			// unwrapped presentation preserve the same raw logical tree.
			b := writeFixtureZIP(t, source, "", zip.Deflate, true)
			entries, data := readZIPTree(t, b, l)
			if !slices.Equal(entries, wantEntries) || !reflect.DeepEqual(data, source.data) {
				t.Fatal("metadata/order variant changed tree")
			}
		})
	}
}

type zipLocations struct {
	local, central int
	name           string
	data           int
	compressed     uint32
}

func locateZIP(t testing.TB, b []byte) []zipLocations {
	t.Helper()
	end := bytes.LastIndex(b, []byte{'P', 'K', 5, 6})
	if end < 0 {
		t.Fatal("no EOCD")
	}
	cd := int(binary.LittleEndian.Uint32(b[end+16:]))
	count := int(binary.LittleEndian.Uint16(b[end+10:]))
	out := []zipLocations{}
	for i := 0; i < count; i++ {
		if binary.LittleEndian.Uint32(b[cd:]) != 0x02014b50 {
			t.Fatal("central marker")
		}
		n, x, c := int(binary.LittleEndian.Uint16(b[cd+28:])), int(binary.LittleEndian.Uint16(b[cd+30:])), int(binary.LittleEndian.Uint16(b[cd+32:]))
		local := int(binary.LittleEndian.Uint32(b[cd+42:]))
		data := local + 30 + int(binary.LittleEndian.Uint16(b[local+26:])) + int(binary.LittleEndian.Uint16(b[local+28:]))
		out = append(out, zipLocations{local, cd, string(b[cd+46 : cd+46+n]), data, binary.LittleEndian.Uint32(b[cd+20:])})
		cd += 46 + n + x + c
	}
	return out
}
func TestZIPCentralLocalAdversarialCases(t *testing.T) {
	l := pkg.DefaultLimits()
	base, _ := zipFixture(t, "zip-unwrapped")
	for _, name := range []string{"local-name", "local-method", "local-flags", "local-size", "local-crc", "central-encryption", "strong-encryption", "reserved-flags", "unsupported-method", "special-link", "special-fifo", "reparse", "disk-entry", "disk-end", "count", "extent", "offset-overlap", "utf8-flag", "invalid-utf8", "truncated-end", "bomb-policy", "entry-policy", "unicode-extra-ignored", "descriptor-size", "descriptor-crc"} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(base)
			policy := l
			locations := locateZIP(t, b)
			r := locations[0]
			end := bytes.LastIndex(b, []byte{'P', 'K', 5, 6})
			switch name {
			case "local-name":
				b[r.local+30] ^= 1
			case "local-method":
				binary.LittleEndian.PutUint16(b[r.local+8:], 0)
			case "local-flags":
				binary.LittleEndian.PutUint16(b[r.local+6:], 0x800)
			case "local-size":
				binary.LittleEndian.PutUint32(b[r.local+22:], 999)
			case "local-crc":
				binary.LittleEndian.PutUint32(b[r.local+14:], 99)
			case "central-encryption":
				binary.LittleEndian.PutUint16(b[r.central+8:], 1)
			case "strong-encryption":
				binary.LittleEndian.PutUint16(b[r.central+8:], 64)
			case "reserved-flags":
				binary.LittleEndian.PutUint16(b[r.central+8:], 1<<14)
			case "unsupported-method":
				binary.LittleEndian.PutUint16(b[r.central+10:], 99)
			case "special-link":
				binary.LittleEndian.PutUint32(b[r.central+38:], 0xa1ff0000)
			case "special-fifo":
				binary.LittleEndian.PutUint32(b[r.central+38:], 0x11a40000)
			case "reparse":
				binary.LittleEndian.PutUint32(b[r.central+38:], 0x400)
			case "disk-entry":
				binary.LittleEndian.PutUint16(b[r.central+34:], 1)
			case "disk-end":
				binary.LittleEndian.PutUint16(b[end+4:], 1)
			case "count":
				binary.LittleEndian.PutUint16(b[end+8:], 13)
				binary.LittleEndian.PutUint16(b[end+10:], 13)
			case "extent":
				binary.LittleEndian.PutUint32(b[r.central+20:], 0xffffffff)
			case "offset-overlap":
				binary.LittleEndian.PutUint32(b[locations[1].central+42:], 0)
			case "utf8-flag": // valid UTF-8 spelling but absent flag, same byte length
				copy(b[r.central+46:], []byte("é"))
				copy(b[r.local+30:], []byte("é"))
			case "invalid-utf8":
				b[r.central+46] = 255
				b[r.local+30] = 255
			case "truncated-end":
				b = b[:len(b)-1]
			case "bomb-policy":
				policy.MaxCompressionRatio = 1
			case "entry-policy":
				policy.MaxEntries = 1
			case "unicode-extra-ignored":
				// A safe raw name with an unsafe Unicode path-extra override is
				// accepted using only the original entry name.
				s := treeFixture(t, "minimal-valid")
				var buffer bytes.Buffer
				w := zip.NewWriter(&buffer)
				for _, e := range s.entries {
					p := e.Path
					if e.Kind == "directory" && !strings.HasSuffix(p, "/") {
						p += "/"
					}
					h := &zip.FileHeader{Name: p, Method: zip.Store, Flags: 0x800}
					if e.Kind == "directory" {
						h.SetMode(fs.ModeDir | 0700)
					} else {
						h.SetMode(0600)
					}
					payload := append([]byte{1, 0, 0, 0, 0}, []byte("../unsafe-override")...)
					h.Extra = append([]byte{0x75, 0x70, byte(len(payload)), 0}, payload...)
					out, err := w.CreateHeader(h)
					if err != nil {
						t.Fatal(err)
					}
					if e.Kind == "file" {
						_, _ = out.Write(s.data[e.Path])
					}
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				b = buffer.Bytes()
			case "descriptor-size", "descriptor-crc":
				b = writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Store, false)
				r = locateZIP(t, b)[0]
				dd := r.data + int(r.compressed)
				if name == "descriptor-size" {
					binary.LittleEndian.PutUint32(b[dd+8:], 1)
				} else {
					binary.LittleEndian.PutUint32(b[dd+4:], 1)
				}
			}
			s, err := zipSource(t, b, policy).BeginSnapshot(context.Background())
			if name == "unicode-extra-ignored" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = pkg.ReadHistory(context.Background(), s, l, supportAllVocabulary()); err != nil {
					t.Fatal(err)
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if s != nil {
				_ = s.Close()
				t.Fatal("unsafe tree exposed")
			}
			if err == nil {
				t.Fatal("unsafe ZIP accepted")
			}
			if name == "bomb-policy" || name == "entry-policy" {
				requireCode(t, err, pkg.ReasonResourceLimit)
			}
		})
	}
}

func TestZIPTraversalCollisionAndRootPreflight(t *testing.T) {
	for _, name := range []string{"case-conflict", "unicode-normalization-conflict", "traversal", "absolute", "backslash", "drive", "duplicate", "file-parent", "multiple-roots", "extra-sibling", "file-directory-conflict"} {
		t.Run(name, func(t *testing.T) {
			source := treeFixture(t, "minimal-valid")
			wrapper := "Demo"
			expected := pkg.ReasonUnsafeArchive
			switch name {
			case "case-conflict":
				source = treeFixture(t, name)
				expected = pkg.ReasonCaseConflict
			case "unicode-normalization-conflict":
				source = treeFixture(t, name)
				expected = pkg.ReasonUnicodeNormalizationConflict
			case "traversal":
				source.addFile("../bad", []byte("x"))
				expected = pkg.ReasonPathTraversal
			case "absolute":
				wrapper = ""
				source.addFile("/bad", []byte("x"))
				expected = pkg.ReasonPathTraversal
			case "backslash":
				source.addFile("bad\\name", []byte("x"))
				expected = pkg.ReasonPathTraversal
			case "drive":
				wrapper = ""
				source.addFile("C:/bad", []byte("x"))
				expected = pkg.ReasonPathTraversal
			case "duplicate":
				source.entries = append(source.entries, source.entries[0])
			case "file-parent":
				source.addFile("hello.txt/child", []byte("x"))
				expected = pkg.ReasonInvalidPath
			case "multiple-roots":
				wrapper = ""
				for _, e := range slices.Clone(source.entries) {
					e.Path = "Another/" + e.Path
					source.entries = append(source.entries, e)
				}
				for p, b := range mapsCloneBytes(source.data) {
					source.data["Another/"+p] = b
				}
			case "extra-sibling":
				wrapper = ""
				for i, e := range source.entries {
					source.entries[i].Path = "Demo/" + e.Path
				}
				for p, b := range mapsCloneBytes(source.data) {
					source.data["Demo/"+p] = b
					delete(source.data, p)
				}
				source.addFile("sibling", []byte("x"))
			case "file-directory-conflict":
				source.entries = append(source.entries, pkg.TreeEntry{Path: "hello.txt/", Kind: "directory"})
			}
			b := writeFixtureZIP(t, source, wrapper, zip.Store, false)
			s, err := zipSource(t, b, pkg.DefaultLimits()).BeginSnapshot(context.Background())
			if s != nil {
				_ = s.Close()
				t.Fatal("unsafe tree exposed")
			}
			requireCode(t, err, expected)
		})
	}
	for _, name := range []string{"case-conflict", "unicode-normalization-conflict", "missing-object", "missing-parent"} {
		t.Run("writer-before-output-"+name, func(t *testing.T) {
			var pending bytes.Buffer
			out, err := pkg.WriteZIP(context.Background(), treeFixture(t, name), &pending, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Store}, pkg.DefaultLimits(), supportAllVocabulary())
			if err == nil || out != (pkg.ZIPWriteResult{}) || pending.Len() != 0 {
				t.Fatal(out, err, pending.Len())
			}
		})
	}
}
func mapsCloneBytes(in map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for p, b := range in {
		out[p] = bytes.Clone(b)
	}
	return out
}

func TestZIPCRCActualExpansionAndCompressedExtent(t *testing.T) {
	for _, name := range []string{"wrong-crc", "truncated-deflate", "actual-expansion", "trailing-compressed-junk", "empty-directory-crc"} {
		t.Run(name, func(t *testing.T) {
			b := writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Store, false)
			if name == "truncated-deflate" || name == "trailing-compressed-junk" || name == "actual-expansion" {
				b = writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Deflate, false)
			}
			locs := locateZIP(t, b)
			var r zipLocations
			for _, x := range locs {
				if x.name == "hello.txt" {
					r = x
				}
			}
			switch name {
			case "wrong-crc":
				binary.LittleEndian.PutUint32(b[r.central+16:], 0)
				binary.LittleEndian.PutUint32(b[r.data+int(r.compressed)+4:], 0)
			case "truncated-deflate":
				b[r.data] = 255
			case "actual-expansion":
				binary.LittleEndian.PutUint32(b[r.central+24:], 5)
				binary.LittleEndian.PutUint32(b[r.data+int(r.compressed)+12:], 5)
			case "trailing-compressed-junk": // replace the compressed stream with
				// a valid empty deflate prefix followed by old bytes.
				copy(b[r.data:], []byte{3, 0})
				binary.LittleEndian.PutUint32(b[r.central+24:], 0)
				binary.LittleEndian.PutUint32(b[r.central+16:], 0)
				dd := r.data + int(r.compressed)
				binary.LittleEndian.PutUint32(b[dd+4:], 0)
				binary.LittleEndian.PutUint32(b[dd+12:], 0)
			case "empty-directory-crc":
				for _, x := range locs {
					if strings.HasSuffix(x.name, "/") {
						r = x
						break
					}
				}
				binary.LittleEndian.PutUint32(b[r.central+16:], 1)
				binary.LittleEndian.PutUint32(b[r.local+14:], 1)
			}
			s, err := zipSource(t, b, pkg.DefaultLimits()).BeginSnapshot(context.Background())
			if name == "empty-directory-crc" {
				if s != nil {
					_ = s.Close()
					t.Fatal("invalid extent/directory accepted")
				}
				requireCode(t, err, pkg.ReasonUnsafeArchive)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			stream, err := s.Open(context.Background(), "hello.txt")
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(stream)
			err = errors.Join(err, stream.Close())
			requireCode(t, err, pkg.ReasonUnsafeArchive)
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestZIP64WriterAndBoundedReader(t *testing.T) {
	if testing.Short() {
		t.Skip("large-entry-count Zip64 behavior")
	}
	source := treeFixture(t, "core-minimal")
	for i := 0; i < 65536; i++ {
		source.entries = append(source.entries, pkg.TreeEntry{Path: fmt.Sprintf("empty-%05d", i), Kind: "directory"})
	}
	l := pkg.DefaultLimits()
	l.MaxEntries = 70000
	l.MaxTotalBytes = 32 << 20
	var pending bytes.Buffer
	result, err := pkg.WriteZIP(context.Background(), source, &pending, pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Store}, l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pending.Bytes(), []byte{'P', 'K', 6, 6}) || !bytes.Contains(pending.Bytes(), []byte{'P', 'K', 6, 7}) || result.Bytes != int64(pending.Len()) {
		t.Fatal("Zip64 writer did not emit 64-bit end/locator")
	}
	s, err := zipSource(t, pending.Bytes(), l).BeginSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := s.List(context.Background(), l.MaxEntries)
	if err != nil || len(entries) < 65536 {
		t.Fatal(len(entries), err)
	}
	if _, err = pkg.ReadHistory(context.Background(), s, l, supportAllVocabulary()); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	small := l
	small.MaxEntries = 100
	s, err = zipSource(t, pending.Bytes(), small).BeginSnapshot(context.Background())
	if s != nil {
		_ = s.Close()
		t.Fatal("Zip64 count ignored")
	}
	requireCode(t, err, pkg.ReasonResourceLimit)
}

func TestZIPHostFailuresAndCancellation(t *testing.T) {
	b, _ := zipFixture(t, "zip-wrapped")
	fault := errors.New("ZIP Host fault")
	for _, phase := range []string{"begin", "read", "stable", "close", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			host := &testArchiveSource{data: b}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch phase {
			case "begin":
				host.beginError = fault
			case "read":
				host.readError = fault
			case "stable":
				host.checkError = fault
			case "close":
				host.closeError = fault
			case "cancel":
				host.readHook = func(int64) { cancel() }
			}
			source, err := pkg.NewZIPSource(host, pkg.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			s, err := source.BeginSnapshot(ctx)
			if phase == "close" {
				if err != nil {
					t.Fatal(err)
				}
				if err = s.Close(); !errors.Is(err, fault) {
					t.Fatal(err)
				}
				return
			}
			if s != nil {
				_ = s.Close()
				t.Fatal("failure returned usable tree")
			}
			expected := fault
			if phase == "cancel" {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) {
				t.Fatal(err)
			}
			if phase != "begin" && host.closes != 1 {
				t.Fatal("archive observation leaked", host.closes)
			}
		})
	}
	for _, phase := range []string{"write", "source-stable", "source-close", "canceled", "invalid-display", "unsupported-method", "ratio-policy"} {
		t.Run("writer-"+phase, func(t *testing.T) {
			source := treeFixture(t, "minimal-valid")
			var buffer bytes.Buffer
			var pending io.Writer = &buffer
			options := pkg.ZIPOptions{DisplayDirectory: "Demo", Method: zip.Deflate, CompressionLevel: flate.BestCompression}
			ctx := context.Background()
			l := pkg.DefaultLimits()
			switch phase {
			case "write":
				pending = writerFailure{fault}
			case "source-stable":
				source.checkError = fault
			case "source-close":
				source.closeError = fault
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "invalid-display":
				options.DisplayDirectory = "../bad"
			case "unsupported-method":
				options.Method = 99
			case "ratio-policy":
				l.MaxCompressionRatio = 1
			}
			out, err := pkg.WriteZIP(ctx, source, pending, options, l, supportAllVocabulary())
			if err == nil || out != (pkg.ZIPWriteResult{}) {
				t.Fatal(out, err)
			}
		})
	}
}

type writerFailure struct{ err error }

func (w writerFailure) Write([]byte) (int, error) { return 0, w.err }

type codecContentFault struct {
	pkg.TreeReader
	phase string
	cause error
}

func (s codecContentFault) Open(ctx context.Context, p string) (io.ReadCloser, error) {
	if !strings.HasPrefix(p, ".packtell/objects/sha256/") {
		return s.TreeReader.Open(ctx, p)
	}
	if s.phase == "open" {
		return nil, s.cause
	}
	r, err := s.TreeReader.Open(ctx, p)
	if err != nil {
		return r, err
	}
	return &codecContentFaultStream{ReadCloser: r, phase: s.phase, cause: s.cause}, nil
}

type codecContentFaultStream struct {
	io.ReadCloser
	phase string
	cause error
}

func (s *codecContentFaultStream) Read(p []byte) (int, error) {
	if s.phase == "read" {
		return 0, s.cause
	}
	return s.ReadCloser.Read(p)
}
func (s *codecContentFaultStream) Close() error {
	err := s.ReadCloser.Close()
	if s.phase == "close" {
		err = errors.Join(err, s.cause)
	}
	return err
}
func TestCommittedObjectsKeepCodecAndPolicyErrors(t *testing.T) {
	for _, code := range []pkg.ReasonCode{pkg.ReasonUnsafeArchive, pkg.ReasonResourceLimit} {
		for _, phase := range []string{"open", "read", "close"} {
			t.Run(string(code)+"-"+phase, func(t *testing.T) {
				source := codecContentFault{TreeReader: treeFixture(t, "minimal-valid"), phase: phase, cause: &pkg.ProtocolError{Code: code, Detail: "test codec/policy failure"}}
				report, err := pkg.VerifyCommittedContent(context.Background(), source, pkg.DefaultLimits(), supportAllVocabulary())
				requireCode(t, err, code)
				if report.Integrity != pkg.IntegrityNotChecked {
					t.Fatal("codec failure mislabeled semantic content", report)
				}
			})
		}
	}
}

func FuzzZIPWholeTreePreflight(f *testing.F) {
	for _, name := range []string{"zip-wrapped", "zip-unwrapped", "zip-traversal", "zip-duplicate"} {
		b, _ := zipFixture(f, name)
		f.Add(b)
	}
	f.Add([]byte("PK\x05\x06"))
	f.Add([]byte{})
	var tiny bytes.Buffer
	w := zip.NewWriter(&tiny)
	entry, err := w.CreateHeader(&zip.FileHeader{Name: ".packtell/format.json", Method: zip.Store, Flags: 0x800})
	if err != nil {
		f.Fatal(err)
	}
	if _, err = io.WriteString(entry, "{}"); err != nil {
		f.Fatal(err)
	}
	if err = w.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(tiny.Bytes())
	f.Add(forceSmallZIP64(f, tiny.Bytes()))
	f.Fuzz(func(t *testing.T, b []byte) {
		l := pkg.DefaultLimits()
		l.MaxEntries = 200
		l.MaxTotalBytes = 1 << 20
		l.MaxFileBytes = 1 << 20
		l.MaxPathBytes = 512
		l.MaxTreeDepth = 32
		l.MaxCompressionRatio = 100
		s, err := zipSource(t, b, l).BeginSnapshot(context.Background())
		if err != nil {
			if s != nil {
				t.Fatal("unsafe observation escaped")
			}
			return
		}
		entries, err := s.List(context.Background(), l.MaxEntries)
		if err != nil {
			t.Fatal(err)
		}
		validated, err := pkg.PreflightTree(context.Background(), entries, l)
		if err != nil || !slices.Equal(validated, entries) {
			t.Fatal("accepted tree unsafe", err)
		}
		for _, e := range entries {
			if e.Kind != "file" {
				continue
			}
			r, err := s.Open(context.Background(), e.Path)
			if err != nil {
				t.Fatal(err)
			}
			n, readErr := io.Copy(io.Discard, r)
			readErr = errors.Join(readErr, r.Close())
			if readErr == nil && n != e.Size {
				t.Fatal("false expanded size")
			}
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
