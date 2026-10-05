// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

type cryptoVector struct {
	Canonical []struct {
		Input  json.RawMessage `json:"input"`
		Hex    string          `json:"expected_utf8_hex"`
		Digest pkg.ContentID   `json:"expected_digest"`
	} `json:"canonical_json"`
	Invalid        []string        `json:"invalid_json"`
	Package        json.RawMessage `json:"package"`
	Version        json.RawMessage `json:"version"`
	Manifest       json.RawMessage `json:"manifest"`
	Subject        json.RawMessage `json:"subject"`
	ManifestDigest pkg.ContentID   `json:"manifest_digest"`
	SubjectHex     string          `json:"subject_canonical_hex"`
	SubjectDigest  pkg.ContentID   `json:"subject_digest"`
	SigningHex     string          `json:"signing_input_hex"`
	Envelope       json.RawMessage `json:"signature_envelope"`
}

func readCryptoVector(t *testing.T) cryptoVector {
	t.Helper()
	b, err := fs.ReadFile(conformance.Assets(), "vectors/crypto.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v cryptoVector
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func cryptoModels(t *testing.T) (pkg.Package, pkg.Version, pkg.Manifest) {
	t.Helper()
	ctx := context.Background()
	l := pkg.DefaultLimits()
	vec := readCryptoVector(t)
	p, err := pkg.ReadPackage(ctx, bytes.NewReader(vec.Package), l)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pkg.ReadVersion(ctx, bytes.NewReader(vec.Version), l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	m, err := pkg.ReadManifest(ctx, bytes.NewReader(vec.Manifest), l)
	if err != nil {
		t.Fatal(err)
	}
	return p, v, m
}
func TestCanonicalFrozenExactBytesAndDigests(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	v := readCryptoVector(t)
	for i, c := range v.Canonical {
		got, err := pkg.ReadCanonicalJSON(ctx, bytes.NewReader(c.Input), l)
		if err != nil {
			t.Fatal(i, err)
		}
		if !bytes.Equal(got, decodeHex(t, c.Hex)) || pkg.ContentIDForBytes(got) != c.Digest {
			t.Fatalf("frozen canonical %d got %x / %s", i, got, pkg.ContentIDForBytes(got))
		}
	}
	for _, raw := range v.Invalid {
		_, err := pkg.ReadCanonicalJSON(ctx, strings.NewReader(raw), l)
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
	// Every C0 code has precisely the frozen short/lowercase escape spelling.
	var text strings.Builder
	for i := 0; i < 32; i++ {
		text.WriteByte(byte(i))
	}
	out, err := pkg.CanonicalJSON(ctx, text.String(), l)
	if err != nil {
		t.Fatal(err)
	}
	want := `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`
	if string(out) != want {
		t.Fatalf("%q != %q", out, want)
	}
}
func TestCanonicalUTF8OrderingNoNormalizationAndExactBudgets(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	value := map[string]any{"😀": int64(1), "\ue000": int64(2), "a": "e\u0301/<>&\u2028\u2029"}
	out, err := pkg.CanonicalJSON(ctx, value, l)
	if err != nil || string(out) != `{"a":"é/<>&`+"\u2028\u2029"+`","`+"\ue000"+`":2,"😀":1}` {
		t.Fatal(string(out), err)
	}
	l.MaxJSONBytes = int64(len(out))
	if _, err = pkg.CanonicalJSON(ctx, value, l); err != nil {
		t.Fatal("exact canonical budget overestimated HTML bytes", err)
	}
	l.MaxJSONBytes--
	_, err = pkg.CanonicalJSON(ctx, value, l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	for _, v := range []any{1.0, json.Number("-0"), json.Number("1.0"), json.Number("1e0"), json.Number(" 1 "), int64(pkg.MaxProtocolInteger + 1), uint64(pkg.MaxProtocolInteger + 1), string([]byte{255}), map[string]any{string([]byte{255}): true}, struct{ X int }{1}} {
		_, err = pkg.CanonicalJSON(ctx, v, pkg.DefaultLimits())
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
	for _, v := range []any{int(1), int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1), json.Number("1")} {
		out, err = pkg.CanonicalJSON(ctx, v, pkg.DefaultLimits())
		if err != nil || string(out) != "1" {
			t.Fatal(out, err)
		}
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	_, err = pkg.CanonicalJSON(ctx, cycle, pkg.DefaultLimits())
	requireCode(t, err, pkg.ReasonResourceLimit)
	l = pkg.DefaultLimits()
	l.MaxEntries = 1
	_, err = pkg.CanonicalJSON(ctx, map[string]any{"a": 1, "b": 2}, l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	l = pkg.DefaultLimits()
	l.MaxJSONDepth = 1
	_, err = pkg.CanonicalJSON(ctx, []any{[]any{true}}, l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = pkg.CanonicalJSON(canceled, []any{}, pkg.DefaultLimits())
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Huge key inventories / shared strings stop before sorting/expansion.
	l = pkg.DefaultLimits()
	l.MaxJSONBytes = 1
	_, err = pkg.CanonicalJSON(ctx, map[string]any{strings.Repeat("x", 10000): nil}, l)
	requireCode(t, err, pkg.ReasonResourceLimit)
}
func TestVersionSubjectFrozenExactDerivation(t *testing.T) {
	p, v, m := cryptoModels(t)
	vec := readCryptoVector(t)
	ctx := context.Background()
	l := pkg.DefaultLimits()
	s, digest, err := pkg.DeriveVersionSubject(ctx, p, v, m, l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := s.Canonical(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, decodeHex(t, vec.SubjectHex)) || digest != vec.SubjectDigest || s.ManifestDigest != vec.ManifestDigest {
		t.Fatal(s, digest, string(canonical))
	}
	expected, err := pkg.ReadCanonicalJSON(ctx, bytes.NewReader(vec.Subject), l)
	if err != nil || !bytes.Equal(expected, canonical) {
		t.Fatal(err)
	}
	if s.ParentVersionID != nil || !bytes.Contains(canonical, []byte(`"parent_version_id":null`)) {
		t.Fatal("root parent omitted/non-null", s)
	}
	child := v
	childID := pkg.VersionID(memoryID(5))
	parent := v.VersionID
	child.VersionID = childID
	child.ParentVersionID = &parent
	child.Ordinal = 2
	m.VersionID = childID
	s, _, err = pkg.DeriveVersionSubject(ctx, p, child, m, l, supportAllVocabulary())
	if err != nil || s.ParentVersionID == nil || *s.ParentVersionID != parent {
		t.Fatal(s, err)
	}
	canonical, err = s.Canonical(ctx, l)
	if err != nil || !bytes.Contains(canonical, []byte(`"parent_version_id":"`+string(parent)+`"`)) {
		t.Fatal(string(canonical), err)
	}
}
func TestContentCommitmentDedupAndEmpty(t *testing.T) {
	_, _, m := cryptoModels(t)
	ctx := context.Background()
	l := pkg.DefaultLimits()
	first, err := pkg.ContentCommitment(ctx, m, l)
	if err != nil {
		t.Fatal(err)
	}
	copy := m.Entries[0]
	copy.FileID = pkg.FileID(memoryID(4))
	copy.Name = "copy.txt"
	m.Entries = append(m.Entries, copy)
	second, err := pkg.ContentCommitment(ctx, m, l)
	if err != nil || second != first {
		t.Fatal(second, err)
	}
	m.Entries[0].Name = "renamed.txt"
	third, err := pkg.ContentCommitment(ctx, m, l)
	if err != nil || third != first {
		t.Fatal(third, err)
	}
	m.Entries = []pkg.Entry{}
	empty, err := pkg.ContentCommitment(ctx, m, l)
	if err != nil || empty != pkg.ContentIDForBytes([]byte(pkg.ContentSetDomain+"\n[]")) {
		t.Fatal(empty, err)
	}
	m.Entries = []pkg.Entry{copy}
	m.Entries[0].ContentID = pkg.ContentIDForBytes(nil)
	m.Entries[0].Size = 0
	if _, err = pkg.ContentCommitment(ctx, m, l); err != nil {
		t.Fatal(err)
	}
	m.Entries[0].Extra = map[string]any{"bad": 1.1}
	_, err = pkg.ContentCommitment(ctx, m, l)
	requireCode(t, err, pkg.ReasonInvalidSchema)
}
func TestSubjectOptionalFactsBindButMutableAndContainersExcluded(t *testing.T) {
	ctx := context.Background()
	l := pkg.DefaultLimits()
	p, v, m := cryptoModels(t)
	original, digest, err := pkg.DeriveVersionSubject(ctx, p, v, m, l, supportAllVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	label := "sealed label"
	v.Label = &label
	v.Extra = map[string]any{"future": int64(7)}
	m.Extra = map[string]any{"future": true}
	m.Entries[0].Extra = map[string]any{"future": "fact"}
	changed, nextDigest, err := pkg.DeriveVersionSubject(ctx, p, v, m, l, supportAllVocabulary())
	if err != nil || nextDigest == digest || changed.VersionDigest == original.VersionDigest || changed.ManifestDigest == original.ManifestDigest || changed.ContentCommitment != original.ContentCommitment {
		t.Fatal(changed, nextDigest, err)
	}
	p, v, m = cryptoModels(t)
	v.SealedMetadata.Extra = map[string]any{"new": true}
	changed, _, err = pkg.DeriveVersionSubject(ctx, p, v, m, l, supportAllVocabulary())
	if err != nil || changed.SealedMetadataDigest == original.SealedMetadataDigest {
		t.Fatal(changed, err)
	}
	for _, name := range []string{"multi-delivery", "later-evidence-append"} {
		s := treeFixture(t, name)
		s.setFile("hello.txt", []byte("dirty working bytes"))
		s.setFile(".packtell/metadata/package.json", jsonBytes(t, pkg.Metadata{Schema: "orbifabric.package.metadata.v1", PackageID: p.PackageID, Title: "changed current title"}))
		derived, got, err := pkg.DeriveSubjectAt(ctx, s, pkg.VersionID(memoryID(2)), l, supportAllVocabulary())
		if err != nil || got != digest || !reflect.DeepEqual(derived, original) {
			t.Fatal(name, got, err)
		}
	}
}
func TestSubjectRejectsCallerInvalidDomainsRelationsAndExpansion(t *testing.T) {
	for _, name := range []string{"cross-ID", "root-ordinal", "self-parent", "entry-float", "entry-shared-expansion", "version-cycle", "bad-title-UTF8", "shadow"} {
		t.Run(name, func(t *testing.T) {
			p, v, m := cryptoModels(t)
			l := pkg.DefaultLimits()
			code := pkg.ReasonInvalidSchema
			switch name {
			case "cross-ID":
				m.PackageID = pkg.PackageID(memoryID(99))
			case "root-ordinal":
				v.Ordinal = 2
				code = pkg.ReasonNonLinearHistory
			case "self-parent":
				id := v.VersionID
				v.ParentVersionID = &id
				v.Ordinal = 2
				code = pkg.ReasonNonLinearHistory
			case "entry-float":
				m.Entries[0].Extra = map[string]any{"x": 1.2}
			case "entry-shared-expansion":
				l.MaxJSONBytes = 2048
				x := strings.Repeat("x", 1000)
				m.Entries[0].Extra = map[string]any{"x": []any{x, x, x}}
				code = pkg.ReasonResourceLimit
			case "version-cycle":
				x := map[string]any{}
				x["x"] = x
				v.Extra = x
				code = pkg.ReasonResourceLimit
			case "bad-title-UTF8":
				v.SealedMetadata.Title = string([]byte{255})
			case "shadow":
				v.Extra = map[string]any{"label": "shadow"}
			}
			_, _, err := pkg.DeriveVersionSubject(context.Background(), p, v, m, l, supportAllVocabulary())
			requireCode(t, err, code)
		})
	}
}
func FuzzCanonicalRestrictedDomain(f *testing.F) {
	for _, s := range []string{`{"b":1,"a":"/<>&😀"}`, `null`, `[]`, `-0`, `1e0`, `"\ud800"`, `{"a":1,"a":2}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l := pkg.DefaultLimits()
		l.MaxJSONBytes = 64 << 10
		l.MaxJSONDepth = 16
		l.MaxEntries = 256
		out, err := pkg.ReadCanonicalJSON(context.Background(), bytes.NewReader(b), l)
		if err != nil {
			return
		}
		again, err := pkg.ReadCanonicalJSON(context.Background(), bytes.NewReader(out), l)
		if err != nil || !bytes.Equal(out, again) {
			t.Fatal("canonical output not idempotent", err)
		}
		if !json.Valid(out) {
			t.Fatal("non-JSON canonical output")
		}
	})
}

func TestCanonicalAndSubjectAggregateJSONPolicy(t *testing.T) {
	l := pkg.DefaultLimits()
	l.MaxTotalJSONBytes = 5
	_, err := pkg.CanonicalJSON(context.Background(), "long text", l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	_, err = pkg.ReadCanonicalJSON(context.Background(), strings.NewReader(`{"key":1}`), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	p, v, m := cryptoModels(t)
	l = pkg.DefaultLimits()
	l.MaxTotalJSONBytes = int64(len(jsonBytes(t, p))+len(jsonBytes(t, v))+len(jsonBytes(t, m))) - 1
	_, _, err = pkg.DeriveVersionSubject(context.Background(), p, v, m, l, supportAllVocabulary())
	requireCode(t, err, pkg.ReasonResourceLimit)
}
