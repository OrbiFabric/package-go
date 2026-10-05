// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

func requireCode(t *testing.T, err error, code pkg.ReasonCode) {
	t.Helper()
	var p *pkg.ProtocolError
	if !errors.As(err, &p) || p.Code != code {
		t.Fatalf("got %v; want %s", err, code)
	}
}
func fixtureFormat(t *testing.T, id string) ([]byte, pkg.Recognition, []pkg.ReasonCode) {
	t.Helper()
	b, err := fs.ReadFile(conformance.Assets(), "fixtures/"+id+".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input struct {
			Entries []struct {
				Path  string
				Bytes string `json:"bytes_base64"`
			}
		}
		Expected struct {
			Recognition pkg.Recognition
			ReasonCodes []pkg.ReasonCode `json:"reason_codes"`
		}
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.Input.Entries {
		if e.Path == ".packtell/format.json" {
			b, err := base64.StdEncoding.DecodeString(e.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			return b, f.Expected.Recognition, f.Expected.ReasonCodes
		}
	}
	t.Fatal("fixture missing format")
	return nil, "", nil
}
func supportAllVocabulary() pkg.CapabilitySupport {
	return pkg.CapabilitySupport{
		Capabilities: []string{pkg.CapabilityLinearHistory, pkg.CapabilityContentSHA256, pkg.CapabilityPortableMemory, pkg.CapabilityVersionSignature, pkg.CapabilityDeliveryEvidence}, Profiles: []string{pkg.ProfileComplete},
	}
}
func TestS01SharedFormatContracts(t *testing.T) {
	// Deliberately tests ONLY format recognition; full tree/crypto/codec results
	// belong to subsequent stage adapters and the complete producer gate.
	for _, id := range []string{"core-minimal", "unknown-required-capability"} {
		t.Run(id, func(t *testing.T) {
			b, want, codes := fixtureFormat(t, id)
			_, got, err := pkg.ReadFormat(context.Background(), bytes.NewReader(b), pkg.DefaultLimits(), supportAllVocabulary())
			if got != want {
				t.Fatalf("recognition %s want %s", got, want)
			}
			if id == "core-minimal" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, codes[0])
			}
		})
	}
}
func formatMap(t *testing.T) map[string]any {
	t.Helper()
	b, _, _ := fixtureFormat(t, "core-minimal")
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func TestFormatSchemaAndCapabilityBoundaries(t *testing.T) {
	cases := []struct {
		name        string
		edit        func(map[string]any)
		recognition pkg.Recognition
		code        pkg.ReasonCode
	}{
		{"missing discriminator", func(m map[string]any) { delete(m, "protocol") }, pkg.NotPackage, pkg.ReasonNotPackage},
		{"old protocol", func(m map[string]any) { m["protocol_version"] = "1.0" }, pkg.Unsupported, pkg.ReasonUnsupportedProtocol},
		{"wrong tree", func(m map[string]any) { m["tree_profile"] = "unknown" }, pkg.Unsupported, pkg.ReasonUnsupportedProtocol},
		{"unknown closed property", func(m map[string]any) { m["extra"] = true }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"wrong schema", func(m map[string]any) { m["schema"] = "other" }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"missing array", func(m map[string]any) { delete(m, "profiles") }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"null array", func(m map[string]any) { m["profiles"] = nil }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"duplicate", func(m map[string]any) {
			m["required_capabilities"] = []string{pkg.CapabilityContentSHA256, pkg.CapabilityContentSHA256, pkg.CapabilityLinearHistory}
		}, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"unsorted", func(m map[string]any) {
			m["required_capabilities"] = []string{pkg.CapabilityLinearHistory, pkg.CapabilityContentSHA256}
		}, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"missing mandatory", func(m map[string]any) { m["required_capabilities"] = []string{pkg.CapabilityLinearHistory} }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"overlap", func(m map[string]any) { m["optional_capabilities"] = []string{pkg.CapabilityContentSHA256} }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"invalid namespace", func(m map[string]any) { m["optional_capabilities"] = []string{"bad_name"} }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"unknown profile", func(m map[string]any) { m["profiles"] = []string{"org.example.profile"} }, pkg.Unsupported, pkg.ReasonUnsupportedProtocol},
		{"complete missing memory", func(m map[string]any) { m["profiles"] = []string{pkg.ProfileComplete} }, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"unsupported semantic capability", func(m map[string]any) {
			m["required_capabilities"] = []string{pkg.CapabilityContentSHA256, pkg.CapabilityLinearHistory, pkg.CapabilityPortableMemory}
		}, pkg.Unsupported, pkg.ReasonUnknownRequiredCapability},
		{"undeclared extension capability", func(m map[string]any) {
			m["extensions"] = []any{map[string]any{"namespace": "org.example", "required_capability": "org.example.required"}}
		}, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"extension missing null", func(m map[string]any) {
			m["extensions"] = []any{map[string]any{"namespace": "org.example", "other": nil}}
		}, pkg.Recognized, pkg.ReasonInvalidSchema},
		{"duplicate extension", func(m map[string]any) {
			m["extensions"] = []any{map[string]any{"namespace": "org.example", "required_capability": nil}, map[string]any{"namespace": "org.example", "required_capability": nil}}
		}, pkg.Recognized, pkg.ReasonInvalidSchema},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := formatMap(t)
			c.edit(m)
			b, _ := json.Marshal(m)
			_, r, err := pkg.ReadFormat(context.Background(), bytes.NewReader(b), pkg.DefaultLimits(), pkg.CoreSupport())
			if r != c.recognition {
				t.Fatalf("recognition %s", r)
			}
			requireCode(t, err, c.code)
		})
	}
	m := formatMap(t)
	m["optional_capabilities"] = []string{"org.example.opaque"}
	m["extensions"] = []any{map[string]any{"namespace": "org.example", "required_capability": nil}}
	b, _ := json.Marshal(m)
	f, r, err := pkg.ReadFormat(context.Background(), bytes.NewReader(b), pkg.DefaultLimits(), pkg.CoreSupport())
	if err != nil || r != pkg.Recognized {
		t.Fatalf("optional facts: %s %v", r, err)
	}
	if f.OptionalCapabilities[0] != "org.example.opaque" || f.Extensions[0].Namespace != "org.example" || f.Extensions[0].RequiredCapability != nil {
		t.Fatal("lost optional declarations")
	}
}
func TestStrictProtocolJSON(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"x":{"a":1,"a":2}}`, `-0`, `1.0`, `1e0`, `9007199254740992`, `-9007199254740992`, `01`, `NaN`, `Infinity`, `{} {}`, "\xef\xbb\xbf{}", "\xff", `"\ud800"`, `"\udc00"`, `"\ud800\u0041"`, `"\ud800\\udc00"`} {
		t.Run(s, func(t *testing.T) {
			_, err := pkg.ReadProtocolJSON(context.Background(), strings.NewReader(s), pkg.DefaultLimits())
			requireCode(t, err, pkg.ReasonInvalidSchema)
		})
	}
	for _, s := range []string{`null`, `true`, `-9007199254740991`, `9007199254740991`, `0`, `"\ud83d\ude00"`, `"\ufffd"`, `"\\ud800"`, ` { "x" : ["😀",null,0] } `} {
		if _, err := pkg.ReadProtocolJSON(context.Background(), strings.NewReader(s), pkg.DefaultLimits()); err != nil {
			t.Errorf("valid %s: %v", s, err)
		}
	}
	l := pkg.DefaultLimits()
	l.MaxJSONDepth = 2
	if _, err := pkg.ReadProtocolJSON(context.Background(), strings.NewReader(`{"x":[1]}`), l); err != nil {
		t.Fatal(err)
	}
	_, err := pkg.ReadProtocolJSON(context.Background(), strings.NewReader(`{"x":[[]]}`), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	l = pkg.DefaultLimits()
	l.MaxJSONBytes = 2
	_, err = pkg.ReadProtocolJSON(context.Background(), strings.NewReader(`null`), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
}
func TestUncheckedResultAndReasons(t *testing.T) {
	r := pkg.UncheckedResult()
	if r.CommittedIntegrity != pkg.IntegrityNotChecked || r.HistoryCompleteness != pkg.HistoryNotChecked || r.WorkingState != pkg.WorkingNotChecked || r.Signature != pkg.SignatureNotChecked || r.Evidence != pkg.EvidenceNotChecked || r.Online != pkg.OnlineNotRequested || r.Identity != pkg.IdentityUnknown {
		t.Fatal("unrun dimension advertised success")
	}
	r.AddReason(pkg.ReasonBadSignature)
	r.AddReason(pkg.ReasonBadSignature)
	r.WorkingState = pkg.WorkingDirty
	r.CommittedIntegrity = pkg.IntegrityValid
	if len(r.ReasonCodes) != 1 || r.CommittedIntegrity != pkg.IntegrityValid || r.Signature != pkg.SignatureNotChecked {
		t.Fatal("dimensions/reasons coupled")
	}
}

type countingReader struct {
	calls int
	r     io.Reader
}

func (r *countingReader) Read(b []byte) (int, error) { r.calls++; return r.r.Read(b) }

type cancellingReader struct{ cancel context.CancelFunc }

func (r cancellingReader) Read(b []byte) (int, error) { r.cancel(); b[0] = 'x'; return 1, nil }
func TestBoundedReadAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &countingReader{r: strings.NewReader("content")}
	if _, err := pkg.ReadBounded(ctx, r, 5); !errors.Is(err, context.Canceled) || r.calls != 0 {
		t.Fatalf("read after cancellation: %v %d", err, r.calls)
	}
	ctx, cancel = context.WithCancel(context.Background())
	_, err := pkg.ReadBounded(ctx, cancellingReader{cancel}, 5)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_, err = pkg.ReadBounded(context.Background(), strings.NewReader("123456"), 5)
	requireCode(t, err, pkg.ReasonResourceLimit)
	if b, err := pkg.ReadBounded(context.Background(), strings.NewReader("12345"), 5); err != nil || string(b) != "12345" {
		t.Fatalf("exact limit: %q %v", b, err)
	}
	for _, n := range []int64{0, -1, math.MaxInt64} {
		_, err := pkg.ReadBounded(context.Background(), strings.NewReader(""), n)
		requireCode(t, err, pkg.ReasonResourceLimit)
	}
}
func TestResourcePolicy(t *testing.T) {
	if err := pkg.DefaultLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*pkg.Limits){func(l *pkg.Limits) { l.MaxEntries = 0 }, func(l *pkg.Limits) { l.MaxFileBytes = 0 }, func(l *pkg.Limits) { l.MaxTotalBytes = 0 }, func(l *pkg.Limits) { l.MaxJSONBytes = math.MaxInt64 }, func(l *pkg.Limits) { l.MaxJSONDepth = 0 }, func(l *pkg.Limits) { l.MaxNDJSONLineBytes = 0 }, func(l *pkg.Limits) { l.MaxCompressionRatio = math.NaN() }, func(l *pkg.Limits) { l.MaxCompressionRatio = math.Inf(1) }} {
		l := pkg.DefaultLimits()
		edit(&l)
		requireCode(t, l.Validate(), pkg.ReasonResourceLimit)
	}
}
func TestVerifiedHostBytes(t *testing.T) {
	b := []byte("hello\n")
	h := sha256.Sum256(b)
	id := "sha256:" + hex.EncodeToString(h[:])
	for _, c := range []struct {
		name string
		data []byte
		size int64
		id   string
		code pkg.ReasonCode
	}{
		{"correct", b, 6, id, ""}, {"wrong bytes", []byte("HELLO\n"), 6, id, pkg.ReasonObjectHashMismatch}, {"short", b[:5], 6, id, pkg.ReasonObjectHashMismatch}, {"extra", append(bytes.Clone(b), 'x'), 6, id, pkg.ReasonObjectHashMismatch}, {"negative", b, -1, id, pkg.ReasonInvalidSchema}, {"uppercase digest", b, 6, strings.ToUpper(id), pkg.ReasonInvalidSchema}, {"invalid digest", b, 6, "sha256:" + strings.Repeat("z", 64), pkg.ReasonInvalidSchema},
	} {
		t.Run(c.name, func(t *testing.T) {
			var pending bytes.Buffer
			err := pkg.CopyVerifiedContent(context.Background(), &pending, bytes.NewReader(c.data), pkg.ContentID(c.id), c.size, pkg.DefaultLimits())
			if c.code != "" {
				requireCode(t, err, c.code)
			} else if err != nil || !bytes.Equal(pending.Bytes(), b) {
				t.Fatalf("%v", err)
			}
		})
	}
	empty := sha256.Sum256(nil)
	if err := pkg.CopyVerifiedContent(context.Background(), io.Discard, strings.NewReader(""), pkg.ContentID("sha256:"+hex.EncodeToString(empty[:])), 0, pkg.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	l := pkg.DefaultLimits()
	l.MaxFileBytes = 5
	src := &countingReader{r: bytes.NewReader(b)}
	requireCode(t, pkg.CopyVerifiedContent(context.Background(), io.Discard, src, pkg.ContentID(id), 6, l), pkg.ReasonResourceLimit)
	if src.calls != 0 {
		t.Fatal("read before resource check")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := pkg.CopyVerifiedContent(ctx, io.Discard, bytes.NewReader(b), pkg.ContentID(id), 6, pkg.DefaultLimits())
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestOfflineAssets(t *testing.T) {
	if conformance.SpecCommit != pkg.SpecCommit {
		t.Fatal("authority drift")
	}
	if err := conformance.VerifyAssets(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"schemas/format.v2.schema.json", "conformance/manifest.v2.json", "profiles/complete.v1.json", "vectors/crypto.v2.json"} {
		if _, err := fs.ReadFile(conformance.Assets(), p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fs.ReadFile(conformance.Assets(), "../checksums.json"); err == nil {
		t.Fatal("asset boundary traversal")
	}
}

type cancelWriter struct{ cancel context.CancelFunc }

func (w cancelWriter) Write(b []byte) (int, error) { w.cancel(); return len(b), nil }

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestPendingWriteFailureAndCancellation(t *testing.T) {
	b := []byte("hello\n")
	h := sha256.Sum256(b)
	id := "sha256:" + hex.EncodeToString(h[:])
	ctx, cancel := context.WithCancel(context.Background())
	if err := pkg.CopyVerifiedContent(ctx, cancelWriter{cancel}, bytes.NewReader(b), pkg.ContentID(id), 6, pkg.DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("final write cancellation: %v", err)
	}
	if err := pkg.CopyVerifiedContent(context.Background(), failWriter{}, bytes.NewReader(b), pkg.ContentID(id), 6, pkg.DefaultLimits()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error: %v", err)
	}
	l := pkg.DefaultLimits()
	l.MaxEntries = 2
	_, err := pkg.ReadProtocolJSON(context.Background(), strings.NewReader(`[1,2,3]`), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
	_, err = pkg.ReadProtocolJSON(context.Background(), strings.NewReader(`{"a":1,"b":2,"c":3}`), l)
	requireCode(t, err, pkg.ReasonResourceLimit)
}

func FuzzProtocolJSONAndFormat(f *testing.F) {
	for _, seed := range []string{`{"x":1}`, `{"x":1,"x":2}`, `"\ud800"`, `{"protocol":[]}`, `[[[]]]`, `-0`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l := pkg.DefaultLimits()
		l.MaxJSONBytes = 16384
		l.MaxJSONDepth = 16
		l.MaxEntries = 100
		v, err := pkg.ReadProtocolJSON(context.Background(), bytes.NewReader(b), l)
		if err == nil {
			encoded, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pkg.ReadProtocolJSON(context.Background(), bytes.NewReader(encoded), l); err != nil {
				t.Fatalf("accepted value cannot round trip: %v", err)
			}
		}
		_, _, _ = pkg.ReadFormat(context.Background(), bytes.NewReader(b), l, pkg.CoreSupport())
	})
}
