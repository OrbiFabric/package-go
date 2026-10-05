// SPDX-License-Identifier: Apache-2.0
package unicode16

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func codepoints(s string) string {
	out := []rune{}
	for _, n := range strings.Fields(s) {
		v, err := strconv.ParseInt(n, 16, 32)
		if err != nil {
			panic(err)
		}
		out = append(out, rune(v))
	}
	return string(out)
}
func TestUnicode16Normalization(t *testing.T) {
	f, err := os.Open("testdata/NormalizationTest.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	scan := bufio.NewScanner(r)
	cases := 0
	for scan.Scan() {
		line := strings.TrimSpace(strings.Split(scan.Text(), "#")[0])
		if line == "" || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) < 5 {
			t.Fatal(line)
		}
		c := []string{}
		for _, s := range fields[:5] {
			c = append(c, codepoints(s))
		}
		for i, want := range []string{c[1], c[1], c[1], c[3], c[3]} {
			if got := NFC(c[i]); got != want {
				t.Fatalf("case %d column %d NFC(%U) = %U want %U", cases, i, []rune(c[i]), []rune(got), []rune(want))
			}
		}
		cases++
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if cases != 19965 {
		t.Fatalf("unexpected case count %d", cases)
	}
	t.Logf("all %d Unicode 16 NFC rows PASS", cases)
}
func TestPinnedTables(t *testing.T) {
	b, err := os.ReadFile("source-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Version string
		Digest  string `json:"tables_sha256"`
	}
	if err = json.Unmarshal(b, &lock); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(rawTables)
	if lock.Version != "16.0.0" || hex.EncodeToString(h[:]) != lock.Digest {
		t.Fatal("Unicode table drift")
	}
}
func TestNoStreamSafeMutation(t *testing.T) {
	s := "a" + strings.Repeat("\u0300", 64)
	want := "à" + strings.Repeat("\u0300", 63)
	if NFC(s) != want {
		t.Fatal("introduced non-normative CGJ or changed repeated marks")
	}
}
