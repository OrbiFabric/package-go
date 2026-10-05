// SPDX-License-Identifier: Apache-2.0
package unicode16

import (
	"bufio"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

func TestUnicode16FullCaseFolding(t *testing.T) {
	f, err := os.Open("testdata/CaseFolding.txt.gz")
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
	tested := map[rune]bool{}
	count := 0
	for scan.Scan() {
		fields := strings.Split(strings.Split(scan.Text(), "#")[0], ";")
		if len(fields) < 3 {
			continue
		}
		status := strings.TrimSpace(fields[1])
		if status != "C" && status != "F" {
			continue
		}
		input, want := codepoints(fields[0]), codepoints(fields[2])
		if got := Fold(input); got != want {
			t.Fatalf("Fold(%U)=%U want %U", []rune(input), []rune(got), []rune(want))
		}
		tested[[]rune(input)[0]] = true
		count++
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 1557 {
		t.Fatal(count)
	}
	// Unlisted scalars must stay unchanged, including those unassigned in 16.0.
	for cp := rune(0); cp <= 0x10ffff; cp++ {
		if cp >= 0xd800 && cp <= 0xdfff || tested[cp] {
			continue
		}
		s := string(cp)
		if Fold(s) != s {
			t.Fatalf("unlisted %U changed", cp)
		}
	}
	if Fold("Iİ") != "ii\u0307" {
		t.Fatal("Turkic mapping leaked into default fold")
	}
}
