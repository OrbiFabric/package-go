// SPDX-License-Identifier: Apache-2.0
// Package unicode16 implements exact Unicode 16.0.0 canonical normalization.
// It never inserts stream-safe CGJ characters or uses current Go Unicode tables.
// Tables derive from public UCD inputs; see source-lock.json and UNICODE-LICENSE.
package unicode16

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

//go:embed tables.json
var rawTables []byte
var ccc map[rune]int
var decomp map[rune][]rune
var compose map[[2]rune]rune

func init() {
	var t struct {
		Version string
		CCC     map[string]int
		Decomp  map[string][]rune
		Compose map[string]rune
	}
	if err := json.Unmarshal(rawTables, &t); err != nil || t.Version != "16.0.0" {
		panic("invalid pinned Unicode 16 tables")
	}
	ccc = map[rune]int{}
	decomp = map[rune][]rune{}
	compose = map[[2]rune]rune{}
	for k, v := range t.CCC {
		n, _ := strconv.Atoi(k)
		ccc[rune(n)] = v
	}
	for k, v := range t.Decomp {
		n, _ := strconv.Atoi(k)
		decomp[rune(n)] = v
	}
	for k, v := range t.Compose {
		p := strings.Split(k, ",")
		a, _ := strconv.Atoi(p[0])
		b, _ := strconv.Atoi(p[1])
		compose[[2]rune{rune(a), rune(b)}] = v
	}
}

const (
	sBase  = 0xac00
	lBase  = 0x1100
	vBase  = 0x1161
	tBase  = 0x11a7
	lCount = 19
	vCount = 21
	tCount = 28
	nCount = vCount * tCount
	sCount = lCount * nCount
)

func appendDecomposed(out []rune, c rune) []rune {
	if c >= sBase && c < sBase+sCount {
		n := c - sBase
		out = append(out, lBase+n/nCount, vBase+(n%nCount)/tCount)
		if n%tCount != 0 {
			out = append(out, tBase+n%tCount)
		}
		return out
	}
	if d, ok := decomp[c]; ok {
		for _, n := range d {
			out = appendDecomposed(out, n)
		}
		return out
	}
	return append(out, c)
}
func composition(a, b rune) (rune, bool) {
	if a >= lBase && a < lBase+lCount && b >= vBase && b < vBase+vCount {
		return sBase + (a-lBase)*nCount + (b-vBase)*tCount, true
	}
	if a >= sBase && a < sBase+sCount && (a-sBase)%tCount == 0 && b > tBase && b < tBase+tCount {
		return a + (b - tBase), true
	}
	c, ok := compose[[2]rune{a, b}]
	return c, ok
}

// NFC expects a valid UTF-8 component bounded by the caller's path policy.
func NFC(s string) string {
	decomposed := []rune{}
	for _, r := range s {
		decomposed = appendDecomposed(decomposed, r)
	}
	for i := 1; i < len(decomposed); i++ {
		class := ccc[decomposed[i]]
		if class == 0 {
			continue
		}
		for j := i; j > 0 && ccc[decomposed[j-1]] > class; j-- {
			decomposed[j-1], decomposed[j] = decomposed[j], decomposed[j-1]
		}
	}
	out := []rune{}
	starter := -1
	lastClass := 0
	for _, c := range decomposed {
		class := ccc[c]
		if starter >= 0 && (lastClass < class || lastClass == 0) {
			if combined, ok := composition(out[starter], c); ok {
				out[starter] = combined
				continue
			}
		}
		out = append(out, c)
		if class == 0 {
			starter = len(out) - 1
		}
		lastClass = class
	}
	return string(out)
}
