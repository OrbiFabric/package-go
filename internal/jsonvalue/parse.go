// SPDX-License-Identifier: Apache-2.0
// Package jsonvalue parses the restricted protocol JSON domain. Canonical
// encoding is a separate operation and does not influence input acceptance.
package jsonvalue

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid protocol JSON")
var ErrDepth = errors.New("JSON depth limit")
var ErrEntries = errors.New("JSON collection entry limit")

const MaxInteger int64 = 9007199254740991

// Parse rejects duplicate keys, invalid UTF-8/surrogates and non-domain numbers.
// Input is already bounded by the public I/O boundary before token allocation.
func Parse(data []byte, maxDepth, maxEntries int) (any, error) {
	if !utf8.Valid(data) || !validSurrogates(data) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := value(d, 0, maxDepth, maxEntries)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}
func value(d *json.Decoder, depth, max, maxEntries int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	if delim, ok := t.(json.Delim); ok {
		if depth >= max {
			return nil, ErrDepth
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				if len(m) >= maxEntries {
					return nil, ErrEntries
				}
				k, err := d.Token()
				if err != nil {
					return nil, ErrInvalid
				}
				key, ok := k.(string)
				if !ok {
					return nil, ErrInvalid
				}
				if _, ok = m[key]; ok {
					return nil, ErrInvalid
				}
				v, err := value(d, depth+1, max, maxEntries)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= maxEntries {
					return nil, ErrEntries
				}
				v, err := value(d, depth+1, max, maxEntries)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	}
	if n, ok := t.(json.Number); ok {
		s := string(n)
		if s == "-0" || strings.ContainsAny(s, ".eE") {
			return nil, ErrInvalid
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil || i < -MaxInteger || i > MaxInteger {
			return nil, ErrInvalid
		}
		return i, nil
	}
	return t, nil
}

// encoding/json replaces lone surrogate escapes with U+FFFD. Reject those before
// decoding while retaining valid explicit U+FFFD and paired surrogate scalars.
func validSurrogates(b []byte) bool {
	in := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			in = !in
			continue
		}
		if !in || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
