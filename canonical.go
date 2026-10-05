// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CanonicalJSON independently implements orbifabric.canonical-json.v1, not
// encoding/json/JCS. Values use the restricted JSON domain: map[string]any,
// []any, UTF-8 strings, booleans, nil and safe Go integer types/json.Number.
// Floats, custom marshalers and other Go representations are rejected. The
// output byte budget counts actual canonical bytes, not HTML-escaped estimates.
func CanonicalJSON(ctx context.Context, value any, l Limits) ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	e := canonicalEncoder{ctx: ctx, l: l}
	if err := e.value(value, 0); err != nil {
		return nil, err
	}
	return e.out, nil
}
func ReadCanonicalJSON(ctx context.Context, r io.Reader, l Limits) ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	inputLimits := l
	inputLimits.MaxJSONBytes = min(l.MaxJSONBytes, l.MaxTotalJSONBytes)
	value, err := ReadProtocolJSON(ctx, r, inputLimits)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(ctx, value, l)
}

type canonicalEncoder struct {
	ctx context.Context
	l   Limits
	out []byte
}

func (e *canonicalEncoder) write(s string) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if int64(len(s)) > min(e.l.MaxJSONBytes, e.l.MaxTotalJSONBytes)-int64(len(e.out)) {
		return protocolError(ReasonResourceLimit, "canonical JSON byte budget")
	}
	e.out = append(e.out, s...)
	return nil
}
func (e *canonicalEncoder) text(s string) error {
	if int64(len(s))+2 > min(e.l.MaxJSONBytes, e.l.MaxTotalJSONBytes)-int64(len(e.out)) {
		return protocolError(ReasonResourceLimit, "canonical string byte budget")
	}
	if !utf8.ValidString(s) {
		return schemaError("invalid canonical UTF-8")
	}
	if err := e.write("\""); err != nil {
		return err
	}
	start := 0
	const hex = "0123456789abcdef"
	for i := 0; i < len(s); i++ {
		var escape string
		switch s[i] {
		case '"':
			escape = `\"`
		case '\\':
			escape = `\\`
		case '\b':
			escape = `\b`
		case '\t':
			escape = `\t`
		case '\n':
			escape = `\n`
		case '\f':
			escape = `\f`
		case '\r':
			escape = `\r`
		default:
			if s[i] < 32 {
				escape = string([]byte{'\\', 'u', '0', '0', hex[s[i]>>4], hex[s[i]&15]})
			}
		}
		if escape != "" {
			if err := e.write(s[start:i]); err != nil {
				return err
			}
			if err := e.write(escape); err != nil {
				return err
			}
			start = i + 1
		}
	}
	if err := e.write(s[start:]); err != nil {
		return err
	}
	return e.write("\"")
}
func (e *canonicalEncoder) integer(n int64) error {
	if n < -MaxProtocolInteger || n > MaxProtocolInteger {
		return schemaError("canonical integer outside safe domain")
	}
	return e.write(strconv.FormatInt(n, 10))
}
func (e *canonicalEncoder) unsigned(n uint64) error {
	if n > uint64(MaxProtocolInteger) {
		return schemaError("canonical integer outside safe domain")
	}
	return e.integer(int64(n))
}
func (e *canonicalEncoder) value(v any, depth int) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	switch x := v.(type) {
	case nil:
		return e.write("null")
	case bool:
		if x {
			return e.write("true")
		}
		return e.write("false")
	case string:
		return e.text(x)
	case int:
		return e.integer(int64(x))
	case int8:
		return e.integer(int64(x))
	case int16:
		return e.integer(int64(x))
	case int32:
		return e.integer(int64(x))
	case int64:
		return e.integer(x)
	case uint:
		return e.unsigned(uint64(x))
	case uint8:
		return e.unsigned(uint64(x))
	case uint16:
		return e.unsigned(uint64(x))
	case uint32:
		return e.unsigned(uint64(x))
	case uint64:
		return e.unsigned(x)
	case json.Number:
		if int64(len(x)) > e.l.MaxJSONBytes {
			return protocolError(ReasonResourceLimit, "canonical number byte budget")
		}
		parsed, err := ReadProtocolJSON(e.ctx, strings.NewReader(string(x)), e.l)
		if err != nil {
			return err
		}
		n, ok := parsed.(int64)
		if !ok {
			return schemaError("invalid canonical number")
		}
		if strconv.FormatInt(n, 10) != string(x) {
			return schemaError("non-integer json.Number lexical form")
		}
		return e.integer(n)
	case []any:
		if depth >= e.l.MaxJSONDepth || len(x) > e.l.MaxEntries {
			return protocolError(ReasonResourceLimit, "canonical array policy")
		}
		if err := e.write("["); err != nil {
			return err
		}
		for i, v := range x {
			if i > 0 {
				if err := e.write(","); err != nil {
					return err
				}
			}
			if err := e.value(v, depth+1); err != nil {
				return err
			}
		}
		return e.write("]")
	case map[string]any:
		if depth >= e.l.MaxJSONDepth || len(x) > e.l.MaxEntries {
			return protocolError(ReasonResourceLimit, "canonical object policy")
		}
		minimum := int64(2)
		for k := range x {
			if err := e.ctx.Err(); err != nil {
				return err
			}
			minimum += int64(len(k)) + 4
			if minimum > min(e.l.MaxJSONBytes, e.l.MaxTotalJSONBytes)-int64(len(e.out)) {
				return protocolError(ReasonResourceLimit, "canonical key allocation budget")
			}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return schemaError("invalid canonical key")
			}
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if err := e.write("{"); err != nil {
			return err
		}
		for i, k := range keys {
			if i > 0 {
				if err := e.write(","); err != nil {
					return err
				}
			}
			if err := e.text(k); err != nil {
				return err
			}
			if err := e.write(":"); err != nil {
				return err
			}
			if err := e.value(x[k], depth+1); err != nil {
				return err
			}
		}
		return e.write("}")
	default:
		return schemaError("Go value is outside the restricted canonical domain")
	}
}
