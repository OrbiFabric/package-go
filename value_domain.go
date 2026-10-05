// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Validate caller-created optional JSON before serialization. Aggregate encoded
// bytes/depth/member policy stops shared-value expansion and cyclic values before
// encoding/json allocates a document. Redaction remains explicit Host work.
func validateOptionalValue(ctx context.Context, v any, l Limits, depth int) error {
	remaining := l.MaxJSONBytes
	return walkOptional(ctx, v, l, depth, &remaining)
}
func consumeJSON(n int64, remaining *int64) error {
	if n > *remaining {
		return protocolError(ReasonResourceLimit, "optional JSON byte budget")
	}
	*remaining -= n
	return nil
}
func encodedStringSize(s string) int64 {
	n := int64(2)
	for _, r := range s {
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			n += 2
		case '<', '>', '&', '\u2028', '\u2029':
			n += 6
		default:
			if r < 32 {
				n += 6
			} else {
				n += int64(utf8.RuneLen(r))
			}
		}
	}
	return n
}
func walkOptional(ctx context.Context, v any, l Limits, depth int, remaining *int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	integer := func(n int64) error {
		if n < -MaxProtocolInteger || n > MaxProtocolInteger {
			return schemaError("optional integer outside JSON domain")
		}
		return consumeJSON(int64(len(strconv.FormatInt(n, 10))), remaining)
	}
	switch x := v.(type) {
	case nil:
		return consumeJSON(4, remaining)
	case bool:
		if x {
			return consumeJSON(4, remaining)
		}
		return consumeJSON(5, remaining)
	case string:
		if !utf8.ValidString(x) {
			return schemaError("invalid optional UTF-8 text")
		}
		if int64(len(x)) > *remaining {
			return protocolError(ReasonResourceLimit, "optional text byte budget")
		}
		return consumeJSON(encodedStringSize(x), remaining)
	case int:
		return integer(int64(x))
	case int8:
		return integer(int64(x))
	case int16:
		return integer(int64(x))
	case int32:
		return integer(int64(x))
	case int64:
		return integer(x)
	case uint:
		if uint64(x) > uint64(MaxProtocolInteger) {
			return schemaError("optional integer outside JSON domain")
		}
		return integer(int64(x))
	case uint8:
		return integer(int64(x))
	case uint16:
		return integer(int64(x))
	case uint32:
		return integer(int64(x))
	case uint64:
		if x > uint64(MaxProtocolInteger) {
			return schemaError("optional integer outside JSON domain")
		}
		return integer(int64(x))
	case json.Number:
		if err := consumeJSON(int64(len(x)), remaining); err != nil {
			return err
		}
		value, err := ReadProtocolJSON(ctx, strings.NewReader(string(x)), l)
		if err != nil {
			return err
		}
		if _, ok := value.(int64); !ok {
			return schemaError("invalid optional JSON number")
		}
		return nil
	case map[string]any:
		if depth >= l.MaxJSONDepth || len(x) > l.MaxEntries {
			return protocolError(ReasonResourceLimit, "optional object resource policy")
		}
		base := int64(2)
		if len(x) > 0 {
			base += int64(len(x) - 1)
		}
		if err := consumeJSON(base, remaining); err != nil {
			return err
		}
		for key, value := range x {
			if !utf8.ValidString(key) {
				return schemaError("invalid optional key")
			}
			if int64(len(key)) > *remaining {
				return protocolError(ReasonResourceLimit, "optional key byte budget")
			}
			if err := consumeJSON(encodedStringSize(key)+1, remaining); err != nil {
				return err
			}
			if err := walkOptional(ctx, value, l, depth+1, remaining); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if depth >= l.MaxJSONDepth || len(x) > l.MaxEntries {
			return protocolError(ReasonResourceLimit, "optional array resource policy")
		}
		base := int64(2)
		if len(x) > 0 {
			base += int64(len(x) - 1)
		}
		if err := consumeJSON(base, remaining); err != nil {
			return err
		}
		for _, value := range x {
			if err := walkOptional(ctx, value, l, depth+1, remaining); err != nil {
				return err
			}
		}
		return nil
	default:
		return schemaError("unsupported optional JSON value type")
	}
}
