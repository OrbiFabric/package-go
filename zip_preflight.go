// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	zipLocalSignature      = 0x04034b50
	zipCentralSignature    = 0x02014b50
	zipEndSignature        = 0x06054b50
	zip64EndSignature      = 0x06064b50
	zip64LocatorSignature  = 0x07064b50
	zipDescriptorSignature = 0x08074b50
)

var zipOrder = binary.LittleEndian

func unsafeZIP(detail string) error { return protocolError(ReasonUnsafeArchive, detail) }

type zipRecord struct {
	name, kind                     string
	flags, method                  uint16
	crc                            uint32
	size, compressed, offset, data int64
}
type zipPlan struct {
	entries []TreeEntry
	files   map[string]zipRecord
	wrapper string
}
type zipEnd struct{ count, offset, size, end int64 }

func readZIPRange(ctx context.Context, a ArchiveSnapshot, offset, size int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if offset < 0 || size < 0 || offset > a.Size() || size > a.Size()-offset || size > int64(math.MaxInt) {
		return nil, unsafeZIP("ZIP record outside artifact")
	}
	b := make([]byte, int(size))
	n, err := a.ReadAt(ctx, b, offset)
	if cancel := ctx.Err(); cancel != nil {
		return nil, cancel
	}
	if n != len(b) {
		if err == nil || errors.Is(err, io.EOF) {
			err = unsafeZIP("truncated ZIP record")
		}
		return nil, err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b, nil
}
func readZIPEnd(ctx context.Context, a ArchiveSnapshot, l Limits) (zipEnd, error) {
	size := a.Size()
	if size < 22 {
		return zipEnd{}, unsafeZIP("missing ZIP end record")
	}
	if size > l.MaxTotalBytes {
		return zipEnd{}, protocolError(ReasonResourceLimit, "ZIP artifact byte policy")
	}
	n := min(size, int64(22+65535))
	tail, err := readZIPRange(ctx, a, size-n, n)
	if err != nil {
		return zipEnd{}, err
	}
	pos := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if zipOrder.Uint32(tail[i:]) == zipEndSignature && i+22+int(zipOrder.Uint16(tail[i+20:])) == len(tail) {
			pos = i
			break
		}
	}
	if pos < 0 {
		return zipEnd{}, unsafeZIP("invalid ZIP end/comment boundary")
	}
	b := tail[pos:]
	end := size - n + int64(pos)
	if zipOrder.Uint16(b[4:]) != 0 || zipOrder.Uint16(b[6:]) != 0 || zipOrder.Uint16(b[8:]) != zipOrder.Uint16(b[10:]) {
		return zipEnd{}, unsafeZIP("multi-volume ZIP unsupported")
	}
	classicCount := uint64(zipOrder.Uint16(b[10:]))
	classicSize := uint64(zipOrder.Uint32(b[12:]))
	classicOffset := uint64(zipOrder.Uint32(b[16:]))
	count, cdSize, offset := classicCount, classicSize, classicOffset
	locatorPresent := false
	if end >= 20 {
		loc, err := readZIPRange(ctx, a, end-20, 20)
		if err != nil {
			return zipEnd{}, err
		}
		if zipOrder.Uint32(loc) == zip64LocatorSignature {
			locatorPresent = true
			if zipOrder.Uint32(loc[4:]) != 0 || zipOrder.Uint32(loc[16:]) != 1 {
				return zipEnd{}, unsafeZIP("multi-volume ZIP64 unsupported")
			}
			p := zipOrder.Uint64(loc[8:])
			if p > uint64(end-20) || uint64(end-20)-p < 56 {
				return zipEnd{}, unsafeZIP("unsupported ZIP64 end layout")
			}
			z, err := readZIPRange(ctx, a, int64(p), 56)
			if err != nil {
				return zipEnd{}, err
			}
			recordSize := zipOrder.Uint64(z[4:])
			if recordSize < 44 || recordSize > uint64(end-20)-p-12 || recordSize+12 != uint64(end-20)-p {
				return zipEnd{}, unsafeZIP("ZIP64 end size/locator boundary disagree")
			}
			if zipOrder.Uint32(z) != zip64EndSignature || zipOrder.Uint16(z[14:]) > 45 || zipOrder.Uint32(z[16:]) != 0 || zipOrder.Uint32(z[20:]) != 0 || zipOrder.Uint64(z[24:]) != zipOrder.Uint64(z[32:]) {
				return zipEnd{}, unsafeZIP("invalid/unsupported ZIP64 end record")
			}
			count = zipOrder.Uint64(z[32:])
			cdSize = zipOrder.Uint64(z[40:])
			offset = zipOrder.Uint64(z[48:])
			if classicCount != 0xffff && classicCount != count || classicSize != 0xffffffff && classicSize != cdSize || classicOffset != 0xffffffff && classicOffset != offset {
				return zipEnd{}, unsafeZIP("classic/ZIP64 directory facts disagree")
			}
			end = int64(p)
		}
	}
	if !locatorPresent && (classicSize == 0xffffffff || classicOffset == 0xffffffff) {
		return zipEnd{}, unsafeZIP("missing ZIP64 locator")
	}
	if count > uint64(l.MaxEntries) {
		return zipEnd{}, protocolError(ReasonResourceLimit, "ZIP central entry policy")
	}
	if offset > uint64(end) || cdSize > uint64(end)-offset || offset+cdSize != uint64(end) || count > cdSize/46 {
		return zipEnd{}, unsafeZIP("ZIP directory count/range mismatch")
	}
	return zipEnd{int64(count), int64(offset), int64(cdSize), end}, nil
}

func zipExtra64(extra []byte, needed []bool) ([]uint64, error) {
	values := make([]uint64, len(needed))
	seen := false
	for len(extra) > 0 {
		if len(extra) < 4 {
			return nil, unsafeZIP("truncated ZIP extra field")
		}
		id, size := zipOrder.Uint16(extra), int(zipOrder.Uint16(extra[2:]))
		extra = extra[4:]
		if size > len(extra) {
			return nil, unsafeZIP("ZIP extra field length")
		}
		field := extra[:size]
		extra = extra[size:]
		if id != 1 {
			continue
		}
		if seen {
			return nil, unsafeZIP("duplicate ZIP64 extra field")
		}
		seen = true
		for i, need := range needed {
			if !need {
				continue
			}
			width := 8
			if i == 3 {
				width = 4
			}
			if len(field) < width {
				return nil, unsafeZIP("missing ZIP64 field")
			}
			if width == 8 {
				values[i] = zipOrder.Uint64(field)
			} else {
				values[i] = uint64(zipOrder.Uint32(field))
			}
			field = field[width:]
		}
	}
	for _, need := range needed {
		if need && !seen {
			return nil, unsafeZIP("missing ZIP64 extra field")
		}
	}
	return values, nil
}
func zipFlags(flags, method, version uint16) error {
	if flags & ^uint16(0x080e) != 0 {
		return unsafeZIP("encrypted/patched/reserved ZIP flags unsupported")
	}
	if method != 0 && method != 8 {
		return unsafeZIP("ZIP compression method unsupported")
	}
	if method == 0 && flags&6 != 0 || version > 45 {
		return unsafeZIP("ZIP feature/version unsupported")
	}
	return nil
}
func zipEntryKind(name string, attrs uint32) (string, error) {
	mode := (attrs >> 16) & 0xf000
	if mode != 0 && mode != 0x8000 && mode != 0x4000 || attrs&0x408 != 0 {
		return "", unsafeZIP("ZIP link/reparse/volume/special entry")
	}
	dir := strings.HasSuffix(name, "/") || mode == 0x4000 || attrs&0x10 != 0
	if mode == 0x8000 && dir {
		return "", unsafeZIP("ZIP entry mode/name disagree")
	}
	if dir {
		return "directory", nil
	}
	return "file", nil
}

func preflightZIP(ctx context.Context, a ArchiveSnapshot, l Limits) (zipPlan, error) {
	end, err := readZIPEnd(ctx, a, l)
	if err != nil {
		return zipPlan{}, err
	}
	records := make([]zipRecord, 0, int(end.count))
	raw := make([]TreeEntry, 0, int(end.count))
	seen := map[string]bool{}
	position := end.offset
	var total int64
	for n := int64(0); n < end.count; n++ {
		if position > end.end-46 {
			return zipPlan{}, unsafeZIP("central record outside directory")
		}
		b, err := readZIPRange(ctx, a, position, 46)
		if err != nil {
			return zipPlan{}, err
		}
		if zipOrder.Uint32(b) != zipCentralSignature {
			return zipPlan{}, unsafeZIP("invalid central record")
		}
		flags, method, version := zipOrder.Uint16(b[8:]), zipOrder.Uint16(b[10:]), zipOrder.Uint16(b[6:])
		if err = zipFlags(flags, method, version); err != nil {
			return zipPlan{}, err
		}
		namesize, extrasize, commentsize := int64(zipOrder.Uint16(b[28:])), int64(zipOrder.Uint16(b[30:])), int64(zipOrder.Uint16(b[32:]))
		if namesize > int64(l.MaxPathBytes) {
			return zipPlan{}, protocolError(ReasonResourceLimit, "ZIP entry name policy")
		}
		length := 46 + namesize + extrasize + commentsize
		if length > end.end-position {
			return zipPlan{}, unsafeZIP("central variable fields outside directory")
		}
		fields, err := readZIPRange(ctx, a, position+46, namesize+extrasize)
		if err != nil {
			return zipPlan{}, err
		}
		name := string(fields[:namesize])
		if !utf8.ValidString(name) {
			return zipPlan{}, protocolError(ReasonInvalidPath, "ZIP name is not UTF-8")
		}
		if flags&0x800 == 0 {
			for _, r := range name {
				if r > 127 {
					return zipPlan{}, unsafeZIP("non-ASCII ZIP name lacks UTF-8 flag")
				}
			}
		}
		size, compressed, offset, disk := uint64(zipOrder.Uint32(b[24:])), uint64(zipOrder.Uint32(b[20:])), uint64(zipOrder.Uint32(b[42:])), uint64(zipOrder.Uint16(b[34:]))
		needed := []bool{size == 0xffffffff, compressed == 0xffffffff, offset == 0xffffffff, disk == 0xffff}
		large, err := zipExtra64(fields[namesize:], needed)
		if err != nil {
			return zipPlan{}, err
		}
		values := []*uint64{&size, &compressed, &offset, &disk}
		for i, need := range needed {
			if need {
				*values[i] = large[i]
			}
		}
		if disk != 0 {
			return zipPlan{}, unsafeZIP("multi-volume ZIP entry")
		}
		if size > uint64(l.MaxFileBytes) || size > uint64(l.MaxTotalBytes-total) || size > uint64(MaxProtocolInteger) {
			return zipPlan{}, protocolError(ReasonResourceLimit, "ZIP expanded byte policy")
		}
		if compressed > uint64(end.offset) || offset > uint64(end.offset) || compressed > uint64(end.offset)-offset {
			return zipPlan{}, unsafeZIP("compressed ZIP body outside local region")
		}
		if size != 0 && (compressed == 0 || float64(size) > float64(compressed)*l.MaxCompressionRatio) {
			return zipPlan{}, protocolError(ReasonResourceLimit, "ZIP compression ratio policy")
		}
		if method == 0 && size != compressed {
			return zipPlan{}, unsafeZIP("STORE ZIP size mismatch")
		}
		kind, err := zipEntryKind(name, zipOrder.Uint32(b[38:]))
		if err != nil {
			return zipPlan{}, err
		}
		if kind == "directory" && size != 0 {
			return zipPlan{}, unsafeZIP("ZIP directory carries payload")
		}
		key := name
		if kind == "directory" {
			key = strings.TrimSuffix(name, "/")
		}
		if seen[key] {
			return zipPlan{}, unsafeZIP("duplicate ZIP path")
		}
		seen[key] = true
		raw = append(raw, TreeEntry{Path: name, Kind: kind, Size: int64(size)})
		records = append(records, zipRecord{name: name, kind: kind, flags: flags, method: method, crc: zipOrder.Uint32(b[16:]), size: int64(size), compressed: int64(compressed), offset: int64(offset)})
		total += int64(size)
		position += length
	}
	if position != end.end {
		return zipPlan{}, unsafeZIP("central directory has extra/unaccounted records")
	}
	// ALL paths (including names outside any candidate Root) precede local
	// header/content reads and any extraction. No path cleaning or renaming.
	entries, err := preflightTree(ctx, raw, l, false)
	if err != nil {
		return zipPlan{}, err
	}
	plan, err := selectZIPRoot(ctx, entries, records, l)
	if err != nil {
		return zipPlan{}, err
	}
	slices.SortFunc(records, func(a, b zipRecord) int {
		if a.offset < b.offset {
			return -1
		}
		if a.offset > b.offset {
			return 1
		}
		return 0
	})
	previous := int64(0)
	for i := range records {
		r := &records[i]
		if r.offset != previous {
			return zipPlan{}, unsafeZIP("overlapping/gapped/self-extracting local ZIP region")
		}
		next := end.offset
		if i+1 < len(records) {
			next = records[i+1].offset
		}
		if err = validateZIPLocal(ctx, a, r, next); err != nil {
			return zipPlan{}, err
		}
		previous = next
		if r.kind == "directory" {
			stream := openZIPRecord(ctx, a, *r)
			_, readErr := io.Copy(io.Discard, stream)
			err = errors.Join(readErr, stream.Close())
			if err != nil {
				return zipPlan{}, err
			}
		} else {
			path := r.name
			if plan.wrapper != "" {
				path = strings.TrimPrefix(path, plan.wrapper+"/")
			}
			plan.files[path] = *r
		}
	}
	if previous != end.offset {
		return zipPlan{}, unsafeZIP("unaccounted local ZIP bytes")
	}
	return plan, nil
}

func selectZIPRoot(ctx context.Context, entries []TreeEntry, records []zipRecord, l Limits) (zipPlan, error) {
	candidates := []string{}
	for _, r := range records {
		if r.kind != "file" {
			continue
		}
		if r.name == ".packtell/format.json" {
			candidates = append(candidates, "")
		} else if strings.Count(r.name, "/") == 2 && strings.HasSuffix(r.name, "/.packtell/format.json") {
			candidates = append(candidates, strings.SplitN(r.name, "/", 2)[0])
		}
	}
	if len(candidates) == 0 {
		if _, err := PreflightTree(ctx, entries, l); err != nil {
			return zipPlan{}, err
		}
		return zipPlan{}, protocolError(ReasonNotPackage, "ZIP has no Package Root discriminator")
	}
	if len(candidates) != 1 {
		return zipPlan{}, unsafeZIP("ZIP requires one designated wrapped/unwrapped Package Root")
	}
	wrapper := candidates[0]
	stripped := make([]TreeEntry, 0, len(entries))
	for _, e := range entries {
		if wrapper != "" {
			if e.Path == wrapper && e.Kind == "directory" {
				continue
			}
			if !strings.HasPrefix(e.Path, wrapper+"/") {
				return zipPlan{}, unsafeZIP("extra top-level ZIP sibling")
			}
			e.Path = strings.TrimPrefix(e.Path, wrapper+"/")
		}
		stripped = append(stripped, e)
	}
	stripped, err := PreflightTree(ctx, stripped, l)
	if err != nil {
		return zipPlan{}, err
	}
	return zipPlan{entries: stripped, files: map[string]zipRecord{}, wrapper: wrapper}, nil
}

func validateZIPLocal(ctx context.Context, a ArchiveSnapshot, r *zipRecord, next int64) error {
	if r.offset < 0 || next < r.offset || next-r.offset < 30 {
		return unsafeZIP("overlapping/truncated ZIP local header")
	}
	b, err := readZIPRange(ctx, a, r.offset, 30)
	if err != nil {
		return err
	}
	if zipOrder.Uint32(b) != zipLocalSignature {
		return unsafeZIP("invalid ZIP local header")
	}
	flags, method, version := zipOrder.Uint16(b[6:]), zipOrder.Uint16(b[8:]), zipOrder.Uint16(b[4:])
	if err = zipFlags(flags, method, version); err != nil {
		return err
	}
	if flags != r.flags || method != r.method {
		return unsafeZIP("local/central ZIP method/flags disagree")
	}
	namesize, extrasize := int64(zipOrder.Uint16(b[26:])), int64(zipOrder.Uint16(b[28:]))
	if namesize != int64(len(r.name)) || 30+namesize+extrasize > next-r.offset {
		return unsafeZIP("local/central ZIP name/length disagree")
	}
	fields, err := readZIPRange(ctx, a, r.offset+30, namesize+extrasize)
	if err != nil {
		return err
	}
	if !bytes.Equal(fields[:namesize], []byte(r.name)) {
		return unsafeZIP("local/central ZIP name disagree")
	}
	size, compressed := uint64(zipOrder.Uint32(b[22:])), uint64(zipOrder.Uint32(b[18:]))
	needed := []bool{size == 0xffffffff, compressed == 0xffffffff, false, false}
	large, err := zipExtra64(fields[namesize:], needed)
	if err != nil {
		return err
	}
	if needed[0] {
		size = large[0]
	}
	if needed[1] {
		compressed = large[1]
	}
	crc := zipOrder.Uint32(b[14:])
	deferred := flags&8 != 0
	if !deferred && (size != uint64(r.size) || compressed != uint64(r.compressed) || crc != r.crc) || deferred && (size != 0 && size != uint64(r.size) || compressed != 0 && compressed != uint64(r.compressed) || crc != 0 && crc != r.crc) {
		return unsafeZIP("local/central ZIP size/CRC disagree")
	}
	r.data = r.offset + 30 + namesize + extrasize
	if r.compressed > next-r.data {
		return unsafeZIP("overlapping ZIP compressed data")
	}
	end := r.data + r.compressed
	if !deferred {
		if end != next {
			return unsafeZIP("unaccounted local ZIP data")
		}
		return nil
	}
	length := next - end
	if length != 12 && length != 16 && length != 20 && length != 24 {
		return unsafeZIP("invalid ZIP data descriptor length")
	}
	d, err := readZIPRange(ctx, a, end, length)
	if err != nil {
		return err
	}
	if length == 16 || length == 24 {
		if zipOrder.Uint32(d) != zipDescriptorSignature {
			return unsafeZIP("invalid ZIP data descriptor signature")
		}
		d = d[4:]
	}
	if zipOrder.Uint32(d) != r.crc {
		return unsafeZIP("ZIP descriptor CRC disagree")
	}
	d = d[4:]
	var dc, ds uint64
	if len(d) == 8 {
		dc = uint64(zipOrder.Uint32(d))
		ds = uint64(zipOrder.Uint32(d[4:]))
	} else {
		dc = zipOrder.Uint64(d)
		ds = zipOrder.Uint64(d[8:])
	}
	if dc != uint64(r.compressed) || ds != uint64(r.size) {
		return unsafeZIP("ZIP descriptor sizes disagree")
	}
	return nil
}
