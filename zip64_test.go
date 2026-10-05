// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

// Assemble real ZIP64 size fields and a ZIP64 directory for small payloads,
// independent of the SDK parser. This exercises 64-bit value decoding without
// allocating or claiming to test a physical >4 GiB payload.
func forceSmallZIP64(t testing.TB, original []byte) []byte {
	t.Helper()
	records := locateZIP(t, original)
	first := records[0]
	end := bytes.LastIndex(original, []byte{'P', 'K', 5, 6})
	oldCD := int(binary.LittleEndian.Uint32(original[end+16:]))
	firstEnd := oldCD
	if len(records) > 1 {
		firstEnd = records[1].local
	}
	deferred := binary.LittleEndian.Uint16(original[first.local+6:])&8 != 0
	compressed := uint64(binary.LittleEndian.Uint32(original[first.central+20:]))
	size := uint64(binary.LittleEndian.Uint32(original[first.central+24:]))
	localExtra := make([]byte, 20)
	binary.LittleEndian.PutUint16(localExtra, 1)
	binary.LittleEndian.PutUint16(localExtra[2:], 16)
	if !deferred {
		binary.LittleEndian.PutUint64(localExtra[4:], size)
		binary.LittleEndian.PutUint64(localExtra[12:], compressed)
	}
	header := bytes.Clone(original[:first.data])
	binary.LittleEndian.PutUint16(header[first.local+4:], 45)
	binary.LittleEndian.PutUint32(header[first.local+18:], 0xffffffff)
	binary.LittleEndian.PutUint32(header[first.local+22:], 0xffffffff)
	binary.LittleEndian.PutUint16(header[first.local+28:], binary.LittleEndian.Uint16(header[first.local+28:])+20)
	body := append(header, localExtra...)
	body = append(body, original[first.data:first.data+int(compressed)]...)
	if deferred {
		descriptor := make([]byte, 24)
		binary.LittleEndian.PutUint32(descriptor, 0x08074b50)
		binary.LittleEndian.PutUint32(descriptor[4:], binary.LittleEndian.Uint32(original[first.central+16:]))
		binary.LittleEndian.PutUint64(descriptor[8:], compressed)
		binary.LittleEndian.PutUint64(descriptor[16:], size)
		body = append(body, descriptor...)
	}
	body = append(body, original[firstEnd:oldCD]...)
	delta := len(body) - oldCD
	newCD := len(body)
	for i, r := range records {
		length := 46 + int(binary.LittleEndian.Uint16(original[r.central+28:])) + int(binary.LittleEndian.Uint16(original[r.central+30:])) + int(binary.LittleEndian.Uint16(original[r.central+32:]))
		entry := bytes.Clone(original[r.central : r.central+length])
		if i != 0 {
			binary.LittleEndian.PutUint32(entry[42:], uint32(r.local+delta))
		}
		if i == 0 {
			namesize, extrasize := int(binary.LittleEndian.Uint16(entry[28:])), int(binary.LittleEndian.Uint16(entry[30:]))
			extraEnd := 46 + namesize + extrasize
			binary.LittleEndian.PutUint16(entry[6:], 45)
			binary.LittleEndian.PutUint32(entry[20:], 0xffffffff)
			binary.LittleEndian.PutUint32(entry[24:], 0xffffffff)
			binary.LittleEndian.PutUint16(entry[30:], uint16(extrasize+20))
			large := make([]byte, 20)
			binary.LittleEndian.PutUint16(large, 1)
			binary.LittleEndian.PutUint16(large[2:], 16)
			binary.LittleEndian.PutUint64(large[4:], size)
			binary.LittleEndian.PutUint64(large[12:], compressed)
			expanded := append(bytes.Clone(entry[:extraEnd]), large...)
			expanded = append(expanded, entry[extraEnd:]...)
			entry = expanded
		}
		body = append(body, entry...)
	}
	cdSize := len(body) - newCD
	zip64Position := len(body)
	z := make([]byte, 56)
	binary.LittleEndian.PutUint32(z, 0x06064b50)
	binary.LittleEndian.PutUint64(z[4:], 44)
	binary.LittleEndian.PutUint16(z[12:], 45)
	binary.LittleEndian.PutUint16(z[14:], 45)
	binary.LittleEndian.PutUint64(z[24:], uint64(len(records)))
	binary.LittleEndian.PutUint64(z[32:], uint64(len(records)))
	binary.LittleEndian.PutUint64(z[40:], uint64(cdSize))
	binary.LittleEndian.PutUint64(z[48:], uint64(newCD))
	body = append(body, z...)
	locator := make([]byte, 20)
	binary.LittleEndian.PutUint32(locator, 0x07064b50)
	binary.LittleEndian.PutUint64(locator[8:], uint64(zip64Position))
	binary.LittleEndian.PutUint32(locator[16:], 1)
	body = append(body, locator...)
	classic := bytes.Clone(original[end:])
	binary.LittleEndian.PutUint16(classic[8:], 0xffff)
	binary.LittleEndian.PutUint16(classic[10:], 0xffff)
	binary.LittleEndian.PutUint32(classic[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(classic[16:], 0xffffffff)
	return append(body, classic...)
}

func TestZIP64SmallSizesOffsetsAndDescriptors(t *testing.T) {
	plain, _ := zipFixture(t, "zip-unwrapped")
	descriptor := writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Store, false)
	for _, original := range [][]byte{plain, descriptor} {
		b := forceSmallZIP64(t, original)
		_, want := readZIPTree(t, original, pkg.DefaultLimits())
		_, got := readZIPTree(t, b, pkg.DefaultLimits())
		if len(want) != len(got) {
			t.Fatal("ZIP64 lost files")
		}
		for p, v := range want {
			if !bytes.Equal(v, got[p]) {
				t.Fatal("ZIP64 byte mismatch", p)
			}
		}
		// A bounded variable-length ZIP64 end record is skipped as container
		// metadata. Its extra bytes must fit the exact locator boundary.
		loc := bytes.LastIndex(b, []byte{'P', 'K', 6, 7})
		end64 := int(binary.LittleEndian.Uint64(b[loc+8:]))
		extended := append(bytes.Clone(b[:loc]), []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
		extended = append(extended, b[loc:]...)
		binary.LittleEndian.PutUint64(extended[end64+4:], 52)
		_, extra := readZIPTree(t, extended, pkg.DefaultLimits())
		for p, v := range want {
			if !bytes.Equal(v, extra[p]) {
				t.Fatal("ZIP64 extended end changed bytes", p)
			}
		}
		// The independent standard reader also accepts this test archive.
		standard, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range standard.File {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, r)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for _, fault := range []string{"locator-disk", "end-disk", "count-overflow", "offset-overflow", "size-overflow", "record-length", "missing-extra"} {
			t.Run(fault, func(t *testing.T) {
				bad := bytes.Clone(b)
				loc := bytes.LastIndex(bad, []byte{'P', 'K', 6, 7})
				z := int(binary.LittleEndian.Uint64(bad[loc+8:]))
				cd := int(binary.LittleEndian.Uint64(bad[z+48:]))
				switch fault {
				case "locator-disk":
					binary.LittleEndian.PutUint32(bad[loc+16:], 2)
				case "end-disk":
					binary.LittleEndian.PutUint32(bad[z+16:], 1)
				case "count-overflow":
					binary.LittleEndian.PutUint64(bad[z+24:], ^uint64(0))
					binary.LittleEndian.PutUint64(bad[z+32:], ^uint64(0))
				case "offset-overflow":
					binary.LittleEndian.PutUint64(bad[z+48:], ^uint64(0))
				case "size-overflow":
					extra := cd + 46 + int(binary.LittleEndian.Uint16(bad[cd+28:]))
					for binary.LittleEndian.Uint16(bad[extra:]) != 1 {
						extra += 4 + int(binary.LittleEndian.Uint16(bad[extra+2:]))
					}
					binary.LittleEndian.PutUint64(bad[extra+4:], ^uint64(0))
				case "record-length":
					binary.LittleEndian.PutUint64(bad[z+4:], ^uint64(0))
				case "missing-extra":
					extra := cd + 46 + int(binary.LittleEndian.Uint16(bad[cd+28:]))
					for binary.LittleEndian.Uint16(bad[extra:]) != 1 {
						extra += 4 + int(binary.LittleEndian.Uint16(bad[extra+2:]))
					}
					binary.LittleEndian.PutUint16(bad[extra:], 2)
				}
				s, err := zipSource(t, bad, pkg.DefaultLimits()).BeginSnapshot(context.Background())
				if s != nil {
					_ = s.Close()
					t.Fatal("invalid ZIP64 escaped")
				}
				if err == nil {
					t.Fatal("invalid ZIP64 accepted")
				}
				if fault == "count-overflow" || fault == "size-overflow" {
					requireCode(t, err, pkg.ReasonResourceLimit)
				}
			})
		}
	}
}

func TestZIPUnsignedDataDescriptors(t *testing.T) {
	original := writeFixtureZIP(t, treeFixture(t, "minimal-valid"), "", zip.Deflate, false)
	records := locateZIP(t, original)
	end := bytes.LastIndex(original, []byte{'P', 'K', 5, 6})
	oldCD := int(binary.LittleEndian.Uint32(original[end+16:]))
	body := []byte{}
	offsets := make([]int, len(records))
	for i, r := range records {
		offsets[i] = len(body)
		next := oldCD
		if i+1 < len(records) {
			next = records[i+1].local
		}
		dd := r.data + int(r.compressed)
		body = append(body, original[r.local:dd]...)
		if binary.LittleEndian.Uint16(original[r.local+6:])&8 != 0 {
			if binary.LittleEndian.Uint32(original[dd:]) != 0x08074b50 {
				t.Fatal("test source lacks descriptor marker")
			}
			body = append(body, original[dd+4:next]...)
		} else {
			body = append(body, original[dd:next]...)
		}
	}
	newCD := len(body)
	for i, r := range records {
		next := end
		if i+1 < len(records) {
			next = records[i+1].central
		}
		record := bytes.Clone(original[r.central:next])
		binary.LittleEndian.PutUint32(record[42:], uint32(offsets[i]))
		body = append(body, record...)
	}
	classic := bytes.Clone(original[end:])
	binary.LittleEndian.PutUint32(classic[16:], uint32(newCD))
	body = append(body, classic...)
	_, want := readZIPTree(t, original, pkg.DefaultLimits())
	_, got := readZIPTree(t, body, pkg.DefaultLimits())
	for p, b := range want {
		if !bytes.Equal(b, got[p]) {
			t.Fatal(p)
		}
	}
}
