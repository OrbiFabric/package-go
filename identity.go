// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

// Distinct types prevent accidental interchange of entity and content identity.
type UUID string
type PackageID UUID
type VersionID UUID
type FileID UUID
type FolderID UUID
type ContentID string

const MaxProtocolInteger int64 = 9007199254740991
const timestampLayout = "2006-01-02T15:04:05.000000Z"

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var timestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)

func (id UUID) Validate() error {
	if !uuidPattern.MatchString(string(id)) {
		return protocolError(ReasonInvalidSchema, "invalid lowercase UUIDv7")
	}
	return nil
}
func (id ContentID) Validate() error {
	s := string(id)
	if len(s) != 71 || s[:7] != "sha256:" {
		return protocolError(ReasonInvalidSchema, "invalid ContentID")
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return protocolError(ReasonInvalidSchema, "invalid ContentID")
		}
	}
	return nil
}

// ContentIDForBytes commits the whole raw byte sequence, independently of path.
func ContentIDForBytes(b []byte) ContentID {
	h := sha256.Sum256(b)
	return ContentID("sha256:" + hex.EncodeToString(h[:]))
}
func ParseTimestamp(s string) (time.Time, error) {
	if !timestampPattern.MatchString(s) {
		return time.Time{}, protocolError(ReasonInvalidSchema, "invalid timestamp representation")
	}
	t, err := time.Parse(timestampLayout, s)
	if err != nil || t.Year() < 1 || t.Year() > 9999 || t.Format(timestampLayout) != s {
		return time.Time{}, protocolError(ReasonInvalidSchema, "invalid Gregorian timestamp")
	}
	return t, nil
}

// Timestamp renders an explicit creation/commit time in UTC at microsecond
// precision; it does not claim third-party timestamp trust.
func Timestamp(t time.Time) (string, error) {
	t = t.UTC()
	if t.Year() < 1 || t.Year() > 9999 {
		return "", protocolError(ReasonInvalidSchema, "timestamp year outside protocol domain")
	}
	return t.Format(timestampLayout), nil
}

// IDGenerator retains the Package's complete previously-used ID inventory,
// including removed entities. Hosts must seed/reserve all historical IDs and
// serialize generation with publication across processes; timestamp sorting is
// never parent authority. nil entropy selects crypto/rand.Reader. A supplied
// entropy stream is a Host responsibility and must be cryptographically secure
// and cancellable. Generation rejects repeated collisions after 128 attempts.
type IDGenerator struct {
	mu      sync.Mutex
	entropy io.Reader
	used    map[UUID]struct{}
}

func NewIDGenerator(entropy io.Reader, existing []UUID) (*IDGenerator, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	g := &IDGenerator{entropy: entropy, used: map[UUID]struct{}{}}
	for _, id := range existing {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		g.used[id] = struct{}{}
	}
	return g, nil
}
func (g *IDGenerator) Reserve(ids ...UUID) error {
	if g == nil {
		return fmt.Errorf("ID generator is not initialized")
	}
	for _, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used == nil || g.entropy == nil {
		return fmt.Errorf("ID generator is not initialized")
	}
	for _, id := range ids {
		g.used[id] = struct{}{}
	}
	return nil
}
func (g *IDGenerator) Generate(ctx context.Context, at time.Time) (UUID, error) {
	if g == nil {
		return "", fmt.Errorf("ID generator is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ms := at.UnixMilli()
	if ms < 0 || ms > 0xffffffffffff {
		return "", protocolError(ReasonInvalidSchema, "UUIDv7 timestamp outside 48-bit epoch domain")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used == nil || g.entropy == nil {
		return "", fmt.Errorf("ID generator is not initialized")
	}
	for attempt := 0; attempt < 128; attempt++ {
		var b [16]byte
		if _, err := io.ReadFull(contextReader{ctx, g.entropy}, b[:]); err != nil {
			return "", err
		}
		for i := 5; i >= 0; i-- {
			b[i] = byte(uint64(ms) >> uint(8*(5-i)))
		}
		b[6] = (b[6] & 15) | 0x70
		b[8] = (b[8] & 63) | 0x80
		s := hex.EncodeToString(b[:])
		id := UUID(s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:])
		if _, used := g.used[id]; used {
			continue
		}
		g.used[id] = struct{}{}
		return id, nil
	}
	return "", protocolError(ReasonResourceLimit, "UUID collision retry policy exhausted")
}
