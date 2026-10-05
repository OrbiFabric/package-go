// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"encoding/json"
	"io"
)

// TreeEntry is an untrusted relative path; it is not authorization to open it.
// Readers/codecs must preflight all paths and kinds before reading payloads.
type TreeEntry struct {
	Path string
	Kind string
	Size int64
}

// TreeReader is a Host-authorized view of one explicit Root. List must stop at
// maxEntries and return RESOURCE_LIMIT rather than allocate an unbounded tree.
// Open returns a stable regular-file stream, never follows links, and both the
// operation and subsequent reads must honor ctx. The caller closes each stream.
type TreeReader interface {
	List(ctx context.Context, maxEntries int) ([]TreeEntry, error)
	Open(ctx context.Context, relativePath string) (io.ReadCloser, error)
}

// ContentRequest contains portable facts and an optional opaque Host revision.
// A revision is transient Host selection state and must never be serialized in
// place of a portable ContentID or confused with a Provider checksum.
type ContentRequest struct {
	ContentID        ContentID
	Size             int64
	ExpectedRevision string
}
type ResolvedContent struct {
	Reader   io.ReadCloser
	Revision string
}

// ContentResolver is called only by an explicit hydration/export request, never
// by offline completeness verification. Resolve and its stream must honor ctx;
// callers close Reader. SDK consumers must rehash and count all returned bytes.
type ContentResolver interface {
	Resolve(ctx context.Context, request ContentRequest) (ResolvedContent, error)
}

// SigningProfile contains public facts only. Official facts follow the frozen
// envelope schema; no keyring locator, private key or credentials belong here.
type SigningProfile struct {
	SignerType string
	PublicKey  []byte
	Official   json.RawMessage
}

// Signer signs SDK-derived domain-separated envelope bytes. It must honor ctx
// and must not silently select a different key/profile or fallback signer.
// The SDK must verify the response before accepting it as a signature.
type Signer interface {
	Profile(ctx context.Context) (SigningProfile, error)
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}

// TrustPolicy is explicit Host authority, separate from signature mathematics.
// Purpose distinguishes Version signing from each independent evidence kind.
type TrustRequest struct {
	Purpose   string
	PublicKey []byte
	Official  json.RawMessage
}
type TrustPolicy interface {
	Trusted(ctx context.Context, request TrustRequest) (bool, error)
}
