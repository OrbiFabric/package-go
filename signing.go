// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"github.com/orbifabric/package-go/internal/strict25519"
	"strings"
	"time"
	"unicode/utf8"
)

type SignVersionRequest struct {
	VersionID VersionID
	At        time.Time
	KeyID     string
	// These are explicit Host-selected public key/profile pins, preventing a
	// selected signer from silently changing key/type/environment/profile.
	SignerType          string
	PublicKey           []byte
	OfficialProfileID   string
	OfficialEnvironment string
}

// CreateVersionSignature signs an actual committed Version under one Host
// snapshot and one explicitly selected signer. It returns a verified proposal,
// never writes a signature file, changes Version/HEAD, publishes a container or
// claims trusted identity. Caller publication must preserve the selected facts,
// prevent ID overwrite and keep output isolated until full validation.
func CreateVersionSignature(ctx context.Context, source SnapshotSource, signer Signer, request SignVersionRequest, l Limits, support CapabilitySupport) (out VersionSignature, err error) {
	if err = l.Validate(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = UUID(request.VersionID).Validate(); err != nil {
		return out, err
	}
	at, err := Timestamp(request.At)
	if err != nil {
		return out, err
	}
	if !containsText([]string{"local_device", "orbifabric_official"}, request.SignerType) || len(request.PublicKey) != 32 || !utf8.ValidString(request.KeyID) || utf8.RuneCountInString(request.KeyID) < 1 || utf8.RuneCountInString(request.KeyID) > 256 {
		return out, schemaError("invalid selected signing request")
	}
	if request.SignerType == "orbifabric_official" {
		if request.OfficialProfileID == "" || !containsText([]string{"development", "test", "production"}, request.OfficialEnvironment) || !utf8.ValidString(request.OfficialProfileID) {
			return out, schemaError("official selection needs profile/environment")
		}
	} else if request.OfficialProfileID != "" || request.OfficialEnvironment != "" {
		return out, schemaError("local selection carries official pins")
	}
	if int64(len(request.OfficialProfileID)) > l.MaxJSONBytes {
		return out, protocolError(ReasonResourceLimit, "selected profile byte policy")
	}
	if source == nil || signer == nil {
		return out, schemaError("missing selected snapshot/signer")
	}
	selectedKey := bytes.Clone(request.PublicKey)
	if err = strict25519.CheckPublicKey(ctx, selectedKey); err != nil {
		if errors.Is(err, strict25519.ErrInvalid) {
			return out, protocolError(ReasonBadSignature, "invalid selected signing public key")
		}
		return out, err
	}
	snapshot, err := source.BeginSnapshot(ctx)
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		return out, err
	}
	if snapshot == nil {
		return out, schemaError("missing signing snapshot")
	}
	defer func() {
		err = errors.Join(err, snapshot.Close())
		if err != nil {
			out = VersionSignature{}
		}
	}()
	h, err := ReadHistory(ctx, snapshot, l, support)
	if err != nil {
		return out, err
	}
	memory, err := readPortableMemory(ctx, snapshot, h, l)
	if err != nil {
		return out, err
	}
	var record CommittedVersion
	found := false
	for _, v := range h.Versions {
		if v.Version.VersionID == request.VersionID {
			record = v
			found = true
			break
		}
	}
	if !found {
		return out, schemaError("selected signing Version absent from history")
	}
	if !declaredVersionSigning(h.Root.Format.RequiredCapabilities, h.Root.Format.OptionalCapabilities) || !declaredVersionSigning(record.Version.RequiredCapabilities, record.Version.OptionalCapabilities) {
		return out, schemaError("selected Version/format omits signature capability")
	}
	_, digest, err := DeriveVersionSubject(ctx, h.Root.Package, record.Version, record.Manifest, l, support)
	if err != nil {
		return out, err
	}
	ids := append(h.KnownIDs(), memory.KnownIDs()...)
	for _, e := range h.Root.Entries {
		if !strings.HasPrefix(e.Path, ".packtell/verification/") && !strings.HasPrefix(e.Path, ".packtell/evidence/") {
			continue
		}
		for _, part := range strings.Split(e.Path, "/") {
			part = strings.TrimSuffix(part, ".json")
			if validUUID(part) {
				ids = append(ids, UUID(part))
			}
		}
	}
	generator, err := NewIDGenerator(nil, ids)
	if err != nil {
		return out, err
	}
	id, err := generator.Generate(ctx, request.At)
	if err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	profile, err := signer.Profile(ctx)
	if err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if profile.SignerType != request.SignerType || !bytes.Equal(profile.PublicKey, selectedKey) {
		return out, protocolError(ReasonBadSignature, "selected signer changed type or public key")
	}
	var official *OfficialSignerFacts
	if profile.SignerType == "orbifabric_official" {
		if int64(len(profile.Official)) > l.MaxJSONBytes {
			return out, protocolError(ReasonResourceLimit, "official profile byte policy")
		}
		value, parseErr := ReadProtocolJSON(ctx, bytes.NewReader(profile.Official), l)
		if parseErr != nil {
			return out, parseErr
		}
		official, err = parseOfficial(value)
		if err != nil {
			return out, err
		}
		if official.Environment != request.OfficialEnvironment || official.ProfileID != request.OfficialProfileID {
			return out, protocolError(ReasonBadSignature, "selected official environment/profile changed")
		}
	} else if len(profile.Official) != 0 {
		return out, schemaError("local signer carries official facts")
	}
	envelope := VersionSignature{Schema: VersionSignatureDomain, SignatureID: SignatureID(id), PackageID: h.Root.Package.PackageID, VersionID: request.VersionID, SubjectDigest: digest, SignerType: request.SignerType, KeyID: request.KeyID, Algorithm: "ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(selectedKey), Fingerprint: ContentIDForBytes(selectedKey), SignedAt: at, Official: official}
	input, err := SignatureSigningInput(ctx, envelope, l)
	if err != nil {
		return out, err
	}
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	// Own input bytes: a Host may retain/mutate its argument, never the verifier's
	// expected envelope. Response must match the originally selected key/message.
	signature, err := signer.Sign(ctx, bytes.Clone(input))
	if err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	signature = bytes.Clone(signature)
	if err = VerifyEd25519Strict(ctx, selectedKey, input, signature, l); err != nil {
		return out, err
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err = snapshot.CheckStable(ctx); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	return envelope, nil
}
