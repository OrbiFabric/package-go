// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"errors"
	"io"
	"regexp"
	"slices"

	"github.com/orbifabric/package-go/internal/jsonvalue"
)

// Format is the exact closed format.v2 document. Unknown optional capabilities
// and declared optional extension bytes must survive downstream round trips.
type Format struct {
	Schema               string                 `json:"schema"`
	Protocol             string                 `json:"protocol"`
	ProtocolVersion      string                 `json:"protocol_version"`
	TreeProfile          string                 `json:"tree_profile"`
	Profiles             []string               `json:"profiles"`
	RequiredCapabilities []string               `json:"required_capabilities"`
	OptionalCapabilities []string               `json:"optional_capabilities"`
	Extensions           []ExtensionDeclaration `json:"extensions"`
}
type ExtensionDeclaration struct {
	Namespace          string  `json:"namespace"`
	RequiredCapability *string `json:"required_capability"`
}

// CapabilitySupport states implemented semantics, not merely known vocabulary.
// CoreSupport is the foundation contract; further stages add tested semantics.
type CapabilitySupport struct {
	Capabilities []string
	Profiles     []string
}

func CoreSupport() CapabilitySupport {
	return CapabilitySupport{Capabilities: []string{CapabilityContentSHA256, CapabilityLinearHistory}, Profiles: []string{}}
}

var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)

// ReadProtocolJSON handles the common bounded strict parsing contract.
func ReadProtocolJSON(ctx context.Context, r io.Reader, limits Limits) (any, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	b, err := ReadBounded(ctx, r, limits.MaxJSONBytes)
	if err != nil {
		return nil, err
	}
	v, err := jsonvalue.Parse(b, limits.MaxJSONDepth, limits.MaxEntries)
	if errors.Is(err, jsonvalue.ErrDepth) || errors.Is(err, jsonvalue.ErrEntries) {
		return nil, protocolError(ReasonResourceLimit, "JSON structure exceeds policy")
	}
	if err != nil {
		return nil, protocolError(ReasonInvalidSchema, "invalid protocol JSON")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return v, nil
}

// ReadFormat recognizes one caller-supplied discriminator, without opening
// history, payloads, extensions, credentials, filesystem ancestors or networks.
// It does not verify the remaining tree or claim a conformance level.
func ReadFormat(ctx context.Context, r io.Reader, limits Limits, support CapabilitySupport) (Format, Recognition, error) {
	v, err := ReadProtocolJSON(ctx, r, limits)
	if err != nil {
		return Format{}, "", err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Format{}, "", protocolError(ReasonInvalidSchema, "format must be an object")
	}
	for _, k := range []string{"schema", "protocol", "protocol_version", "tree_profile"} {
		if _, ok := m[k]; !ok {
			return Format{}, NotPackage, protocolError(ReasonNotPackage, "missing discriminator")
		}
	}
	if m["protocol"] != Protocol || m["protocol_version"] != ProtocolVersion || m["tree_profile"] != TreeProfile {
		return Format{}, Unsupported, protocolError(ReasonUnsupportedProtocol, "unsupported protocol/version/tree")
	}
	f, err := parseFormat(m)
	if err != nil {
		return Format{}, Recognized, err
	}
	for _, capability := range f.RequiredCapabilities {
		if !slices.Contains(support.Capabilities, capability) {
			return f, Unsupported, protocolError(ReasonUnknownRequiredCapability, "unsupported required capability")
		}
	}
	for _, profile := range f.Profiles {
		if !slices.Contains(support.Profiles, profile) {
			return f, Unsupported, protocolError(ReasonUnsupportedProtocol, "unsupported profile")
		}
	}
	if err := ctx.Err(); err != nil {
		return Format{}, "", err
	}
	return f, Recognized, nil
}
func parseFormat(m map[string]any) (Format, error) {
	bad := func() (Format, error) {
		return Format{}, protocolError(ReasonInvalidSchema, "invalid format schema or relationships")
	}
	if len(m) != 8 || m["schema"] != "orbifabric.package.format.v2" {
		return bad()
	}
	f := Format{Schema: "orbifabric.package.format.v2", Protocol: Protocol, ProtocolVersion: ProtocolVersion, TreeProfile: TreeProfile}
	var ok bool
	if f.Profiles, ok = names(m["profiles"]); !ok {
		return bad()
	}
	if f.RequiredCapabilities, ok = names(m["required_capabilities"]); !ok {
		return bad()
	}
	if f.OptionalCapabilities, ok = names(m["optional_capabilities"]); !ok {
		return bad()
	}
	for _, capability := range f.OptionalCapabilities {
		if slices.Contains(f.RequiredCapabilities, capability) {
			return bad()
		}
	}
	for _, capability := range []string{CapabilityContentSHA256, CapabilityLinearHistory} {
		if !slices.Contains(f.RequiredCapabilities, capability) {
			return bad()
		}
	}
	if slices.Contains(f.Profiles, ProfileComplete) && !slices.Contains(f.RequiredCapabilities, CapabilityPortableMemory) {
		return bad()
	}
	a, ok := m["extensions"].([]any)
	if !ok {
		return bad()
	}
	f.Extensions = []ExtensionDeclaration{}
	prior := ""
	for _, item := range a {
		e, ok := item.(map[string]any)
		if !ok || len(e) != 2 {
			return bad()
		}
		n, ok := e["namespace"].(string)
		if !ok || !namespacePattern.MatchString(n) || n <= prior {
			return bad()
		}
		prior = n
		capability, exists := e["required_capability"]
		if !exists {
			return bad()
		}
		decl := ExtensionDeclaration{Namespace: n}
		if capability != nil {
			c, ok := capability.(string)
			if !ok || !slices.Contains(f.RequiredCapabilities, c) {
				return bad()
			}
			decl.RequiredCapability = &c
		}
		f.Extensions = append(f.Extensions, decl)
	}
	return f, nil
}
func names(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []string{}
	prior := ""
	for _, v := range a {
		s, ok := v.(string)
		if !ok || !namespacePattern.MatchString(s) || s <= prior {
			return nil, false
		}
		out = append(out, s)
		prior = s
	}
	return out, true
}
