// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"encoding/json"
	"io/fs"
	"testing"
	"time"

	pkg "github.com/orbifabric/package-go"
	"github.com/orbifabric/package-go/conformance"
)

func TestProtocolUTCTimestampVectors(t *testing.T) {
	b, err := fs.ReadFile(conformance.Assets(), "vectors/crypto.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Times struct {
			Valid   []string `json:"valid"`
			Invalid []string `json:"invalid"`
		} `json:"canonical_timestamps"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Times.Valid) != 4 || len(v.Times.Invalid) != 15 {
		t.Fatal("unhandled upstream timestamp inventory")
	}
	for _, input := range v.Times.Valid {
		at, err := pkg.ParseTimestamp(input)
		if err != nil || at.Location() != time.UTC {
			t.Fatalf("canonical UTC %q: %v %v", input, at, err)
		}
		// An explicit nonzero Host zone must render the same UTC microsecond.
		output, err := pkg.Timestamp(at.In(time.FixedZone("Host", -4*3600)))
		if err != nil || output != input {
			t.Fatalf("UTC round trip %q: %q %v", input, output, err)
		}
	}
	for _, input := range v.Times.Invalid {
		_, err := pkg.ParseTimestamp(input)
		requireCode(t, err, pkg.ReasonInvalidSchema)
	}
}
