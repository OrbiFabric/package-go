// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

func TestActualAttestationNeedsDeclaredRootAndVersionCapability(t *testing.T) {
	for _, scenario := range []struct{ name, fixture, path, capability string }{
		{"root-signature", "valid-signature", ".packtell/format.json", pkg.CapabilityVersionSignature},
		{"version-signature", "valid-signature", ".packtell/versions/019a0000-0000-7000-8000-000000000002/version.json", pkg.CapabilityVersionSignature},
		{"root-evidence", "later-evidence-append", ".packtell/format.json", pkg.CapabilityDeliveryEvidence},
		{"version-evidence", "later-evidence-append", ".packtell/versions/019a0000-0000-7000-8000-000000000002/version.json", pkg.CapabilityDeliveryEvidence},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s := treeFixture(t, scenario.fixture)
			var doc map[string]any
			if err := json.Unmarshal(s.data[scenario.path], &doc); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"required_capabilities", "optional_capabilities"} {
				values := doc[field].([]any)
				doc[field] = slices.DeleteFunc(values, func(v any) bool { return v == scenario.capability })
			}
			s.setFile(scenario.path, jsonBytes(t, doc))
			got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			t.Logf("actual=%+v error=%v", got.Result, err)
			if got.Result.HistoryCompleteness == pkg.HistoryFull || got.Result.Structure != pkg.StructureInvalid {
				t.Fatal("illegal actual capability presence became valid/FULL")
			}
			requireCode(t, err, pkg.ReasonInvalidSchema)
			for _, p := range s.opens {
				if strings.HasPrefix(p, ".packtell/objects/") {
					t.Fatal("illegal declarations reached objects", p)
				}
			}
			host := &transferMemoryHost{}
			out, err := pkg.PublishDirectory(context.Background(), s, host, conformancePolicy(), pkg.CompleteSupport())
			requireCode(t, err, pkg.ReasonInvalidSchema)
			if out != (pkg.DirectoryPublication{}) || host.begins != 0 {
				t.Fatal("illegal declarations reached publication")
			}
			plan, err := pkg.PlanExport(context.Background(), s, conformancePolicy(), pkg.CompleteSupport(), testTransferOptions())
			requireCode(t, err, pkg.ReasonInvalidSchema)
			if plan.Summary().PackageID != "" {
				t.Fatal("illegal declarations got plan")
			}
			var pending bytes.Buffer
			artifact, err := pkg.WriteZIP(context.Background(), s, &pending, pkg.ZIPOptions{DisplayDirectory: "Capability Proof", Method: zip.Store}, conformancePolicy(), pkg.CompleteSupport())
			requireCode(t, err, pkg.ReasonInvalidSchema)
			if artifact != (pkg.ZIPWriteResult{}) || pending.Len() != 0 {
				t.Fatal("illegal declarations wrote ZIP")
			}
		})
	}
}

func TestKnownAttestationSchemaFailureCannotProveFULL(t *testing.T) {
	for _, kind := range []string{"signature", "evidence"} {
		t.Run(kind, func(t *testing.T) {
			s := treeFixture(t, "valid-signature")
			prefix := ".packtell/verification/versions/"
			if kind == "evidence" {
				s = treeFixture(t, "later-evidence-append")
				prefix = ".packtell/evidence/objects/"
			}
			for p, b := range s.data {
				if !strings.HasPrefix(p, prefix) {
					continue
				}
				var document map[string]any
				if err := json.Unmarshal(b, &document); err != nil {
					t.Fatal(err)
				}
				document["unknown_closed_property"] = true
				s.setFile(p, jsonBytes(t, document))
				break
			}
			got, err := pkg.Verify(context.Background(), s, conformancePolicy(), pkg.VerificationOptions{Support: pkg.CompleteSupport()})
			t.Logf("actual=%+v error=%v", got.Result, err)
			if got.Result.HistoryCompleteness == pkg.HistoryFull || got.Result.Structure != pkg.StructureInvalid {
				t.Fatal("known control schema failure became valid/FULL")
			}
			requireCode(t, err, pkg.ReasonInvalidSchema)
		})
	}
}
