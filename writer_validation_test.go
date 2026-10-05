// SPDX-License-Identifier: Apache-2.0
package packagego_test

import (
	"archive/zip"
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	pkg "github.com/orbifabric/package-go"
)

func TestS11EveryWriterRejectsKnownBadAttestationsWithoutRepair(t *testing.T) {
	for _, name := range []string{"bad-signature", "bad-evidence", "invalid-memory"} {
		t.Run(name, func(t *testing.T) {
			ctx, l, support := context.Background(), conformancePolicy(), pkg.CompleteSupport()
			s := treeFixture(t, "bad-signature")
			code := pkg.ReasonBadSignature
			if name == "bad-evidence" {
				s = treeFixture(t, "later-evidence-append")
				e := anchorFromSource(t, s)
				e.KeyID = "changed key attribution"
				s.setFile(evidencePath(e.Subject.EvidenceID), jsonBytes(t, e))
				code = pkg.ReasonInvalidEvidence
			}
			if name == "invalid-memory" {
				s = treeFixture(t, "minimal-valid")
				s.setFile(".packtell/metadata/notes.json", []byte(`{"schema":"wrong"}`))
				code = pkg.ReasonInvalidSchema
			}
			original := mapsCloneBytes(s.data)
			view, err := pkg.Verify(ctx, s, l, pkg.VerificationOptions{Support: support})
			if name != "invalid-memory" && (err != nil || view.Result.HistoryCompleteness != pkg.HistoryFull || view.Result.CommittedIntegrity != pkg.IntegrityValid) {
				t.Fatal("original independent proof", view, err)
			}
			for _, planner := range []func(context.Context, pkg.SnapshotSource, pkg.Limits, pkg.CapabilitySupport, pkg.TransferOptions) (pkg.TransferPlan, error){pkg.PlanImport, pkg.PlanExport} {
				plan, err := planner(ctx, s, l, support, testTransferOptions())
				requireCode(t, err, code)
				if plan.Summary().PackageID != "" {
					t.Fatal("negative input got a transfer plan")
				}
			}
			host := &transferMemoryHost{}
			publication, err := pkg.PublishDirectory(ctx, s, host, l, support)
			requireCode(t, err, code)
			if publication != (pkg.DirectoryPublication{}) || host.begins != 0 {
				t.Fatal("negative source started publication", publication, host.begins)
			}
			var pending bytes.Buffer
			artifact, err := pkg.WriteZIP(ctx, s, &pending, pkg.ZIPOptions{DisplayDirectory: "Writer Rejection", Method: zip.Deflate}, l, support)
			requireCode(t, err, code)
			if artifact != (pkg.ZIPWriteResult{}) || pending.Len() != 0 || !equalTransferBytes(original, s.data) {
				t.Fatal("negative source repaired or wrote output", artifact, pending.Len())
			}
			if name == "invalid-memory" {
				for _, path := range s.opens {
					if strings.HasPrefix(path, ".packtell/objects/") {
						t.Fatal("object read before malformed portable schema rejected", path)
					}
				}
			}
		})
	}
}

func TestS11UninterpretedEvidenceCannotProduceTransferFULL(t *testing.T) {
	s := treeFixture(t, "later-evidence-append")
	support := pkg.CompleteSupport()
	support.Capabilities = slices.DeleteFunc(support.Capabilities, func(c string) bool { return c == pkg.CapabilityDeliveryEvidence })
	plan, err := pkg.PlanExport(context.Background(), s, conformancePolicy(), support, testTransferOptions())
	if err != nil || plan.Summary().Input.HistoryCompleteness != pkg.HistoryNotChecked {
		t.Fatal("unexecuted embedded obligations became FULL", plan.Summary(), err)
	}
	host := &transferMemoryHost{}
	out, err := pkg.ExecuteTransferDirectory(context.Background(), plan, host, nil)
	if err == nil || out.PackageID != "" || host.tx == nil || host.tx.published || !host.tx.aborted {
		t.Fatal("unexecuted output proof published", out, err)
	}
}
