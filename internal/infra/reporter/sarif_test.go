package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

func TestSARIF_ValidStructureAndLevels(t *testing.T) {
	a := model.Analysis{
		ToolVersion: "test",
		Recommendations: []model.Recommendation{
			{ID: "container-trivy", Category: model.CatContainerScan, Tool: "trivy", Severity: model.SevHigh, Rationale: "scan images."},
		},
		Pipelines: []model.PipelineAudit{{
			Platform: "GitHub Actions", Path: ".github/workflows/ci.yml",
			Findings: []model.Finding{{
				PipelineRef: ".github/workflows/ci.yml", Category: model.CatSBOM,
				Severity: model.SevMedium, Message: "no sbom stage", Location: ".github/workflows/ci.yml",
			}},
		}},
	}

	var buf bytes.Buffer
	if err := (SARIF{}).Render(context.Background(), a, scoring.Report{}, &buf); err != nil {
		t.Fatal(err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("want version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "devsec" {
		t.Fatalf("want driver devsec, got %s", run.Tool.Driver.Name)
	}
	// One finding result (medium → warning) + one recommendation (high → error).
	var gotError, gotWarning bool
	for _, r := range run.Results {
		switch r.Level {
		case "error":
			gotError = true
		case "warning":
			gotWarning = true
		}
	}
	if !gotError || !gotWarning {
		t.Fatalf("expected both error and warning levels, results=%+v", run.Results)
	}
}
