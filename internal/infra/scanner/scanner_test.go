package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// memFS adapts fstest.MapFS to port.FileSystem.
type memFS struct{ fstest.MapFS }

func (m memFS) Root() string { return "/repo" }
func (m memFS) List() ([]string, error) {
	var out []string
	for name := range m.MapFS {
		out = append(out, name)
	}
	return out, nil
}

func TestGitleaks_ImportFindings(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		"gitleaks-report.json": {Data: []byte(`[
			{"Description":"AWS key","File":"config.yml","StartLine":12,"RuleID":"aws-access-key"}]`)},
	}}
	res, err := Gitleaks{}.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if len(res[0].Covers) != 1 || res[0].Covers[0] != model.CatSecretScan {
		t.Fatalf("expected secret_scan coverage, got %v", res[0].Covers)
	}
	if len(res[0].Findings) != 1 || res[0].Findings[0].Severity != model.SevHigh {
		t.Fatalf("expected 1 high finding, got %+v", res[0].Findings)
	}
}

func TestGitleaks_CleanReportStillCovers(t *testing.T) {
	// An empty gitleaks array means the scan ran and found nothing — that still
	// proves secret scanning is in place.
	fsys := memFS{fstest.MapFS{"gitleaks.json": {Data: []byte(`[]`)}}}
	res, _ := Gitleaks{}.Import(context.Background(), fsys)
	if len(res) != 1 || len(res[0].Covers) != 1 {
		t.Fatalf("clean report should still credit coverage, got %+v", res)
	}
	if len(res[0].Findings) != 0 {
		t.Fatalf("clean report should have no findings, got %+v", res[0].Findings)
	}
}

func TestSemgrep_ImportFindings(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		"semgrep.json": {Data: []byte(`{"results":[
			{"check_id":"py.lang.security.audit","path":"app.py","start":{"line":7},
			 "extra":{"message":"eval is dangerous","severity":"ERROR"}}]}`)},
	}}
	res, _ := Semgrep{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatSAST {
		t.Fatalf("expected sast coverage, got %+v", res)
	}
	if res[0].Findings[0].Severity != model.SevHigh {
		t.Fatalf("ERROR should map to high, got %s", res[0].Findings[0].Severity)
	}
}

func TestSnyk_ImportFindings(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		"snyk.json": {Data: []byte(`{"ok":false,"dependencyCount":42,"vulnerabilities":[
			{"id":"SNYK-JS-LODASH","title":"Prototype Pollution","severity":"high","packageName":"lodash","version":"4.17.0"}]}`)},
	}}
	res, _ := Snyk{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDependencyScan {
		t.Fatalf("expected dependency_scan coverage, got %+v", res)
	}
	if res[0].Findings[0].Severity != model.SevHigh {
		t.Fatalf("expected high finding, got %+v", res[0].Findings)
	}
}

func TestSARIF_ImportMapsDriverToCategory(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		"results.sarif": {Data: []byte(`{"runs":[{"tool":{"driver":{"name":"semgrep"}},
			"results":[{"ruleId":"r1","level":"error","message":{"text":"bug"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":3}}}]}]}]}`)},
	}}
	res, _ := SARIF{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatSAST {
		t.Fatalf("expected semgrep→sast from SARIF, got %+v", res)
	}
	if res[0].Findings[0].Location != "a.go:3" {
		t.Fatalf("expected location a.go:3, got %q", res[0].Findings[0].Location)
	}
}

func TestSARIF_UnknownDriverSkipped(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		"x.sarif": {Data: []byte(`{"runs":[{"tool":{"driver":{"name":"mystery-tool"}},"results":[]}]}`)},
	}}
	res, _ := SARIF{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("unknown driver should be skipped, got %+v", res)
	}
}
