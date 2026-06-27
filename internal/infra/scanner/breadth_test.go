package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

func firstResult(t *testing.T, im port.ResultImporter, fsys port.FileSystem) model.ScanResult {
	t.Helper()
	res, err := im.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	return res[0]
}

func TestTruffleHog_NDJSON(t *testing.T) {
	ndjson := `{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA...","SourceMetadata":{"Data":{"Filesystem":{"file":"cfg.go","line":3}}}}
{"DetectorName":"GitHub","Verified":false,"Redacted":"ghp_...","SourceMetadata":{"Data":{"Filesystem":{"file":"x.go","line":7}}}}`
	fsys := memFS{fstest.MapFS{"trufflehog.json": {Data: []byte(ndjson)}}}
	r := firstResult(t, TruffleHog{}, fsys)
	if r.Covers[0] != model.CatSecretScan || len(r.Findings) != 2 {
		t.Fatalf("expected 2 secret findings, got %+v", r)
	}
	if r.Findings[0].Severity != model.SevCritical { // verified secret
		t.Fatalf("verified secret should be critical, got %s", r.Findings[0].Severity)
	}
}

func TestGrype_JSON(t *testing.T) {
	js := `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"Critical"},"artifact":{"name":"openssl","version":"1.1"}}]}`
	fsys := memFS{fstest.MapFS{"grype.json": {Data: []byte(js)}}}
	r := firstResult(t, Grype{}, fsys)
	if r.Covers[0] != model.CatContainerScan || r.Findings[0].Severity != model.SevCritical {
		t.Fatalf("expected critical container finding, got %+v", r)
	}
}

func TestHadolint_JSON(t *testing.T) {
	js := `[{"file":"Dockerfile","line":3,"code":"DL3008","level":"warning","message":"Pin versions"}]`
	fsys := memFS{fstest.MapFS{"hadolint.json": {Data: []byte(js)}}}
	r := firstResult(t, Hadolint{}, fsys)
	if r.Covers[0] != model.CatContainerScan || r.Findings[0].Severity != model.SevMedium {
		t.Fatalf("warning should map to medium container finding, got %+v", r)
	}
}

func TestTfsec_JSON(t *testing.T) {
	js := `{"results":[{"rule_id":"aws-s3-no-public","severity":"HIGH","description":"public bucket","location":{"filename":"main.tf","start_line":5}}]}`
	fsys := memFS{fstest.MapFS{"tfsec.json": {Data: []byte(js)}}}
	r := firstResult(t, Tfsec{}, fsys)
	if r.Covers[0] != model.CatIaCScan || r.Findings[0].Severity != model.SevHigh {
		t.Fatalf("expected high iac finding, got %+v", r)
	}
	if r.Findings[0].Location != "main.tf:5" {
		t.Fatalf("expected location main.tf:5, got %q", r.Findings[0].Location)
	}
}

func TestKubescape_JSON(t *testing.T) {
	js := `{"summaryDetails":{"controls":{
		"C-0001":{"name":"Allowed hostPath","statusInfo":{"status":"failed"},"scoreFactor":8},
		"C-0002":{"name":"Resource limits","statusInfo":{"status":"passed"},"scoreFactor":3}}}}`
	fsys := memFS{fstest.MapFS{"kubescape.json": {Data: []byte(js)}}}
	r := firstResult(t, Kubescape{}, fsys)
	if r.Covers[0] != model.CatPolicy {
		t.Fatalf("expected policy coverage, got %v", r.Covers)
	}
	// only the failed control becomes a finding (and scoreFactor 8 → high)
	if len(r.Findings) != 1 || r.Findings[0].Severity != model.SevHigh {
		t.Fatalf("expected 1 high policy finding, got %+v", r.Findings)
	}
}

func TestSARIF_NewDriverMappings(t *testing.T) {
	cases := map[string]model.SecurityCategory{
		"grype":      model.CatContainerScan,
		"hadolint":   model.CatContainerScan,
		"trufflehog": model.CatSecretScan,
		"kubescape":  model.CatPolicy,
	}
	for driver, want := range cases {
		got, ok := driverCategory(driver)
		if !ok || got != want {
			t.Fatalf("driver %s: want %s, got %s (ok=%v)", driver, want, got, ok)
		}
	}
}
