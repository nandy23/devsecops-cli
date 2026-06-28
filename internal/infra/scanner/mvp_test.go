package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestOWASPDependencyCheck_Import(t *testing.T) {
	js := `{"dependencies":[{"fileName":"log4j-core-2.14.1.jar","vulnerabilities":[{"name":"CVE-2021-44228","severity":"CRITICAL"}]}]}`
	fsys := memFS{fstest.MapFS{"dependency-check-report.json": {Data: []byte(js)}}}
	res, _ := OWASPDependencyCheck{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDependencyScan {
		t.Fatalf("expected dependency_scan coverage, got %+v", res)
	}
	if res[0].Findings[0].Severity != model.SevCritical {
		t.Fatalf("CRITICAL should map to critical, got %s", res[0].Findings[0].Severity)
	}
}

func TestNpmAudit_ModerateMapsToMedium(t *testing.T) {
	js := `{"vulnerabilities":{"lodash":{"name":"lodash","severity":"moderate","range":"<4.17.21"}}}`
	fsys := memFS{fstest.MapFS{"npm-audit.json": {Data: []byte(js)}}}
	res, _ := NpmAudit{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Findings[0].Severity != model.SevMedium {
		t.Fatalf("npm 'moderate' should map to medium, got %+v", res)
	}
}

func TestK8sManifest_BestPracticeChecks(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: myapp:latest
          securityContext:
            privileged: true
`
	fsys := memFS{fstest.MapFS{"deploy.yaml": {Data: []byte(manifest)}}}
	res, _ := K8sManifest{}.Import(context.Background(), fsys)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	var gotPriv, gotLatest, gotNonRoot bool
	for _, f := range res[0].Findings {
		switch {
		case f.Severity == model.SevCritical:
			gotPriv = true
		case contains(f.Message, "mutable/:latest"):
			gotLatest = true
		case contains(f.Message, "runAsNonRoot"):
			gotNonRoot = true
		}
	}
	if !gotPriv || !gotLatest || !gotNonRoot {
		t.Fatalf("missing expected checks: priv=%v latest=%v nonroot=%v", gotPriv, gotLatest, gotNonRoot)
	}
}

func TestK8sManifest_NoManifestsNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"app.go": {Data: []byte("package main")}}}
	res, _ := K8sManifest{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("non-k8s repo should produce no result, got %+v", res)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
