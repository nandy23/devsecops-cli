package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestTrivy_MultiCategoryFromOneReport(t *testing.T) {
	report := `{"Results":[
		{"Target":"go.mod","Class":"lang-pkgs","Vulnerabilities":[
			{"VulnerabilityID":"CVE-1","PkgName":"golang.org/x/net","InstalledVersion":"0.1","Severity":"HIGH"}]},
		{"Target":"main.tf","Class":"config","Misconfigurations":[
			{"ID":"AVD-AWS-1","Title":"public bucket","Severity":"CRITICAL","CauseMetadata":{"StartLine":4}}]},
		{"Target":"cfg.yaml","Class":"secret","Secrets":[
			{"RuleID":"aws-access-key","Title":"AWS key","Severity":"CRITICAL","StartLine":2}]}]}`
	fsys := memFS{fstest.MapFS{"trivy.json": {Data: []byte(report)}}}

	res, err := Trivy{}.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	got := map[model.SecurityCategory]bool{}
	for _, c := range res[0].Covers {
		got[c] = true
	}
	for _, want := range []model.SecurityCategory{model.CatDependencyScan, model.CatIaCScan, model.CatSecretScan} {
		if !got[want] {
			t.Fatalf("expected %s covered from one trivy report, got %v", want, res[0].Covers)
		}
	}
	if len(res[0].Findings) != 3 {
		t.Fatalf("want 3 findings (vuln+misconfig+secret), got %d", len(res[0].Findings))
	}
}
