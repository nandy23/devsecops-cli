package scanner

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestTrivy_LicenseFindings(t *testing.T) {
	js := `{"Results":[
		{"Target":"Node.js","Class":"license","Licenses":[
			{"Severity":"HIGH","Category":"restricted","PkgName":"leftpad","Name":"GPL-3.0","FilePath":""},
			{"Severity":"LOW","Category":"notice","PkgName":"lodash","Name":"MIT"}
		]}
	]}`
	fsys := memFS{fstest.MapFS{"trivy.json": {Data: []byte(js)}}}
	res, _ := Trivy{}.Import(context.Background(), fsys)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if !coversCategory(res[0].Covers, model.CatLicense) {
		t.Fatalf("expected license coverage, got %+v", res[0].Covers)
	}
	if len(res[0].Findings) != 2 {
		t.Fatalf("want 2 license findings, got %d: %+v", len(res[0].Findings), res[0].Findings)
	}
	if res[0].Findings[0].Severity != model.SevHigh {
		t.Fatalf("HIGH license should map to high, got %s", res[0].Findings[0].Severity)
	}
	if !strings.Contains(res[0].Findings[0].Message, "GPL-3.0") ||
		!strings.Contains(res[0].Findings[0].Message, "restricted") {
		t.Fatalf("finding should name the license and its category, got %q", res[0].Findings[0].Message)
	}
}

func TestTrivy_LicenseAndVulnsCreditBothCategories(t *testing.T) {
	js := `{"Results":[
		{"Target":"pkgs","Class":"lang-pkgs","Vulnerabilities":[
			{"VulnerabilityID":"CVE-2021-1","PkgName":"foo","InstalledVersion":"1.0","Severity":"CRITICAL"}
		]},
		{"Target":"licenses","Class":"license","Licenses":[
			{"Severity":"MEDIUM","Category":"reciprocal","PkgName":"bar","Name":"MPL-2.0"}
		]}
	]}`
	fsys := memFS{fstest.MapFS{"trivy.json": {Data: []byte(js)}}}
	res, _ := Trivy{}.Import(context.Background(), fsys)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if !coversCategory(res[0].Covers, model.CatDependencyScan) || !coversCategory(res[0].Covers, model.CatLicense) {
		t.Fatalf("expected both dependency_scan and license coverage, got %+v", res[0].Covers)
	}
}

func coversCategory(covers []model.SecurityCategory, cat model.SecurityCategory) bool {
	for _, c := range covers {
		if c == cat {
			return true
		}
	}
	return false
}
