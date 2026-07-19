package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestZAP_Import(t *testing.T) {
	js := `{"@version":"2.14.0","site":[{"@name":"http://app.local","alerts":[
		{"pluginid":"40012","alert":"Cross Site Scripting (Reflected)","name":"XSS","riskcode":"3",
		 "instances":[{"uri":"http://app.local/search?q=1","method":"GET"}]},
		{"pluginid":"10038","alert":"Content Security Policy Header Not Set","riskcode":"1","instances":[]}
	]}]}`
	fsys := memFS{fstest.MapFS{"zap.json": {Data: []byte(js)}}}
	res, _ := ZAP{}.Import(context.Background(), fsys)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].Covers[0] != model.CatDAST {
		t.Fatalf("want dast coverage, got %+v", res[0].Covers)
	}
	if len(res[0].Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res[0].Findings))
	}
	if res[0].Findings[0].Severity != model.SevHigh {
		t.Fatalf("riskcode 3 should map to high, got %s", res[0].Findings[0].Severity)
	}
	if res[0].Findings[0].Location != "GET http://app.local/search?q=1" {
		t.Fatalf("unexpected location: %q", res[0].Findings[0].Location)
	}
	if res[0].Findings[1].Severity != model.SevLow {
		t.Fatalf("riskcode 1 should map to low, got %s", res[0].Findings[1].Severity)
	}
}

func TestZAP_ZeroAlertsStillCreditsCoverage(t *testing.T) {
	js := `{"site":[{"@name":"http://app.local","alerts":[]}]}`
	fsys := memFS{fstest.MapFS{"zap-report.json": {Data: []byte(js)}}}
	res, _ := ZAP{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST {
		t.Fatalf("a clean ZAP scan should still credit dast, got %+v", res)
	}
	if len(res[0].Findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(res[0].Findings))
	}
}

func TestZAP_UnrelatedJSONNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"zap.json": {Data: []byte(`{"results":[]}`)}}}
	res, _ := ZAP{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("json without a site should produce no result, got %+v", res)
	}
}

func TestNuclei_JSONL(t *testing.T) {
	jsonl := `{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical"},"host":"http://app.local","matched-at":"http://app.local/api"}
{"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},"host":"http://app.local","matched-at":"http://app.local"}`
	fsys := memFS{fstest.MapFS{"nuclei.jsonl": {Data: []byte(jsonl)}}}
	res, _ := Nuclei{}.Import(context.Background(), fsys)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].Covers[0] != model.CatDAST {
		t.Fatalf("want dast coverage, got %+v", res[0].Covers)
	}
	if len(res[0].Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res[0].Findings))
	}
	if res[0].Findings[0].Severity != model.SevCritical {
		t.Fatalf("critical should map to critical, got %s", res[0].Findings[0].Severity)
	}
	if res[0].Findings[0].Location != "http://app.local/api" {
		t.Fatalf("unexpected location: %q", res[0].Findings[0].Location)
	}
}

func TestNuclei_JSONArray(t *testing.T) {
	arr := `[{"template-id":"exposed-panel","info":{"name":"Admin Panel","severity":"medium"},"matched-at":"http://app.local/admin"}]`
	fsys := memFS{fstest.MapFS{"nuclei.json": {Data: []byte(arr)}}}
	res, _ := Nuclei{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Findings[0].Severity != model.SevMedium {
		t.Fatalf("array form: want 1 medium finding, got %+v", res)
	}
}

func TestNuclei_UnrelatedJSONNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"nuclei.json": {Data: []byte(`{"foo":"bar"}`)}}}
	res, _ := Nuclei{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("json without nuclei fields should produce no result, got %+v", res)
	}
}
