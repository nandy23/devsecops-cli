package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestDastardly_Import(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Dastardly" tests="2" failures="2">
    <testcase name="CORS misconfiguration" classname="http://app.local/api">
      <failure message="Severity: High. Permissive CORS policy" type="High">detail</failure>
    </testcase>
    <testcase name="Cookie without secure flag" classname="http://app.local/login">
      <failure message="Severity: Low" type="Low">detail</failure>
    </testcase>
  </testsuite>
</testsuites>`
	fsys := memFS{fstest.MapFS{"dastardly.xml": {Data: []byte(xml)}}}
	res, _ := Dastardly{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST {
		t.Fatalf("want dast coverage, got %+v", res)
	}
	if len(res[0].Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res[0].Findings))
	}
	if res[0].Findings[0].Severity != model.SevHigh {
		t.Fatalf("first finding should be high, got %s", res[0].Findings[0].Severity)
	}
	if res[0].Findings[1].Severity != model.SevLow {
		t.Fatalf("second finding should be low, got %s", res[0].Findings[1].Severity)
	}
	if res[0].Findings[0].Location != "http://app.local/api" {
		t.Fatalf("unexpected location: %q", res[0].Findings[0].Location)
	}
}

func TestDastardly_CleanScanCreditsCoverage(t *testing.T) {
	xml := `<testsuites><testsuite name="Dastardly" tests="1" failures="0"><testcase name="ok"/></testsuite></testsuites>`
	fsys := memFS{fstest.MapFS{"dastardly.xml": {Data: []byte(xml)}}}
	res, _ := Dastardly{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST || len(res[0].Findings) != 0 {
		t.Fatalf("clean dastardly scan should credit dast with 0 findings, got %+v", res)
	}
}

func TestNikto_Import(t *testing.T) {
	js := `{"host":"app.local","ip":"1.2.3.4","port":"80","vulnerabilities":[
		{"id":"999957","method":"GET","url":"/","msg":"The X-Frame-Options header is not present."}
	]}`
	fsys := memFS{fstest.MapFS{"nikto.json": {Data: []byte(js)}}}
	res, _ := Nikto{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST {
		t.Fatalf("want dast coverage, got %+v", res)
	}
	if len(res[0].Findings) != 1 || res[0].Findings[0].Severity != model.SevMedium {
		t.Fatalf("want 1 medium finding, got %+v", res[0].Findings)
	}
	if res[0].Findings[0].Location != "GET app.local:80/" {
		t.Fatalf("unexpected location: %q", res[0].Findings[0].Location)
	}
}

func TestNikto_UnrelatedJSONNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"nikto.json": {Data: []byte(`{"foo":"bar"}`)}}}
	res, _ := Nikto{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("json without nikto fields should produce no result, got %+v", res)
	}
}

func TestNmap_Import(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <hostnames><hostname name="app.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/><script id="ssl-heartbleed" output="VULNERABLE: heartbleed"/></port>
    </ports>
  </host>
</nmaprun>`
	fsys := memFS{fstest.MapFS{"nmap.xml": {Data: []byte(xml)}}}
	res, _ := Nmap{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatRecon {
		t.Fatalf("want recon coverage, got %+v", res)
	}
	// 2 open ports + 1 vuln script = 3 findings; the closed port is skipped.
	if len(res[0].Findings) != 3 {
		t.Fatalf("want 3 findings, got %d: %+v", len(res[0].Findings), res[0].Findings)
	}
	if res[0].Findings[0].Location != "app.local:80/tcp" {
		t.Fatalf("unexpected location: %q", res[0].Findings[0].Location)
	}
	var gotHigh bool
	for _, f := range res[0].Findings {
		if f.Severity == model.SevHigh {
			gotHigh = true
		}
	}
	if !gotHigh {
		t.Fatalf("VULNERABLE NSE script should map to high, got %+v", res[0].Findings)
	}
}

func TestNmap_UnrelatedXMLNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"nmap.xml": {Data: []byte(`<foo><bar/></foo>`)}}}
	res, _ := Nmap{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("non-nmap xml should produce no result, got %+v", res)
	}
}
