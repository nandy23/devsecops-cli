package scanner

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestSSLyze_Import(t *testing.T) {
	js := `{"server_scan_results":[{
		"server_location":{"hostname":"app.local","port":443},
		"scan_result":{
			"ssl_2_0_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
			"ssl_3_0_cipher_suites":{"result":{"accepted_cipher_suites":[{"cipher_suite":{"name":"SSL_CK_RC4_128"}}]}},
			"tls_1_0_cipher_suites":{"result":{"accepted_cipher_suites":[{"cipher_suite":{"name":"TLS_RSA_WITH_AES_128"}}]}},
			"tls_1_1_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
			"heartbleed":{"result":{"is_vulnerable_to_heartbleed":true}},
			"openssl_ccs_injection":{"result":{"is_vulnerable_to_ccs_injection":false}},
			"robot":{"result":{"robot_result":"NOT_VULNERABLE_NO_ORACLE"}},
			"certificate_info":{"result":{"certificate_deployments":[{"path_validation_results":[{"was_validation_successful":false}]}]}}
		}}]}`
	fsys := memFS{fstest.MapFS{"sslyze.json": {Data: []byte(js)}}}
	res, _ := SSLyze{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST {
		t.Fatalf("want dast coverage, got %+v", res)
	}
	// SSLv3 accepted + TLS1.0 accepted + Heartbleed + cert failure = 4 findings.
	if len(res[0].Findings) != 4 {
		t.Fatalf("want 4 findings, got %d: %+v", len(res[0].Findings), res[0].Findings)
	}
	var gotCritical, gotHeartbleed bool
	for _, f := range res[0].Findings {
		if f.Location != "app.local:443" {
			t.Fatalf("unexpected location: %q", f.Location)
		}
		if f.Severity == model.SevCritical {
			gotCritical = true
		}
		if strings.Contains(f.Message, "Heartbleed") {
			gotHeartbleed = true
		}
	}
	if !gotCritical || !gotHeartbleed {
		t.Fatalf("expected a critical Heartbleed finding, got %+v", res[0].Findings)
	}
}

func TestSSLyze_CleanScanCreditsCoverage(t *testing.T) {
	js := `{"server_scan_results":[{
		"server_location":{"hostname":"app.local","port":443},
		"scan_result":{
			"ssl_2_0_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
			"ssl_3_0_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
			"tls_1_0_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
			"tls_1_1_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
			"heartbleed":{"result":{"is_vulnerable_to_heartbleed":false}},
			"robot":{"result":{"robot_result":"NOT_VULNERABLE_NO_ORACLE"}},
			"certificate_info":{"result":{"certificate_deployments":[{"path_validation_results":[{"was_validation_successful":true}]}]}}
		}}]}`
	fsys := memFS{fstest.MapFS{"sslyze.json": {Data: []byte(js)}}}
	res, _ := SSLyze{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST || len(res[0].Findings) != 0 {
		t.Fatalf("clean sslyze scan should credit dast with 0 findings, got %+v", res)
	}
}

func TestSSLyze_UnrelatedJSONNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"sslyze.json": {Data: []byte(`{"foo":"bar"}`)}}}
	res, _ := SSLyze{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("json without server_scan_results should produce no result, got %+v", res)
	}
}

func TestTestSSL_Import(t *testing.T) {
	js := `[
		{"id":"SSLv2","fqdn/ip":"app.local/1.2.3.4","port":"443","severity":"OK","finding":"not offered"},
		{"id":"heartbleed","fqdn/ip":"app.local/1.2.3.4","port":"443","severity":"OK","finding":"not vulnerable"},
		{"id":"cipherlist_3DES","fqdn/ip":"app.local/1.2.3.4","port":"443","severity":"MEDIUM","finding":"3DES offered"},
		{"id":"BREACH","fqdn/ip":"app.local/1.2.3.4","port":"443","severity":"HIGH","finding":"potentially vulnerable","cve":"CVE-2013-3587"}
	]`
	fsys := memFS{fstest.MapFS{"testssl.json": {Data: []byte(js)}}}
	res, _ := TestSSL{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST {
		t.Fatalf("want dast coverage, got %+v", res)
	}
	// OK rows dropped; MEDIUM + HIGH kept = 2 findings.
	if len(res[0].Findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(res[0].Findings), res[0].Findings)
	}
	var gotHighCVE bool
	for _, f := range res[0].Findings {
		if f.Location != "app.local/1.2.3.4:443" {
			t.Fatalf("unexpected location: %q", f.Location)
		}
		if f.Severity == model.SevHigh && strings.Contains(f.Message, "CVE-2013-3587") {
			gotHighCVE = true
		}
	}
	if !gotHighCVE {
		t.Fatalf("expected a HIGH finding carrying the CVE, got %+v", res[0].Findings)
	}
}

func TestTestSSL_AllOKCreditsCoverage(t *testing.T) {
	js := `[{"id":"SSLv2","fqdn/ip":"app.local","port":"443","severity":"OK","finding":"not offered"}]`
	fsys := memFS{fstest.MapFS{"testssl.json": {Data: []byte(js)}}}
	res, _ := TestSSL{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatDAST || len(res[0].Findings) != 0 {
		t.Fatalf("clean testssl scan should credit dast with 0 findings, got %+v", res)
	}
}

func TestTestSSL_UnrelatedArrayNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"testssl.json": {Data: []byte(`[{"foo":"bar"}]`)}}}
	res, _ := TestSSL{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("array without testssl fields should produce no result, got %+v", res)
	}
}
