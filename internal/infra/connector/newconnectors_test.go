package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func covers(res model.ConnectorResult, cat model.SecurityCategory) bool {
	for _, c := range res.Covers {
		if c == cat {
			return true
		}
	}
	return false
}

// ---- Dependency-Track ----

func TestDTrack_CollectCreditsSBOM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`[{"uuid":"u1","name":"demo","metrics":{"components":120,"vulnerabilities":4,"critical":1,"high":2}}]`))
	})
	mux.HandleFunc("/api/v1/finding/project/u1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"vulnerability":{"vulnId":"CVE-2021-1","severity":"HIGH"},"component":{"name":"log4j","version":"2.14"}}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := NewDTrack(DTrackConfig{URL: srv.URL, Project: "demo", APIKey: "key"})
	if err := d.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := d.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !covers(res, model.CatSBOM) {
		t.Fatalf("expected sbom coverage, got %v", res.Covers)
	}
	if res.Metrics["components"] != "120" {
		t.Fatalf("want 120 components, got %q", res.Metrics["components"])
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SevHigh {
		t.Fatalf("expected 1 high finding, got %+v", res.Findings)
	}
}

func TestDTrack_EmptySBOMDropsCoverage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"uuid":"u1","name":"demo","metrics":{"components":0}}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := NewDTrack(DTrackConfig{URL: srv.URL, Project: "demo", APIKey: "key"})
	res, _ := d.Collect(context.Background())
	if covers(res, model.CatSBOM) {
		t.Fatalf("empty SBOM must not credit sbom, got %v", res.Covers)
	}
}

// ---- JFrog Xray ----

func TestXray_CollectCreditsDepAndContainer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/xray/api/v1/system/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"xray_version":"3.0.0"}`))
	})
	mux.HandleFunc("/xray/api/v1/violations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte(`{"total_violations":2,"violations":[
			{"type":"security","severity":"High","issue_id":"XRAY-1","summary":"RCE"},
			{"type":"license","severity":"Low","issue_id":"XRAY-2","summary":"GPL"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	x := NewXray(XrayConfig{URL: srv.URL, Watch: "all", Token: "tok"})
	if err := x.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := x.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !covers(res, model.CatDependencyScan) || !covers(res, model.CatContainerScan) {
		t.Fatalf("expected dep+container coverage, got %v", res.Covers)
	}
	if res.Metrics["security_violations"] != "1" || res.Metrics["license_violations"] != "1" {
		t.Fatalf("violation counts wrong: %+v", res.Metrics)
	}
	if len(res.Findings) != 1 { // only the High security violation
		t.Fatalf("want 1 finding, got %+v", res.Findings)
	}
}

// ---- DefectDojo ----

func TestDefectDojo_MapsTagsToCategories(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/products/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"id":7}]}`))
	})
	mux.HandleFunc("/api/v2/findings/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":3,"results":[
			{"title":"SQLi","severity":"High","tags":["sast"]},
			{"title":"AWS key","severity":"Critical","tags":["secrets"]},
			{"title":"Old lib","severity":"Medium","tags":["dependency"]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := NewDefectDojo(DefectDojoConfig{URL: srv.URL, Product: "demo", Token: "tok"})
	res, err := d.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !covers(res, model.CatSAST) || !covers(res, model.CatSecretScan) || !covers(res, model.CatDependencyScan) {
		t.Fatalf("expected sast+secret+dependency coverage, got %v", res.Covers)
	}
	// High SQLi + Critical AWS key surface as findings; Medium does not.
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings, got %+v", res.Findings)
	}
}

// ---- Kyverno ----

func TestKyverno_CollectCreditsPolicy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"gitVersion":"v1.29.0"}`))
	})
	mux.HandleFunc("/apis/wgpolicyk8s.io/v1alpha2/policyreports", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"pr-1","namespace":"default"},
			"summary":{"pass":10,"fail":2,"warn":1},
			"results":[{"policy":"require-limits","rule":"limits","result":"fail","severity":"high","message":"no limits"}]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	k := NewKyverno(KyvernoConfig{URL: srv.URL, Token: "tok"})
	if err := k.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := k.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !covers(res, model.CatPolicy) {
		t.Fatalf("expected policy coverage, got %v", res.Covers)
	}
	if res.Metrics["fail"] != "2" {
		t.Fatalf("want 2 fails, got %q", res.Metrics["fail"])
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SevHigh {
		t.Fatalf("want 1 high policy finding, got %+v", res.Findings)
	}
}

func TestKyverno_NoReportsDropsCoverage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/apis/wgpolicyk8s.io/v1alpha2/policyreports", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	k := NewKyverno(KyvernoConfig{URL: srv.URL, Token: "tok"})
	res, _ := k.Collect(context.Background())
	if covers(res, model.CatPolicy) {
		t.Fatalf("no reports must not credit policy, got %v", res.Covers)
	}
	if res.Status != "no policy reports" {
		t.Fatalf("want 'no policy reports', got %q", res.Status)
	}
}
