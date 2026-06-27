package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func fakeHarbor(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2.0/users/current", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "robot$ci" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"username":"robot$ci"}`))
	})
	mux.HandleFunc("/api/v2.0/projects/demo/repositories", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"demo/api"},{"name":"demo/web"}]`))
	})
	// Scanned artifact with criticals/highs.
	mux.HandleFunc("/api/v2.0/projects/demo/repositories/api/artifacts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"digest":"sha256:aaaaaaaaaaaaaaaa","scan_overview":{
			"application/vnd.security.vulnerability.report; version=1.1":{
				"severity":"Critical",
				"summary":{"total":12,"fixable":8,"summary":{"Critical":2,"High":3,"Medium":7}}}}}]`))
	})
	// Unscanned artifact.
	mux.HandleFunc("/api/v2.0/projects/demo/repositories/web/artifacts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"digest":"sha256:bbbbbbbbbbbbbbbb","scan_overview":{}}]`))
	})
	return httptest.NewServer(mux)
}

func newTestHarbor(url string) *Harbor {
	return NewHarbor(HarborConfig{URL: url, Project: "demo", Username: "robot$ci", Secret: "secret"})
}

func TestHarbor_ConnectRequiresConfig(t *testing.T) {
	if err := NewHarbor(HarborConfig{}).Connect(context.Background()); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestHarbor_ValidateAndCollect(t *testing.T) {
	srv := fakeHarbor(t)
	defer srv.Close()
	h := newTestHarbor(srv.URL)
	ctx := context.Background()

	if err := h.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := h.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if res.Metrics["repositories"] != "2" {
		t.Fatalf("want 2 repositories, got %q", res.Metrics["repositories"])
	}
	if res.Metrics["scanned"] != "1" || res.Metrics["unscanned"] != "1" {
		t.Fatalf("want 1 scanned / 1 unscanned, got scanned=%q unscanned=%q", res.Metrics["scanned"], res.Metrics["unscanned"])
	}
	if res.Metrics["critical"] != "2" || res.Metrics["high"] != "3" {
		t.Fatalf("want 2 critical / 3 high, got critical=%q high=%q", res.Metrics["critical"], res.Metrics["high"])
	}
	// Covers container_scan since at least one artifact is scanned.
	if len(res.Covers) != 1 || res.Covers[0] != model.CatContainerScan {
		t.Fatalf("expected to cover container_scan, got %v", res.Covers)
	}
	// One critical finding (api) + one unscanned finding (web).
	var gotCritical, gotUnscanned bool
	for _, f := range res.Findings {
		if f.Severity == model.SevCritical {
			gotCritical = true
		}
		if strings.Contains(f.Message, "no vulnerability scan") {
			gotUnscanned = true
		}
	}
	if !gotCritical || !gotUnscanned {
		t.Fatalf("expected critical and unscanned findings, got %+v", res.Findings)
	}
}

func TestHarbor_NoScansDropsCoverage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2.0/users/current", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"robot$ci"}`))
	})
	mux.HandleFunc("/api/v2.0/projects/demo/repositories", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"demo/api"}]`))
	})
	mux.HandleFunc("/api/v2.0/projects/demo/repositories/api/artifacts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"digest":"sha256:cccccccccccccccc","scan_overview":{}}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := newTestHarbor(srv.URL)
	_ = h.Connect(context.Background())
	res, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Covers) != 0 {
		t.Fatalf("with nothing scanned, container_scan must NOT be credited, got %v", res.Covers)
	}
	if res.Status != "no scans" {
		t.Fatalf("want status 'no scans', got %q", res.Status)
	}
}
