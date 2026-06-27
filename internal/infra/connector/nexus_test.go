package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func fakeNexus(t *testing.T, withReport bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/applications", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("publicId") != "demo-app" {
			_, _ = w.Write([]byte(`{"applications":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"applications":[{"id":"abc123","publicId":"demo-app","name":"Demo App"}]}`))
	})
	mux.HandleFunc("/api/v2/reports/applications/abc123", func(w http.ResponseWriter, r *http.Request) {
		if !withReport {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`[
			{"stage":"build","evaluationDate":"2026-01-01","reportDataUrl":"api/v2/applications/abc123/reports/r-build"},
			{"stage":"release","evaluationDate":"2026-02-01","reportDataUrl":"api/v2/applications/abc123/reports/r-release"}]`))
	})
	// The release report should be preferred (higher stage rank).
	mux.HandleFunc("/api/v2/applications/abc123/reports/r-release/policy", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"components":[
			{"displayName":"jackson-databind-2.9.0","violations":[{"policyName":"Security-Critical","policyThreatLevel":9}]},
			{"displayName":"commons-text-1.9","violations":[{"policyName":"Security-High","policyThreatLevel":7}]},
			{"displayName":"guava-30.0","violations":[{"policyName":"Security-Low","policyThreatLevel":2}]},
			{"displayName":"clean-lib-1.0","violations":[]}]}`))
	})
	return httptest.NewServer(mux)
}

func newTestNexus(url string) *Nexus {
	return NewNexus(NexusConfig{URL: url, Application: "demo-app", Username: "admin", Secret: "token"})
}

func TestNexus_ConnectRequiresConfig(t *testing.T) {
	if err := NewNexus(NexusConfig{}).Connect(context.Background()); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestNexus_ValidateAndCollect(t *testing.T) {
	srv := fakeNexus(t, true)
	defer srv.Close()
	n := newTestNexus(srv.URL)
	ctx := context.Background()

	if err := n.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := n.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if res.Status != "release" {
		t.Fatalf("expected the release report to win, got stage %q", res.Status)
	}
	if res.Metrics["components"] != "4" {
		t.Fatalf("want 4 components, got %q", res.Metrics["components"])
	}
	if res.Metrics["violating_components"] != "3" {
		t.Fatalf("want 3 violating components, got %q", res.Metrics["violating_components"])
	}
	if res.Metrics["critical"] != "1" || res.Metrics["high"] != "1" || res.Metrics["low"] != "1" {
		t.Fatalf("want 1 crit / 1 high / 1 low, got %+v", res.Metrics)
	}
	// Critical + high violations (threat >= 6) become findings; low does not.
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings (crit+high), got %d: %+v", len(res.Findings), res.Findings)
	}
	if len(res.Covers) != 1 || res.Covers[0] != model.CatDependencyScan {
		t.Fatalf("expected to cover dependency_scan, got %v", res.Covers)
	}
}

func TestNexus_NoEvaluationDropsCoverage(t *testing.T) {
	srv := fakeNexus(t, false)
	defer srv.Close()
	n := newTestNexus(srv.URL)
	_ = n.Connect(context.Background())
	res, err := n.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Covers) != 0 {
		t.Fatalf("with no evaluation, dependency_scan must NOT be credited, got %v", res.Covers)
	}
	if res.Status != "no evaluation" {
		t.Fatalf("want status 'no evaluation', got %q", res.Status)
	}
}
