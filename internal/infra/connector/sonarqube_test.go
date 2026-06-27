package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// fakeSonar serves canned SonarQube Web API responses.
func fakeSonar(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/authentication/validate", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/incorrect bearer token: %q", got)
		}
		_, _ = w.Write([]byte(`{"valid":true}`))
	})
	mux.HandleFunc("/api/qualitygates/project_status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"projectStatus":{"status":"ERROR","conditions":[
			{"metricKey":"new_coverage","status":"ERROR","actualValue":"45.0","errorThreshold":"80"}]}}`))
	})
	mux.HandleFunc("/api/measures/component", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"component":{"measures":[
			{"metric":"vulnerabilities","value":"3"},
			{"metric":"coverage","value":"45.0"}]}}`))
	})
	mux.HandleFunc("/api/issues/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total":1,"issues":[
			{"rule":"java:S2076","severity":"CRITICAL","message":"OS command injection","component":"my-proj:src/App.java","line":42}]}`))
	})
	return httptest.NewServer(mux)
}

func newTestSonar(url string) *Sonar {
	return NewSonar(SonarConfig{URL: url, Project: "my-proj", Token: "test-token"})
}

func TestSonar_ConnectRequiresConfig(t *testing.T) {
	s := NewSonar(SonarConfig{})
	if err := s.Connect(context.Background()); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestSonar_ValidateAndCollect(t *testing.T) {
	srv := fakeSonar(t)
	defer srv.Close()
	s := newTestSonar(srv.URL)

	ctx := context.Background()
	if err := s.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := s.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if res.Status != "ERROR" {
		t.Fatalf("want quality gate ERROR, got %s", res.Status)
	}
	if res.Metrics["vulnerabilities"] != "3" {
		t.Fatalf("want 3 vulnerabilities metric, got %q", res.Metrics["vulnerabilities"])
	}
	if res.Metrics["open_vulnerabilities"] != "1" {
		t.Fatalf("want 1 open vulnerability, got %q", res.Metrics["open_vulnerabilities"])
	}
	// One failing quality-gate condition + one VULNERABILITY issue = 2 findings.
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(res.Findings), res.Findings)
	}
	// The CRITICAL Sonar issue should map to High severity.
	var foundHigh bool
	for _, f := range res.Findings {
		if f.Severity == model.SevHigh {
			foundHigh = true
		}
	}
	if !foundHigh {
		t.Fatalf("expected a high-severity finding, got %+v", res.Findings)
	}
	if len(res.Covers) != 1 || res.Covers[0] != model.CatSAST {
		t.Fatalf("expected to cover SAST, got %v", res.Covers)
	}
}

func TestSonar_AuthFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/authentication/validate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := newTestSonar(srv.URL)
	if err := s.Validate(context.Background()); err == nil {
		t.Fatal("expected auth failure error")
	}
}
