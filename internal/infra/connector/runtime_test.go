package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// ---- Falco ----

func TestFalco_ReadyDaemonSetCreditsRuntime(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"gitVersion":"v1.29"}`))
	})
	mux.HandleFunc("/apis/apps/v1/namespaces/falco/daemonsets/falco", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"desiredNumberScheduled":3,"numberReady":3}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := NewFalco(FalcoConfig{URL: srv.URL, Token: "tok"})
	if err := f.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := f.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !covers(res, model.CatRuntime) {
		t.Fatalf("ready Falco should credit runtime, got %v", res.Covers)
	}
	if res.Status != "active" || res.Metrics["ready"] != "3" {
		t.Fatalf("unexpected status/metrics: %s %+v", res.Status, res.Metrics)
	}
}

func TestFalco_NotReadyDropsRuntime(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/apis/apps/v1/namespaces/falco/daemonsets/falco", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"desiredNumberScheduled":3,"numberReady":0}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := NewFalco(FalcoConfig{URL: srv.URL, Token: "tok"})
	res, _ := f.Collect(context.Background())
	if covers(res, model.CatRuntime) {
		t.Fatalf("Falco with 0 ready pods must not credit runtime, got %v", res.Covers)
	}
}

// ---- Rekor ----

func TestRekor_EntriesCreditSigning(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/log", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"treeSize":42}`))
	})
	mux.HandleFunc("/api/v1/index/retrieve", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["uuid-1","uuid-2"]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rk := NewRekor(RekorConfig{URL: srv.URL, Email: "ci@example.com"})
	if err := rk.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := rk.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !covers(res, model.CatSigning) || res.Metrics["log_entries"] != "2" {
		t.Fatalf("expected signing credited with 2 entries, got %v / %+v", res.Covers, res.Metrics)
	}
}

func TestRekor_NoEntriesDropsSigning(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/index/retrieve", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rk := NewRekor(RekorConfig{URL: srv.URL, Hash: "abc123"})
	res, _ := rk.Collect(context.Background())
	if covers(res, model.CatSigning) {
		t.Fatalf("no entries must not credit signing, got %v", res.Covers)
	}
}

// ---- Jenkins ----

func TestJenkins_DetectsSecurityStages(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"mode":"NORMAL"}`))
	})
	mux.HandleFunc("/job/app/api/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"lastBuild":{"result":"SUCCESS","number":42}}`))
	})
	mux.HandleFunc("/job/app/config.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<flow-definition><script>
			stage('SAST'){ sh 'semgrep ci' }
			stage('Secrets'){ sh 'gitleaks detect' }
			stage('Sign'){ sh 'cosign sign img' }
		</script></flow-definition>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	j := NewJenkins(JenkinsConfig{URL: srv.URL, Job: "app", Username: "u", Token: "t"})
	if err := j.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := j.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "SUCCESS" {
		t.Fatalf("want last build SUCCESS, got %q", res.Status)
	}
	if !covers(res, model.CatSAST) || !covers(res, model.CatSecretScan) || !covers(res, model.CatSigning) {
		t.Fatalf("expected sast+secret+signing detected, got %v", res.Covers)
	}
}

func TestJenkins_NoStagesNoCoverage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/job/app/api/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"lastBuild":{"result":"SUCCESS","number":1}}`))
	})
	mux.HandleFunc("/job/app/config.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<flow-definition><script>stage('Build'){ sh 'make' }</script></flow-definition>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	j := NewJenkins(JenkinsConfig{URL: srv.URL, Job: "app", Username: "u", Token: "t"})
	res, _ := j.Collect(context.Background())
	if len(res.Covers) != 0 {
		t.Fatalf("no security stages should mean no coverage, got %v", res.Covers)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected a finding about missing security stages")
	}
}
