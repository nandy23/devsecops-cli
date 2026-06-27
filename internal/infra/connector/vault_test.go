package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// fakeVault serves canned Vault API responses. health controls the cluster
// state and mountsStatus controls the /sys/mounts response.
func fakeVault(t *testing.T, healthBody string, mountsStatus int, mountsBody string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.testtoken" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"display_name":"token"}}`))
	})
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(healthBody))
	})
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(mountsStatus)
		if mountsBody != "" {
			_, _ = w.Write([]byte(mountsBody))
		}
	})
	return httptest.NewServer(mux)
}

func newTestVault(url string) *Vault {
	return NewVault(VaultConfig{URL: url, Token: "s.testtoken"})
}

func TestVault_ConnectRequiresConfig(t *testing.T) {
	if err := NewVault(VaultConfig{}).Connect(context.Background()); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestVault_OperationalWithKVEngine(t *testing.T) {
	mounts := `{"data":{"secret/":{"type":"kv","options":{"version":"2"}},"sys/":{"type":"system"},"cubbyhole/":{"type":"cubbyhole"}}}`
	srv := fakeVault(t, `{"initialized":true,"sealed":false,"standby":false,"version":"1.15.0"}`, 200, mounts)
	defer srv.Close()

	v := newTestVault(srv.URL)
	ctx := context.Background()
	if err := v.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := v.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "operational" {
		t.Fatalf("want operational, got %q", res.Status)
	}
	if res.Metrics["kv_engines"] != "1" {
		t.Fatalf("want 1 kv engine, got %q", res.Metrics["kv_engines"])
	}
	if res.Metrics["secret_engines"] != "3" {
		t.Fatalf("want 3 total engines, got %q", res.Metrics["secret_engines"])
	}
	if len(res.Covers) != 1 || res.Covers[0] != model.CatSecretScan {
		t.Fatalf("expected to cover secret_scan, got %v", res.Covers)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("operational Vault with KV should have no findings, got %+v", res.Findings)
	}
}

func TestVault_SealedDropsCoverage(t *testing.T) {
	srv := fakeVault(t, `{"initialized":true,"sealed":true,"version":"1.15.0"}`, 200, "")
	defer srv.Close()

	v := newTestVault(srv.URL)
	_ = v.Connect(context.Background())
	res, err := v.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Covers) != 0 {
		t.Fatalf("sealed Vault must NOT credit secret_scan, got %v", res.Covers)
	}
	if res.Status != "sealed" {
		t.Fatalf("want status 'sealed', got %q", res.Status)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SevHigh {
		t.Fatalf("expected one high finding for sealed Vault, got %+v", res.Findings)
	}
}

func TestVault_ForbiddenMountsStillCovers(t *testing.T) {
	// A non-privileged token can't list mounts (403) but Vault is still
	// operational, so secret_scan should still be credited.
	srv := fakeVault(t, `{"initialized":true,"sealed":false,"version":"1.15.0"}`, http.StatusForbidden, "")
	defer srv.Close()

	v := newTestVault(srv.URL)
	_ = v.Connect(context.Background())
	res, err := v.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Covers) != 1 || res.Covers[0] != model.CatSecretScan {
		t.Fatalf("operational Vault should cover secret_scan even without mount access, got %v", res.Covers)
	}
	// Could not enumerate, so no "no KV engines" finding should be raised.
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings when enumeration is forbidden, got %+v", res.Findings)
	}
}
