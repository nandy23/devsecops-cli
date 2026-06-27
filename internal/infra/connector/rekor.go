package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// RekorConfig configures the Sigstore Rekor connector.
type RekorConfig struct {
	URL   string       // Rekor server, e.g. https://rekor.sigstore.dev
	Email string       // signer identity to search for (OIDC email)
	Hash  string       // OR an artifact sha256 to search for
	HTTP  *http.Client // optional; injected in tests
}

// Rekor is a connector for the Sigstore Rekor transparency log. Finding entries
// for a signer identity (or artifact hash) proves signatures are being recorded,
// so it credits the signing category.
type Rekor struct {
	cfg  RekorConfig
	http *http.Client
}

// NewRekor builds a Rekor connector.
func NewRekor(cfg RekorConfig) *Rekor {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Rekor{cfg: cfg, http: hc}
}

func (r *Rekor) Name() string { return "rekor" }

// Connect validates required configuration is present.
func (r *Rekor) Connect(_ context.Context) error {
	if r.cfg.URL == "" {
		return fmt.Errorf("rekor: url is required")
	}
	if r.cfg.Email == "" && r.cfg.Hash == "" {
		return fmt.Errorf("rekor: a signer email or an artifact hash is required to search")
	}
	return nil
}

// Validate confirms the Rekor log is reachable.
func (r *Rekor) Validate(ctx context.Context) error {
	var out struct {
		TreeSize int64 `json:"treeSize"`
	}
	if err := r.getJSON(ctx, "/api/v1/log", &out); err != nil {
		return fmt.Errorf("rekor: validate failed: %w", err)
	}
	return nil
}

// Collect searches the log for the configured identity/hash.
func (r *Rekor) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: r.Name(),
		Project:   firstNonEmpty(r.cfg.Email, r.cfg.Hash),
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatSigning},
	}

	body := map[string]string{}
	if r.cfg.Email != "" {
		body["email"] = r.cfg.Email
	} else {
		body["hash"] = normalizeHash(r.cfg.Hash)
	}

	var uuids []string
	if err := r.postJSON(ctx, "/api/v1/index/retrieve", body, &uuids); err != nil {
		return res, err
	}
	res.Metrics["log_entries"] = fmt.Sprintf("%d", len(uuids))

	// No transparency-log entries → nothing is being signed/recorded.
	if len(uuids) == 0 {
		res.Covers = nil
		res.Status = "no entries"
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "rekor",
			Category:    model.CatSigning,
			Severity:    model.SevMedium,
			Message:     "no Rekor transparency-log entries found for " + res.Project,
			Location:    r.cfg.URL,
			Suggestion:  "sign artifacts with cosign so signatures are recorded in Rekor",
		})
		return res, nil
	}
	res.Status = "signed"
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (r *Rekor) Disconnect(_ context.Context) error { return nil }

func (r *Rekor) getJSON(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.URL+path, nil)
	req.Header.Set("Accept", "application/json")
	return r.do(req, out)
}

func (r *Rekor) postJSON(ctx context.Context, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return r.do(req, out)
}

func (r *Rekor) do(req *http.Request, out any) error {
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response from %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func normalizeHash(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "sha256:") {
		return h
	}
	return "sha256:" + h
}
