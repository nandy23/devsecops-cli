package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// VaultConfig configures the HashiCorp Vault connector.
type VaultConfig struct {
	URL   string       // e.g. https://vault.example.com:8200
	Token string       // Vault token (sent as X-Vault-Token)
	HTTP  *http.Client // optional; injected in tests
}

// Vault is a connector for HashiCorp Vault. It proves the secret_scan category
// is covered when Vault is operational (initialized + unsealed) and reports the
// configured KV secret engines.
type Vault struct {
	cfg  VaultConfig
	http *http.Client
}

// NewVault builds a Vault connector.
func NewVault(cfg VaultConfig) *Vault {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Vault{cfg: cfg, http: hc}
}

func (v *Vault) Name() string { return "vault" }

// Connect validates required configuration is present.
func (v *Vault) Connect(_ context.Context) error {
	if v.cfg.URL == "" {
		return fmt.Errorf("vault: url is required")
	}
	if v.cfg.Token == "" {
		return fmt.Errorf("vault: token is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the token authenticates via token self-lookup.
func (v *Vault) Validate(ctx context.Context) error {
	var out struct {
		Data struct {
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if _, err := v.get(ctx, "/v1/auth/token/lookup-self", &out, false); err != nil {
		return fmt.Errorf("vault: validate failed: %w", err)
	}
	return nil
}

type vaultHealth struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	Version     string `json:"version"`
}

type vaultMount struct {
	Type    string            `json:"type"`
	Options map[string]string `json:"options"`
}

// Collect reads health, seal state and secret engines.
func (v *Vault) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: v.Name(),
		Project:   v.cfg.URL,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatSecretScan},
	}

	// Health endpoint returns non-200 status codes by design (503 sealed, 501
	// uninitialized), so read the body leniently.
	var health vaultHealth
	if _, err := v.get(ctx, "/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200", &health, true); err != nil {
		return res, err
	}
	res.Metrics["version"] = health.Version
	res.Metrics["initialized"] = fmt.Sprintf("%t", health.Initialized)
	res.Metrics["sealed"] = fmt.Sprintf("%t", health.Sealed)

	// An unhealthy Vault means secret management is not actually operational.
	if !health.Initialized {
		res.Covers = nil
		res.Status = "uninitialized"
		res.Findings = append(res.Findings, finding(v.cfg.URL, model.SevHigh,
			"Vault is not initialized", "initialize Vault before relying on it for secrets"))
		return res, nil
	}
	if health.Sealed {
		res.Covers = nil
		res.Status = "sealed"
		res.Findings = append(res.Findings, finding(v.cfg.URL, model.SevHigh,
			"Vault is sealed", "unseal Vault so applications can retrieve secrets"))
		return res, nil
	}
	res.Status = "operational"

	// Enumerate secret engines (requires a privileged token; tolerate 403).
	kv, total, enumerated := v.countEngines(ctx)
	res.Metrics["secret_engines"] = fmt.Sprintf("%d", total)
	res.Metrics["kv_engines"] = fmt.Sprintf("%d", kv)
	if enumerated && kv == 0 {
		res.Findings = append(res.Findings, finding(v.cfg.URL, model.SevMedium,
			"Vault is running but no KV secret engines are configured",
			"mount a KV secret engine and migrate hardcoded secrets into Vault"))
	}
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (v *Vault) Disconnect(_ context.Context) error { return nil }

// --- helpers ---

// countEngines returns the number of KV engines, total mounts, and whether
// enumeration succeeded (a non-privileged token returns 403, which is fine).
func (v *Vault) countEngines(ctx context.Context) (kv, total int, enumerated bool) {
	var raw map[string]json.RawMessage
	status, err := v.get(ctx, "/v1/sys/mounts", &raw, true)
	if err != nil || status == http.StatusForbidden || status >= 300 {
		return 0, 0, false
	}
	// Newer Vault wraps mounts under "data"; older returns them at top level.
	mounts := raw
	if data, ok := raw["data"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(data, &inner) == nil && len(inner) > 0 {
			mounts = inner
		}
	}
	for key, rawMount := range mounts {
		// Skip response metadata keys when reading a top-level (unwrapped) body.
		switch key {
		case "request_id", "lease_id", "renewable", "lease_duration", "wrap_info", "warnings", "auth", "data":
			continue
		}
		var m vaultMount
		if json.Unmarshal(rawMount, &m) != nil || m.Type == "" {
			continue
		}
		total++
		if m.Type == "kv" {
			kv++
		}
	}
	return kv, total, true
}

// get performs an authenticated GET. When lenient is false, non-2xx and auth
// failures return an error; when true, the body is decoded regardless of status
// (used for Vault's health/mounts endpoints). It always returns the status.
func (v *Vault) get(ctx context.Context, path string, out any, lenient bool) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.URL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Token", v.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if !lenient {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return resp.StatusCode, fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 300 {
			return resp.StatusCode, fmt.Errorf("unexpected response from %s: HTTP %d", path, resp.StatusCode)
		}
	}
	if out != nil {
		// Ignore decode errors in lenient mode (empty bodies on some statuses).
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !lenient {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func finding(loc string, sev model.Severity, msg, suggestion string) model.Finding {
	return model.Finding{
		PipelineRef: "vault",
		Category:    model.CatSecretScan,
		Severity:    sev,
		Message:     msg,
		Location:    loc,
		Suggestion:  suggestion,
	}
}
