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

// XrayConfig configures the JFrog Xray connector.
type XrayConfig struct {
	URL   string       // e.g. https://mycompany.jfrog.io
	Token string       // access token (Bearer)
	Watch string       // Xray watch name to query violations for
	HTTP  *http.Client // optional; injected in tests
}

// Xray is a connector for JFrog Xray. It reads security violations for a watch
// and credits dependency_scan and container_scan.
type Xray struct {
	cfg  XrayConfig
	http *http.Client
}

// NewXray builds a JFrog Xray connector.
func NewXray(cfg XrayConfig) *Xray {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Xray{cfg: cfg, http: hc}
}

func (x *Xray) Name() string { return "jfrog-xray" }

// Connect validates required configuration is present.
func (x *Xray) Connect(_ context.Context) error {
	if x.cfg.URL == "" {
		return fmt.Errorf("jfrog-xray: url is required")
	}
	if x.cfg.Watch == "" {
		return fmt.Errorf("jfrog-xray: watch name is required")
	}
	if x.cfg.Token == "" {
		return fmt.Errorf("jfrog-xray: access token is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the server is reachable and the token authenticates.
func (x *Xray) Validate(ctx context.Context) error {
	var out struct {
		XrayVersion string `json:"xray_version"`
	}
	if err := x.do(ctx, http.MethodGet, "/xray/api/v1/system/version", nil, &out); err != nil {
		return fmt.Errorf("jfrog-xray: validate failed: %w", err)
	}
	return nil
}

// Collect queries violations for the configured watch.
func (x *Xray) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: x.Name(),
		Project:   x.cfg.Watch,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatDependencyScan, model.CatContainerScan},
	}

	body := map[string]any{
		"filters":    map[string]any{"watch_name": x.cfg.Watch},
		"pagination": map[string]any{"order_by": "created", "limit": 50},
	}
	var out struct {
		TotalViolations int `json:"total_violations"`
		Violations      []struct {
			Type     string `json:"type"`
			Severity string `json:"severity"`
			IssueID  string `json:"issue_id"`
			Summary  string `json:"summary"`
		} `json:"violations"`
	}
	if err := x.do(ctx, http.MethodPost, "/xray/api/v1/violations", body, &out); err != nil {
		return res, err
	}
	res.Status = fmt.Sprintf("%d violations", out.TotalViolations)
	res.Metrics["total_violations"] = fmt.Sprintf("%d", out.TotalViolations)

	var security, license int
	for _, v := range out.Violations {
		switch strings.ToLower(v.Type) {
		case "security":
			security++
		case "license":
			license++
		}
		sev := xraySeverity(v.Severity)
		if sev == model.SevHigh || sev == model.SevCritical {
			res.Findings = append(res.Findings, model.Finding{
				PipelineRef: "jfrog-xray:" + x.cfg.Watch,
				Category:    model.CatDependencyScan,
				Severity:    sev,
				Message:     fmt.Sprintf("%s: %s (%s)", v.Type, v.Summary, v.IssueID),
				Location:    x.cfg.URL,
				Suggestion:  "remediate the violation flagged by Xray",
			})
		}
	}
	res.Metrics["security_violations"] = fmt.Sprintf("%d", security)
	res.Metrics["license_violations"] = fmt.Sprintf("%d", license)
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (x *Xray) Disconnect(_ context.Context) error { return nil }

func (x *Xray) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, x.cfg.URL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+x.cfg.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := x.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response from %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func xraySeverity(s string) model.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return model.SevCritical
	case "high":
		return model.SevHigh
	case "medium":
		return model.SevMedium
	case "low":
		return model.SevLow
	default:
		return model.SevInfo
	}
}
