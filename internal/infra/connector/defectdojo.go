package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// DefectDojoConfig configures the DefectDojo connector.
type DefectDojoConfig struct {
	URL     string       // e.g. https://defectdojo.example.com
	Token   string       // API token (Authorization: Token <token>)
	Product string       // product name
	HTTP    *http.Client // optional; injected in tests
}

// DefectDojo is a connector for the DefectDojo vulnerability aggregator. It maps
// a product's active findings to devsec categories by their tags, so it can
// cover several categories at once depending on what scanners feed it.
type DefectDojo struct {
	cfg  DefectDojoConfig
	http *http.Client
}

// NewDefectDojo builds a DefectDojo connector.
func NewDefectDojo(cfg DefectDojoConfig) *DefectDojo {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &DefectDojo{cfg: cfg, http: hc}
}

func (d *DefectDojo) Name() string { return "defectdojo" }

// Connect validates required configuration is present.
func (d *DefectDojo) Connect(_ context.Context) error {
	if d.cfg.URL == "" {
		return fmt.Errorf("defectdojo: url is required")
	}
	if d.cfg.Product == "" {
		return fmt.Errorf("defectdojo: product name is required")
	}
	if d.cfg.Token == "" {
		return fmt.Errorf("defectdojo: token is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the server is reachable and the token authenticates.
func (d *DefectDojo) Validate(ctx context.Context) error {
	if _, err := d.productID(ctx); err != nil {
		return fmt.Errorf("defectdojo: validate failed: %w", err)
	}
	return nil
}

// tagCategory maps a finding tag to a devsec security category.
func tagCategory(tag string) (model.SecurityCategory, bool) {
	switch strings.ToLower(tag) {
	case "sast", "code":
		return model.CatSAST, true
	case "secret", "secrets":
		return model.CatSecretScan, true
	case "dependency", "sca", "dependencies":
		return model.CatDependencyScan, true
	case "container", "image":
		return model.CatContainerScan, true
	case "iac", "infrastructure":
		return model.CatIaCScan, true
	case "sbom":
		return model.CatSBOM, true
	default:
		return "", false
	}
}

// Collect resolves the product and aggregates its active findings by category.
func (d *DefectDojo) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: d.Name(),
		Project:   d.cfg.Product,
		Metrics:   map[string]string{},
	}

	pid, err := d.productID(ctx)
	if err != nil {
		return res, err
	}

	var page struct {
		Count   int `json:"count"`
		Results []struct {
			Title    string   `json:"title"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
		} `json:"results"`
	}
	q := url.Values{"product": {fmt.Sprintf("%d", pid)}, "active": {"true"}, "limit": {"100"}}
	if err := d.get(ctx, "/api/v2/findings/?"+q.Encode(), &page); err != nil {
		return res, err
	}
	res.Status = fmt.Sprintf("%d active findings", page.Count)
	res.Metrics["active_findings"] = fmt.Sprintf("%d", page.Count)

	covers := map[model.SecurityCategory]bool{}
	var crit, high int
	for _, f := range page.Results {
		var cat model.SecurityCategory
		for _, tag := range f.Tags {
			if c, ok := tagCategory(tag); ok {
				cat = c
				covers[c] = true
				break
			}
		}
		sev := ddSeverity(f.Severity)
		switch sev {
		case model.SevCritical:
			crit++
		case model.SevHigh:
			high++
		}
		if cat != "" && (sev == model.SevHigh || sev == model.SevCritical) {
			res.Findings = append(res.Findings, model.Finding{
				PipelineRef: "defectdojo:" + d.cfg.Product,
				Category:    cat,
				Severity:    sev,
				Message:     f.Title,
				Location:    d.cfg.URL,
				Suggestion:  "triage and remediate in DefectDojo",
			})
		}
	}
	res.Metrics["critical"] = fmt.Sprintf("%d", crit)
	res.Metrics["high"] = fmt.Sprintf("%d", high)
	for c := range covers {
		res.Covers = append(res.Covers, c)
	}
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (d *DefectDojo) Disconnect(_ context.Context) error { return nil }

func (d *DefectDojo) productID(ctx context.Context) (int, error) {
	var page struct {
		Results []struct {
			ID int `json:"id"`
		} `json:"results"`
	}
	if err := d.get(ctx, "/api/v2/products/?"+url.Values{"name": {d.cfg.Product}}.Encode(), &page); err != nil {
		return 0, err
	}
	if len(page.Results) == 0 {
		return 0, fmt.Errorf("product %q not found", d.cfg.Product)
	}
	return page.Results[0].ID, nil
}

func (d *DefectDojo) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.URL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+d.cfg.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
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

func ddSeverity(s string) model.Severity {
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
