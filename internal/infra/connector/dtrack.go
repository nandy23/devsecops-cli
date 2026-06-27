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

// DTrackConfig configures the OWASP Dependency-Track connector.
type DTrackConfig struct {
	URL     string       // e.g. https://dtrack.example.com
	APIKey  string       // sent as X-Api-Key
	Project string       // project name
	Version string       // optional project version
	HTTP    *http.Client // optional; injected in tests
}

// DTrack is a connector for OWASP Dependency-Track. Because Dependency-Track
// analyzes uploaded SBOMs, its presence proves SBOM management; it credits the
// sbom category and reports component vulnerabilities.
type DTrack struct {
	cfg  DTrackConfig
	http *http.Client
}

// NewDTrack builds a Dependency-Track connector.
func NewDTrack(cfg DTrackConfig) *DTrack {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &DTrack{cfg: cfg, http: hc}
}

func (d *DTrack) Name() string { return "dependency-track" }

// Connect validates required configuration is present.
func (d *DTrack) Connect(_ context.Context) error {
	if d.cfg.URL == "" {
		return fmt.Errorf("dependency-track: url is required")
	}
	if d.cfg.Project == "" {
		return fmt.Errorf("dependency-track: project name is required")
	}
	if d.cfg.APIKey == "" {
		return fmt.Errorf("dependency-track: api key is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the server is reachable and the API key authenticates.
func (d *DTrack) Validate(ctx context.Context) error {
	if _, err := d.lookupProject(ctx); err != nil {
		return fmt.Errorf("dependency-track: validate failed: %w", err)
	}
	return nil
}

type dtrackProject struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Metrics struct {
		Components      int `json:"components"`
		Vulnerabilities int `json:"vulnerabilities"`
		Critical        int `json:"critical"`
		High            int `json:"high"`
		Medium          int `json:"medium"`
		Low             int `json:"low"`
	} `json:"metrics"`
}

// Collect resolves the project and reports its SBOM-driven vulnerability metrics.
func (d *DTrack) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: d.Name(),
		Project:   d.cfg.Project,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatSBOM},
	}

	proj, err := d.lookupProject(ctx)
	if err != nil {
		return res, err
	}
	res.Status = "analyzed"
	res.Metrics["components"] = fmt.Sprintf("%d", proj.Metrics.Components)
	res.Metrics["vulnerabilities"] = fmt.Sprintf("%d", proj.Metrics.Vulnerabilities)
	res.Metrics["critical"] = fmt.Sprintf("%d", proj.Metrics.Critical)
	res.Metrics["high"] = fmt.Sprintf("%d", proj.Metrics.High)

	// An SBOM with zero components has not really been analyzed.
	if proj.Metrics.Components == 0 {
		res.Covers = nil
		res.Status = "no sbom analyzed"
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "dependency-track:" + d.cfg.Project,
			Category:    model.CatSBOM,
			Severity:    model.SevMedium,
			Message:     "no SBOM components found for this project",
			Location:    d.cfg.URL,
			Suggestion:  "upload a CycloneDX SBOM to Dependency-Track from your build",
		})
		return res, nil
	}

	var findings []struct {
		Vulnerability struct {
			VulnID   string `json:"vulnId"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	}
	if err := d.get(ctx, "/api/v1/finding/project/"+url.PathEscape(proj.UUID), &findings); err != nil {
		return res, err
	}
	for _, f := range findings {
		sev := dtrackSeverity(f.Vulnerability.Severity)
		if sev == model.SevHigh || sev == model.SevCritical {
			res.Findings = append(res.Findings, model.Finding{
				PipelineRef: "dependency-track:" + d.cfg.Project,
				Category:    model.CatSBOM,
				Severity:    sev,
				Message:     fmt.Sprintf("%s in %s@%s", f.Vulnerability.VulnID, f.Component.Name, f.Component.Version),
				Location:    d.cfg.URL,
				Suggestion:  "upgrade the affected component",
			})
		}
	}
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (d *DTrack) Disconnect(_ context.Context) error { return nil }

func (d *DTrack) lookupProject(ctx context.Context) (dtrackProject, error) {
	q := url.Values{"name": {d.cfg.Project}}
	if d.cfg.Version != "" {
		q.Set("version", d.cfg.Version)
		var p dtrackProject
		if err := d.get(ctx, "/api/v1/project/lookup?"+q.Encode(), &p); err != nil {
			return dtrackProject{}, err
		}
		return p, nil
	}
	var projects []dtrackProject
	if err := d.get(ctx, "/api/v1/project?"+q.Encode(), &projects); err != nil {
		return dtrackProject{}, err
	}
	if len(projects) == 0 {
		return dtrackProject{}, fmt.Errorf("project %q not found", d.cfg.Project)
	}
	return projects[0], nil
}

func (d *DTrack) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.URL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", d.cfg.APIKey)
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

func dtrackSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SevCritical
	case "HIGH":
		return model.SevHigh
	case "MEDIUM":
		return model.SevMedium
	case "LOW":
		return model.SevLow
	default:
		return model.SevInfo
	}
}
