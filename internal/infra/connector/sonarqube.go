// Package connector contains adapters that integrate enterprise DevSecOps
// platforms. Connectors collect findings that merge into the unified analysis.
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

// SonarConfig configures the SonarQube connector.
type SonarConfig struct {
	URL     string       // e.g. https://sonarqube.example.com
	Token   string       // user/analysis token (sent as Bearer)
	Project string       // project key
	HTTP    *http.Client // optional; injected in tests
}

// Sonar is a SonarQube connector implementing port.Connector. It reads the
// project quality gate, key measures and open vulnerabilities via the Web API.
type Sonar struct {
	cfg  SonarConfig
	http *http.Client
}

// NewSonar builds a SonarQube connector.
func NewSonar(cfg SonarConfig) *Sonar {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Sonar{cfg: cfg, http: hc}
}

func (s *Sonar) Name() string { return "sonarqube" }

// Connect validates required configuration is present.
func (s *Sonar) Connect(_ context.Context) error {
	if s.cfg.URL == "" {
		return fmt.Errorf("sonarqube: url is required")
	}
	if s.cfg.Project == "" {
		return fmt.Errorf("sonarqube: project key is required")
	}
	if s.cfg.Token == "" {
		return fmt.Errorf("sonarqube: token is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the server is reachable and the token authenticates.
func (s *Sonar) Validate(ctx context.Context) error {
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := s.get(ctx, "/api/authentication/validate", nil, &out); err != nil {
		return fmt.Errorf("sonarqube: validate failed: %w", err)
	}
	if !out.Valid {
		return fmt.Errorf("sonarqube: token is not valid")
	}
	return nil
}

// Collect gathers the quality gate, measures and vulnerabilities.
func (s *Sonar) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: s.Name(),
		Project:   s.cfg.Project,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatSAST},
	}

	// 1. Quality gate status.
	var gate struct {
		ProjectStatus struct {
			Status     string `json:"status"`
			Conditions []struct {
				MetricKey      string `json:"metricKey"`
				Status         string `json:"status"`
				ActualValue    string `json:"actualValue"`
				ErrorThreshold string `json:"errorThreshold"`
			} `json:"conditions"`
		} `json:"projectStatus"`
	}
	if err := s.get(ctx, "/api/qualitygates/project_status", url.Values{"projectKey": {s.cfg.Project}}, &gate); err != nil {
		return res, err
	}
	res.Status = gate.ProjectStatus.Status
	for _, c := range gate.ProjectStatus.Conditions {
		if c.Status == "ERROR" {
			res.Findings = append(res.Findings, model.Finding{
				PipelineRef: "sonarqube:" + s.cfg.Project,
				Category:    model.CatSAST,
				Severity:    model.SevHigh,
				Message:     fmt.Sprintf("quality gate condition failed: %s = %s (threshold %s)", c.MetricKey, c.ActualValue, c.ErrorThreshold),
				Location:    s.projectURL(),
				Suggestion:  "fix the failing quality gate condition in SonarQube",
			})
		}
	}

	// 2. Key measures.
	var measures struct {
		Component struct {
			Measures []struct {
				Metric string `json:"metric"`
				Value  string `json:"value"`
			} `json:"measures"`
		} `json:"component"`
	}
	metricKeys := "bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density"
	if err := s.get(ctx, "/api/measures/component",
		url.Values{"component": {s.cfg.Project}, "metricKeys": {metricKeys}}, &measures); err != nil {
		return res, err
	}
	for _, m := range measures.Component.Measures {
		res.Metrics[m.Metric] = m.Value
	}

	// 3. Open vulnerabilities → findings.
	var issues struct {
		Total  int `json:"total"`
		Issues []struct {
			Rule      string `json:"rule"`
			Severity  string `json:"severity"`
			Message   string `json:"message"`
			Component string `json:"component"`
			Line      int    `json:"line"`
		} `json:"issues"`
	}
	if err := s.get(ctx, "/api/issues/search",
		url.Values{"componentKeys": {s.cfg.Project}, "types": {"VULNERABILITY"}, "resolved": {"false"}, "ps": {"50"}}, &issues); err != nil {
		return res, err
	}
	res.Metrics["open_vulnerabilities"] = fmt.Sprintf("%d", issues.Total)
	for _, is := range issues.Issues {
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "sonarqube:" + s.cfg.Project,
			Category:    model.CatSAST,
			Severity:    mapSonarSeverity(is.Severity),
			Message:     fmt.Sprintf("%s (%s)", is.Message, is.Rule),
			Location:    fmt.Sprintf("%s:%d", componentPath(is.Component), is.Line),
			Suggestion:  "remediate the vulnerability reported by SonarQube",
		})
	}

	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (s *Sonar) Disconnect(_ context.Context) error { return nil }

// --- helpers ---

func (s *Sonar) get(ctx context.Context, path string, q url.Values, out any) error {
	u := s.cfg.URL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
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

func (s *Sonar) projectURL() string {
	return fmt.Sprintf("%s/dashboard?id=%s", s.cfg.URL, url.QueryEscape(s.cfg.Project))
}

func mapSonarSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "BLOCKER":
		return model.SevCritical
	case "CRITICAL":
		return model.SevHigh
	case "MAJOR":
		return model.SevMedium
	case "MINOR":
		return model.SevLow
	default:
		return model.SevInfo
	}
}

// componentPath strips the "projectKey:" prefix SonarQube prepends to file
// components, leaving a repo-relative path.
func componentPath(component string) string {
	if i := strings.IndexByte(component, ':'); i >= 0 {
		return component[i+1:]
	}
	return component
}
