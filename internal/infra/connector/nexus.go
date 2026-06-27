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

// NexusConfig configures the Nexus IQ (Lifecycle) connector.
type NexusConfig struct {
	URL         string       // e.g. https://nexus-iq.example.com
	Username    string       // IQ user or token (Basic auth)
	Secret      string       // password or token
	Application string       // application public id
	HTTP        *http.Client // optional; injected in tests
}

// Nexus is a connector for Sonatype Nexus IQ Server. It reads the latest policy
// evaluation for an application and proves the dependency_scan category is
// covered by reporting component vulnerabilities and policy violations.
type Nexus struct {
	cfg  NexusConfig
	http *http.Client
}

// NewNexus builds a Nexus IQ connector.
func NewNexus(cfg NexusConfig) *Nexus {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Nexus{cfg: cfg, http: hc}
}

func (n *Nexus) Name() string { return "nexus-iq" }

// Connect validates required configuration is present.
func (n *Nexus) Connect(_ context.Context) error {
	if n.cfg.URL == "" {
		return fmt.Errorf("nexus-iq: url is required")
	}
	if n.cfg.Application == "" {
		return fmt.Errorf("nexus-iq: application public id is required")
	}
	if n.cfg.Username == "" || n.cfg.Secret == "" {
		return fmt.Errorf("nexus-iq: username and secret are required (use a token; never commit it)")
	}
	return nil
}

// Validate confirms the server is reachable, credentials authenticate and the
// application exists.
func (n *Nexus) Validate(ctx context.Context) error {
	if _, err := n.applicationID(ctx); err != nil {
		return fmt.Errorf("nexus-iq: validate failed: %w", err)
	}
	return nil
}

type iqApplications struct {
	Applications []struct {
		ID       string `json:"id"`
		PublicID string `json:"publicId"`
		Name     string `json:"name"`
	} `json:"applications"`
}

type iqReport struct {
	Stage          string `json:"stage"`
	EvaluationDate string `json:"evaluationDate"`
	ReportDataURL  string `json:"reportDataUrl"`
}

type iqPolicyReport struct {
	Components []iqComponent `json:"components"`
}

type iqComponent struct {
	DisplayName string        `json:"displayName"`
	Violations  []iqViolation `json:"violations"`
}

type iqViolation struct {
	PolicyName        string `json:"policyName"`
	PolicyThreatLevel int    `json:"policyThreatLevel"`
	Grandfathered     bool   `json:"grandfathered"`
}

// Collect resolves the application, finds the latest report and summarizes the
// policy violations.
func (n *Nexus) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: n.Name(),
		Project:   n.cfg.Application,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatDependencyScan},
	}

	appID, err := n.applicationID(ctx)
	if err != nil {
		return res, err
	}

	report, ok, err := n.latestReport(ctx, appID)
	if err != nil {
		return res, err
	}
	if !ok {
		// No evaluation has ever run → scanning is not actually in place.
		res.Covers = nil
		res.Status = "no evaluation"
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "nexus-iq:" + n.cfg.Application,
			Category:    model.CatDependencyScan,
			Severity:    model.SevMedium,
			Message:     "no Nexus IQ policy evaluation found for this application",
			Location:    n.cfg.URL,
			Suggestion:  "run a Nexus IQ evaluation in your pipeline (e.g. the build stage)",
		})
		return res, nil
	}
	res.Status = report.Stage

	policy, err := n.policyReport(ctx, report.ReportDataURL)
	if err != nil {
		return res, err
	}

	var crit, high, med, low, violating int
	for _, c := range policy.Components {
		worst := 0
		for _, v := range c.Violations {
			if v.Grandfathered {
				continue
			}
			if v.PolicyThreatLevel > worst {
				worst = v.PolicyThreatLevel
			}
		}
		if worst == 0 {
			continue
		}
		violating++
		switch sev := threatSeverity(worst); sev {
		case model.SevCritical:
			crit++
		case model.SevHigh:
			high++
		case model.SevMedium:
			med++
		default:
			low++
		}
		if worst >= 6 { // high or critical → surface as a finding
			res.Findings = append(res.Findings, model.Finding{
				PipelineRef: "nexus-iq:" + n.cfg.Application,
				Category:    model.CatDependencyScan,
				Severity:    threatSeverity(worst),
				Message:     fmt.Sprintf("%s violates policy (threat level %d)", c.DisplayName, worst),
				Location:    n.cfg.URL,
				Suggestion:  "upgrade the component to a non-vulnerable version",
			})
		}
	}

	res.Metrics["components"] = fmt.Sprintf("%d", len(policy.Components))
	res.Metrics["violating_components"] = fmt.Sprintf("%d", violating)
	res.Metrics["critical"] = fmt.Sprintf("%d", crit)
	res.Metrics["high"] = fmt.Sprintf("%d", high)
	res.Metrics["medium"] = fmt.Sprintf("%d", med)
	res.Metrics["low"] = fmt.Sprintf("%d", low)
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (n *Nexus) Disconnect(_ context.Context) error { return nil }

// --- API helpers ---

func (n *Nexus) applicationID(ctx context.Context) (string, error) {
	var apps iqApplications
	if err := n.get(ctx, "/api/v2/applications", url.Values{"publicId": {n.cfg.Application}}, &apps); err != nil {
		return "", err
	}
	if len(apps.Applications) == 0 {
		return "", fmt.Errorf("application %q not found", n.cfg.Application)
	}
	return apps.Applications[0].ID, nil
}

// latestReport returns the most recent report (preferring release/build stages).
func (n *Nexus) latestReport(ctx context.Context, appID string) (iqReport, bool, error) {
	var reports []iqReport
	if err := n.get(ctx, "/api/v2/reports/applications/"+url.PathEscape(appID), nil, &reports); err != nil {
		return iqReport{}, false, err
	}
	if len(reports) == 0 {
		return iqReport{}, false, nil
	}
	best := reports[0]
	for _, r := range reports {
		if stageRank(r.Stage) > stageRank(best.Stage) {
			best = r
		}
	}
	return best, true, nil
}

func (n *Nexus) policyReport(ctx context.Context, reportDataURL string) (iqPolicyReport, error) {
	var pr iqPolicyReport
	path := "/" + strings.TrimPrefix(reportDataURL, "/")
	if !strings.HasSuffix(path, "/policy") {
		path += "/policy"
	}
	if err := n.get(ctx, path, nil, &pr); err != nil {
		return pr, err
	}
	return pr, nil
}

func (n *Nexus) get(ctx context.Context, path string, q url.Values, out any) error {
	u := n.cfg.URL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(n.cfg.Username, n.cfg.Secret)
	req.Header.Set("Accept", "application/json")

	resp, err := n.http.Do(req)
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

// threatSeverity maps a Nexus IQ policy threat level (0-10) to a severity.
func threatSeverity(level int) model.Severity {
	switch {
	case level >= 8:
		return model.SevCritical
	case level >= 6:
		return model.SevHigh
	case level >= 4:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

// stageRank prioritizes report stages so the most authoritative one wins.
func stageRank(stage string) int {
	switch strings.ToLower(stage) {
	case "release":
		return 4
	case "stage-release":
		return 3
	case "build":
		return 2
	case "develop", "source":
		return 1
	default:
		return 0
	}
}
