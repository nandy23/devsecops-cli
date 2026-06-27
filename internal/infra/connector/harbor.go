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

// HarborConfig configures the Harbor connector.
type HarborConfig struct {
	URL      string       // e.g. https://harbor.example.com
	Username string       // user or robot account (e.g. robot$ci)
	Secret   string       // password or robot token (Basic auth)
	Project  string       // Harbor project name
	HTTP     *http.Client // optional; injected in tests
}

// Harbor is a connector for the Harbor container registry. It reads the
// per-artifact vulnerability scan overview (Harbor's built-in Trivy scans) and
// proves the container_scan category is covered.
type Harbor struct {
	cfg  HarborConfig
	http *http.Client
}

// NewHarbor builds a Harbor connector.
func NewHarbor(cfg HarborConfig) *Harbor {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Harbor{cfg: cfg, http: hc}
}

func (h *Harbor) Name() string { return "harbor" }

// Connect validates required configuration is present.
func (h *Harbor) Connect(_ context.Context) error {
	if h.cfg.URL == "" {
		return fmt.Errorf("harbor: url is required")
	}
	if h.cfg.Project == "" {
		return fmt.Errorf("harbor: project is required")
	}
	if h.cfg.Username == "" || h.cfg.Secret == "" {
		return fmt.Errorf("harbor: username and secret are required (use a robot account; never commit the secret)")
	}
	return nil
}

// Validate confirms the server is reachable and credentials authenticate.
func (h *Harbor) Validate(ctx context.Context) error {
	var out struct {
		Username string `json:"username"`
	}
	if err := h.get(ctx, "/api/v2.0/users/current", nil, &out); err != nil {
		return fmt.Errorf("harbor: validate failed: %w", err)
	}
	return nil
}

// harborScanReport is the value stored in an artifact's scan_overview map.
type harborScanReport struct {
	Severity string `json:"severity"`
	Summary  struct {
		Total   int            `json:"total"`
		Fixable int            `json:"fixable"`
		Summary map[string]int `json:"summary"` // Critical/High/Medium/Low -> count
	} `json:"summary"`
}

// Collect walks the project's repositories and aggregates scan results.
func (h *Harbor) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: h.Name(),
		Project:   h.cfg.Project,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatContainerScan},
	}

	repos, err := h.repositories(ctx)
	if err != nil {
		return res, err
	}

	var totalArtifacts, scanned, totalCritical, totalHigh, totalUnscanned int
	for _, repo := range repos {
		short := strings.TrimPrefix(repo, h.cfg.Project+"/")
		arts, err := h.artifacts(ctx, short)
		if err != nil {
			continue // fail-soft per repository
		}
		for _, art := range arts {
			totalArtifacts++
			report, ok := firstScanReport(art.ScanOverview)
			if !ok {
				totalUnscanned++
				res.Findings = append(res.Findings, model.Finding{
					PipelineRef: "harbor:" + repo,
					Category:    model.CatContainerScan,
					Severity:    model.SevMedium,
					Message:     fmt.Sprintf("artifact %s@%s has no vulnerability scan", short, shortDigest(art.Digest)),
					Location:    h.artifactURL(short, art.Digest),
					Suggestion:  "enable automatic scan-on-push or trigger a scan in Harbor",
				})
				continue
			}
			scanned++
			crit := report.Summary.Summary["Critical"]
			high := report.Summary.Summary["High"]
			totalCritical += crit
			totalHigh += high
			if crit > 0 || high > 0 {
				res.Findings = append(res.Findings, model.Finding{
					PipelineRef: "harbor:" + repo,
					Category:    model.CatContainerScan,
					Severity:    severityForCounts(crit, high),
					Message:     fmt.Sprintf("artifact %s@%s has %d critical and %d high vulnerabilities", short, shortDigest(art.Digest), crit, high),
					Location:    h.artifactURL(short, art.Digest),
					Suggestion:  "rebuild on a patched base image and re-push",
				})
			}
		}
	}

	res.Metrics["repositories"] = fmt.Sprintf("%d", len(repos))
	res.Metrics["artifacts"] = fmt.Sprintf("%d", totalArtifacts)
	res.Metrics["scanned"] = fmt.Sprintf("%d", scanned)
	res.Metrics["unscanned"] = fmt.Sprintf("%d", totalUnscanned)
	res.Metrics["critical"] = fmt.Sprintf("%d", totalCritical)
	res.Metrics["high"] = fmt.Sprintf("%d", totalHigh)

	// If nothing is scanned at all, scanning is effectively not in place.
	if totalArtifacts > 0 && scanned == 0 {
		res.Covers = nil
		res.Status = "no scans"
	} else if scanned > 0 {
		res.Status = "scanning active"
	}

	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (h *Harbor) Disconnect(_ context.Context) error { return nil }

// --- API helpers ---

type harborRepo struct {
	Name string `json:"name"`
}

type harborArtifact struct {
	Digest       string                      `json:"digest"`
	ScanOverview map[string]harborScanReport `json:"scan_overview"`
}

func (h *Harbor) repositories(ctx context.Context) ([]string, error) {
	var repos []harborRepo
	path := fmt.Sprintf("/api/v2.0/projects/%s/repositories", url.PathEscape(h.cfg.Project))
	if err := h.get(ctx, path, url.Values{"page_size": {"100"}}, &repos); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(repos))
	for _, r := range repos {
		out = append(out, r.Name)
	}
	return out, nil
}

func (h *Harbor) artifacts(ctx context.Context, repoShort string) ([]harborArtifact, error) {
	var arts []harborArtifact
	// Harbor requires the repository name URL-encoded (slashes as %2F), which
	// url.PathEscape handles.
	path := fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts",
		url.PathEscape(h.cfg.Project), url.PathEscape(repoShort))
	q := url.Values{"with_scan_overview": {"true"}, "page_size": {"50"}}
	if err := h.get(ctx, path, q, &arts); err != nil {
		return nil, err
	}
	return arts, nil
}

func (h *Harbor) get(ctx context.Context, path string, q url.Values, out any) error {
	u := h.cfg.URL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(h.cfg.Username, h.cfg.Secret)
	req.Header.Set("Accept", "application/json")

	resp, err := h.http.Do(req)
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

func (h *Harbor) artifactURL(repoShort, digest string) string {
	return fmt.Sprintf("%s/harbor/projects/_/repositories/%s/artifacts-tab/artifacts/%s",
		h.cfg.URL, url.PathEscape(repoShort), digest)
}

// firstScanReport returns the single scan report from an artifact's
// scan_overview map (keyed by an unpredictable report mime type).
func firstScanReport(overview map[string]harborScanReport) (harborScanReport, bool) {
	for _, r := range overview {
		return r, true
	}
	return harborScanReport{}, false
}

func severityForCounts(crit, high int) model.Severity {
	if crit > 0 {
		return model.SevCritical
	}
	if high > 0 {
		return model.SevHigh
	}
	return model.SevMedium
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
