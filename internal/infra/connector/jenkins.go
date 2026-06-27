package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// JenkinsConfig configures the Jenkins connector.
type JenkinsConfig struct {
	URL      string       // e.g. https://jenkins.example.com
	Username string       // Jenkins user
	Token    string       // API token (Basic auth)
	Job      string       // job name to audit
	HTTP     *http.Client // optional; injected in tests
}

// Jenkins audits a remote Jenkins job: it reads the last build result and scans
// the job's pipeline definition for security stages, crediting whichever
// categories are actually wired into the pipeline.
type Jenkins struct {
	cfg  JenkinsConfig
	http *http.Client
}

// NewJenkins builds a Jenkins connector.
func NewJenkins(cfg JenkinsConfig) *Jenkins {
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Jenkins{cfg: cfg, http: hc}
}

func (j *Jenkins) Name() string { return "jenkins" }

// Connect validates required configuration is present.
func (j *Jenkins) Connect(_ context.Context) error {
	if j.cfg.URL == "" {
		return fmt.Errorf("jenkins: url is required")
	}
	if j.cfg.Job == "" {
		return fmt.Errorf("jenkins: job name is required")
	}
	if j.cfg.Username == "" || j.cfg.Token == "" {
		return fmt.Errorf("jenkins: username and API token are required (never commit the token)")
	}
	return nil
}

// Validate confirms the server is reachable and credentials authenticate.
func (j *Jenkins) Validate(ctx context.Context) error {
	if _, err := j.getText(ctx, "/api/json?tree=mode"); err != nil {
		return fmt.Errorf("jenkins: validate failed: %w", err)
	}
	return nil
}

// jenkinsSignatures maps a security category to substrings that indicate it is
// present in a Jenkins pipeline definition.
var jenkinsSignatures = map[model.SecurityCategory][]string{
	model.CatSAST:           {"semgrep", "codeql", "sonar", "sonarqube"},
	model.CatSecretScan:     {"gitleaks", "trufflehog", "detect-secrets"},
	model.CatDependencyScan: {"dependency-check", "owasp", "snyk", "trivy fs"},
	model.CatIaCScan:        {"checkov", "terrascan", "tfsec", "kics"},
	model.CatContainerScan:  {"trivy image", "trivy ", "grype", "clair"},
	model.CatSBOM:           {"syft", "cyclonedx", "sbom"},
	model.CatSigning:        {"cosign", "sigstore"},
	model.CatPolicy:         {"kyverno", "conftest", "opa "},
	model.CatRuntime:        {"falco"},
}

// Collect reads the last build result and detects security stages in the config.
func (j *Jenkins) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: j.Name(),
		Project:   j.cfg.Job,
		Metrics:   map[string]string{},
	}

	// Last build result.
	var jobInfo struct {
		LastBuild struct {
			Result string `json:"result"`
			Number int    `json:"number"`
		} `json:"lastBuild"`
	}
	body, err := j.getText(ctx, "/job/"+url.PathEscape(j.cfg.Job)+"/api/json?tree=lastBuild[result,number]")
	if err != nil {
		return res, err
	}
	_ = json.Unmarshal([]byte(body), &jobInfo)
	res.Status = firstNonEmpty(jobInfo.LastBuild.Result, "unknown")
	res.Metrics["last_build"] = fmt.Sprintf("#%d", jobInfo.LastBuild.Number)
	res.Metrics["last_result"] = res.Status

	// Pipeline definition → detect security stages.
	config, err := j.getText(ctx, "/job/"+url.PathEscape(j.cfg.Job)+"/config.xml")
	if err != nil {
		return res, err
	}
	low := strings.ToLower(config)
	for _, cat := range model.AllCategories() {
		for _, sig := range jenkinsSignatures[cat] {
			if strings.Contains(low, sig) {
				res.Covers = append(res.Covers, cat)
				break
			}
		}
	}
	res.Metrics["security_stages"] = fmt.Sprintf("%d", len(res.Covers))

	if len(res.Covers) == 0 {
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "jenkins:" + j.cfg.Job,
			Category:    model.CatSAST,
			Severity:    model.SevMedium,
			Message:     "no security stages detected in the Jenkins pipeline",
			Location:    j.cfg.URL + "/job/" + j.cfg.Job,
			Suggestion:  "add security stages (see `devsec init --platform jenkins`)",
		})
	}
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (j *Jenkins) Disconnect(_ context.Context) error { return nil }

func (j *Jenkins) getText(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.cfg.URL+path, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(j.cfg.Username, j.cfg.Token)
	resp, err := j.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected response from %s: HTTP %d", path, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
