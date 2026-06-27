package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// KyvernoConfig configures the Kubernetes/Kyverno PolicyReport connector.
type KyvernoConfig struct {
	URL       string       // kube-apiserver URL, e.g. https://10.0.0.1:6443
	Token     string       // service-account bearer token
	Namespace string       // optional; empty = cluster-wide policyreports
	Insecure  bool         // skip TLS verification (self-signed apiservers)
	HTTP      *http.Client // optional; injected in tests
}

// Kyverno reads wgpolicyk8s.io PolicyReport resources (produced by Kyverno /
// Policy Reporter) from the Kubernetes API and credits the policy category.
type Kyverno struct {
	cfg  KyvernoConfig
	http *http.Client
}

// NewKyverno builds a Kubernetes PolicyReport connector.
func NewKyverno(cfg KyvernoConfig) *Kyverno {
	hc := cfg.HTTP
	if hc == nil {
		tr := &http.Transport{}
		if cfg.Insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - opt-in for self-signed apiservers
		}
		hc = &http.Client{Timeout: 15 * time.Second, Transport: tr}
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Kyverno{cfg: cfg, http: hc}
}

func (k *Kyverno) Name() string { return "kyverno" }

// Connect validates required configuration is present.
func (k *Kyverno) Connect(_ context.Context) error {
	if k.cfg.URL == "" {
		return fmt.Errorf("kyverno: kube-apiserver url is required")
	}
	if k.cfg.Token == "" {
		return fmt.Errorf("kyverno: service-account token is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the apiserver is reachable and the token authenticates.
func (k *Kyverno) Validate(ctx context.Context) error {
	var out struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := k.get(ctx, "/version", &out); err != nil {
		return fmt.Errorf("kyverno: validate failed: %w", err)
	}
	return nil
}

type policyReportList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Summary struct {
			Pass  int `json:"pass"`
			Fail  int `json:"fail"`
			Warn  int `json:"warn"`
			Error int `json:"error"`
			Skip  int `json:"skip"`
		} `json:"summary"`
		Results []struct {
			Policy   string `json:"policy"`
			Rule     string `json:"rule"`
			Result   string `json:"result"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"results"`
	} `json:"items"`
}

// Collect lists PolicyReports and aggregates their pass/fail summary.
func (k *Kyverno) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: k.Name(),
		Project:   firstNonEmpty(k.cfg.Namespace, "cluster-wide"),
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatPolicy},
	}

	path := "/apis/wgpolicyk8s.io/v1alpha2/policyreports"
	if k.cfg.Namespace != "" {
		path = "/apis/wgpolicyk8s.io/v1alpha2/namespaces/" + k.cfg.Namespace + "/policyreports"
	}
	var list policyReportList
	if err := k.get(ctx, path, &list); err != nil {
		return res, err
	}

	var pass, fail, warn int
	for _, pr := range list.Items {
		pass += pr.Summary.Pass
		fail += pr.Summary.Fail
		warn += pr.Summary.Warn
		for _, r := range pr.Results {
			if r.Result != "fail" {
				continue
			}
			res.Findings = append(res.Findings, model.Finding{
				PipelineRef: "kyverno:" + pr.Metadata.Name,
				Category:    model.CatPolicy,
				Severity:    policySeverity(r.Severity),
				Message:     fmt.Sprintf("policy %s/%s failed: %s", r.Policy, r.Rule, r.Message),
				Location:    pr.Metadata.Namespace + "/" + pr.Metadata.Name,
				Suggestion:  "fix the workload or adjust the Kyverno policy",
			})
		}
	}
	res.Metrics["reports"] = fmt.Sprintf("%d", len(list.Items))
	res.Metrics["pass"] = fmt.Sprintf("%d", pass)
	res.Metrics["fail"] = fmt.Sprintf("%d", fail)
	res.Metrics["warn"] = fmt.Sprintf("%d", warn)

	// No PolicyReports means policy enforcement is not actually running.
	if len(list.Items) == 0 {
		res.Covers = nil
		res.Status = "no policy reports"
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "kyverno",
			Category:    model.CatPolicy,
			Severity:    model.SevMedium,
			Message:     "no PolicyReports found in the cluster",
			Location:    k.cfg.URL,
			Suggestion:  "install Kyverno/Policy Reporter and apply admission policies",
		})
		return res, nil
	}
	res.Status = "policy active"
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (k *Kyverno) Disconnect(_ context.Context) error { return nil }

func (k *Kyverno) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.cfg.URL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.cfg.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.http.Do(req)
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

func policySeverity(s string) model.Severity {
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
		return model.SevMedium
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
