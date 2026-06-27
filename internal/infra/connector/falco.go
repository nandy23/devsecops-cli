package connector

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// FalcoConfig configures the Falco runtime-security connector.
type FalcoConfig struct {
	URL       string       // kube-apiserver URL
	Token     string       // service-account bearer token
	Namespace string       // Falco namespace (default "falco")
	DaemonSet string       // Falco DaemonSet name (default "falco")
	Insecure  bool         // skip TLS verification (self-signed apiservers)
	HTTP      *http.Client // optional; injected in tests
}

// Falco verifies that Falco is actually deployed and ready as a DaemonSet in
// the cluster. A running Falco DaemonSet proves runtime threat detection is
// active, so it credits the runtime category.
type Falco struct {
	cfg  FalcoConfig
	kube *kubeClient
}

// NewFalco builds a Falco connector.
func NewFalco(cfg FalcoConfig) *Falco {
	if cfg.Namespace == "" {
		cfg.Namespace = "falco"
	}
	if cfg.DaemonSet == "" {
		cfg.DaemonSet = "falco"
	}
	return &Falco{cfg: cfg, kube: newKubeClient(cfg.URL, cfg.Token, cfg.Insecure, cfg.HTTP)}
}

func (f *Falco) Name() string { return "falco" }

// Connect validates required configuration is present.
func (f *Falco) Connect(_ context.Context) error {
	if f.cfg.URL == "" {
		return fmt.Errorf("falco: kube-apiserver url is required")
	}
	if f.cfg.Token == "" {
		return fmt.Errorf("falco: service-account token is required (set via env, never commit it)")
	}
	return nil
}

// Validate confirms the apiserver is reachable and the token authenticates.
func (f *Falco) Validate(ctx context.Context) error {
	var out struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := f.kube.get(ctx, "/version", &out); err != nil {
		return fmt.Errorf("falco: validate failed: %w", err)
	}
	return nil
}

type daemonSet struct {
	Status struct {
		DesiredNumberScheduled int `json:"desiredNumberScheduled"`
		NumberReady            int `json:"numberReady"`
		NumberAvailable        int `json:"numberAvailable"`
	} `json:"status"`
}

// Collect reads the Falco DaemonSet status and credits runtime when ready.
func (f *Falco) Collect(ctx context.Context) (model.ConnectorResult, error) {
	res := model.ConnectorResult{
		Connector: f.Name(),
		Project:   f.cfg.Namespace + "/" + f.cfg.DaemonSet,
		Metrics:   map[string]string{},
		Covers:    []model.SecurityCategory{model.CatRuntime},
	}

	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/daemonsets/%s", f.cfg.Namespace, f.cfg.DaemonSet)
	var ds daemonSet
	if err := f.kube.get(ctx, path, &ds); err != nil {
		return res, err
	}
	res.Metrics["desired"] = fmt.Sprintf("%d", ds.Status.DesiredNumberScheduled)
	res.Metrics["ready"] = fmt.Sprintf("%d", ds.Status.NumberReady)

	// Falco present but no ready pods → runtime detection is not actually running.
	if ds.Status.NumberReady == 0 {
		res.Covers = nil
		res.Status = "not ready"
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "falco",
			Category:    model.CatRuntime,
			Severity:    model.SevHigh,
			Message:     "Falco DaemonSet has no ready pods",
			Location:    res.Project,
			Suggestion:  "investigate why Falco pods are not running",
		})
		return res, nil
	}
	res.Status = "active"
	if ds.Status.NumberReady < ds.Status.DesiredNumberScheduled {
		res.Findings = append(res.Findings, model.Finding{
			PipelineRef: "falco",
			Category:    model.CatRuntime,
			Severity:    model.SevMedium,
			Message:     fmt.Sprintf("Falco partially rolled out: %d/%d nodes covered", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
			Location:    res.Project,
			Suggestion:  "ensure Falco runs on every node for full runtime coverage",
		})
	}
	return res, nil
}

// Disconnect is a no-op for the stateless HTTP connector.
func (f *Falco) Disconnect(_ context.Context) error { return nil }
