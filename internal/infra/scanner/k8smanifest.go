package scanner

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// K8sManifest is a built-in Kubernetes manifest checker. Unlike the other
// importers it does not read a scanner report — it parses the repo's K8s YAML
// directly and runs best-practice checks on Deployments, Services, Ingresses,
// CronJobs and other workloads. Findings are informational (no score credit).
type K8sManifest struct{}

func (K8sManifest) Tool() string { return "k8s-manifest" }

var k8sWorkloadKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "Pod": true, "ReplicaSet": true,
}
var k8sKnownKinds = map[string]bool{
	"Service": true, "Ingress": true, "ConfigMap": true, "Secret": true,
	"Namespace": true, "HorizontalPodAutoscaler": true, "NetworkPolicy": true,
}

type k8sDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		Template    *k8sPodTemplate `yaml:"template"`
		JobTemplate *struct {
			Spec struct {
				Template k8sPodTemplate `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
		TLS   []any `yaml:"tls"`
		Rules []any `yaml:"rules"`
	} `yaml:"spec"`
}

type k8sPodTemplate struct {
	Spec struct {
		Containers      []k8sContainer `yaml:"containers"`
		SecurityContext *k8sSecCtx     `yaml:"securityContext"`
	} `yaml:"spec"`
}

type k8sContainer struct {
	Name      string `yaml:"name"`
	Image     string `yaml:"image"`
	Resources struct {
		Limits map[string]any `yaml:"limits"`
	} `yaml:"resources"`
	SecurityContext *k8sSecCtx `yaml:"securityContext"`
	LivenessProbe   any        `yaml:"livenessProbe"`
	ReadinessProbe  any        `yaml:"readinessProbe"`
}

type k8sSecCtx struct {
	RunAsNonRoot *bool `yaml:"runAsNonRoot"`
	Privileged   *bool `yaml:"privileged"`
}

func (k K8sManifest) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	paths, err := fsys.List()
	if err != nil {
		return nil, err
	}
	res := model.ScanResult{Tool: k.Tool(), Source: "kubernetes manifests"}
	inventory := map[string]int{}

	for _, p := range paths {
		if !isYAMLFile(p) || isCIFile(p) {
			continue
		}
		data, err := read(fsys, p)
		if err != nil {
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var doc k8sDoc
			if err := dec.Decode(&doc); err != nil {
				break
			}
			if doc.Kind == "" || doc.APIVersion == "" {
				continue
			}
			if !k8sWorkloadKinds[doc.Kind] && !k8sKnownKinds[doc.Kind] {
				continue
			}
			inventory[doc.Kind]++
			res.Findings = append(res.Findings, checkDoc(p, doc)...)
		}
	}

	if len(inventory) == 0 {
		return nil, nil // no Kubernetes manifests in this repo
	}
	res.Findings = append([]model.Finding{{
		PipelineRef: k.Tool(),
		Category:    model.CatPolicy,
		Severity:    model.SevInfo,
		Message:     "Kubernetes resources detected: " + inventorySummary(inventory),
		Location:    "manifests",
	}}, res.Findings...)
	return []model.ScanResult{res}, nil
}

func checkDoc(path string, doc k8sDoc) []model.Finding {
	var out []model.Finding
	ref := doc.Kind + "/" + doc.Metadata.Name
	add := func(sev model.Severity, msg string) {
		out = append(out, model.Finding{
			PipelineRef: "k8s-manifest:" + ref,
			Category:    model.CatPolicy,
			Severity:    sev,
			Message:     msg,
			Location:    path,
			Suggestion:  "apply Kubernetes security best practices",
		})
	}

	// Ingress should terminate TLS.
	if doc.Kind == "Ingress" && len(doc.Spec.TLS) == 0 {
		add(model.SevMedium, ref+": Ingress has no TLS block (traffic may be unencrypted)")
	}

	pod := podTemplateOf(doc)
	if pod == nil {
		return out
	}
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.RunAsNonRoot == nil || !*pod.Spec.SecurityContext.RunAsNonRoot {
		add(model.SevHigh, ref+": pod does not enforce runAsNonRoot: true")
	}
	for _, c := range pod.Spec.Containers {
		cref := ref + " container " + c.Name
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			add(model.SevCritical, cref+": runs as privileged")
		}
		if usesMutableTag(c.Image) {
			add(model.SevMedium, cref+": image '"+c.Image+"' uses a mutable/:latest tag (pin a digest or version)")
		}
		if len(c.Resources.Limits) == 0 {
			add(model.SevMedium, cref+": no resource limits set (risk of noisy-neighbor/DoS)")
		}
		if doc.Kind == "Deployment" && c.LivenessProbe == nil && c.ReadinessProbe == nil {
			add(model.SevLow, cref+": no liveness/readiness probe")
		}
	}
	return out
}

func podTemplateOf(doc k8sDoc) *k8sPodTemplate {
	if doc.Spec.Template != nil {
		return doc.Spec.Template
	}
	if doc.Spec.JobTemplate != nil { // CronJob
		return &doc.Spec.JobTemplate.Spec.Template
	}
	return nil
}

func usesMutableTag(image string) bool {
	if image == "" {
		return false
	}
	// strip registry host (may contain ':' for port) by looking at last segment
	name := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		name = image[i+1:]
	}
	if !strings.Contains(name, ":") {
		return true // no tag → defaults to :latest
	}
	return strings.HasSuffix(name, ":latest")
}

func inventorySummary(inv map[string]int) string {
	var parts []string
	for k, n := range inv {
		parts = append(parts, fmt.Sprintf("%s×%d", k, n))
	}
	return strings.Join(parts, ", ")
}

func isYAMLFile(p string) bool {
	return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")
}

func isCIFile(p string) bool {
	low := strings.ToLower(p)
	return strings.Contains(low, ".github/workflows/") ||
		strings.HasSuffix(low, ".gitlab-ci.yml") ||
		strings.Contains(low, "azure-pipelines")
}
