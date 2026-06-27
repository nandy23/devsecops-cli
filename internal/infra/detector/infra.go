package detector

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// InfraDetector identifies orchestration and IaC technologies.
type InfraDetector struct{}

func (InfraDetector) Name() string  { return "infra" }
func (InfraDetector) Priority() int { return 80 }

func (d InfraDetector) Detect(_ context.Context, fsys port.FileSystem) ([]model.Technology, error) {
	paths, bases, err := scan(fsys)
	if err != nil {
		return nil, err
	}
	var out []model.Technology

	// Helm: Chart.yaml is the strong signal.
	if p, ok := bases["chart.yaml"]; ok {
		out = append(out, tech(model.KindOrchestrator, "Helm", 0.97, p, "Chart.yaml"))
	}

	// Terraform.
	if p, ok := hasExt(paths, ".tf"); ok {
		out = append(out, tech(model.KindIaC, "Terraform", 0.97, p, "*.tf files"))
	}
	// Pulumi.
	for _, name := range []string{"pulumi.yaml", "pulumi.yml"} {
		if p, ok := bases[name]; ok {
			out = append(out, tech(model.KindIaC, "Pulumi", 0.95, p, "Pulumi project"))
		}
	}
	// Packer.
	if p, ok := hasExt(paths, ".pkr.hcl"); ok {
		out = append(out, tech(model.KindIaC, "Packer", 0.9, p, "*.pkr.hcl"))
	}
	// Bicep.
	if p, ok := hasExt(paths, ".bicep"); ok {
		out = append(out, tech(model.KindIaC, "Bicep", 0.95, p, "*.bicep"))
	}
	// Ansible: playbooks or roles.
	if p, ok := bases["ansible.cfg"]; ok {
		out = append(out, tech(model.KindIaC, "Ansible", 0.9, p, "ansible.cfg"))
	} else {
		for _, p := range paths {
			if strings.Contains(p, "playbook") && isYAML(p) {
				out = append(out, tech(model.KindIaC, "Ansible", 0.6, p, "playbook yaml"))
				break
			}
		}
	}

	// Kubernetes: any yaml with apiVersion+kind markers (best-effort sniff).
	for _, p := range paths {
		if !isYAML(p) {
			continue
		}
		snip := readSnippet(fsys, p, 512)
		if strings.Contains(snip, "apiVersion:") && strings.Contains(snip, "kind:") {
			out = append(out, tech(model.KindOrchestrator, "Kubernetes", 0.85, p, "k8s manifest markers"))
			break
		}
	}
	return out, nil
}

func isYAML(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}
