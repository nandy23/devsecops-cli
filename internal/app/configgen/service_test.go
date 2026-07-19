package configgen

import (
	"strings"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestGenerate_NodeContainerStack(t *testing.T) {
	a := model.Analysis{
		Repository: model.Repository{Name: "my-svc"},
		Technologies: []model.Technology{
			{Kind: model.KindLanguage, Name: "NodeJS"},
			{Kind: model.KindContainer, Name: "Docker"},
			{Kind: model.KindPackageMgr, Name: "npm"},
		},
	}
	files := New().Generate(a)

	for _, want := range []string{"sonar-project.properties", ".gitleaks.toml", "trivy.yaml", "syft.yaml", ".hadolint.yaml"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("expected %s to be generated, got keys %v", want, keys(files))
		}
	}
	for _, unwanted := range []string{".checkov.yaml", ".ansible-lint"} {
		if _, ok := files[unwanted]; ok {
			t.Fatalf("did not expect %s for a Node/container stack", unwanted)
		}
	}
	if !strings.Contains(files["sonar-project.properties"], "sonar.projectKey=my-svc") {
		t.Fatalf("sonar projectKey should use the repo name, got:\n%s", files["sonar-project.properties"])
	}
	// Never embed secrets.
	if strings.Contains(files["sonar-project.properties"], "sonar.token=") &&
		!strings.Contains(files["sonar-project.properties"], "$SONAR_TOKEN") {
		t.Fatalf("sonar config must not embed a literal token")
	}
}

func TestGenerate_TerraformStack(t *testing.T) {
	a := model.Analysis{
		Technologies: []model.Technology{{Kind: model.KindIaC, Name: "Terraform"}},
	}
	files := New().Generate(a)

	checkov, ok := files[".checkov.yaml"]
	if !ok {
		t.Fatalf("expected .checkov.yaml for Terraform, got %v", keys(files))
	}
	if !strings.Contains(checkov, "terraform") {
		t.Fatalf("checkov config should target terraform, got:\n%s", checkov)
	}
	// No language detected → no sonar config; gitleaks is always generated.
	if _, ok := files["sonar-project.properties"]; ok {
		t.Fatalf("no language detected, sonar config should be skipped")
	}
	if _, ok := files[".gitleaks.toml"]; !ok {
		t.Fatalf(".gitleaks.toml should always be generated")
	}
}

func TestGenerate_KubernetesChecovFramework(t *testing.T) {
	a := model.Analysis{
		Technologies: []model.Technology{{Kind: model.KindOrchestrator, Name: "Kubernetes"}},
	}
	files := New().Generate(a)
	checkov, ok := files[".checkov.yaml"]
	if !ok || !strings.Contains(checkov, "kubernetes") {
		t.Fatalf("expected checkov with kubernetes framework, got %q", checkov)
	}
}

func TestGenerate_Ansible(t *testing.T) {
	a := model.Analysis{
		Technologies: []model.Technology{{Kind: model.KindIaC, Name: "Ansible"}},
	}
	files := New().Generate(a)
	if _, ok := files[".ansible-lint"]; !ok {
		t.Fatalf("expected .ansible-lint for an Ansible stack, got %v", keys(files))
	}
}

func TestGenerate_EmptyRepoOnlyGitleaks(t *testing.T) {
	files := New().Generate(model.Analysis{})
	if len(files) != 1 {
		t.Fatalf("empty repo should produce only the universal gitleaks config, got %v", keys(files))
	}
	if _, ok := files[".gitleaks.toml"]; !ok {
		t.Fatalf("expected .gitleaks.toml, got %v", keys(files))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
