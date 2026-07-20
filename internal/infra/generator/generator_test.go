package generator

import (
	"context"
	"strings"
	"testing"

	assets "github.com/nandy23/devsecops-cli"
	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
	"gopkg.in/yaml.v3"
)

// assertValidYAML fails if content (after stripping leading comment lines) is
// not parseable YAML — catching issues like an unquoted "name: SAST: semgrep".
func assertValidYAML(t *testing.T, platform, content string) {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(content), &v); err != nil {
		t.Fatalf("%s: generated output is not valid YAML: %v\n%s", platform, err, content)
	}
}

func sampleSpec(platform string) pipeline.Spec {
	return pipeline.Spec{
		Name:     "test",
		Platform: platform,
		Stages: []pipeline.Stage{
			{ID: "checkout", Name: "Checkout", Kind: pipeline.StageCheckout},
			{ID: "container_scan", Name: "Container Scan", Kind: pipeline.StageContainerScan,
				Tools: []string{"trivy"}, DependsOn: []string{"checkout"}},
		},
	}
}

func TestBuiltin_AllPlatformsRender(t *testing.T) {
	gens := Builtin(assets.Templates)
	want := map[string]string{
		"github":    ".github/workflows/devsec.yml",
		"gitlab":    ".gitlab-ci.yml",
		"azure":     "azure-pipelines.yml",
		"jenkins":   "Jenkinsfile",
		"bitbucket": "bitbucket-pipelines.yml",
		"circleci":  ".circleci/config.yml",
	}
	seen := map[string]bool{}
	for _, g := range gens {
		seen[g.Platform()] = true
		files, err := g.Generate(context.Background(), sampleSpec(g.Platform()))
		if err != nil {
			t.Fatalf("%s: %v", g.Platform(), err)
		}
		outPath, ok := want[g.Platform()]
		if !ok {
			t.Fatalf("unexpected platform %s", g.Platform())
		}
		content, ok := files[outPath]
		if !ok {
			t.Fatalf("%s: expected output file %s, got %v", g.Platform(), outPath, files)
		}
		if !strings.Contains(content, "trivy") {
			t.Fatalf("%s: rendered output missing recommended tool trivy", g.Platform())
		}
	}
	for p := range want {
		if !seen[p] {
			t.Fatalf("platform %s not registered", p)
		}
	}
}

// multiStageSpec covers a structural stage plus two security stages so ordering
// and per-tool steps are exercised.
func multiStageSpec(platform string) pipeline.Spec {
	return pipeline.Spec{
		Name:     "test",
		Platform: platform,
		Lang:     "nodejs",
		Stages: []pipeline.Stage{
			{ID: "checkout", Name: "Checkout", Kind: pipeline.StageCheckout},
			{ID: "dependencies", Name: "Dependencies", Kind: pipeline.StageDependencies, DependsOn: []string{"checkout"}},
			{ID: "sast", Name: "SAST", Kind: pipeline.StageSAST, Tools: []string{"semgrep"}, DependsOn: []string{"dependencies"}},
			{ID: "container_scan", Name: "Container Scan", Kind: pipeline.StageContainerScan, Tools: []string{"trivy"}, DependsOn: []string{"sast"}},
		},
	}
}

func render(t *testing.T, platform string) string {
	t.Helper()
	for _, g := range Builtin(assets.Templates) {
		if g.Platform() != platform {
			continue
		}
		files, err := g.Generate(context.Background(), multiStageSpec(platform))
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		for _, content := range files {
			return content
		}
	}
	t.Fatalf("platform %s not found", platform)
	return ""
}

func TestBitbucket_Structure(t *testing.T) {
	out := render(t, "bitbucket")
	for _, want := range []string{"pipelines:", "default:", "- step:", "semgrep", "trivy", "artifacts:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("bitbucket output missing %q:\n%s", want, out)
		}
	}
	// Bitbucket clones automatically — no explicit checkout step.
	if strings.Contains(out, "name: Checkout") {
		t.Fatalf("bitbucket should not emit a checkout step:\n%s", out)
	}
	assertValidYAML(t, "bitbucket", out)
}

func TestCircleCI_Structure(t *testing.T) {
	out := render(t, "circleci")
	for _, want := range []string{"version: 2.1", "jobs:", "- checkout", "workflows:", "requires:", "sast-semgrep", "container_scan-trivy", "store_artifacts:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("circleci output missing %q:\n%s", want, out)
		}
	}
	assertValidYAML(t, "circleci", out)
}
