package generator

import (
	"context"
	"strings"
	"testing"

	assets "github.com/nandy23/devsecops-cli"
	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

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
		"github":  ".github/workflows/devsec.yml",
		"gitlab":  ".gitlab-ci.yml",
		"azure":   "azure-pipelines.yml",
		"jenkins": "Jenkinsfile",
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
