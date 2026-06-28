package generator

import (
	"strings"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// GitLabFuncs renders a full GitLab CI pipeline with real, runnable jobs.
func GitLabFuncs() template.FuncMap {
	return template.FuncMap{"gitlabRender": gitlabRender}
}

func gitlabRender(spec pipeline.Spec) string {
	var b strings.Builder

	// stages list (GitLab clones automatically, so no checkout stage)
	b.WriteString("stages:\n")
	for _, s := range spec.Stages {
		if s.Kind == pipeline.StageCheckout {
			continue
		}
		b.WriteString("  - " + s.ID + "\n")
	}
	b.WriteString("\n")

	for _, s := range spec.Stages {
		if s.Kind == pipeline.StageCheckout {
			continue // GitLab clones the repo automatically
		}
		if len(s.Tools) == 0 {
			writeGitlabJob(&b, s.ID, s.ID, langImage(spec.Lang), structuralCmds(s.Kind, spec.Lang), false)
			continue
		}
		for _, tool := range s.Tools {
			img := toolImage(tool)
			if img == "" {
				img = langImage(spec.Lang)
			}
			writeGitlabJob(&b, s.ID+"_"+tool, s.ID, img, toolShell(tool, s.Kind), true)
		}
	}
	return b.String()
}

func writeGitlabJob(b *strings.Builder, name, stage, image string, script []string, scanner bool) {
	b.WriteString(name + ":\n")
	b.WriteString("  stage: " + stage + "\n")
	b.WriteString("  image: " + image + "\n")
	b.WriteString("  script:\n")
	for _, line := range script {
		b.WriteString("    - " + line + "\n")
	}
	if scanner {
		// Surface findings without hard-blocking the pipeline initially; tune to
		// `allow_failure: false` once the baseline is clean.
		b.WriteString("  allow_failure: true\n")
		b.WriteString("  artifacts:\n    when: always\n    expire_in: 1 week\n    paths:\n      - \"*.json\"\n")
	}
	b.WriteString("\n")
}
