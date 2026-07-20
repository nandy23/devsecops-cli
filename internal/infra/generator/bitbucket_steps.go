package generator

import (
	"strings"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// BitbucketFuncs renders a full Bitbucket Pipelines definition with real,
// runnable steps. Bitbucket clones the repo automatically, so there is no
// explicit checkout step; each step runs in its own container image.
func BitbucketFuncs() template.FuncMap {
	return template.FuncMap{"bitbucketRender": bitbucketRender}
}

func bitbucketRender(spec pipeline.Spec) string {
	var b strings.Builder
	b.WriteString("image: " + langImage(spec.Lang) + "\n\n")
	b.WriteString("pipelines:\n")
	b.WriteString("  default:\n")

	for _, s := range spec.Stages {
		if s.Kind == pipeline.StageCheckout {
			continue // Bitbucket clones automatically
		}
		if len(s.Tools) == 0 {
			writeBitbucketStep(&b, s.Name, "", structuralCmds(s.Kind, spec.Lang), false)
			continue
		}
		for _, tool := range s.Tools {
			writeBitbucketStep(&b, s.Name+": "+tool, toolImage(tool), toolShell(tool, s.Kind), true)
		}
	}
	return b.String()
}

func writeBitbucketStep(b *strings.Builder, name, image string, script []string, scanner bool) {
	b.WriteString("    - step:\n")
	// Quote the name: it can contain ": " (e.g. "SAST: semgrep"), which is
	// otherwise ambiguous in YAML.
	b.WriteString("        name: \"" + name + "\"\n")
	if image != "" {
		b.WriteString("        image: " + image + "\n")
	}
	b.WriteString("        script:\n")
	for _, line := range script {
		b.WriteString("          - " + line + "\n")
	}
	if scanner {
		// Persist reports as downloadable artifacts.
		b.WriteString("        artifacts:\n          - \"*.json\"\n")
	}
}
