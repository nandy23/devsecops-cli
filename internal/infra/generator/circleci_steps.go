package generator

import (
	"strings"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// CircleCIFuncs renders a full CircleCI 2.1 config. Each job runs in its own
// container and checks out the repo (CircleCI jobs are isolated), then the
// workflow chains them in order so security stages gate what follows.
func CircleCIFuncs() template.FuncMap {
	return template.FuncMap{"circleciRender": circleciRender}
}

type circleJob struct {
	name   string
	image  string
	script []string
	report string // report file to persist as an artifact ("" = none)
}

func circleciRender(spec pipeline.Spec) string {
	var jobs []circleJob
	for _, s := range spec.Stages {
		if s.Kind == pipeline.StageCheckout {
			continue // CircleCI checks out inside each job
		}
		if len(s.Tools) == 0 {
			jobs = append(jobs, circleJob{
				name:   s.ID,
				image:  langImage(spec.Lang),
				script: structuralCmds(s.Kind, spec.Lang),
			})
			continue
		}
		for _, tool := range s.Tools {
			img := toolImage(tool)
			if img == "" {
				img = langImage(spec.Lang)
			}
			jobs = append(jobs, circleJob{
				name:   s.ID + "-" + tool,
				image:  img,
				script: toolShell(tool, s.Kind),
				report: reportFile(tool, s.Kind),
			})
		}
	}

	var b strings.Builder
	b.WriteString("version: 2.1\n\njobs:\n")
	for _, j := range jobs {
		b.WriteString("  " + j.name + ":\n")
		b.WriteString("    docker:\n      - image: " + j.image + "\n")
		b.WriteString("    steps:\n")
		b.WriteString("      - checkout\n")
		b.WriteString("      - run:\n          name: " + j.name + "\n          command: |\n")
		for _, line := range j.script {
			b.WriteString("            " + line + "\n")
		}
		if j.report != "" {
			b.WriteString("      - store_artifacts:\n          path: " + j.report + "\n")
		}
	}

	b.WriteString("\nworkflows:\n  version: 2\n  devsec:\n    jobs:\n")
	prev := ""
	for _, j := range jobs {
		if prev == "" {
			b.WriteString("      - " + j.name + "\n")
		} else {
			b.WriteString("      - " + j.name + ":\n          requires:\n            - " + prev + "\n")
		}
		prev = j.name
	}
	return b.String()
}

// reportFile is the best-effort output file a tool writes, used to persist
// scanner reports as CircleCI artifacts. It mirrors the paths in toolShell.
func reportFile(tool string, kind pipeline.StageKind) string {
	switch tool {
	case "trivy":
		if kind == pipeline.StageContainerScan {
			return "trivy-image.json"
		}
		return "trivy.json"
	case "syft":
		return "sbom.spdx.json"
	case "owasp-dependency-check":
		return "dependency-check-report.json"
	case "cosign":
		return ""
	default:
		return tool + ".json"
	}
}
