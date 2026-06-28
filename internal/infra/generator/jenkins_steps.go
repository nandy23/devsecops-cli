package generator

import (
	"strings"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// JenkinsFuncs renders real `sh` steps for each Jenkins pipeline stage.
func JenkinsFuncs() template.FuncMap {
	return template.FuncMap{"jenkinsSteps": jenkinsSteps}
}

// jenkinsSteps renders the steps body for one stage (indented under `steps {`).
func jenkinsSteps(s pipeline.Stage, lang string) string {
	var cmds []string
	if s.Kind == pipeline.StageCheckout {
		return "                checkout scm"
	}
	if len(s.Tools) == 0 {
		cmds = structuralCmds(s.Kind, lang)
	} else {
		for _, tool := range s.Tools {
			cmds = append(cmds, toolShell(tool, s.Kind)...)
		}
	}

	var b strings.Builder
	for i, c := range cmds {
		if i > 0 {
			b.WriteString("\n")
		}
		// single-quoted Groovy sh step; escape any single quotes in the command
		b.WriteString("                sh '" + strings.ReplaceAll(c, "'", "'\\''") + "'")
	}
	return b.String()
}
