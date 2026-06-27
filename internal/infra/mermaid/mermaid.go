// Package mermaid renders a pipeline IR to a Mermaid flowchart.
package mermaid

import (
	"context"
	"fmt"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// Renderer implements port.GraphRenderer.
type Renderer struct{}

// Render produces a Mermaid `flowchart TD` from the pipeline spec.
func (Renderer) Render(_ context.Context, spec pipeline.Spec) (string, error) {
	var b strings.Builder
	b.WriteString("flowchart TD\n")
	for _, s := range spec.Stages {
		label := s.Name
		if len(s.Tools) > 0 {
			label += "\\n(" + strings.Join(s.Tools, ", ") + ")"
		}
		fmt.Fprintf(&b, "    %s[\"%s\"]\n", s.ID, label)
	}
	for _, s := range spec.Stages {
		for _, dep := range s.DependsOn {
			fmt.Fprintf(&b, "    %s --> %s\n", dep, s.ID)
		}
	}
	return b.String(), nil
}
