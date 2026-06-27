// Package graph renders the recommended pipeline as a Mermaid diagram.
package graph

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/app/generate"
	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service produces Mermaid graphs from an analysis.
type Service struct {
	renderer port.GraphRenderer
}

// New builds the graph service.
func New(r port.GraphRenderer) *Service { return &Service{renderer: r} }

// Render builds the recommended pipeline spec and renders it to Mermaid.
func (s *Service) Render(ctx context.Context, a model.Analysis) (string, error) {
	spec := generate.BuildSpec(a, "mermaid")
	return s.renderer.Render(ctx, spec)
}
