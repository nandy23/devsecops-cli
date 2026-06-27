// Package explain answers `devsec explain <tool>` queries.
package explain

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/knowledge"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service wraps the knowledge base.
type Service struct {
	kb port.KnowledgeBase
}

// New builds the explain service.
func New(kb port.KnowledgeBase) *Service { return &Service{kb: kb} }

// Explain returns the knowledge entry for a tool.
func (s *Service) Explain(ctx context.Context, tool string) (knowledge.Tool, error) {
	return s.kb.Lookup(ctx, tool)
}

// List returns all known tools.
func (s *Service) List(ctx context.Context) ([]knowledge.Tool, error) {
	return s.kb.List(ctx)
}
