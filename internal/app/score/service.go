// Package score computes the security maturity score for an analysis.
package score

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

// Service wraps a Scorer.
type Service struct {
	scorer port.Scorer
}

// New builds the score service.
func New(scorer port.Scorer) *Service { return &Service{scorer: scorer} }

// Run scores the analysis.
func (s *Service) Run(ctx context.Context, a model.Analysis) (scoring.Report, error) {
	return s.scorer.Score(ctx, a)
}
