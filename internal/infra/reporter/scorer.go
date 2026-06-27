package reporter

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

// Scorer adapts scoring.Calculator to the port.Scorer interface.
type Scorer struct {
	calc *scoring.Calculator
}

// NewScorer builds a Scorer with the given weights (nil = defaults).
func NewScorer(weights map[model.SecurityCategory]int) *Scorer {
	return &Scorer{calc: scoring.New(weights)}
}

// Score computes the maturity report for an analysis.
func (s *Scorer) Score(_ context.Context, a model.Analysis) (scoring.Report, error) {
	return s.calc.Score(a), nil
}
