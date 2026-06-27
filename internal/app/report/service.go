// Package report renders an analysis + score using a selected reporter.
package report

import (
	"context"
	"fmt"
	"io"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service selects and drives reporters by format name.
type Service struct {
	reporters map[string]port.Reporter
	scorer    port.Scorer
}

// New builds the report service.
func New(reporters []port.Reporter, scorer port.Scorer) *Service {
	m := make(map[string]port.Reporter, len(reporters))
	for _, r := range reporters {
		m[r.Format()] = r
	}
	return &Service{reporters: m, scorer: scorer}
}

// Formats lists supported report formats.
func (s *Service) Formats() []string {
	out := make([]string, 0, len(s.reporters))
	for f := range s.reporters {
		out = append(out, f)
	}
	return out
}

// Render scores the analysis and writes a report in the requested format.
func (s *Service) Render(ctx context.Context, a model.Analysis, format string, w io.Writer) error {
	r, ok := s.reporters[format]
	if !ok {
		return fmt.Errorf("unsupported report format %q (supported: %v)", format, s.Formats())
	}
	score, err := s.scorer.Score(ctx, a)
	if err != nil {
		return err
	}
	return r.Render(ctx, a, score, w)
}
