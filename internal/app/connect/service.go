// Package connect runs enterprise connectors and merges their results into an
// analysis, upgrading coverage for categories the external platform handles.
package connect

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service drives the connector lifecycle (Connect → Validate → Collect →
// Disconnect) for every configured connector.
type Service struct {
	connectors []port.Connector
	log        port.Logger
}

// New builds the connect service.
func New(connectors []port.Connector, log port.Logger) *Service {
	return &Service{connectors: connectors, log: log}
}

// Enabled reports whether any connector is configured.
func (s *Service) Enabled() bool { return len(s.connectors) > 0 }

// Collect runs every connector and returns their results. Failures are logged
// and skipped (fail-soft) so one broken integration does not abort the run.
func (s *Service) Collect(ctx context.Context) []model.ConnectorResult {
	var results []model.ConnectorResult
	for _, c := range s.connectors {
		res, err := s.run(ctx, c)
		if err != nil {
			s.log.Warnf("connector %s skipped: %v", c.Name(), err)
			continue
		}
		results = append(results, res)
	}
	return results
}

func (s *Service) run(ctx context.Context, c port.Connector) (model.ConnectorResult, error) {
	if err := c.Connect(ctx); err != nil {
		return model.ConnectorResult{}, err
	}
	defer func() { _ = c.Disconnect(ctx) }()
	if err := c.Validate(ctx); err != nil {
		return model.ConnectorResult{}, err
	}
	return c.Collect(ctx)
}

// Merge folds connector results into the analysis: results are attached and the
// categories they cover are marked present in the coverage map.
func Merge(a model.Analysis, results []model.ConnectorResult) model.Analysis {
	if len(results) == 0 {
		return a
	}
	a.Connectors = append(a.Connectors, results...)
	if a.Coverage == nil {
		a.Coverage = map[model.SecurityCategory]model.Coverage{}
	}
	for _, r := range results {
		for _, cat := range r.Covers {
			a.Coverage[cat] = model.Coverage{
				Category: cat,
				State:    model.StatePresent,
				Reason:   "covered by " + r.Connector + " (" + r.Project + ")",
			}
		}
	}
	return a
}
