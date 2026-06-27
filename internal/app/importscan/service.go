// Package importscan runs scanner-result importers over a repository and merges
// the parsed results into an analysis, crediting the categories they cover.
package importscan

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service drives the scanner-result importers.
type Service struct {
	importers []port.ResultImporter
	log       port.Logger
}

// New builds the import service.
func New(importers []port.ResultImporter, log port.Logger) *Service {
	return &Service{importers: importers, log: log}
}

// Collect runs every importer over the repo and returns the parsed scan
// results. Failures are logged and skipped (fail-soft).
func (s *Service) Collect(ctx context.Context, fsys port.FileSystem) []model.ScanResult {
	var results []model.ScanResult
	for _, imp := range s.importers {
		res, err := imp.Import(ctx, fsys)
		if err != nil {
			s.log.Warnf("importer %s skipped: %v", imp.Tool(), err)
			continue
		}
		results = append(results, res...)
	}
	return results
}

// Merge folds scan results into the analysis: results are attached and the
// categories they cover are marked present. A parsed report proves the scan
// runs, so coverage is credited even when there are zero findings.
func Merge(a model.Analysis, results []model.ScanResult) model.Analysis {
	if len(results) == 0 {
		return a
	}
	a.Scans = append(a.Scans, results...)
	if a.Coverage == nil {
		a.Coverage = map[model.SecurityCategory]model.Coverage{}
	}
	for _, r := range results {
		for _, cat := range r.Covers {
			// Don't downgrade a category already proven present elsewhere.
			if cur, ok := a.Coverage[cat]; ok && cur.State == model.StatePresent {
				continue
			}
			a.Coverage[cat] = model.Coverage{
				Category: cat,
				State:    model.StatePresent,
				Reason:   "imported from " + r.Tool + " report (" + r.Source + ")",
			}
		}
	}
	return a
}
