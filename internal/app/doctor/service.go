// Package doctor implements the DoctorService, auditing existing pipelines on
// top of the detect backbone and re-deriving coverage from audit results.
package doctor

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/app/connect"
	"github.com/nandy23/devsecops-cli/internal/app/detect"
	"github.com/nandy23/devsecops-cli/internal/app/importscan"
	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service audits CI/CD pipelines, ingests scanner results, queries enterprise
// connectors and recomputes coverage from the combined evidence.
type Service struct {
	detect   *detect.Service
	auditors []port.PipelineAuditor
	imports  *importscan.Service
	connect  *connect.Service
}

// New builds a doctor service. importSvc and connectSvc may be nil.
func New(detectSvc *detect.Service, auditors []port.PipelineAuditor, importSvc *importscan.Service, connectSvc *connect.Service) *Service {
	return &Service{detect: detectSvc, auditors: auditors, imports: importSvc, connect: connectSvc}
}

// Run performs detection, audits pipelines, ingests local scanner reports, then
// merges connector results so coverage reflects pipelines, scanners and
// external platforms together.
func (s *Service) Run(ctx context.Context, fsys port.FileSystem) (model.Analysis, error) {
	a, err := s.detect.Run(ctx, fsys)
	if err != nil {
		return a, err
	}
	for _, au := range s.auditors {
		if !au.CanAudit(fsys) {
			continue
		}
		audits, err := au.Audit(ctx, fsys)
		if err != nil {
			continue // fail-soft per auditor
		}
		a.Pipelines = append(a.Pipelines, audits...)
	}
	a.Coverage = coverageFromAudits(a)

	if s.imports != nil {
		a = importscan.Merge(a, s.imports.Collect(ctx, fsys))
	}
	if s.connect != nil && s.connect.Enabled() {
		a = connect.Merge(a, s.connect.Collect(ctx))
	}
	return a, nil
}

// coverageFromAudits marks a category Present if any audited pipeline contains
// it, otherwise Missing. With no pipelines, everything is Missing.
func coverageFromAudits(a model.Analysis) map[model.SecurityCategory]model.Coverage {
	present := map[model.SecurityCategory]string{}
	for _, pa := range a.Pipelines {
		for _, stage := range pa.DetectedStages {
			present[model.SecurityCategory(stage)] = pa.Platform
		}
	}
	cov := map[model.SecurityCategory]model.Coverage{}
	for _, cat := range model.AllCategories() {
		if plat, ok := present[cat]; ok {
			cov[cat] = model.Coverage{Category: cat, State: model.StatePresent, Reason: "found in " + plat + " pipeline"}
		} else {
			cov[cat] = model.Coverage{Category: cat, State: model.StateMissing, Reason: "not found in any pipeline"}
		}
	}
	return cov
}
