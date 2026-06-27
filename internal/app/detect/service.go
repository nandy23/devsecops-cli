// Package detect implements the DetectService, the backbone use-case that
// produces the Analysis aggregate every other command consumes.
package detect

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service orchestrates detectors and the rule engine.
type Service struct {
	detectors []port.Detector
	rules     port.RuleEngine
	version   string
	log       port.Logger
}

// New builds a detect service.
func New(detectors []port.Detector, rules port.RuleEngine, version string, log port.Logger) *Service {
	return &Service{detectors: detectors, rules: rules, version: version, log: log}
}

// Run executes all detectors in parallel, merges results, derives coverage and
// evaluates recommendation rules.
func (s *Service) Run(ctx context.Context, fsys port.FileSystem) (model.Analysis, error) {
	techs := s.runDetectors(ctx, fsys)

	a := model.Analysis{
		Repository:   model.Repository{Path: fsys.Root(), Name: repoName(fsys.Root())},
		Technologies: techs,
		GeneratedAt:  time.Now().UTC(),
		ToolVersion:  s.version,
	}

	recs, err := s.rules.Evaluate(ctx, a)
	if err != nil {
		return a, err
	}
	a.Recommendations = recs
	a.Coverage = deriveCoverage(a)
	return a, nil
}

func (s *Service) runDetectors(ctx context.Context, fsys port.FileSystem) []model.Technology {
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		all []model.Technology
	)
	for _, d := range s.detectors {
		wg.Add(1)
		go func(d port.Detector) {
			defer wg.Done()
			techs, err := d.Detect(ctx, fsys)
			if err != nil {
				s.log.Warnf("detector %s failed: %v", d.Name(), err)
				return
			}
			mu.Lock()
			all = append(all, techs...)
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return mergeTechs(all)
}

// mergeTechs deduplicates by (kind,name), keeping the highest confidence and
// merging evidence.
func mergeTechs(in []model.Technology) []model.Technology {
	type key struct {
		k model.TechKind
		n string
	}
	idx := map[key]int{}
	var out []model.Technology
	for _, t := range in {
		k := key{t.Kind, t.Name}
		if i, ok := idx[k]; ok {
			out[i].Evidence = append(out[i].Evidence, t.Evidence...)
			if t.Confidence > out[i].Confidence {
				out[i].Confidence = t.Confidence
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// deriveCoverage marks a category present if a recommendation already exists
// for it (meaning a control is applicable) — in detect-only mode everything
// recommended is treated as Missing until a pipeline audit proves otherwise.
func deriveCoverage(a model.Analysis) map[model.SecurityCategory]model.Coverage {
	cov := map[model.SecurityCategory]model.Coverage{}
	for _, cat := range model.AllCategories() {
		cov[cat] = model.Coverage{Category: cat, State: model.StateMissing, Reason: "no control detected"}
	}
	// A pipeline audit (if present) upgrades categories that are covered.
	for _, pa := range a.Pipelines {
		for _, stage := range pa.DetectedStages {
			cat := model.SecurityCategory(stage)
			cov[cat] = model.Coverage{Category: cat, State: model.StatePresent, Reason: "found in " + pa.Platform + " pipeline"}
		}
	}
	return cov
}

func repoName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}
