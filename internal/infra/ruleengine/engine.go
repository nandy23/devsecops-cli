package ruleengine

import (
	"context"
	"sort"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/domain/rule"
)

// Engine is the default RuleEngine. It loads rules from its sources once per
// Evaluate call and matches each rule's condition AST against the analysis.
type Engine struct {
	sources  []port.RuleSource
	disabled map[string]bool
	profile  string
}

// New builds an engine from ordered sources. Later sources override earlier
// ones by rule ID. disabled is an optional set of rule IDs to skip. profile
// selects which profile-scoped rules apply (empty defaults to "balanced").
func New(sources []port.RuleSource, disabled []string, profile string) *Engine {
	d := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		d[id] = true
	}
	if profile == "" {
		profile = "balanced"
	}
	return &Engine{sources: sources, disabled: d, profile: profile}
}

// inProfile reports whether a rule applies to the active profile. A rule with
// no profiles list applies to every profile.
func (e *Engine) inProfile(r rule.Rule) bool {
	if len(r.Profiles) == 0 {
		return true
	}
	for _, p := range r.Profiles {
		if p == e.profile {
			return true
		}
	}
	return false
}

// Evaluate returns recommendations for every matching, enabled rule.
func (e *Engine) Evaluate(ctx context.Context, a model.Analysis) ([]model.Recommendation, error) {
	layers := make([][]rule.Rule, 0, len(e.sources))
	for _, s := range e.sources {
		rs, err := s.Load(ctx)
		if err != nil {
			return nil, err
		}
		layers = append(layers, rs)
	}
	rules := Merge(layers...)

	// Deduplicate recommendations by tool+category, keeping max severity and
	// merging rule provenance.
	type key struct {
		tool string
		cat  model.SecurityCategory
	}
	merged := map[key]*model.Recommendation{}

	for _, r := range rules {
		if r.Disabled || e.disabled[r.ID] {
			continue
		}
		if !e.inProfile(r) {
			continue
		}
		if !eval(r.When, a) {
			continue
		}
		k := key{r.Recommend.Tool, r.Category}
		if existing, ok := merged[k]; ok {
			existing.Sources = append(existing.Sources, r.ID)
			if sevRank(r.Recommend.Severity) > sevRank(existing.Severity) {
				existing.Severity = r.Recommend.Severity
			}
			continue
		}
		rec := model.Recommendation{
			ID:         r.ID,
			Category:   r.Category,
			Tool:       r.Recommend.Tool,
			Severity:   r.Recommend.Severity,
			Stage:      r.Recommend.Stage,
			Rationale:  r.Rationale,
			Sources:    []string{r.ID},
			Confidence: 0.9,
		}
		merged[k] = &rec
	}

	out := make([]model.Recommendation, 0, len(merged))
	for _, r := range merged {
		out = append(out, *r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// eval recursively evaluates a condition against the analysis.
func eval(c rule.Condition, a model.Analysis) bool {
	switch {
	case len(c.All) > 0:
		for _, sub := range c.All {
			if !eval(sub, a) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for _, sub := range c.Any {
			if eval(sub, a) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !eval(*c.Not, a)
	case c.TechKind != "" && c.TechName != "":
		return a.HasTech(c.TechKind, c.TechName)
	case c.TechKind != "":
		return a.HasKind(c.TechKind)
	case c.Category != "" && c.State != "":
		cov, ok := a.Coverage[c.Category]
		return ok && cov.State == c.State
	default:
		return false
	}
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 4
	case model.SevHigh:
		return 3
	case model.SevMedium:
		return 2
	case model.SevLow:
		return 1
	default:
		return 0
	}
}
