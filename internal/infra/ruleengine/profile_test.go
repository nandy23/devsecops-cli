package ruleengine

import (
	"context"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/domain/rule"
)

func profiledRules() []rule.Rule {
	mk := func(id, tool string, profiles []string) rule.Rule {
		return rule.Rule{
			ID:        id,
			Category:  model.CatSAST,
			Profiles:  profiles,
			When:      rule.Condition{TechKind: model.KindLanguage, TechName: "Go"},
			Recommend: rule.Recommendation{Tool: tool, Severity: model.SevMedium},
		}
	}
	return []rule.Rule{
		mk("core", "semgrep", []string{"minimal", "balanced", "strict"}),
		mk("extra", "sonarqube", []string{"strict"}),
		mk("always", "trivy", nil), // no profiles → every profile
	}
}

func evalCount(t *testing.T, profile string) int {
	t.Helper()
	eng := New([]port.RuleSource{staticSource{profiledRules()}}, nil, profile)
	a := model.Analysis{Technologies: []model.Technology{{Kind: model.KindLanguage, Name: "Go"}}}
	recs, err := eng.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

func TestProfile_FiltersRules(t *testing.T) {
	// minimal: core + always = 2
	if n := evalCount(t, "minimal"); n != 2 {
		t.Fatalf("minimal: want 2, got %d", n)
	}
	// strict: core + extra + always = 3
	if n := evalCount(t, "strict"); n != 3 {
		t.Fatalf("strict: want 3, got %d", n)
	}
	// empty defaults to balanced: core + always = 2 (extra is strict-only)
	if n := evalCount(t, ""); n != 2 {
		t.Fatalf("balanced(default): want 2, got %d", n)
	}
}
