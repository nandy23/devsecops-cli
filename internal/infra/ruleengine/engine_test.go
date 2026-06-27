package ruleengine

import (
	"context"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/domain/rule"
)

// staticSource is a test RuleSource backed by an in-memory slice.
type staticSource struct{ rules []rule.Rule }

func (s staticSource) Name() string                              { return "static" }
func (s staticSource) Load(context.Context) ([]rule.Rule, error) { return s.rules, nil }

func dockerRule() rule.Rule {
	return rule.Rule{
		ID:       "container-trivy",
		Category: model.CatContainerScan,
		When: rule.Condition{All: []rule.Condition{
			{TechKind: model.KindContainer, TechName: "Docker"},
		}},
		Recommend: rule.Recommendation{Tool: "trivy", Severity: model.SevHigh, Stage: "container_scan"},
	}
}

func TestEngine_MatchesWhenDockerPresent(t *testing.T) {
	eng := New([]port.RuleSource{staticSource{[]rule.Rule{dockerRule()}}}, nil, "")
	a := model.Analysis{Technologies: []model.Technology{
		{Kind: model.KindContainer, Name: "Docker"},
	}}
	recs, err := eng.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Tool != "trivy" {
		t.Fatalf("expected trivy recommendation, got %+v", recs)
	}
}

func TestEngine_NoMatchWithoutDocker(t *testing.T) {
	eng := New([]port.RuleSource{staticSource{[]rule.Rule{dockerRule()}}}, nil, "")
	recs, err := eng.Evaluate(context.Background(), model.Analysis{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no recommendations, got %+v", recs)
	}
}

func TestEngine_DisabledRuleSkipped(t *testing.T) {
	eng := New([]port.RuleSource{staticSource{[]rule.Rule{dockerRule()}}}, []string{"container-trivy"}, "")
	a := model.Analysis{Technologies: []model.Technology{{Kind: model.KindContainer, Name: "Docker"}}}
	recs, _ := eng.Evaluate(context.Background(), a)
	if len(recs) != 0 {
		t.Fatalf("disabled rule should be skipped, got %+v", recs)
	}
}
