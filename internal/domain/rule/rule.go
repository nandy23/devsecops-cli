// Package rule defines the declarative, data-driven rule model and the
// condition AST that the recommendation engine evaluates against an Analysis.
package rule

import "github.com/nandy23/devsecops-cli/internal/domain/model"

// Rule is a declarative recommendation rule, normally loaded from YAML.
type Rule struct {
	ID          string                 `yaml:"id" json:"id"`
	Description string                 `yaml:"description" json:"description"`
	Category    model.SecurityCategory `yaml:"category" json:"category"`
	When        Condition              `yaml:"when" json:"when"`
	Recommend   Recommendation         `yaml:"recommend" json:"recommend"`
	Rationale   string                 `yaml:"rationale" json:"rationale"`
	WeightHint  int                    `yaml:"weight_hint" json:"weight_hint"`
	Disabled    bool                   `yaml:"disabled" json:"disabled"`
	// Profiles lists which configuration profiles include this rule (e.g.
	// minimal, balanced, strict). Empty means the rule applies to all profiles.
	Profiles []string `yaml:"profiles" json:"profiles"`
}

// Recommendation is the action a rule emits when matched.
type Recommendation struct {
	Tool     string         `yaml:"tool" json:"tool"`
	Severity model.Severity `yaml:"severity" json:"severity"`
	Stage    string         `yaml:"stage" json:"stage"`
}

// Condition is a composable boolean AST node. Exactly one of the fields is
// expected to be populated. All/Any/Not allow arbitrary nesting; the leaf
// predicates query the Analysis.
type Condition struct {
	All []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any []Condition `yaml:"any,omitempty" json:"any,omitempty"`
	Not *Condition  `yaml:"not,omitempty" json:"not,omitempty"`

	// Leaf predicates.
	TechKind model.TechKind         `yaml:"tech.kind,omitempty" json:"tech.kind,omitempty"`
	TechName string                 `yaml:"tech.name,omitempty" json:"tech.name,omitempty"`
	Category model.SecurityCategory `yaml:"coverage.category,omitempty" json:"coverage.category,omitempty"`
	State    model.CoverageState    `yaml:"coverage.state,omitempty" json:"coverage.state,omitempty"`
}
