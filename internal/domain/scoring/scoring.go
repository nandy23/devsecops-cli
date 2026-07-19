// Package scoring implements the weighted security maturity model.
package scoring

import (
	"sort"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// DefaultWeights is the canonical weighting (sums to 100). Late-stage / advanced
// controls that fewer teams adopt (dast, recon, policy, runtime) are weighted 5
// each; core shift-left controls are 10; the supply-chain emphasis (SBOM,
// container_scan) stays at 15. Override via config scoring.weights.
func DefaultWeights() map[model.SecurityCategory]int {
	return map[model.SecurityCategory]int{
		model.CatSAST:           10,
		model.CatDAST:           5,
		model.CatRecon:          5,
		model.CatSecretScan:     10,
		model.CatDependencyScan: 10,
		model.CatIaCScan:        10,
		model.CatSBOM:           15,
		model.CatContainerScan:  15,
		model.CatSigning:        10,
		model.CatPolicy:         5,
		model.CatRuntime:        5,
	}
}

// CategoryScore is the per-category breakdown.
type CategoryScore struct {
	Category model.SecurityCategory `json:"category"`
	Weight   int                    `json:"weight"`
	Earned   int                    `json:"earned"`
	State    model.CoverageState    `json:"state"`
	Reason   string                 `json:"reason"`
}

// Report is the full scoring result.
type Report struct {
	Total      int             `json:"total"`
	Maturity   string          `json:"maturity"`
	Categories []CategoryScore `json:"categories"`
}

// Calculator turns coverage into a weighted score.
type Calculator struct {
	weights map[model.SecurityCategory]int
}

// New builds a calculator. Pass nil to use the default weights.
func New(weights map[model.SecurityCategory]int) *Calculator {
	if weights == nil {
		weights = DefaultWeights()
	}
	return &Calculator{weights: weights}
}

// Score computes a 0..100 maturity score from the analysis coverage.
func (c *Calculator) Score(a model.Analysis) Report {
	var cats []CategoryScore
	total := 0
	for _, cat := range model.AllCategories() {
		w := c.weights[cat]
		cov, ok := a.Coverage[cat]
		state := model.StateMissing
		reason := "no control detected"
		if ok {
			state = cov.State
			if cov.Reason != "" {
				reason = cov.Reason
			}
		}
		earned := earnedFor(state, w)
		total += earned
		cats = append(cats, CategoryScore{
			Category: cat, Weight: w, Earned: earned, State: state, Reason: reason,
		})
	}
	sort.SliceStable(cats, func(i, j int) bool { return cats[i].Weight > cats[j].Weight })
	return Report{Total: total, Maturity: maturity(total), Categories: cats}
}

func earnedFor(s model.CoverageState, w int) int {
	switch s {
	case model.StatePresent, model.StateNotApplicable:
		return w
	case model.StatePartiallyPresent:
		return w / 2
	default:
		return 0
	}
}

func maturity(total int) string {
	switch {
	case total >= 90:
		return "L5 - Optimized"
	case total >= 75:
		return "L4 - Managed"
	case total >= 55:
		return "L3 - Defined"
	case total >= 30:
		return "L2 - Developing"
	default:
		return "L1 - Initial"
	}
}
