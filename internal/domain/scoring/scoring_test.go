package scoring

import (
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestScore_AllMissingIsZero(t *testing.T) {
	a := model.Analysis{Coverage: map[model.SecurityCategory]model.Coverage{}}
	got := New(nil).Score(a)
	if got.Total != 0 {
		t.Fatalf("want 0, got %d", got.Total)
	}
	if got.Maturity != "L1 - Initial" {
		t.Fatalf("want L1, got %s", got.Maturity)
	}
}

func TestScore_AllPresentIs100(t *testing.T) {
	cov := map[model.SecurityCategory]model.Coverage{}
	for _, c := range model.AllCategories() {
		cov[c] = model.Coverage{Category: c, State: model.StatePresent}
	}
	got := New(nil).Score(model.Analysis{Coverage: cov})
	if got.Total != 100 {
		t.Fatalf("want 100, got %d", got.Total)
	}
}

func TestScore_PartialIsHalfWeight(t *testing.T) {
	cov := map[model.SecurityCategory]model.Coverage{
		model.CatSBOM: {Category: model.CatSBOM, State: model.StatePartiallyPresent},
	}
	got := New(nil).Score(model.Analysis{Coverage: cov})
	// SBOM weight is 15, partial => 7.
	if got.Total != 7 {
		t.Fatalf("want 7, got %d", got.Total)
	}
}

func TestDefaultWeightsSumTo100(t *testing.T) {
	sum := 0
	for _, w := range DefaultWeights() {
		sum += w
	}
	if sum != 100 {
		t.Fatalf("weights must sum to 100, got %d", sum)
	}
}
