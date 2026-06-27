package reporter

import (
	"context"
	"encoding/json"
	"io"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

// SARIF renders findings and missing-control recommendations as SARIF 2.1.0 so
// results surface natively in GitHub code scanning and other SARIF consumers.
type SARIF struct{}

func (SARIF) Format() string { return "sarif" }

// --- minimal SARIF 2.1.0 model (only the fields we populate) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func (SARIF) Render(_ context.Context, a model.Analysis, _ scoring.Report, w io.Writer) error {
	rulesByID := map[string]sarifRule{}
	var results []sarifResult

	// Pipeline audit findings → SARIF results with a physical location.
	for _, pa := range a.Pipelines {
		for _, f := range pa.Findings {
			id := "missing-" + string(f.Category)
			if _, ok := rulesByID[id]; !ok {
				rulesByID[id] = sarifRule{
					ID:               id,
					Name:             string(f.Category),
					ShortDescription: sarifText{Text: "Missing security control: " + string(f.Category)},
					Properties:       map[string]any{"category": string(f.Category)},
				}
			}
			results = append(results, sarifResult{
				RuleID:  id,
				Level:   level(f.Severity),
				Message: sarifText{Text: f.Message + ". " + f.Suggestion},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifact{URI: f.Location},
					},
				}},
			})
		}
	}

	// Recommendations (e.g. detect-only mode with no pipelines) → results
	// without a location.
	for _, r := range a.Recommendations {
		id := r.ID
		if _, ok := rulesByID[id]; !ok {
			rulesByID[id] = sarifRule{
				ID:               id,
				Name:             r.Tool,
				ShortDescription: sarifText{Text: "Recommended: " + r.Tool + " for " + string(r.Category)},
				FullDescription:  &sarifText{Text: r.Rationale},
				Properties:       map[string]any{"category": string(r.Category), "tool": r.Tool},
			}
		}
		results = append(results, sarifResult{
			RuleID:  id,
			Level:   level(r.Severity),
			Message: sarifText{Text: "Recommend " + r.Tool + " (" + string(r.Category) + "): " + firstSentence(r.Rationale)},
		})
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "devsec",
				Version:        a.ToolVersion,
				InformationURI: "https://github.com/nandy23/devsecops-cli",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// level maps devsec severity to a SARIF result level.
func level(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func firstSentence(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i+1]
		}
	}
	return s
}
