package scanner

import (
	"context"
	"encoding/json"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Kubescape imports kubescape JSON reports (Kubernetes posture). It reads the
// summaryDetails controls and surfaces failed ones. Category: policy.
type Kubescape struct{}

func (Kubescape) Tool() string { return "kubescape" }

type kubescapeReport struct {
	SummaryDetails struct {
		Controls map[string]struct {
			Name       string `json:"name"`
			StatusInfo struct {
				Status string `json:"status"`
			} `json:"statusInfo"`
			ScoreFactor float64 `json:"scoreFactor"`
		} `json:"controls"`
	} `json:"summaryDetails"`
}

func (k Kubescape) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"kubescape.json", "kubescape-report.json", "kubescape-results.json"},
		[]string{".kubescape.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep kubescapeReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		if rep.SummaryDetails.Controls == nil {
			continue // not a kubescape report
		}
		res := model.ScanResult{Tool: k.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatPolicy}}
		for id, c := range rep.SummaryDetails.Controls {
			if c.StatusInfo.Status != "failed" {
				continue
			}
			res.Findings = append(res.Findings, finding(k.Tool(), path,
				model.CatPolicy, kubescapeSeverity(c.ScoreFactor),
				"control failed: "+c.Name+" ("+id+")", id))
		}
		out = append(out, res)
	}
	return out, nil
}

// kubescapeSeverity derives severity from the control's score factor.
func kubescapeSeverity(score float64) model.Severity {
	switch {
	case score >= 7:
		return model.SevHigh
	case score >= 4:
		return model.SevMedium
	default:
		return model.SevLow
	}
}
