package scanner

import (
	"context"
	"encoding/json"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Tfsec imports tfsec JSON reports (`tfsec --format json`). Category: iac_scan.
type Tfsec struct{}

func (Tfsec) Tool() string { return "tfsec" }

type tfsecReport struct {
	Results []struct {
		RuleID      string `json:"rule_id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Location    struct {
			Filename  string `json:"filename"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
	} `json:"results"`
}

func (t Tfsec) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"tfsec.json", "tfsec-report.json", "tfsec-results.json"},
		[]string{".tfsec.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep tfsecReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		res := model.ScanResult{Tool: t.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatIaCScan}}
		for _, r := range rep.Results {
			res.Findings = append(res.Findings, finding(t.Tool(), path,
				model.CatIaCScan, severityFromWord(r.Severity),
				r.Description+" ("+r.RuleID+")",
				locLine(r.Location.Filename, r.Location.StartLine)))
		}
		out = append(out, res)
	}
	return out, nil
}
