package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Semgrep imports semgrep JSON reports (`semgrep --json`). Category: sast.
type Semgrep struct{}

func (Semgrep) Tool() string { return "semgrep" }

type semgrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
}

func (s Semgrep) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"semgrep.json", "semgrep-report.json", "semgrep-results.json"},
		[]string{".semgrep.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep semgrepReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		// Require the "results" key to avoid matching unrelated JSON.
		if !json.Valid(data) {
			continue
		}
		res := model.ScanResult{
			Tool:   s.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatSAST},
		}
		for _, r := range rep.Results {
			res.Findings = append(res.Findings, finding(s.Tool(), path,
				model.CatSAST, semgrepSeverity(r.Extra.Severity),
				fmt.Sprintf("%s (%s)", r.Extra.Message, r.CheckID),
				fmt.Sprintf("%s:%d", r.Path, r.Start.Line)))
		}
		out = append(out, res)
	}
	return out, nil
}

func semgrepSeverity(s string) model.Severity {
	switch s {
	case "ERROR":
		return model.SevHigh
	case "WARNING":
		return model.SevMedium
	default:
		return model.SevLow
	}
}
