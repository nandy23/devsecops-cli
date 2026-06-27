package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Gitleaks imports gitleaks JSON reports. The native format is a JSON array of
// leak objects. Category: secret_scan.
type Gitleaks struct{}

func (Gitleaks) Tool() string { return "gitleaks" }

type gitleaksLeak struct {
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	RuleID      string `json:"RuleID"`
}

func (g Gitleaks) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"gitleaks.json", "gitleaks-report.json", "gitleaks-results.json"},
		[]string{".gitleaks.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var leaks []gitleaksLeak
		if err := json.Unmarshal(data, &leaks); err != nil {
			continue // not a native gitleaks array (maybe SARIF) — let SARIF handle it
		}
		res := model.ScanResult{
			Tool:   g.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatSecretScan},
		}
		for _, l := range leaks {
			res.Findings = append(res.Findings, finding(g.Tool(), path,
				model.CatSecretScan, model.SevHigh,
				fmt.Sprintf("%s (%s)", l.Description, l.RuleID),
				fmt.Sprintf("%s:%d", l.File, l.StartLine)))
		}
		out = append(out, res)
	}
	return out, nil
}
