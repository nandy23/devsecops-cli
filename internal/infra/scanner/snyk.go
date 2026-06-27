package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Snyk imports snyk JSON reports (`snyk test --json`). Category: dependency_scan.
type Snyk struct{}

func (Snyk) Tool() string { return "snyk" }

type snykReport struct {
	OK              bool `json:"ok"`
	DependencyCount int  `json:"dependencyCount"`
	Vulnerabilities []struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		PackageName string `json:"packageName"`
		Version     string `json:"version"`
	} `json:"vulnerabilities"`
}

func (s Snyk) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"snyk.json", "snyk-report.json", "snyk-results.json"},
		[]string{".snyk.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		// snyk can emit a single object or an array (multi-project). Handle both.
		reports, ok := decodeSnyk(data)
		if !ok {
			continue
		}
		res := model.ScanResult{
			Tool:   s.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDependencyScan},
		}
		for _, rep := range reports {
			for _, v := range rep.Vulnerabilities {
				res.Findings = append(res.Findings, finding(s.Tool(), path,
					model.CatDependencyScan, snykSeverity(v.Severity),
					fmt.Sprintf("%s in %s@%s (%s)", v.Title, v.PackageName, v.Version, v.ID),
					v.PackageName+"@"+v.Version))
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func decodeSnyk(data []byte) ([]snykReport, bool) {
	var single snykReport
	if err := json.Unmarshal(data, &single); err == nil && (single.Vulnerabilities != nil || single.DependencyCount > 0 || single.OK) {
		return []snykReport{single}, true
	}
	var multi []snykReport
	if err := json.Unmarshal(data, &multi); err == nil && len(multi) > 0 {
		return multi, true
	}
	return nil, false
}

func snykSeverity(s string) model.Severity {
	switch s {
	case "critical":
		return model.SevCritical
	case "high":
		return model.SevHigh
	case "medium":
		return model.SevMedium
	default:
		return model.SevLow
	}
}
