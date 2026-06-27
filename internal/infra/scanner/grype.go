package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Grype imports grype JSON reports (`grype -o json`). Category: container_scan.
type Grype struct{}

func (Grype) Tool() string { return "grype" }

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

func (g Grype) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"grype.json", "grype-report.json", "grype-results.json"},
		[]string{".grype.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep grypeReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		res := model.ScanResult{Tool: g.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatContainerScan}}
		for _, m := range rep.Matches {
			res.Findings = append(res.Findings, finding(g.Tool(), path,
				model.CatContainerScan, severityFromWord(m.Vulnerability.Severity),
				fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
				m.Artifact.Name+"@"+m.Artifact.Version))
		}
		out = append(out, res)
	}
	return out, nil
}

// severityFromWord maps common severity words (Critical/High/…) to a Severity.
func severityFromWord(s string) model.Severity {
	switch toLower(s) {
	case "critical":
		return model.SevCritical
	case "high":
		return model.SevHigh
	case "medium":
		return model.SevMedium
	case "low", "negligible":
		return model.SevLow
	default:
		return model.SevInfo
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
