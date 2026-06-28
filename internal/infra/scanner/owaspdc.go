package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// OWASPDependencyCheck imports OWASP Dependency-Check JSON reports — the
// industry-standard SCA tool. Category: dependency_scan.
type OWASPDependencyCheck struct{}

func (OWASPDependencyCheck) Tool() string { return "owasp-dependency-check" }

type owaspReport struct {
	Dependencies []struct {
		FileName        string `json:"fileName"`
		Vulnerabilities []struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	} `json:"dependencies"`
}

func (o OWASPDependencyCheck) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"dependency-check-report.json", "dependency-check.json"},
		[]string{".dependency-check.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep owaspReport
		if err := json.Unmarshal(data, &rep); err != nil || rep.Dependencies == nil {
			continue
		}
		res := model.ScanResult{Tool: o.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatDependencyScan}}
		for _, d := range rep.Dependencies {
			for _, v := range d.Vulnerabilities {
				res.Findings = append(res.Findings, finding(o.Tool(), path,
					model.CatDependencyScan, depSeverity(v.Severity),
					fmt.Sprintf("%s in %s", v.Name, d.FileName), d.FileName))
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// depSeverity maps SCA severity words (incl. npm's "moderate") to a Severity.
func depSeverity(s string) model.Severity {
	switch toLower(s) {
	case "critical":
		return model.SevCritical
	case "high":
		return model.SevHigh
	case "moderate", "medium":
		return model.SevMedium
	case "low":
		return model.SevLow
	default:
		return model.SevInfo
	}
}
