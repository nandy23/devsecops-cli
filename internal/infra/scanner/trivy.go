package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Trivy imports trivy JSON reports. Trivy is multi-purpose: a single report can
// contain OS/library vulnerabilities, IaC misconfigurations and secrets. This
// importer maps each result Class to the right category, so one report can
// credit container_scan, dependency_scan, iac_scan and secret_scan at once.
type Trivy struct{}

func (Trivy) Tool() string { return "trivy" }

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string `json:"Target"`
	Class           string `json:"Class"` // os-pkgs | lang-pkgs | config | secret
	Type            string `json:"Type"`
	Vulnerabilities []struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		Severity         string `json:"Severity"`
	} `json:"Vulnerabilities"`
	Misconfigurations []struct {
		ID            string `json:"ID"`
		Title         string `json:"Title"`
		Severity      string `json:"Severity"`
		CauseMetadata struct {
			StartLine int `json:"StartLine"`
		} `json:"CauseMetadata"`
	} `json:"Misconfigurations"`
	Secrets []struct {
		RuleID    string `json:"RuleID"`
		Title     string `json:"Title"`
		Severity  string `json:"Severity"`
		StartLine int    `json:"StartLine"`
	} `json:"Secrets"`
}

// classCategory maps a Trivy result Class to a devsec category.
func classCategory(class string) (model.SecurityCategory, bool) {
	switch class {
	case "os-pkgs":
		return model.CatContainerScan, true
	case "lang-pkgs":
		return model.CatDependencyScan, true
	case "config":
		return model.CatIaCScan, true
	case "secret":
		return model.CatSecretScan, true
	default:
		return "", false
	}
}

func (t Trivy) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"trivy.json", "trivy-report.json", "trivy-results.json"},
		[]string{".trivy.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep trivyReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		if rep.Results == nil {
			continue // not a trivy report
		}

		res := model.ScanResult{Tool: t.Tool(), Source: path}
		seen := map[model.SecurityCategory]bool{}
		for _, r := range rep.Results {
			cat, ok := classCategory(r.Class)
			if !ok {
				continue
			}
			if !seen[cat] {
				seen[cat] = true
				res.Covers = append(res.Covers, cat)
			}
			for _, v := range r.Vulnerabilities {
				res.Findings = append(res.Findings, finding(t.Tool(), path, cat, severityFromWord(v.Severity),
					fmt.Sprintf("%s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
					v.PkgName+"@"+v.InstalledVersion))
			}
			for _, m := range r.Misconfigurations {
				res.Findings = append(res.Findings, finding(t.Tool(), path, cat, severityFromWord(m.Severity),
					m.Title+" ("+m.ID+")", locLine(r.Target, m.CauseMetadata.StartLine)))
			}
			for _, s := range r.Secrets {
				res.Findings = append(res.Findings, finding(t.Tool(), path, cat, severityFromWord(s.Severity),
					"secret: "+s.Title+" ("+s.RuleID+")", locLine(r.Target, s.StartLine)))
			}
		}
		if len(res.Covers) > 0 {
			out = append(out, res)
		}
	}
	return out, nil
}
