package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// NpmAudit imports `npm audit --json` reports (language-native SCA for NodeJS).
// Category: dependency_scan.
type NpmAudit struct{}

func (NpmAudit) Tool() string { return "npm-audit" }

type npmAuditReport struct {
	Vulnerabilities map[string]struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Range    string `json:"range"`
	} `json:"vulnerabilities"`
}

func (n NpmAudit) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys, []string{"npm-audit.json"}, []string{".npm-audit.json"})
	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep npmAuditReport
		if err := json.Unmarshal(data, &rep); err != nil || rep.Vulnerabilities == nil {
			continue
		}
		res := model.ScanResult{Tool: n.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatDependencyScan}}
		for name, v := range rep.Vulnerabilities {
			res.Findings = append(res.Findings, finding(n.Tool(), path,
				model.CatDependencyScan, depSeverity(v.Severity),
				fmt.Sprintf("%s vulnerable (%s)", name, v.Range), name))
		}
		out = append(out, res)
	}
	return out, nil
}

// PipAudit imports `pip-audit --format json` reports (language-native SCA for
// Python). Category: dependency_scan.
type PipAudit struct{}

func (PipAudit) Tool() string { return "pip-audit" }

type pipAuditReport struct {
	Dependencies []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"vulns"`
	} `json:"dependencies"`
}

func (p PipAudit) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys, []string{"pip-audit.json"}, []string{".pip-audit.json"})
	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep pipAuditReport
		if err := json.Unmarshal(data, &rep); err != nil || rep.Dependencies == nil {
			continue
		}
		res := model.ScanResult{Tool: p.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatDependencyScan}}
		for _, d := range rep.Dependencies {
			for _, v := range d.Vulns {
				res.Findings = append(res.Findings, finding(p.Tool(), path,
					model.CatDependencyScan, model.SevHigh,
					fmt.Sprintf("%s in %s@%s", v.ID, d.Name, d.Version), d.Name+"@"+d.Version))
			}
		}
		out = append(out, res)
	}
	return out, nil
}
