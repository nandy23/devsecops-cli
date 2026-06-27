package scanner

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// SARIF imports any *.sarif file and maps the producing tool (from the SARIF
// driver name) to a security category. This handles gitleaks, semgrep and snyk
// when they emit SARIF, plus any other SARIF-producing scanner.
type SARIF struct{}

func (SARIF) Tool() string { return "sarif" }

// driverCategory maps a known SARIF driver name to its category.
func driverCategory(driver string) (model.SecurityCategory, bool) {
	switch strings.ToLower(driver) {
	case "gitleaks":
		return model.CatSecretScan, true
	case "semgrep", "semgrep oss", "semgrep ce":
		return model.CatSAST, true
	case "snyk", "snyk open source", "snyk code":
		return model.CatDependencyScan, true
	case "trivy", "grype":
		return model.CatContainerScan, true
	case "hadolint":
		return model.CatContainerScan, true
	case "trufflehog":
		return model.CatSecretScan, true
	case "kubescape":
		return model.CatPolicy, true
	case "checkov", "tfsec", "terrascan", "kics":
		return model.CatIaCScan, true
	default:
		return "", false
	}
}

type sarifFile struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func (s SARIF) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys, nil, []string{".sarif", ".sarif.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var sf sarifFile
		if err := json.Unmarshal(data, &sf); err != nil {
			continue
		}
		for _, run := range sf.Runs {
			cat, ok := driverCategory(run.Tool.Driver.Name)
			if !ok {
				continue // unknown tool; skip rather than miscategorize
			}
			res := model.ScanResult{
				Tool:   strings.ToLower(run.Tool.Driver.Name),
				Source: path,
				Covers: []model.SecurityCategory{cat},
			}
			for _, r := range run.Results {
				loc := ""
				if len(r.Locations) > 0 {
					pl := r.Locations[0].PhysicalLocation
					loc = pl.ArtifactLocation.URI
					if pl.Region.StartLine > 0 {
						loc += ":" + itoa(pl.Region.StartLine)
					}
				}
				msg := r.Message.Text
				if r.RuleID != "" {
					msg += " (" + r.RuleID + ")"
				}
				res.Findings = append(res.Findings, finding(res.Tool, path, cat, sarifLevel(r.Level), msg, loc))
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func sarifLevel(level string) model.Severity {
	switch level {
	case "error":
		return model.SevHigh
	case "warning":
		return model.SevMedium
	case "note":
		return model.SevLow
	default:
		return model.SevMedium
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
