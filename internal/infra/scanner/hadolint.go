package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Hadolint imports hadolint JSON reports (Dockerfile linting). The native format
// is a JSON array. Category: container_scan.
type Hadolint struct{}

func (Hadolint) Tool() string { return "hadolint" }

type hadolintItem struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func (h Hadolint) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"hadolint.json", "hadolint-report.json"},
		[]string{".hadolint.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var items []hadolintItem
		if err := json.Unmarshal(data, &items); err != nil {
			continue
		}
		res := model.ScanResult{Tool: h.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatContainerScan}}
		for _, it := range items {
			res.Findings = append(res.Findings, finding(h.Tool(), path,
				model.CatContainerScan, hadolintSeverity(it.Level),
				fmt.Sprintf("%s: %s", it.Code, it.Message),
				locLine(it.File, it.Line)))
		}
		out = append(out, res)
	}
	return out, nil
}

func hadolintSeverity(level string) model.Severity {
	switch toLower(level) {
	case "error":
		return model.SevHigh
	case "warning":
		return model.SevMedium
	case "info", "style":
		return model.SevLow
	default:
		return model.SevInfo
	}
}
