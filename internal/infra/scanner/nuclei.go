package scanner

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Nuclei imports Nuclei reports. Nuclei emits JSONL by default (`-jsonl`, one
// finding per line) and a JSON array with `-json-export`; this importer accepts
// both. Category: dast. Coverage is credited only when at least one valid
// finding is parsed, since a zero-finding Nuclei run produces an empty file.
type Nuclei struct{}

func (Nuclei) Tool() string { return "nuclei" }

type nucleiFinding struct {
	TemplateID string `json:"template-id"`
	Template   string `json:"template"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

func (n Nuclei) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"nuclei.json", "nuclei-report.json", "nuclei-results.json", "nuclei.jsonl"},
		[]string{".nuclei.json", ".nuclei.jsonl"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		records := parseNuclei(data)
		if len(records) == 0 {
			continue // empty or not a nuclei report
		}
		res := model.ScanResult{
			Tool:   n.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDAST},
		}
		for _, r := range records {
			name := r.Info.Name
			id := r.TemplateID
			if id == "" {
				id = r.Template
			}
			if name == "" {
				name = id
			}
			loc := r.MatchedAt
			if loc == "" {
				loc = r.Host
			}
			res.Findings = append(res.Findings, finding(n.Tool(), path,
				model.CatDAST, severityFromWord(r.Info.Severity),
				name+" ("+id+")", loc))
		}
		out = append(out, res)
	}
	return out, nil
}

// parseNuclei accepts either a JSON array or JSONL and returns only records that
// look like Nuclei findings (a template id or an info.name is present).
func parseNuclei(data []byte) []nucleiFinding {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	var records []nucleiFinding
	if strings.HasPrefix(trimmed, "[") {
		var arr []nucleiFinding
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil
		}
		records = arr
	} else {
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var f nucleiFinding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				continue
			}
			records = append(records, f)
		}
	}
	var valid []nucleiFinding
	for _, r := range records {
		if r.TemplateID != "" || r.Template != "" || r.Info.Name != "" {
			valid = append(valid, r)
		}
	}
	return valid
}
