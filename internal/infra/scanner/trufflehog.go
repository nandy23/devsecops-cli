package scanner

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// TruffleHog imports trufflehog reports. trufflehog v3 emits newline-delimited
// JSON (one detection per line). Category: secret_scan.
type TruffleHog struct{}

func (TruffleHog) Tool() string { return "trufflehog" }

type truffleDetection struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Redacted       string `json:"Redacted"`
	SourceMetadata struct {
		Data struct {
			Git struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Git"`
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

func (t TruffleHog) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"trufflehog.json", "trufflehog-report.json", "trufflehog-results.json"},
		[]string{".trufflehog.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		res := model.ScanResult{Tool: t.Tool(), Source: path, Covers: []model.SecurityCategory{model.CatSecretScan}}
		parsedAny := false
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var d truffleDetection
			if json.Unmarshal([]byte(line), &d) != nil || d.DetectorName == "" {
				continue
			}
			parsedAny = true
			loc := d.SourceMetadata.Data.Git.File
			ln := d.SourceMetadata.Data.Git.Line
			if loc == "" {
				loc, ln = d.SourceMetadata.Data.Filesystem.File, d.SourceMetadata.Data.Filesystem.Line
			}
			sev := model.SevMedium
			if d.Verified {
				sev = model.SevCritical // a verified, live secret is critical
			}
			res.Findings = append(res.Findings, finding(t.Tool(), path,
				model.CatSecretScan, sev,
				"secret detected: "+d.DetectorName+" ("+d.Redacted+")",
				locLine(loc, ln)))
		}
		// Only treat as a trufflehog report if at least one line parsed, or the
		// file was an explicit empty trufflehog report (handled by name match).
		if parsedAny || len(res.Findings) == 0 {
			out = append(out, res)
		}
	}
	return out, nil
}

func locLine(file string, line int) string {
	if file == "" {
		return ""
	}
	if line > 0 {
		return file + ":" + itoa(line)
	}
	return file
}
