package scanner

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// TestSSL imports testssl.sh reports produced with the flat `--jsonfile`
// option: a top-level JSON array of graded findings. Category: dast — it tests
// the TLS posture of a running endpoint. Informational rows (OK/INFO/DEBUG) are
// dropped; only graded weaknesses (LOW..CRITICAL) become findings, but a parsed
// report still credits DAST coverage even when everything passes.
type TestSSL struct{}

func (TestSSL) Tool() string { return "testssl" }

type testsslFinding struct {
	ID       string `json:"id"`
	FqdnIP   string `json:"fqdn/ip"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
}

func (ts TestSSL) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"testssl.json", "testssl-report.json", "testssl-results.json"},
		[]string{".testssl.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		trimmed := strings.TrimSpace(string(data))
		if !strings.HasPrefix(trimmed, "[") {
			continue // only the flat --jsonfile array form is supported
		}
		var rows []testsslFinding
		if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
			continue
		}
		if !looksLikeTestSSL(rows) {
			continue
		}
		res := model.ScanResult{
			Tool:   ts.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDAST},
		}
		for _, r := range rows {
			sev, ok := testsslSeverity(r.Severity)
			if !ok {
				continue // OK / INFO / DEBUG: not an actionable finding
			}
			loc := r.FqdnIP
			if loc == "" {
				loc = r.IP
			}
			if r.Port != "" {
				loc += ":" + r.Port
			}
			msg := r.ID + ": " + r.Finding
			if r.CVE != "" {
				msg += " (" + r.CVE + ")"
			}
			res.Findings = append(res.Findings, finding(ts.Tool(), path,
				model.CatDAST, sev, msg, loc))
		}
		out = append(out, res)
	}
	return out, nil
}

// looksLikeTestSSL confirms the array carries testssl rows (id + severity).
func looksLikeTestSSL(rows []testsslFinding) bool {
	for _, r := range rows {
		if r.ID != "" && r.Severity != "" {
			return true
		}
	}
	return false
}

// testsslSeverity maps a testssl severity word to a devsec Severity. The second
// return is false for non-actionable rows (OK/INFO/DEBUG).
func testsslSeverity(s string) (model.Severity, bool) {
	switch toLower(s) {
	case "critical":
		return model.SevCritical, true
	case "high":
		return model.SevHigh, true
	case "medium":
		return model.SevMedium, true
	case "low", "warn":
		return model.SevLow, true
	default:
		return "", false
	}
}
