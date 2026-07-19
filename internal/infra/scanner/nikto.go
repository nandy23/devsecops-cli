package scanner

import (
	"context"
	"encoding/json"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Nikto imports Nikto JSON reports (`nikto -Format json -output nikto.json`).
// Category: dast. Nikto does not grade severity, so findings default to medium.
// A parsed report credits DAST coverage even with zero vulnerabilities.
type Nikto struct{}

func (Nikto) Tool() string { return "nikto" }

type niktoReport struct {
	Host            string `json:"host"`
	IP              string `json:"ip"`
	Port            string `json:"port"`
	Vulnerabilities []struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		URL    string `json:"url"`
		Msg    string `json:"msg"`
	} `json:"vulnerabilities"`
}

func (n Nikto) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"nikto.json", "nikto-report.json", "nikto-results.json"},
		[]string{".nikto.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		// Nikto emits either a single object or an array of scanned hosts.
		reports := parseNikto(data)
		if reports == nil {
			continue // not a Nikto report
		}
		res := model.ScanResult{
			Tool:   n.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDAST},
		}
		for _, rep := range reports {
			base := rep.Host
			if rep.Port != "" {
				base += ":" + rep.Port
			}
			for _, v := range rep.Vulnerabilities {
				loc := base + v.URL
				if v.Method != "" {
					loc = v.Method + " " + loc
				}
				msg := v.Msg
				if v.ID != "" {
					msg += " (" + v.ID + ")"
				}
				res.Findings = append(res.Findings, finding(n.Tool(), path,
					model.CatDAST, model.SevMedium, msg, loc))
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// parseNikto accepts a single Nikto object or an array of them. It returns nil
// when the data does not structurally look like a Nikto report (must carry a
// host and a vulnerabilities array).
func parseNikto(data []byte) []niktoReport {
	var one niktoReport
	if err := json.Unmarshal(data, &one); err == nil && (one.Host != "" || one.Vulnerabilities != nil) {
		return []niktoReport{one}
	}
	var many []niktoReport
	if err := json.Unmarshal(data, &many); err == nil {
		var valid []niktoReport
		for _, r := range many {
			if r.Host != "" || r.Vulnerabilities != nil {
				valid = append(valid, r)
			}
		}
		if len(valid) > 0 {
			return valid
		}
	}
	return nil
}
