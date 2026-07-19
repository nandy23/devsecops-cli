package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// ZAP imports OWASP ZAP JSON reports (`zap.json`, produced by
// `zap-cli report -f json` or the ZAP "JSON" report). Category: dast. A ZAP
// report always describes at least the scanned site, so a parsed report credits
// DAST coverage even when it lists zero alerts.
type ZAP struct{}

func (ZAP) Tool() string { return "zap" }

type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID  string `json:"pluginid"`
			Alert     string `json:"alert"`
			Name      string `json:"name"`
			RiskCode  string `json:"riskcode"` // 0 info, 1 low, 2 medium, 3 high
			RiskDesc  string `json:"riskdesc"`
			Instances []struct {
				URI    string `json:"uri"`
				Method string `json:"method"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

func (z ZAP) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"zap.json", "zap-report.json", "zap-results.json", "owasp-zap.json"},
		[]string{".zap.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep zapReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		// A ZAP report always contains at least one scanned site; require it so
		// we do not credit DAST for unrelated JSON.
		if len(rep.Site) == 0 {
			continue
		}
		res := model.ScanResult{
			Tool:   z.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDAST},
		}
		for _, s := range rep.Site {
			for _, a := range s.Alerts {
				name := a.Alert
				if name == "" {
					name = a.Name
				}
				loc := s.Name
				if len(a.Instances) > 0 && a.Instances[0].URI != "" {
					loc = a.Instances[0].Method + " " + a.Instances[0].URI
				}
				res.Findings = append(res.Findings, finding(z.Tool(), path,
					model.CatDAST, zapSeverity(a.RiskCode),
					fmt.Sprintf("%s (plugin %s)", name, a.PluginID), loc))
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func zapSeverity(riskcode string) model.Severity {
	switch riskcode {
	case "3":
		return model.SevHigh
	case "2":
		return model.SevMedium
	case "1":
		return model.SevLow
	default:
		return model.SevInfo
	}
}
