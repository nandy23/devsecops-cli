package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Nmap imports Nmap XML reports (`nmap -oX nmap.xml`). Category: recon — it maps
// the externally reachable attack surface (open ports/services) and, when NSE
// vuln scripts run, the vulnerabilities they surface. A parsed report credits
// recon coverage even with zero open ports.
type Nmap struct{}

func (Nmap) Tool() string { return "nmap" }

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Address []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
	Scripts []struct {
		ID     string `xml:"id,attr"`
		Output string `xml:"output,attr"`
	} `xml:"script"`
}

func (n Nmap) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"nmap.xml", "nmap-report.xml", "nmap-results.xml"},
		[]string{".nmap.xml"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var run nmapRun
		if err := xml.Unmarshal(data, &run); err != nil || run.XMLName.Local != "nmaprun" {
			continue // not an nmap report
		}
		res := model.ScanResult{
			Tool:   n.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatRecon},
		}
		for _, h := range run.Hosts {
			host := hostLabel(h)
			for _, p := range h.Ports {
				if p.State.State != "open" {
					continue
				}
				loc := fmt.Sprintf("%s:%s/%s", host, p.PortID, p.Protocol)
				svc := strings.TrimSpace(p.Service.Name + " " + p.Service.Product + " " + p.Service.Version)
				res.Findings = append(res.Findings, finding(n.Tool(), path,
					model.CatRecon, model.SevInfo,
					fmt.Sprintf("open port %s/%s (%s)", p.PortID, p.Protocol, strings.TrimSpace(svc)), loc))
				for _, s := range p.Scripts {
					if !isVulnScript(s.ID, s.Output) {
						continue
					}
					sev := model.SevMedium
					if strings.Contains(toLower(s.Output), "vulnerable") {
						sev = model.SevHigh
					}
					res.Findings = append(res.Findings, finding(n.Tool(), path,
						model.CatRecon, sev, "NSE "+s.ID+": "+firstLine(s.Output), loc))
				}
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func hostLabel(h nmapHost) string {
	if len(h.Hostnames) > 0 && h.Hostnames[0].Name != "" {
		return h.Hostnames[0].Name
	}
	if len(h.Address) > 0 {
		return h.Address[0].Addr
	}
	return "host"
}

func isVulnScript(id, output string) bool {
	return strings.Contains(id, "vuln") || strings.Contains(toLower(output), "vulnerable")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
