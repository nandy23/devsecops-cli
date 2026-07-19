package scanner

import (
	"context"
	"encoding/xml"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Dastardly imports PortSwigger Dastardly reports. Dastardly is a free,
// CI-focused DAST scanner (built on Burp) that emits a JUnit XML report, where
// each <failure> is a discovered issue. Category: dast. A parsed report credits
// DAST coverage even with zero failures (a clean scan still proves DAST ran).
type Dastardly struct{}

func (Dastardly) Tool() string { return "dastardly" }

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	XMLName xml.Name    `xml:"testsuite"`
	Name    string      `xml:"name,attr"`
	Cases   []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string         `xml:"name,attr"`
	Classname string         `xml:"classname,attr"`
	Failures  []junitFailure `xml:"failure"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

func (d Dastardly) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"dastardly.xml", "dastardly-report.xml", "dastardly-results.xml"},
		[]string{".dastardly.xml"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		suites := parseJUnit(data)
		if suites == nil {
			continue // not a JUnit/Dastardly report
		}
		res := model.ScanResult{
			Tool:   d.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDAST},
		}
		for _, s := range suites {
			for _, c := range s.Cases {
				for _, f := range c.Failures {
					msg := f.Message
					if msg == "" {
						msg = c.Name
					}
					loc := c.Classname
					if loc == "" {
						loc = c.Name
					}
					sev := dastardlySeverity(c.Name + " " + f.Type + " " + f.Message + " " + f.Text)
					res.Findings = append(res.Findings, finding(d.Tool(), path,
						model.CatDAST, sev, msg, loc))
				}
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// parseJUnit accepts either a <testsuites> wrapper or a single <testsuite> root
// and returns the suites, or nil if the data is not a JUnit report.
func parseJUnit(data []byte) []junitSuite {
	var wrapped junitSuites
	if err := xml.Unmarshal(data, &wrapped); err == nil && len(wrapped.Suites) > 0 {
		return wrapped.Suites
	}
	var single junitSuite
	if err := xml.Unmarshal(data, &single); err == nil && single.XMLName.Local == "testsuite" {
		return []junitSuite{single}
	}
	return nil
}

func dastardlySeverity(text string) model.Severity {
	t := toLower(text)
	switch {
	case strings.Contains(t, "critical"):
		return model.SevCritical
	case strings.Contains(t, "high"):
		return model.SevHigh
	case strings.Contains(t, "low"):
		return model.SevLow
	case strings.Contains(t, "info"):
		return model.SevInfo
	default:
		return model.SevMedium
	}
}
