package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

// Technologies prints a grouped technology inventory.
func Technologies(w io.Writer, a model.Analysis) {
	fmt.Fprintf(w, "Repository: %s\n\n", a.Repository.Name)
	if len(a.Technologies) == 0 {
		fmt.Fprintln(w, "No technologies detected.")
		return
	}
	fmt.Fprintln(w, "Detected technologies:")
	for _, t := range a.Technologies {
		fmt.Fprintf(w, "  • %-14s %-18s %3.0f%%\n", t.Kind, t.Name, t.Confidence*100)
	}
}

// Recommendations prints the recommendation list.
func Recommendations(w io.Writer, a model.Analysis) {
	if len(a.Recommendations) == 0 {
		return
	}
	fmt.Fprintln(w, "\nRecommendations:")
	for _, r := range a.Recommendations {
		fmt.Fprintf(w, "  [%s] %-10s → %-10s  %s\n", strings.ToUpper(string(r.Severity)), r.Category, r.Tool, firstLine(r.Rationale))
	}
}

// Score prints the maturity score breakdown.
func Score(w io.Writer, s scoring.Report) {
	fmt.Fprintf(w, "\nSecurity Score: %d/100  (%s)\n", s.Total, s.Maturity)
	for _, c := range s.Categories {
		fmt.Fprintf(w, "  %-16s %2d/%-2d  %-8s %s\n", c.Category, c.Earned, c.Weight, c.State, c.Reason)
	}
}

// Scans prints imported scanner results.
func Scans(w io.Writer, a model.Analysis) {
	if len(a.Scans) == 0 {
		return
	}
	fmt.Fprintln(w, "\nImported scanner reports:")
	for _, sc := range a.Scans {
		fmt.Fprintf(w, "  %s (%s): %d finding(s)\n", sc.Tool, sc.Source, len(sc.Findings))
		for _, f := range sc.Findings {
			fmt.Fprintf(w, "    ✗ [%s] %s — %s\n", f.Severity, f.Message, f.Location)
		}
	}
}

// Findings prints pipeline audit findings.
func Findings(w io.Writer, a model.Analysis) {
	if len(a.Pipelines) == 0 {
		fmt.Fprintln(w, "\nNo CI/CD pipelines found to audit.")
		return
	}
	for _, pa := range a.Pipelines {
		fmt.Fprintf(w, "\nPipeline: %s (%s)\n", pa.Path, pa.Platform)
		if len(pa.Findings) == 0 {
			fmt.Fprintln(w, "  ✓ all security stages present")
			continue
		}
		for _, f := range pa.Findings {
			fmt.Fprintf(w, "  ✗ [%s] %s\n", f.Severity, f.Message)
		}
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
