// Package scanner ingests the output of security scanners that already ran in
// the repository or CI (gitleaks, semgrep, snyk…). devsec orchestrates scanners
// but never executes them; these importers parse report files and turn them
// into ScanResults that merge into the analysis and credit coverage.
package scanner

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// discover returns repo-relative paths whose basename matches any exact name or
// suffix. Matching is case-insensitive.
func discover(fsys port.FileSystem, names, suffixes []string) []string {
	paths, err := fsys.List()
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range paths {
		base := strings.ToLower(filepath.Base(p))
		if containsFold(names, base) || hasAnySuffix(base, suffixes) {
			out = append(out, p)
		}
	}
	return out
}

func read(fsys port.FileSystem, path string) ([]byte, error) {
	return fs.ReadFile(fsys, path)
}

func containsFold(set []string, s string) bool {
	for _, v := range set {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// Builtin returns the default scanner-result importers.
func Builtin() []port.ResultImporter {
	return []port.ResultImporter{
		Gitleaks{},
		Semgrep{},
		Snyk{},
		Trivy{},
		TruffleHog{},
		Grype{},
		Hadolint{},
		Tfsec{},
		Kubescape{},
		OWASPDependencyCheck{},
		NpmAudit{},
		PipAudit{},
		K8sManifest{},
		ZAP{},
		Nuclei{},
		Dastardly{},
		Nikto{},
		Nmap{},
		SARIF{},
	}
}

// finding builds a ScanResult finding for a category.
func finding(tool, ref string, cat model.SecurityCategory, sev model.Severity, msg, loc string) model.Finding {
	return model.Finding{
		PipelineRef: tool + ":" + ref,
		Category:    cat,
		Severity:    sev,
		Message:     msg,
		Location:    loc,
		Suggestion:  "review and remediate the issue reported by " + tool,
	}
}
