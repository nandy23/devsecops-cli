// Package pipeline provides auditors that inspect existing CI/CD pipeline
// definitions and report missing security stages (devsec doctor).
package pipeline

import (
	"context"
	"io/fs"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// stageSignature maps a security category to substrings that indicate the
// category is already present in a pipeline definition.
var stageSignature = map[model.SecurityCategory][]string{
	model.CatSAST:           {"semgrep", "codeql", "sonar", "sonarqube"},
	model.CatDAST:           {"zap", "owasp-zap", "nuclei", "dastardly", "nikto", "sslyze", "testssl", "dast", "arachni", "wapiti"},
	model.CatRecon:          {"nmap", "masscan", "amass", "recon"},
	model.CatSecretScan:     {"gitleaks", "trufflehog", "detect-secrets"},
	model.CatDependencyScan: {"dependency", "npm audit", "trivy fs", "snyk", "owasp"},
	model.CatIaCScan:        {"checkov", "terrascan", "tfsec", "kics"},
	model.CatContainerScan:  {"trivy", "grype", "clair"},
	model.CatSBOM:           {"syft", "sbom", "cyclonedx", "spdx"},
	model.CatSigning:        {"cosign", "sigstore", "notation"},
	model.CatPolicy:         {"kyverno", "opa", "gatekeeper", "conftest"},
	model.CatRuntime:        {"falco", "tetragon"},
}

// genericAuditor audits a single CI platform identified by file matching.
type genericAuditor struct {
	platform string
	match    func(path string) bool
}

func (a genericAuditor) Platform() string { return a.platform }

func (a genericAuditor) CanAudit(fsys port.FileSystem) bool {
	paths, err := fsys.List()
	if err != nil {
		return false
	}
	for _, p := range paths {
		if a.match(p) {
			return true
		}
	}
	return false
}

func (a genericAuditor) Audit(_ context.Context, fsys port.FileSystem) ([]model.PipelineAudit, error) {
	paths, err := fsys.List()
	if err != nil {
		return nil, err
	}
	var audits []model.PipelineAudit
	for _, p := range paths {
		if !a.match(p) {
			continue
		}
		content := strings.ToLower(readAll(fsys, p))
		audit := model.PipelineAudit{Platform: a.platform, Path: p}
		for _, cat := range model.AllCategories() {
			if categoryPresent(content, cat) {
				audit.DetectedStages = append(audit.DetectedStages, string(cat))
			} else {
				audit.MissingCategories = append(audit.MissingCategories, cat)
				audit.Findings = append(audit.Findings, model.Finding{
					PipelineRef: p,
					Category:    cat,
					Severity:    model.SevMedium,
					Message:     "pipeline has no " + string(cat) + " stage",
					Location:    p,
					Suggestion:  "add a " + string(cat) + " stage (see `devsec init`)",
				})
			}
		}
		audits = append(audits, audit)
	}
	return audits, nil
}

func categoryPresent(content string, cat model.SecurityCategory) bool {
	for _, sig := range stageSignature[cat] {
		if strings.Contains(content, sig) {
			return true
		}
	}
	return false
}

func readAll(fsys port.FileSystem, path string) string {
	b, err := fs.ReadFile(fsys, path)
	if err != nil {
		return ""
	}
	return string(b)
}

// Builtin returns the default auditors for the supported CI platforms.
func Builtin() []port.PipelineAuditor {
	return []port.PipelineAuditor{
		genericAuditor{"GitHub Actions", func(p string) bool {
			return strings.Contains(p, ".github/workflows/") && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"))
		}},
		genericAuditor{"GitLab CI", func(p string) bool {
			return strings.HasSuffix(p, ".gitlab-ci.yml")
		}},
		genericAuditor{"Azure DevOps", func(p string) bool {
			return strings.HasSuffix(p, "azure-pipelines.yml") || strings.HasSuffix(p, "azure-pipelines.yaml")
		}},
		genericAuditor{"Jenkins", func(p string) bool {
			return strings.EqualFold(baseName(p), "jenkinsfile")
		}},
	}
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
