// Package scan runs locally-installed security scanners and ingests their
// reports into the analysis. devsec never bundles the scanners: it resolves
// them on PATH, runs the ones present, then reuses the result importers to
// merge findings into coverage and score.
package scan

import (
	"context"
	"os"
	"path/filepath"

	"github.com/nandy23/devsecops-cli/internal/app/detect"
	"github.com/nandy23/devsecops-cli/internal/app/importscan"
	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Plan describes how to invoke one scanner so it produces a report devsec can
// ingest. This is use-case knowledge (what command yields a report), not infra.
type Plan struct {
	Tool       string
	Bin        string
	ReportName string // report filename written into the temp dir
	// StdoutToFile captures the tool's stdout into the report file (for tools
	// that print JSON) instead of expecting the tool to write the file itself.
	StdoutToFile bool
	// Args builds the command arguments given the absolute repo path and the
	// absolute report path.
	Args func(repoPath, reportPath string) []string
}

// DefaultPlans returns the built-in scanner invocation plans. Report filenames
// are chosen so the existing importers (and SARIF importer) discover them.
func DefaultPlans() []Plan {
	return []Plan{
		{
			Tool: "gitleaks", Bin: "gitleaks", ReportName: "gitleaks.json",
			Args: func(repo, report string) []string {
				return []string{"detect", "--source", repo, "--no-banner", "--report-format", "json", "--report-path", report}
			},
		},
		{
			Tool: "semgrep", Bin: "semgrep", ReportName: "semgrep.json",
			Args: func(repo, report string) []string {
				return []string{"scan", "--config", "auto", "--json", "--output", report, repo}
			},
		},
		{
			Tool: "snyk", Bin: "snyk", ReportName: "snyk.json", StdoutToFile: true,
			Args: func(repo, report string) []string {
				return []string{"test", "--json"}
			},
		},
		{
			// trivy fs with vuln+misconfig+secret scanners → one report credits
			// dependency_scan, iac_scan and secret_scan at once.
			Tool: "trivy", Bin: "trivy", ReportName: "trivy.json",
			Args: func(repo, report string) []string {
				return []string{"fs", "--quiet", "--scanners", "vuln,misconfig,secret",
					"--format", "json", "--output", report, repo}
			},
		},
		{
			Tool: "checkov", Bin: "checkov", ReportName: "results.sarif",
			Args: func(repo, report string) []string {
				return []string{"-d", repo, "-o", "sarif", "--output-file-path", filepath.Dir(report)}
			},
		},
		{
			Tool: "trufflehog", Bin: "trufflehog", ReportName: "trufflehog.json", StdoutToFile: true,
			Args: func(repo, report string) []string {
				return []string{"filesystem", repo, "--json", "--no-update"}
			},
		},
		{
			Tool: "grype", Bin: "grype", ReportName: "grype.json", StdoutToFile: true,
			Args: func(repo, report string) []string {
				return []string{"dir:" + repo, "-o", "json"}
			},
		},
		{
			Tool: "hadolint", Bin: "hadolint", ReportName: "hadolint.json", StdoutToFile: true,
			Args: func(repo, report string) []string {
				return []string{"-f", "json", filepath.Join(repo, "Dockerfile")}
			},
		},
		{
			Tool: "tfsec", Bin: "tfsec", ReportName: "tfsec.json",
			Args: func(repo, report string) []string {
				return []string{repo, "--format", "json", "--out", report}
			},
		},
		{
			Tool: "kubescape", Bin: "kubescape", ReportName: "kubescape.json",
			Args: func(repo, report string) []string {
				return []string{"scan", repo, "--format", "json", "--output", report}
			},
		},
	}
}

// Outcome records what happened for one planned scanner.
type Outcome struct {
	Tool     string `json:"tool"`
	Status   string `json:"status"` // ran | skipped | error
	ExitCode int    `json:"exit_code"`
	Detail   string `json:"detail,omitempty"`
}

// Service orchestrates scanners and result ingestion.
type Service struct {
	detect   *detect.Service
	importer *importscan.Service
	runner   port.CommandRunner
	opener   port.RepoOpener
	plans    []Plan
	log      port.Logger
}

// New builds the scan service.
func New(detectSvc *detect.Service, importer *importscan.Service, runner port.CommandRunner, opener port.RepoOpener, plans []Plan, log port.Logger) *Service {
	return &Service{detect: detectSvc, importer: importer, runner: runner, opener: opener, plans: plans, log: log}
}

// Run detects technologies, runs every available planned scanner over the repo,
// ingests their reports and returns the merged analysis plus per-tool outcomes.
// only optionally restricts execution to a subset of tool names.
func (s *Service) Run(ctx context.Context, fsys port.FileSystem, only []string) (model.Analysis, []Outcome, error) {
	a, err := s.detect.Run(ctx, fsys)
	if err != nil {
		return a, nil, err
	}

	tmp, err := os.MkdirTemp("", "devsec-scan-*")
	if err != nil {
		return a, nil, err
	}
	defer os.RemoveAll(tmp)

	repoPath := fsys.Root()
	var outcomes []Outcome
	for _, p := range s.plans {
		if len(only) > 0 && !contains(only, p.Tool) {
			continue
		}
		outcomes = append(outcomes, s.runOne(ctx, p, repoPath, tmp))
	}

	// Ingest whatever reports were produced from the temp directory.
	reportFS, err := s.opener.OpenDir(tmp)
	if err != nil {
		return a, outcomes, err
	}
	a = importscan.Merge(a, s.importer.Collect(ctx, reportFS))
	return a, outcomes, nil
}

func (s *Service) runOne(ctx context.Context, p Plan, repoPath, tmp string) Outcome {
	binPath, ok := s.runner.Look(p.Bin)
	if !ok {
		s.log.Debugf("scanner %s not installed; skipping", p.Tool)
		return Outcome{Tool: p.Tool, Status: "skipped", Detail: "not installed"}
	}
	reportPath := filepath.Join(tmp, p.ReportName)

	cmd := port.Command{Bin: binPath, Args: p.Args(repoPath, reportPath), Dir: repoPath}
	if p.StdoutToFile {
		f, err := os.Create(reportPath)
		if err != nil {
			return Outcome{Tool: p.Tool, Status: "error", Detail: err.Error()}
		}
		defer f.Close()
		cmd.Stdout = f
	}

	res, err := s.runner.Run(ctx, cmd)
	if err != nil {
		s.log.Warnf("scanner %s failed: %v", p.Tool, err)
		return Outcome{Tool: p.Tool, Status: "error", Detail: err.Error()}
	}
	return Outcome{Tool: p.Tool, Status: "ran", ExitCode: res.ExitCode}
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
