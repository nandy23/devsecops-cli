// Package port declares the interfaces (ports) that the application layer
// depends on. Infrastructure adapters and plugins implement them; the domain
// never imports concrete implementations. This is the seam for DI and testing.
package port

import (
	"context"
	"io"
	"io/fs"

	"github.com/nandy23/devsecops-cli/internal/domain/knowledge"
	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
	"github.com/nandy23/devsecops-cli/internal/domain/rule"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

// FileSystem abstracts repository access so detectors are testable.
type FileSystem interface {
	fs.FS
	Root() string
	// List returns repo-relative file paths, honoring ignore globs.
	List() ([]string, error)
}

// Detector inspects a repository and emits technologies. Implementations must
// be read-only and side-effect free.
type Detector interface {
	Name() string
	Priority() int
	Detect(ctx context.Context, fsys FileSystem) ([]model.Technology, error)
}

// RuleSource provides rules from a backing store (embedded, local, remote).
type RuleSource interface {
	Name() string
	Load(ctx context.Context) ([]rule.Rule, error)
}

// RuleEngine evaluates rules against an analysis to produce recommendations.
type RuleEngine interface {
	Evaluate(ctx context.Context, a model.Analysis) ([]model.Recommendation, error)
}

// PipelineAuditor audits existing CI/CD pipelines (doctor).
type PipelineAuditor interface {
	Platform() string
	CanAudit(fsys FileSystem) bool
	Audit(ctx context.Context, fsys FileSystem) ([]model.PipelineAudit, error)
}

// PipelineGenerator renders a pipeline spec to a concrete platform (init).
type PipelineGenerator interface {
	Platform() string
	Generate(ctx context.Context, spec pipeline.Spec) (map[string]string, error) // path -> content
}

// Connector integrates an enterprise platform (SonarQube, Harbor, Vault…). It
// follows the lifecycle Connect → Validate → Collect → Disconnect. Collected
// results merge into the unified analysis.
type Connector interface {
	Name() string
	Connect(ctx context.Context) error
	Validate(ctx context.Context) error
	Collect(ctx context.Context) (model.ConnectorResult, error)
	Disconnect(ctx context.Context) error
}

// ResultImporter ingests the output of a security scanner that already ran
// (gitleaks, semgrep, snyk…). devsec orchestrates scanners but never runs them;
// importers parse their report files and merge findings into the analysis.
type ResultImporter interface {
	Tool() string
	Import(ctx context.Context, fsys FileSystem) ([]model.ScanResult, error)
}

// Scorer computes a maturity score from an analysis.
type Scorer interface {
	Score(ctx context.Context, a model.Analysis) (scoring.Report, error)
}

// KnowledgeBase answers `explain` queries.
type KnowledgeBase interface {
	Lookup(ctx context.Context, tool string) (knowledge.Tool, error)
	List(ctx context.Context) ([]knowledge.Tool, error)
}

// Reporter renders an analysis + score to an output format.
type Reporter interface {
	Format() string
	Render(ctx context.Context, a model.Analysis, s scoring.Report, w io.Writer) error
}

// GraphRenderer renders a pipeline spec to a Mermaid diagram.
type GraphRenderer interface {
	Render(ctx context.Context, spec pipeline.Spec) (string, error)
}

// Logger is the injected logging seam.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Command describes an external process to execute. devsec runs tools that are
// already installed (it never bundles binaries); Stdout/Stderr let callers
// capture a report or stream a passthrough.
type Command struct {
	Bin    string
	Args   []string
	Dir    string
	Env    []string // extra KEY=VAL entries appended to the inherited environment
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// CommandResult is the outcome of running a Command. A non-zero ExitCode is not
// an error: scanners commonly exit non-zero when they find issues.
type CommandResult struct {
	ExitCode int
}

// CommandRunner executes external tools. It is the seam that keeps `scan` and
// `tool` testable without spawning real processes.
type CommandRunner interface {
	// Look resolves a binary on PATH, reporting whether it is available.
	Look(bin string) (string, bool)
	Run(ctx context.Context, c Command) (CommandResult, error)
}

// RepoOpener builds a FileSystem view over a directory (used to ingest the
// reports produced by `scan` from a temporary directory).
type RepoOpener interface {
	OpenDir(path string) (FileSystem, error)
}

// FixAction is a single proposed, idempotent remediation: the full new content
// for a file plus a human description. devsec previews these by default and only
// writes them with --apply.
type FixAction struct {
	File        string // repo-relative path
	Description string
	NewContent  string
}

// Fixer proposes safe, idempotent remediations for a repository. Plan must not
// mutate anything; writing is the caller's responsibility.
type Fixer interface {
	Name() string
	Plan(ctx context.Context, fsys FileSystem, a model.Analysis) ([]FixAction, error)
}
