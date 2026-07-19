// Package model holds the core domain types of devsec.
//
// These types are pure values with no I/O dependencies. Every command in the
// CLI operates over a single immutable Analysis aggregate produced by the
// detector engine.
package model

import "time"

// TechKind classifies a detected technology.
type TechKind string

const (
	KindLanguage     TechKind = "language"
	KindFramework    TechKind = "framework"
	KindContainer    TechKind = "container"
	KindOrchestrator TechKind = "orchestrator"
	KindIaC          TechKind = "iac"
	KindCloud        TechKind = "cloud"
	KindCIPlatform   TechKind = "ci_platform"
	KindPackageMgr   TechKind = "package_manager"
	KindSecurityTool TechKind = "security_tool"
	KindLinter       TechKind = "linter"
)

// SecurityCategory is the lingua franca that links detectors, rules, scoring,
// the pipeline generator and reporting. Add a category once and it threads
// through every subsystem.
type SecurityCategory string

const (
	CatSAST           SecurityCategory = "sast"
	CatDAST           SecurityCategory = "dast"
	CatRecon          SecurityCategory = "recon"
	CatSecretScan     SecurityCategory = "secret_scan"
	CatDependencyScan SecurityCategory = "dependency_scan"
	CatIaCScan        SecurityCategory = "iac_scan"
	CatSBOM           SecurityCategory = "sbom"
	CatContainerScan  SecurityCategory = "container_scan"
	CatSigning        SecurityCategory = "signing"
	CatPolicy         SecurityCategory = "policy"
	CatRuntime        SecurityCategory = "runtime"
)

// AllCategories returns every security category in canonical order.
func AllCategories() []SecurityCategory {
	return []SecurityCategory{
		CatSAST, CatDAST, CatRecon, CatSecretScan, CatDependencyScan, CatIaCScan, CatSBOM,
		CatContainerScan, CatSigning, CatPolicy, CatRuntime,
	}
}

// Severity ranks recommendations and findings.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// CoverageState describes how well a security category is covered.
type CoverageState string

const (
	StatePresent          CoverageState = "present"
	StatePartiallyPresent CoverageState = "partial"
	StateMissing          CoverageState = "missing"
	StateNotApplicable    CoverageState = "n/a"
)

// Evidence is a concrete signal that justified a detection.
type Evidence struct {
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	Snippet string `json:"snippet,omitempty"`
}

// Technology is a single detected technology with confidence and evidence.
type Technology struct {
	Kind       TechKind   `json:"kind"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Confidence float64    `json:"confidence"` // 0..1
	Evidence   []Evidence `json:"evidence,omitempty"`
}

// Repository is the analyzed target.
type Repository struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// Recommendation is a single actionable suggestion produced by the rule engine.
type Recommendation struct {
	ID         string           `json:"id"`
	Category   SecurityCategory `json:"category"`
	Tool       string           `json:"tool"`
	Severity   Severity         `json:"severity"`
	Stage      string           `json:"stage,omitempty"`
	Rationale  string           `json:"rationale"`
	Sources    []string         `json:"sources,omitempty"` // rule IDs for traceability
	Confidence float64          `json:"confidence"`
}

// Finding is a problem discovered while auditing an existing pipeline.
type Finding struct {
	PipelineRef string           `json:"pipeline_ref"`
	Category    SecurityCategory `json:"category"`
	Severity    Severity         `json:"severity"`
	Message     string           `json:"message"`
	Location    string           `json:"location,omitempty"`
	Suggestion  string           `json:"suggestion,omitempty"`
}

// PipelineAudit is the result of auditing one CI/CD pipeline file.
type PipelineAudit struct {
	Platform          string             `json:"platform"`
	Path              string             `json:"path"`
	DetectedStages    []string           `json:"detected_stages"`
	Findings          []Finding          `json:"findings"`
	MissingCategories []SecurityCategory `json:"missing_categories"`
}

// ConnectorResult is data collected from an enterprise platform (SonarQube,
// Harbor, Vault…) that is merged into the unified analysis.
type ConnectorResult struct {
	Connector string            `json:"connector"`
	Project   string            `json:"project,omitempty"`
	Status    string            `json:"status,omitempty"`  // e.g. quality gate OK/ERROR
	Metrics   map[string]string `json:"metrics,omitempty"` // metric key -> value
	Findings  []Finding         `json:"findings,omitempty"`
	// Covers lists the security categories this connector proves are handled by
	// an external platform, so scoring can credit them.
	Covers []SecurityCategory `json:"covers,omitempty"`
}

// ScanResult is the parsed output of a security scanner (gitleaks, semgrep,
// snyk…) that already ran in the repo or CI. devsec ingests these results — it
// never runs the scanners itself. A successfully parsed report proves the scan
// runs, so it credits its category even with zero findings.
type ScanResult struct {
	Tool     string             `json:"tool"`
	Source   string             `json:"source"` // report file path
	Findings []Finding          `json:"findings,omitempty"`
	Covers   []SecurityCategory `json:"covers,omitempty"`
}

// Analysis is the central immutable aggregate. Detect produces it; every other
// command transforms it.
type Analysis struct {
	Repository      Repository                    `json:"repository"`
	Technologies    []Technology                  `json:"technologies"`
	Pipelines       []PipelineAudit               `json:"pipelines,omitempty"`
	Connectors      []ConnectorResult             `json:"connectors,omitempty"`
	Scans           []ScanResult                  `json:"scans,omitempty"`
	Recommendations []Recommendation              `json:"recommendations,omitempty"`
	Coverage        map[SecurityCategory]Coverage `json:"coverage,omitempty"`
	GeneratedAt     time.Time                     `json:"generated_at"`
	ToolVersion     string                        `json:"tool_version"`
}

// Coverage records the state of a single security category for the repo.
type Coverage struct {
	Category SecurityCategory `json:"category"`
	State    CoverageState    `json:"state"`
	Reason   string           `json:"reason,omitempty"`
}

// HasKind reports whether the analysis contains a technology of the given kind.
func (a Analysis) HasKind(k TechKind) bool {
	for _, t := range a.Technologies {
		if t.Kind == k {
			return true
		}
	}
	return false
}

// HasTech reports whether a technology with the given kind and name exists.
func (a Analysis) HasTech(k TechKind, name string) bool {
	for _, t := range a.Technologies {
		if t.Kind == k && eqFold(t.Name, name) {
			return true
		}
	}
	return false
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
