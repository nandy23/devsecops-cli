// Package di is the composition root. It wires concrete infrastructure
// implementations into the application services. This is the ONLY package that
// is allowed to know about every other package; everything else depends on
// interfaces. Plugins would register here in future versions.
package di

import (
	assets "github.com/nandy23/devsecops-cli"
	appconnect "github.com/nandy23/devsecops-cli/internal/app/connect"
	appdetect "github.com/nandy23/devsecops-cli/internal/app/detect"
	appdoctor "github.com/nandy23/devsecops-cli/internal/app/doctor"
	appexplain "github.com/nandy23/devsecops-cli/internal/app/explain"
	appfix "github.com/nandy23/devsecops-cli/internal/app/fix"
	appgenerate "github.com/nandy23/devsecops-cli/internal/app/generate"
	appgraph "github.com/nandy23/devsecops-cli/internal/app/graph"
	appimport "github.com/nandy23/devsecops-cli/internal/app/importscan"
	appreport "github.com/nandy23/devsecops-cli/internal/app/report"
	appscan "github.com/nandy23/devsecops-cli/internal/app/scan"
	appscore "github.com/nandy23/devsecops-cli/internal/app/score"
	apptool "github.com/nandy23/devsecops-cli/internal/app/tool"
	"github.com/nandy23/devsecops-cli/internal/cli/output"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/infra/config"
	"github.com/nandy23/devsecops-cli/internal/infra/connector"
	"github.com/nandy23/devsecops-cli/internal/infra/detector"
	infraexec "github.com/nandy23/devsecops-cli/internal/infra/exec"
	"github.com/nandy23/devsecops-cli/internal/infra/fixer"
	"github.com/nandy23/devsecops-cli/internal/infra/fsys"
	"github.com/nandy23/devsecops-cli/internal/infra/generator"
	infraknow "github.com/nandy23/devsecops-cli/internal/infra/knowledge"
	"github.com/nandy23/devsecops-cli/internal/infra/mermaid"
	infrapipeline "github.com/nandy23/devsecops-cli/internal/infra/pipeline"
	"github.com/nandy23/devsecops-cli/internal/infra/reporter"
	"github.com/nandy23/devsecops-cli/internal/infra/ruleengine"
	"github.com/nandy23/devsecops-cli/internal/infra/scanner"
)

// Container holds the fully wired application services.
type Container struct {
	Config  config.Config
	Version string

	Detect   *appdetect.Service
	Doctor   *appdoctor.Service
	Generate *appgenerate.Service
	Score    *appscore.Service
	Report   *appreport.Service
	Graph    *appgraph.Service
	Explain  *appexplain.Service
	Connect  *appconnect.Service
	Import   *appimport.Service
	Scan     *appscan.Service
	Tool     *apptool.Service
	Fix      *appfix.Service
}

// Build assembles the container from config.
func Build(cfg config.Config, version string, log port.Logger) (*Container, error) {
	// Rule engine: embedded defaults + optional local override dir.
	ruleSources := []port.RuleSource{
		ruleengine.EmbeddedSource{FS: assets.Rules, Dir: "rules"},
	}
	for _, src := range cfg.Rules.Sources {
		if src != "embedded" {
			ruleSources = append(ruleSources, ruleengine.DirSource{Path: src})
		}
	}
	engine := ruleengine.New(ruleSources, cfg.Rules.Disabled, cfg.Profile)

	// Detectors.
	detectors := detector.Builtin()
	detectSvc := appdetect.New(detectors, engine, version, log)

	// Knowledge base.
	kb, err := infraknow.Load(assets.Knowledge, "knowledge")
	if err != nil {
		return nil, err
	}

	// Scorer + reporters.
	scorer := reporter.NewScorer(cfg.Scoring.Weights)
	reporters := []port.Reporter{reporter.JSON{}, reporter.Markdown{}, reporter.HTML{}, reporter.SARIF{}}

	// Enterprise connectors (built only when enabled in config).
	connectSvc := appconnect.New(connector.Builtin(cfg), log)

	// Scanner-result importers (gitleaks, semgrep, snyk, SARIF).
	importSvc := appimport.New(scanner.Builtin(), log)

	// Tool runner: runs locally-installed binaries (never bundled).
	runner := infraexec.New()
	scanSvc := appscan.New(detectSvc, importSvc, runner, fsys.Opener{}, appscan.DefaultPlans(), log)
	toolSvc := apptool.New(runner, toolSpecs(cfg))

	c := &Container{
		Config:   cfg,
		Version:  version,
		Detect:   detectSvc,
		Doctor:   appdoctor.New(detectSvc, infrapipeline.Builtin(), importSvc, connectSvc),
		Generate: appgenerate.New(generator.Builtin(assets.Templates)),
		Score:    appscore.New(scorer),
		Report:   appreport.New(reporters, scorer),
		Graph:    appgraph.New(mermaid.Renderer{}),
		Explain:  appexplain.New(kb),
		Connect:  connectSvc,
		Import:   importSvc,
		Scan:     scanSvc,
		Tool:     toolSvc,
		Fix:      appfix.New(detectSvc, fixer.Builtin()),
	}
	return c, nil
}

// OpenRepo builds a filesystem view of a repository path honoring ignore rules.
func (c *Container) OpenRepo(path string) (port.FileSystem, error) {
	return fsys.New(path, c.Config.Detect.Ignore)
}

// toolSpecs builds the allow-list for `devsec tool`, injecting configuration
// (Vault address/token, SonarQube host/token) so wrapped CLIs are pre-wired.
func toolSpecs(cfg config.Config) map[string]apptool.Spec {
	specs := map[string]apptool.Spec{
		// Scanners and signing/SBOM tools: plain passthrough.
		"gitleaks":         {Bin: "gitleaks"},
		"semgrep":          {Bin: "semgrep"},
		"snyk":             {Bin: "snyk"},
		"trivy":            {Bin: "trivy"},
		"checkov":          {Bin: "checkov"},
		"terrascan":        {Bin: "terrascan"},
		"tfsec":            {Bin: "tfsec"},
		"hadolint":         {Bin: "hadolint"},
		"grype":            {Bin: "grype"},
		"dependency-check": {Bin: "dependency-check"},
		"pip-audit":        {Bin: "pip-audit"},
		"syft":             {Bin: "syft"},
		"cosign":           {Bin: "cosign"},
		"kubescape":        {Bin: "kubescape"},
		"trufflehog":       {Bin: "trufflehog"},
	}

	// Vault: inject address and token from the connector config.
	vaultEnv := []string{}
	if u := cfg.Connectors.Vault.URL; u != "" {
		vaultEnv = append(vaultEnv, "VAULT_ADDR="+u)
	}
	if t := config.ResolveSecret(cfg.Connectors.Vault.Token); t != "" {
		vaultEnv = append(vaultEnv, "VAULT_TOKEN="+t)
	}
	specs["vault"] = apptool.Spec{Bin: "vault", Env: vaultEnv}

	// sonar-scanner: inject host URL and token from the connector config.
	sonarEnv := []string{}
	if u := cfg.Connectors.SonarQube.URL; u != "" {
		sonarEnv = append(sonarEnv, "SONAR_HOST_URL="+u)
	}
	if t := config.ResolveSecret(cfg.Connectors.SonarQube.Token); t != "" {
		sonarEnv = append(sonarEnv, "SONAR_TOKEN="+t)
	}
	specs["sonar-scanner"] = apptool.Spec{Bin: "sonar-scanner", Env: sonarEnv}

	return specs
}

// compile-time check that output.Logger satisfies port.Logger.
var _ port.Logger = output.Logger{}
