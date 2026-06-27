// Package config loads layered configuration: embedded defaults < config file
// (YAML/JSON) < environment variables. Flags are applied by the CLI layer.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// Config is the strongly-typed runtime configuration.
type Config struct {
	Profile    string           `yaml:"profile" json:"profile"`
	Detect     DetectConfig     `yaml:"detect" json:"detect"`
	Rules      RulesConfig      `yaml:"rules" json:"rules"`
	Scoring    ScoringConfig    `yaml:"scoring" json:"scoring"`
	Generate   GenerateConfig   `yaml:"generate" json:"generate"`
	Report     ReportConfig     `yaml:"report" json:"report"`
	Connectors ConnectorsConfig `yaml:"connectors" json:"connectors"`
}

// ConnectorsConfig groups enterprise connector settings.
type ConnectorsConfig struct {
	SonarQube       SonarQubeConfig       `yaml:"sonarqube" json:"sonarqube"`
	Harbor          HarborConfig          `yaml:"harbor" json:"harbor"`
	Nexus           NexusConfig           `yaml:"nexus" json:"nexus"`
	Vault           VaultConnConfig       `yaml:"vault" json:"vault"`
	DependencyTrack DependencyTrackConfig `yaml:"dependency_track" json:"dependency_track"`
	Xray            XrayConnConfig        `yaml:"xray" json:"xray"`
	DefectDojo      DefectDojoConnConfig  `yaml:"defectdojo" json:"defectdojo"`
	Kyverno         KyvernoConnConfig     `yaml:"kyverno" json:"kyverno"`
	Falco           FalcoConnConfig       `yaml:"falco" json:"falco"`
	Rekor           RekorConnConfig       `yaml:"rekor" json:"rekor"`
	Jenkins         JenkinsConnConfig     `yaml:"jenkins" json:"jenkins"`
}

// FalcoConnConfig configures the Falco runtime connector.
type FalcoConnConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	URL       string `yaml:"url" json:"url"`
	Token     string `yaml:"token" json:"token"`
	Namespace string `yaml:"namespace" json:"namespace"`
	DaemonSet string `yaml:"daemonset" json:"daemonset"`
	Insecure  bool   `yaml:"insecure" json:"insecure"`
}

// RekorConnConfig configures the Sigstore Rekor connector.
type RekorConnConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Email   string `yaml:"email" json:"email"`
	Hash    string `yaml:"hash" json:"hash"`
}

// JenkinsConnConfig configures the Jenkins connector.
type JenkinsConnConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	URL      string `yaml:"url" json:"url"`
	Job      string `yaml:"job" json:"job"`
	Username string `yaml:"username" json:"username"`
	Token    string `yaml:"token" json:"token"`
}

// DependencyTrackConfig configures the OWASP Dependency-Track connector.
type DependencyTrackConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Project string `yaml:"project" json:"project"`
	Version string `yaml:"version" json:"version"`
	APIKey  string `yaml:"api_key" json:"api_key"`
}

// XrayConnConfig configures the JFrog Xray connector.
type XrayConnConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Watch   string `yaml:"watch" json:"watch"`
	Token   string `yaml:"token" json:"token"`
}

// DefectDojoConnConfig configures the DefectDojo connector.
type DefectDojoConnConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Product string `yaml:"product" json:"product"`
	Token   string `yaml:"token" json:"token"`
}

// KyvernoConnConfig configures the Kubernetes/Kyverno PolicyReport connector.
type KyvernoConnConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	URL       string `yaml:"url" json:"url"`
	Token     string `yaml:"token" json:"token"`
	Namespace string `yaml:"namespace" json:"namespace"`
	Insecure  bool   `yaml:"insecure" json:"insecure"`
}

// VaultConnConfig configures the HashiCorp Vault connector. Token should be
// provided via an environment variable reference (e.g. "env:VAULT_TOKEN").
type VaultConnConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Token   string `yaml:"token" json:"token"`
}

// NexusConfig configures the Nexus IQ (Lifecycle) connector. Secret should be
// provided via an environment variable reference (e.g. "env:NEXUS_SECRET").
type NexusConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	URL         string `yaml:"url" json:"url"`
	Application string `yaml:"application" json:"application"`
	Username    string `yaml:"username" json:"username"`
	Secret      string `yaml:"secret" json:"secret"`
}

// HarborConfig configures the Harbor connector. Secret should be provided via
// an environment variable reference (e.g. "env:HARBOR_SECRET").
type HarborConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	URL      string `yaml:"url" json:"url"`
	Project  string `yaml:"project" json:"project"`
	Username string `yaml:"username" json:"username"`
	Secret   string `yaml:"secret" json:"secret"`
}

// SonarQubeConfig configures the SonarQube connector. Token should be provided
// via an environment variable reference (e.g. "env:SONAR_TOKEN") so secrets are
// never committed.
type SonarQubeConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Project string `yaml:"project" json:"project"`
	Token   string `yaml:"token" json:"token"`
}

type DetectConfig struct {
	Ignore []string `yaml:"ignore" json:"ignore"`
}

type RulesConfig struct {
	Sources  []string `yaml:"sources" json:"sources"`
	Disabled []string `yaml:"disabled" json:"disabled"`
}

type ScoringConfig struct {
	Weights map[model.SecurityCategory]int `yaml:"weights" json:"weights"`
}

type GenerateConfig struct {
	Platform string `yaml:"platform" json:"platform"`
}

type ReportConfig struct {
	Format string `yaml:"format" json:"format"`
	Output string `yaml:"output" json:"output"`
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Profile:  "balanced",
		Rules:    RulesConfig{Sources: []string{"embedded", "./rules"}},
		Generate: GenerateConfig{Platform: "github"},
		Report:   ReportConfig{Format: "markdown"},
	}
}

// Load reads defaults, then an optional config file, then env overrides.
// path may be empty, in which case standard locations are probed.
func Load(path string) (Config, error) {
	cfg := Default()

	if path == "" {
		path = discover()
	}
	if path != "" {
		if err := loadFile(path, &cfg); err != nil {
			return cfg, err
		}
	}
	applyEnv(&cfg)
	return cfg, nil
}

func discover() string {
	for _, name := range []string{"devsec.yaml", "devsec.yml", "devsec.json", ".devsec.yaml"} {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
}

func loadFile(path string, cfg *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		return json.Unmarshal(b, cfg)
	}
	return yaml.Unmarshal(b, cfg)
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("DEVSEC_PROFILE"); v != "" {
		cfg.Profile = v
	}
	if v := os.Getenv("DEVSEC_GENERATE_PLATFORM"); v != "" {
		cfg.Generate.Platform = v
	}
	if v := os.Getenv("DEVSEC_REPORT_FORMAT"); v != "" {
		cfg.Report.Format = v
	}
	if v := os.Getenv("DEVSEC_REPORT_OUTPUT"); v != "" {
		cfg.Report.Output = v
	}
	if v := os.Getenv("DEVSEC_SONAR_URL"); v != "" {
		cfg.Connectors.SonarQube.URL = v
		cfg.Connectors.SonarQube.Enabled = true
	}
	if v := os.Getenv("DEVSEC_SONAR_PROJECT"); v != "" {
		cfg.Connectors.SonarQube.Project = v
	}
	if v := os.Getenv("DEVSEC_SONAR_TOKEN"); v != "" {
		cfg.Connectors.SonarQube.Token = v
	}
	if v := os.Getenv("DEVSEC_HARBOR_URL"); v != "" {
		cfg.Connectors.Harbor.URL = v
		cfg.Connectors.Harbor.Enabled = true
	}
	if v := os.Getenv("DEVSEC_HARBOR_PROJECT"); v != "" {
		cfg.Connectors.Harbor.Project = v
	}
	if v := os.Getenv("DEVSEC_HARBOR_USERNAME"); v != "" {
		cfg.Connectors.Harbor.Username = v
	}
	if v := os.Getenv("DEVSEC_HARBOR_SECRET"); v != "" {
		cfg.Connectors.Harbor.Secret = v
	}
	if v := os.Getenv("DEVSEC_NEXUS_URL"); v != "" {
		cfg.Connectors.Nexus.URL = v
		cfg.Connectors.Nexus.Enabled = true
	}
	if v := os.Getenv("DEVSEC_NEXUS_APP"); v != "" {
		cfg.Connectors.Nexus.Application = v
	}
	if v := os.Getenv("DEVSEC_NEXUS_USERNAME"); v != "" {
		cfg.Connectors.Nexus.Username = v
	}
	if v := os.Getenv("DEVSEC_NEXUS_SECRET"); v != "" {
		cfg.Connectors.Nexus.Secret = v
	}
	if v := os.Getenv("DEVSEC_VAULT_URL"); v != "" {
		cfg.Connectors.Vault.URL = v
		cfg.Connectors.Vault.Enabled = true
	}
	if v := os.Getenv("DEVSEC_VAULT_TOKEN"); v != "" {
		cfg.Connectors.Vault.Token = v
	}
	if v := os.Getenv("DEVSEC_DTRACK_URL"); v != "" {
		cfg.Connectors.DependencyTrack.URL = v
		cfg.Connectors.DependencyTrack.Enabled = true
	}
	if v := os.Getenv("DEVSEC_DTRACK_PROJECT"); v != "" {
		cfg.Connectors.DependencyTrack.Project = v
	}
	if v := os.Getenv("DEVSEC_DTRACK_APIKEY"); v != "" {
		cfg.Connectors.DependencyTrack.APIKey = v
	}
	if v := os.Getenv("DEVSEC_XRAY_URL"); v != "" {
		cfg.Connectors.Xray.URL = v
		cfg.Connectors.Xray.Enabled = true
	}
	if v := os.Getenv("DEVSEC_XRAY_WATCH"); v != "" {
		cfg.Connectors.Xray.Watch = v
	}
	if v := os.Getenv("DEVSEC_XRAY_TOKEN"); v != "" {
		cfg.Connectors.Xray.Token = v
	}
	if v := os.Getenv("DEVSEC_DEFECTDOJO_URL"); v != "" {
		cfg.Connectors.DefectDojo.URL = v
		cfg.Connectors.DefectDojo.Enabled = true
	}
	if v := os.Getenv("DEVSEC_DEFECTDOJO_PRODUCT"); v != "" {
		cfg.Connectors.DefectDojo.Product = v
	}
	if v := os.Getenv("DEVSEC_DEFECTDOJO_TOKEN"); v != "" {
		cfg.Connectors.DefectDojo.Token = v
	}
	if v := os.Getenv("DEVSEC_KYVERNO_URL"); v != "" {
		cfg.Connectors.Kyverno.URL = v
		cfg.Connectors.Kyverno.Enabled = true
	}
	if v := os.Getenv("DEVSEC_KYVERNO_TOKEN"); v != "" {
		cfg.Connectors.Kyverno.Token = v
	}
	if v := os.Getenv("DEVSEC_KYVERNO_NAMESPACE"); v != "" {
		cfg.Connectors.Kyverno.Namespace = v
	}
	if v := os.Getenv("DEVSEC_FALCO_URL"); v != "" {
		cfg.Connectors.Falco.URL = v
		cfg.Connectors.Falco.Enabled = true
	}
	if v := os.Getenv("DEVSEC_FALCO_TOKEN"); v != "" {
		cfg.Connectors.Falco.Token = v
	}
	if v := os.Getenv("DEVSEC_FALCO_NAMESPACE"); v != "" {
		cfg.Connectors.Falco.Namespace = v
	}
	if v := os.Getenv("DEVSEC_REKOR_URL"); v != "" {
		cfg.Connectors.Rekor.URL = v
		cfg.Connectors.Rekor.Enabled = true
	}
	if v := os.Getenv("DEVSEC_REKOR_EMAIL"); v != "" {
		cfg.Connectors.Rekor.Email = v
	}
	if v := os.Getenv("DEVSEC_REKOR_HASH"); v != "" {
		cfg.Connectors.Rekor.Hash = v
	}
	if v := os.Getenv("DEVSEC_JENKINS_URL"); v != "" {
		cfg.Connectors.Jenkins.URL = v
		cfg.Connectors.Jenkins.Enabled = true
	}
	if v := os.Getenv("DEVSEC_JENKINS_JOB"); v != "" {
		cfg.Connectors.Jenkins.Job = v
	}
	if v := os.Getenv("DEVSEC_JENKINS_USERNAME"); v != "" {
		cfg.Connectors.Jenkins.Username = v
	}
	if v := os.Getenv("DEVSEC_JENKINS_TOKEN"); v != "" {
		cfg.Connectors.Jenkins.Token = v
	}
}

// ResolveSecret expands a secret reference. "env:NAME" reads the NAME
// environment variable; a bare value is returned as-is (discouraged). This
// keeps tokens out of committed config files.
func ResolveSecret(ref string) string {
	if strings.HasPrefix(ref, "env:") {
		return os.Getenv(strings.TrimPrefix(ref, "env:"))
	}
	if strings.HasPrefix(ref, "${") && strings.HasSuffix(ref, "}") {
		return os.Getenv(ref[2 : len(ref)-1])
	}
	return ref
}
