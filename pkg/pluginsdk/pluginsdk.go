// Package pluginsdk is the stable, public contract that third-party plugins
// implement. It re-exports the domain types and interfaces needed to build a
// plugin without importing devsec internals, so the core stays free to evolve.
//
// In v0.1 plugins are compiled in via the DI container. The external-process
// protocol (stdio/gRPC, manifest-described) is planned for v0.5 — see ROADMAP.
package pluginsdk

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/knowledge"
	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
	"github.com/nandy23/devsecops-cli/internal/domain/rule"
)

// APIVersion is the plugin contract version used for capability negotiation.
const APIVersion = "devsec.io/v1alpha1"

// Re-exported stable domain types.
type (
	Technology     = model.Technology
	Analysis       = model.Analysis
	Recommendation = model.Recommendation
	Tool           = knowledge.Tool
	Rule           = rule.Rule
	PipelineSpec   = pipeline.Spec
)

// DetectorPlugin contributes technology detection.
type DetectorPlugin interface {
	Name() string
	Detect(ctx context.Context, files []string, read func(path string) ([]byte, error)) ([]Technology, error)
}

// RuleProviderPlugin contributes additional recommendation rules.
type RuleProviderPlugin interface {
	Name() string
	Rules(ctx context.Context) ([]Rule, error)
}

// ReporterPlugin contributes a new report output format.
type ReporterPlugin interface {
	Format() string
	Render(ctx context.Context, a Analysis) ([]byte, error)
}

// ConnectorPlugin integrates an enterprise platform (SonarQube, Harbor, Vault…).
// Connectors collect findings that are merged into the unified report.
type ConnectorPlugin interface {
	Name() string
	Connect(ctx context.Context, config map[string]string) error
	Validate(ctx context.Context) error
	Collect(ctx context.Context) ([]Recommendation, error)
	Disconnect(ctx context.Context) error
}

// GeneratorPlugin renders a pipeline spec to a new CI platform.
type GeneratorPlugin interface {
	Platform() string
	Generate(ctx context.Context, spec PipelineSpec) (map[string]string, error)
}

// KnowledgeProviderPlugin contributes tool knowledge entries for `explain`.
type KnowledgeProviderPlugin interface {
	Tools(ctx context.Context) ([]Tool, error)
}
