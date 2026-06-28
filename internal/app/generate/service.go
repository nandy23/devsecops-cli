// Package generate builds a platform-agnostic pipeline spec from an analysis
// and renders it to a chosen CI platform.
package generate

import (
	"context"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service produces pipeline files.
type Service struct {
	generators map[string]port.PipelineGenerator
}

// New builds the generate service indexed by platform name.
func New(gens []port.PipelineGenerator) *Service {
	m := make(map[string]port.PipelineGenerator, len(gens))
	for _, g := range gens {
		m[g.Platform()] = g
	}
	return &Service{generators: m}
}

// Platforms lists supported platform names.
func (s *Service) Platforms() []string {
	out := make([]string, 0, len(s.generators))
	for p := range s.generators {
		out = append(out, p)
	}
	return out
}

// BuildSpec turns an analysis into a pipeline IR, including only stages that
// apply to the detected technologies and recommendations.
func BuildSpec(a model.Analysis, platform string) pipeline.Spec {
	// Map recommended tools onto their pipeline stages.
	stageTools := map[pipeline.StageKind][]string{}
	for _, r := range a.Recommendations {
		k := stageKind(r.Stage)
		stageTools[k] = append(stageTools[k], r.Tool)
	}

	// Always offer SonarQube (sonar-scanner CLI) as a SAST step alongside the
	// recommended SAST tool, since it is the most common enterprise SAST.
	if !containsTool(stageTools[pipeline.StageSAST], "sonarqube") {
		stageTools[pipeline.StageSAST] = append(stageTools[pipeline.StageSAST], "sonarqube")
	}

	spec := pipeline.Spec{Name: "devsec-secure-pipeline", Platform: platform, Lang: primaryLang(a)}
	var prev string
	for _, kind := range pipeline.CanonicalOrder() {
		tools := stageTools[kind]
		// Always include structural stages; include security stages only when
		// a tool was recommended for them.
		if !structural(kind) && len(tools) == 0 {
			continue
		}
		st := pipeline.Stage{
			ID:    string(kind),
			Name:  stageName(kind),
			Kind:  kind,
			Tools: tools,
		}
		if prev != "" {
			st.DependsOn = []string{prev}
		}
		spec.Stages = append(spec.Stages, st)
		prev = st.ID
	}
	return spec
}

// Generate renders the spec for the requested platform.
func (s *Service) Generate(ctx context.Context, a model.Analysis, platform string) (map[string]string, pipeline.Spec, error) {
	g, ok := s.generators[platform]
	if !ok {
		return nil, pipeline.Spec{}, fmt.Errorf("unsupported platform %q (supported: %v)", platform, s.Platforms())
	}
	spec := BuildSpec(a, platform)
	files, err := g.Generate(ctx, spec)
	return files, spec, err
}

// primaryLang returns a normalized language key for pipeline generation, picking
// the highest-confidence detected language.
func primaryLang(a model.Analysis) string {
	best := ""
	bestConf := 0.0
	for _, t := range a.Technologies {
		if t.Kind != model.KindLanguage || t.Confidence < bestConf {
			continue
		}
		switch t.Name {
		case "NodeJS":
			best, bestConf = "nodejs", t.Confidence
		case "Go":
			best, bestConf = "go", t.Confidence
		case "Python":
			best, bestConf = "python", t.Confidence
		case "Java":
			best, bestConf = "java", t.Confidence
		}
	}
	return best
}

func containsTool(tools []string, name string) bool {
	for _, t := range tools {
		if t == name {
			return true
		}
	}
	return false
}

func structural(k pipeline.StageKind) bool {
	switch k {
	case pipeline.StageCheckout, pipeline.StageDependencies, pipeline.StageUnitTest,
		pipeline.StageBuild, pipeline.StageArtifact, pipeline.StageDeploy:
		return true
	default:
		return false
	}
}

func stageKind(s string) pipeline.StageKind {
	switch s {
	case "sast":
		return pipeline.StageSAST
	case "secret_scan":
		return pipeline.StageSecretScan
	case "iac_scan":
		return pipeline.StageIaCScan
	case "container_scan":
		return pipeline.StageContainerScan
	case "sbom":
		return pipeline.StageSBOM
	case "dependencies":
		return pipeline.StageDependencies
	case "artifact":
		return pipeline.StageArtifact
	case "deploy":
		return pipeline.StageDeploy
	default:
		return pipeline.StageKind(s)
	}
}

func stageName(k pipeline.StageKind) string {
	names := map[pipeline.StageKind]string{
		pipeline.StageCheckout:      "Checkout",
		pipeline.StageDependencies:  "Dependencies",
		pipeline.StageUnitTest:      "Unit Test",
		pipeline.StageSAST:          "SAST",
		pipeline.StageSecretScan:    "Secret Scan",
		pipeline.StageIaCScan:       "IaC Scan",
		pipeline.StageBuild:         "Build",
		pipeline.StageContainerScan: "Container Scan",
		pipeline.StageSBOM:          "SBOM",
		pipeline.StageArtifact:      "Artifact",
		pipeline.StageDeploy:        "Deploy",
	}
	if n, ok := names[k]; ok {
		return n
	}
	return string(k)
}
