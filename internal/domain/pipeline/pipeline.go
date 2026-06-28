// Package pipeline defines the platform-agnostic pipeline intermediate
// representation (IR). Generators render this IR to concrete CI/CD platforms,
// and the graph command renders it to Mermaid.
package pipeline

// StageKind enumerates the canonical secure-pipeline stages.
type StageKind string

const (
	StageCheckout      StageKind = "checkout"
	StageDependencies  StageKind = "dependencies"
	StageUnitTest      StageKind = "unit_test"
	StageSAST          StageKind = "sast"
	StageSecretScan    StageKind = "secret_scan"
	StageIaCScan       StageKind = "iac_scan"
	StageBuild         StageKind = "build"
	StageContainerScan StageKind = "container_scan"
	StageSBOM          StageKind = "sbom"
	StageArtifact      StageKind = "artifact"
	StageDeploy        StageKind = "deploy"
)

// Stage is one node of the pipeline IR.
type Stage struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      StageKind `json:"kind"`
	Tools     []string  `json:"tools,omitempty"`
	DependsOn []string  `json:"depends_on,omitempty"`
	Optional  bool      `json:"optional,omitempty"`
}

// Spec is the full platform-agnostic pipeline description.
type Spec struct {
	Name     string  `json:"name"`
	Platform string  `json:"platform"`
	Lang     string  `json:"lang,omitempty"` // primary language: nodejs|go|python|java
	Stages   []Stage `json:"stages"`
}

// CanonicalOrder is the default secure pipeline flow.
func CanonicalOrder() []StageKind {
	return []StageKind{
		StageCheckout, StageDependencies, StageUnitTest, StageSAST, StageSecretScan,
		StageIaCScan, StageBuild, StageContainerScan, StageSBOM, StageArtifact, StageDeploy,
	}
}
