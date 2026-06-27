package detector

import (
	"context"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// CIDetector identifies the CI/CD platform(s) and cloud provider signals.
type CIDetector struct{}

func (CIDetector) Name() string  { return "ci" }
func (CIDetector) Priority() int { return 70 }

func (d CIDetector) Detect(_ context.Context, fsys port.FileSystem) ([]model.Technology, error) {
	paths, bases, err := scan(fsys)
	if err != nil {
		return nil, err
	}
	var out []model.Technology

	// GitHub Actions: any file under .github/workflows.
	for _, p := range paths {
		if strings.Contains(p, ".github/workflows/") && isYAML(p) {
			out = append(out, tech(model.KindCIPlatform, "GitHub Actions", 0.98, p, "workflow file"))
			break
		}
	}
	if p, ok := bases[".gitlab-ci.yml"]; ok {
		out = append(out, tech(model.KindCIPlatform, "GitLab CI", 0.98, p, ".gitlab-ci.yml"))
	}
	for _, name := range []string{"azure-pipelines.yml", "azure-pipelines.yaml"} {
		if p, ok := bases[name]; ok {
			out = append(out, tech(model.KindCIPlatform, "Azure DevOps", 0.98, p, name))
		}
	}
	if p, ok := bases["jenkinsfile"]; ok {
		out = append(out, tech(model.KindCIPlatform, "Jenkins", 0.97, p, "Jenkinsfile"))
	}
	for _, p := range paths {
		if strings.Contains(p, ".circleci/config") {
			out = append(out, tech(model.KindCIPlatform, "CircleCI", 0.97, p, ".circleci/config"))
			break
		}
	}

	// Cloud provider hints.
	for _, p := range paths {
		low := strings.ToLower(p)
		switch {
		case strings.Contains(low, "cloudformation") || strings.HasSuffix(low, ".template.yaml"):
			out = append(out, tech(model.KindCloud, "AWS", 0.7, p, "CloudFormation"))
		case strings.Contains(low, "serverless.yml"):
			out = append(out, tech(model.KindCloud, "AWS", 0.6, p, "Serverless framework"))
		}
	}
	return out, nil
}
