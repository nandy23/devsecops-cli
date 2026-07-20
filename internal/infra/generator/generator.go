// Package generator renders the platform-agnostic pipeline IR to concrete CI
// platform files using embedded templates.
package generator

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// templated is a generator backed by a single embedded template file. funcs are
// optional template helpers (used by the GitHub generator to render real steps).
type templated struct {
	platform string
	tmplPath string
	outPath  string
	fsys     fs.FS
	funcs    template.FuncMap
}

func (g templated) Platform() string { return g.platform }

func (g templated) Generate(_ context.Context, spec pipeline.Spec) (map[string]string, error) {
	b, err := fs.ReadFile(g.fsys, g.tmplPath)
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", g.tmplPath, err)
	}
	t, err := template.New(g.platform).Funcs(g.funcs).Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("parse template %s: %w", g.tmplPath, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, spec); err != nil {
		return nil, fmt.Errorf("render %s: %w", g.platform, err)
	}
	return map[string]string{g.outPath: buf.String()}, nil
}

// Builtin returns the default generators backed by the embedded templates FS.
func Builtin(templates fs.FS) []port.PipelineGenerator {
	return []port.PipelineGenerator{
		templated{"github", "templates/github/workflow.yml.tmpl", ".github/workflows/devsec.yml", templates, GitHubFuncs()},
		templated{"gitlab", "templates/gitlab/gitlab-ci.yml.tmpl", ".gitlab-ci.yml", templates, GitLabFuncs()},
		templated{"azure", "templates/azure/azure-pipelines.yml.tmpl", "azure-pipelines.yml", templates, AzureFuncs()},
		templated{"jenkins", "templates/jenkins/Jenkinsfile.tmpl", "Jenkinsfile", templates, JenkinsFuncs()},
		templated{"bitbucket", "templates/bitbucket/bitbucket-pipelines.yml.tmpl", "bitbucket-pipelines.yml", templates, BitbucketFuncs()},
		templated{"circleci", "templates/circleci/config.yml.tmpl", ".circleci/config.yml", templates, CircleCIFuncs()},
	}
}
