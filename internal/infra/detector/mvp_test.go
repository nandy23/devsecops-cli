package detector

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestLanguageDetector_GoVersion(t *testing.T) {
	fsys := memFS{fstest.MapFS{"go.mod": {Data: []byte("module x\n\ngo 1.22\n")}}}
	techs, _ := LanguageDetector{}.Detect(context.Background(), fsys)
	var ver string
	for _, tch := range techs {
		if tch.Kind == model.KindLanguage && tch.Name == "Go" {
			ver = tch.Version
		}
	}
	if ver != "1.22" {
		t.Fatalf("want Go version 1.22, got %q", ver)
	}
}

func TestLanguageDetector_NodeVersionFromNvmrc(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		"package.json": {Data: []byte(`{"name":"x"}`)},
		".nvmrc":       {Data: []byte("v20.11.0\n")},
	}}
	techs, _ := LanguageDetector{}.Detect(context.Background(), fsys)
	var ver string
	for _, tch := range techs {
		if tch.Name == "NodeJS" {
			ver = tch.Version
		}
	}
	if ver != "20.11.0" {
		t.Fatalf("want node version 20.11.0 from .nvmrc, got %q", ver)
	}
}

func TestLintDetector_FindsConfigs(t *testing.T) {
	fsys := memFS{fstest.MapFS{
		".golangci.yml": {Data: []byte("linters: {}")},
		".prettierrc":   {Data: []byte("{}")},
	}}
	techs, _ := LintDetector{}.Detect(context.Background(), fsys)
	names := map[string]bool{}
	for _, tch := range techs {
		if tch.Kind == model.KindLinter {
			names[tch.Name] = true
		}
	}
	if !names["golangci-lint"] || !names["Prettier"] {
		t.Fatalf("expected golangci-lint + Prettier, got %v", names)
	}
}
