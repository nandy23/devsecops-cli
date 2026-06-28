package detector

import (
	"context"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// LintDetector identifies linters and formatters configured in the repository.
type LintDetector struct{}

func (LintDetector) Name() string  { return "lint" }
func (LintDetector) Priority() int { return 60 }

// lintSignal maps a config basename (exact or prefix) to a linter/formatter.
type lintSignal struct {
	match  string // matched against the basename; trailing * means prefix
	name   string
	prefix bool
}

var lintSignals = []lintSignal{
	// JavaScript / TypeScript
	{".eslintrc", "ESLint", true},
	{"eslint.config.js", "ESLint", false},
	{"eslint.config.mjs", "ESLint", false},
	{".prettierrc", "Prettier", true},
	{"prettier.config.js", "Prettier", false},
	{"biome.json", "Biome", false},
	// Go
	{".golangci.yml", "golangci-lint", false},
	{".golangci.yaml", "golangci-lint", false},
	// Python
	{".flake8", "Flake8", false},
	{".pylintrc", "Pylint", false},
	{"ruff.toml", "Ruff", false},
	{".ruff.toml", "Ruff", false},
	// Java / general
	{"checkstyle.xml", "Checkstyle", false},
	{".editorconfig", "EditorConfig", false},
}

func (d LintDetector) Detect(_ context.Context, fsys port.FileSystem) ([]model.Technology, error) {
	paths, bases, err := scan(fsys)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []model.Technology

	emit := func(name, path string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, tech(model.KindLinter, name, 0.95, path, "config file"))
	}

	for base, path := range bases {
		for _, s := range lintSignals {
			if s.prefix {
				if strings.HasPrefix(base, s.match) {
					emit(s.name, path)
				}
			} else if base == s.match {
				emit(s.name, path)
			}
		}
	}

	// pyproject.toml may configure black/ruff/isort under [tool.*].
	if p, ok := bases["pyproject.toml"]; ok {
		content := readSnippet(fsys, p, 8192)
		for marker, name := range map[string]string{
			"[tool.black]": "Black", "[tool.ruff]": "Ruff",
			"[tool.isort]": "isort", "[tool.flake8]": "Flake8",
		} {
			if strings.Contains(content, marker) {
				emit(name, p)
			}
		}
	}
	// package.json may declare prettier/eslint config keys.
	if p, ok := bases["package.json"]; ok {
		content := readSnippet(fsys, p, 8192)
		if strings.Contains(content, "\"eslintConfig\"") {
			emit("ESLint", p)
		}
		if strings.Contains(content, "\"prettier\"") {
			emit("Prettier", p)
		}
	}
	_ = paths
	return out, nil
}
