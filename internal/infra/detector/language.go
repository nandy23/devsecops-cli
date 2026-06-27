package detector

import (
	"context"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// LanguageDetector identifies programming languages from manifest files.
type LanguageDetector struct{}

func (LanguageDetector) Name() string  { return "language" }
func (LanguageDetector) Priority() int { return 100 }

// langSignal maps a manifest basename to a language + package manager.
type langSignal struct {
	file    string
	lang    string
	pkgMgr  string
	confhit float64
}

var langSignals = []langSignal{
	{"go.mod", "Go", "go modules", 0.99},
	{"pom.xml", "Java", "maven", 0.95},
	{"build.gradle", "Java", "gradle", 0.9},
	{"build.gradle.kts", "Kotlin", "gradle", 0.9},
	{"package.json", "NodeJS", "npm", 0.95},
	{"requirements.txt", "Python", "pip", 0.9},
	{"pyproject.toml", "Python", "pip", 0.95},
	{"Pipfile", "Python", "pipenv", 0.9},
	{"composer.json", "PHP", "composer", 0.95},
	{"Cargo.toml", "Rust", "cargo", 0.99},
	{"Gemfile", "Ruby", "bundler", 0.9},
}

func (d LanguageDetector) Detect(_ context.Context, fsys port.FileSystem) ([]model.Technology, error) {
	paths, bases, err := scan(fsys)
	if err != nil {
		return nil, err
	}
	var out []model.Technology
	for _, s := range langSignals {
		if p, ok := bases[lower(s.file)]; ok {
			out = append(out, tech(model.KindLanguage, s.lang, s.confhit, p, "manifest "+s.file))
			out = append(out, tech(model.KindPackageMgr, s.pkgMgr, s.confhit, p, "manifest "+s.file))
		}
	}
	// .NET project files (*.csproj / *.sln).
	if p, ok := hasExt(paths, ".csproj"); ok {
		out = append(out, tech(model.KindLanguage, ".NET", 0.95, p, "csproj project file"))
	} else if p, ok := hasExt(paths, ".sln"); ok {
		out = append(out, tech(model.KindLanguage, ".NET", 0.9, p, "solution file"))
	}
	// Heuristic by source extension when no manifest matched.
	if !containsKind(out, model.KindLanguage) {
		for ext, name := range map[string]string{
			".go": "Go", ".py": "Python", ".rs": "Rust", ".java": "Java",
			".kt": "Kotlin", ".php": "PHP", ".ts": "NodeJS", ".js": "NodeJS",
		} {
			if p, ok := hasExt(paths, ext); ok {
				out = append(out, tech(model.KindLanguage, name, 0.6, p, "source files "+ext))
			}
		}
	}
	return out, nil
}

func containsKind(techs []model.Technology, k model.TechKind) bool {
	for _, t := range techs {
		if t.Kind == k {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
