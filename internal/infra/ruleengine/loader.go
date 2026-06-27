// Package ruleengine loads rules from layered sources and evaluates them
// against an Analysis to produce recommendations.
package ruleengine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/nandy23/devsecops-cli/internal/domain/rule"
)

type ruleFile struct {
	Rules []rule.Rule `yaml:"rules"`
}

// EmbeddedSource loads the built-in rules shipped in the binary.
type EmbeddedSource struct {
	FS  fs.FS
	Dir string
}

func (s EmbeddedSource) Name() string { return "embedded" }

func (s EmbeddedSource) Load(_ context.Context) ([]rule.Rule, error) {
	return loadFromFS(s.FS, s.Dir)
}

// DirSource loads rules from a directory on disk (project or user overrides).
type DirSource struct {
	Path string
}

func (s DirSource) Name() string { return "dir:" + s.Path }

func (s DirSource) Load(_ context.Context) ([]rule.Rule, error) {
	if _, err := os.Stat(s.Path); err != nil {
		return nil, nil // missing override dir is not an error
	}
	return loadFromFS(os.DirFS(s.Path), ".")
}

func loadFromFS(fsys fs.FS, dir string) ([]rule.Rule, error) {
	var out []rule.Rule
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil // fail-soft per file
		}
		var rf ruleFile
		if err := yaml.Unmarshal(b, &rf); err != nil {
			return fmt.Errorf("parse rules %s: %w", p, err)
		}
		out = append(out, rf.Rules...)
		return nil
	})
	return out, err
}

// Merge layers rule sets by ID, with later sources overriding earlier ones.
func Merge(layers ...[]rule.Rule) []rule.Rule {
	idx := map[string]int{}
	var out []rule.Rule
	for _, layer := range layers {
		for _, r := range layer {
			if i, ok := idx[r.ID]; ok {
				out[i] = r
				continue
			}
			idx[r.ID] = len(out)
			out = append(out, r)
		}
	}
	return out
}
