// Package knowledge implements an embedded-YAML KnowledgeBase for `explain`.
package knowledge

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	domain "github.com/nandy23/devsecops-cli/internal/domain/knowledge"
)

type file struct {
	Tools []domain.Tool `yaml:"tools"`
}

// Base is an in-memory knowledge base loaded from an fs.FS.
type Base struct {
	byName map[string]domain.Tool
}

// Load reads all *.yaml under dir in fsys into a Base.
func Load(fsys fs.FS, dir string) (*Base, error) {
	b := &Base{byName: map[string]domain.Tool{}}
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil
		}
		var f file
		if err := yaml.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("parse knowledge %s: %w", p, err)
		}
		for _, t := range f.Tools {
			b.byName[strings.ToLower(t.Name)] = t
		}
		return nil
	})
	return b, err
}

// Lookup returns the tool entry by case-insensitive name.
func (b *Base) Lookup(_ context.Context, tool string) (domain.Tool, error) {
	t, ok := b.byName[strings.ToLower(strings.TrimSpace(tool))]
	if !ok {
		return domain.Tool{}, fmt.Errorf("no knowledge entry for %q (try `devsec explain` to list)", tool)
	}
	return t, nil
}

// List returns all known tools sorted by name.
func (b *Base) List(_ context.Context) ([]domain.Tool, error) {
	out := make([]domain.Tool, 0, len(b.byName))
	for _, t := range b.byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
