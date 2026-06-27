// Package fix plans and applies safe, idempotent remediations to a repository.
package fix

import (
	"context"
	"os"
	"path/filepath"

	"github.com/nandy23/devsecops-cli/internal/app/detect"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Service plans remediations from registered fixers and optionally applies them.
type Service struct {
	detect *detect.Service
	fixers []port.Fixer
}

// New builds the fix service.
func New(detectSvc *detect.Service, fixers []port.Fixer) *Service {
	return &Service{detect: detectSvc, fixers: fixers}
}

// Plan detects the repo then collects proposed fixes from every fixer.
func (s *Service) Plan(ctx context.Context, fsys port.FileSystem) ([]port.FixAction, error) {
	a, err := s.detect.Run(ctx, fsys)
	if err != nil {
		return nil, err
	}
	var actions []port.FixAction
	for _, f := range s.fixers {
		acts, err := f.Plan(ctx, fsys, a)
		if err != nil {
			continue // fail-soft per fixer
		}
		actions = append(actions, acts...)
	}
	return actions, nil
}

// Apply writes the proposed file contents to disk under repoRoot.
func (s *Service) Apply(repoRoot string, actions []port.FixAction) error {
	for _, act := range actions {
		dest := filepath.Join(repoRoot, act.File)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, []byte(act.NewContent), 0o644); err != nil {
			return err
		}
	}
	return nil
}
