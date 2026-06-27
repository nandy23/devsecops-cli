package detector

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// ContainerDetector identifies Docker, Compose and Podman usage.
type ContainerDetector struct{}

func (ContainerDetector) Name() string  { return "container" }
func (ContainerDetector) Priority() int { return 90 }

func (d ContainerDetector) Detect(_ context.Context, fsys port.FileSystem) ([]model.Technology, error) {
	paths, bases, err := scan(fsys)
	if err != nil {
		return nil, err
	}
	var out []model.Technology
	for _, p := range paths {
		base := strings.ToLower(filepath.Base(p))
		if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
			out = append(out, tech(model.KindContainer, "Docker", 0.98, p, "Dockerfile present"))
			break
		}
	}
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		if p, ok := bases[name]; ok {
			out = append(out, tech(model.KindContainer, "Docker Compose", 0.95, p, "compose file"))
			break
		}
	}
	if p, ok := bases["containerfile"]; ok {
		out = append(out, tech(model.KindContainer, "Podman", 0.8, p, "Containerfile present"))
	}
	return out, nil
}
