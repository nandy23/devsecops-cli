package detector

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

// memFS adapts fstest.MapFS to port.FileSystem.
type memFS struct {
	fstest.MapFS
}

func (m memFS) Root() string { return "/repo" }
func (m memFS) List() ([]string, error) {
	var out []string
	for name := range m.MapFS {
		out = append(out, name)
	}
	return out, nil
}

func TestLanguageDetector_Go(t *testing.T) {
	fsys := memFS{fstest.MapFS{"go.mod": {Data: []byte("module x\n")}}}
	techs, err := LanguageDetector{}.Detect(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if !containsKind(techs, model.KindLanguage) {
		t.Fatalf("expected a language, got %+v", techs)
	}
}

func TestContainerDetector_Dockerfile(t *testing.T) {
	fsys := memFS{fstest.MapFS{"Dockerfile": {Data: []byte("FROM scratch\n")}}}
	techs, err := ContainerDetector{}.Detect(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tch := range techs {
		if tch.Name == "Docker" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Docker, got %+v", techs)
	}
}

func TestInfraDetector_Terraform(t *testing.T) {
	fsys := memFS{fstest.MapFS{"main.tf": {Data: []byte("resource \"x\" \"y\" {}")}}}
	techs, _ := InfraDetector{}.Detect(context.Background(), fsys)
	found := false
	for _, tch := range techs {
		if tch.Name == "Terraform" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Terraform, got %+v", techs)
	}
}
