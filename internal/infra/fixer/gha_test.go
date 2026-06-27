package fixer

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

type memFS struct{ fstest.MapFS }

func (m memFS) Root() string { return "/repo" }
func (m memFS) List() ([]string, error) {
	var out []string
	for n := range m.MapFS {
		out = append(out, n)
	}
	return out, nil
}

func TestGHA_AddsLeastPrivilegePermissions(t *testing.T) {
	wf := "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
	fsys := memFS{fstest.MapFS{".github/workflows/ci.yml": {Data: []byte(wf)}}}

	actions, err := GitHubActions{}.Plan(context.Background(), fsys, model.Analysis{})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("want 1 action, got %d", len(actions))
	}
	if !strings.Contains(actions[0].NewContent, "permissions:") ||
		!strings.Contains(actions[0].NewContent, "contents: read") {
		t.Fatalf("expected least-privilege permissions added:\n%s", actions[0].NewContent)
	}
	if strings.Contains(actions[0].NewContent, "security-events") {
		t.Fatalf("no SARIF upload present, should not add security-events")
	}
}

func TestGHA_AddsSecurityEventsForSARIF(t *testing.T) {
	wf := "name: scan\non: [push]\njobs:\n  s:\n    steps:\n      - uses: github/codeql-action/upload-sarif@v3\n"
	fsys := memFS{fstest.MapFS{".github/workflows/scan.yml": {Data: []byte(wf)}}}

	actions, _ := GitHubActions{}.Plan(context.Background(), fsys, model.Analysis{})
	if len(actions) != 1 || !strings.Contains(actions[0].NewContent, "security-events: write") {
		t.Fatalf("expected security-events: write added for SARIF upload, got %+v", actions)
	}
}

func TestGHA_IdempotentWhenPermissionsPresent(t *testing.T) {
	wf := "name: ci\npermissions:\n  contents: read\non: [push]\njobs:\n  b:\n    steps:\n      - run: make\n"
	fsys := memFS{fstest.MapFS{".github/workflows/ci.yml": {Data: []byte(wf)}}}

	actions, _ := GitHubActions{}.Plan(context.Background(), fsys, model.Analysis{})
	if len(actions) != 0 {
		t.Fatalf("workflow already hardened; expected no actions, got %+v", actions)
	}
}
