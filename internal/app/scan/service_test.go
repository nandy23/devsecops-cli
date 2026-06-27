package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/app/detect"
	"github.com/nandy23/devsecops-cli/internal/app/importscan"
	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/infra/fsys"
	"github.com/nandy23/devsecops-cli/internal/infra/scanner"
)

// nopLogger satisfies port.Logger.
type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// fakeRunner pretends gitleaks is installed and writes a canned report.
type fakeRunner struct {
	available map[string]bool
}

func (f fakeRunner) Look(bin string) (string, bool) {
	if f.available[bin] {
		return "/usr/bin/" + bin, true
	}
	return "", false
}

func (f fakeRunner) Run(_ context.Context, c port.Command) (port.CommandResult, error) {
	// Simulate gitleaks writing a JSON report to the path after --report-path.
	for i, a := range c.Args {
		if a == "--report-path" && i+1 < len(c.Args) {
			_ = os.WriteFile(c.Args[i+1],
				[]byte(`[{"Description":"AWS key","File":"x.go","StartLine":1,"RuleID":"aws"}]`), 0o644)
		}
	}
	return port.CommandResult{ExitCode: 1}, nil // gitleaks exits 1 when leaks found
}

// nopRules is a RuleEngine that returns nothing (keeps the test focused).
type nopRules struct{}

func (nopRules) Evaluate(context.Context, model.Analysis) ([]model.Recommendation, error) {
	return nil, nil
}

func TestScan_RunsAvailableToolAndIngests(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsysRepo, err := fsys.New(repo, nil)
	if err != nil {
		t.Fatal(err)
	}

	detectSvc := detect.New(nil, nopRules{}, "test", nopLogger{})
	importSvc := importscan.New(scanner.Builtin(), nopLogger{})
	runner := fakeRunner{available: map[string]bool{"gitleaks": true}} // only gitleaks "installed"

	svc := New(detectSvc, importSvc, runner, fsys.Opener{}, DefaultPlans(), nopLogger{})
	a, outcomes, err := svc.Run(context.Background(), fsysRepo, nil)
	if err != nil {
		t.Fatal(err)
	}

	// gitleaks ran; the others were skipped (not installed).
	var ranGitleaks, skipped int
	for _, o := range outcomes {
		if o.Tool == "gitleaks" && o.Status == "ran" {
			ranGitleaks++
		}
		if o.Status == "skipped" {
			skipped++
		}
	}
	if ranGitleaks != 1 {
		t.Fatalf("expected gitleaks to run, got outcomes %+v", outcomes)
	}
	if skipped == 0 {
		t.Fatalf("expected some scanners to be skipped, got %+v", outcomes)
	}

	// The gitleaks report was ingested and credits secret_scan.
	if cov, ok := a.Coverage[model.CatSecretScan]; !ok || cov.State != model.StatePresent {
		t.Fatalf("expected secret_scan present from ingested report, got %+v", a.Coverage[model.CatSecretScan])
	}
	if len(a.Scans) == 0 || len(a.Scans[0].Findings) == 0 {
		t.Fatalf("expected ingested scan findings, got %+v", a.Scans)
	}
}

func TestScan_OnlyFilter(t *testing.T) {
	repo := t.TempDir()
	fsysRepo, _ := fsys.New(repo, nil)
	detectSvc := detect.New(nil, nopRules{}, "test", nopLogger{})
	importSvc := importscan.New(scanner.Builtin(), nopLogger{})
	runner := fakeRunner{available: map[string]bool{"gitleaks": true, "semgrep": true}}

	svc := New(detectSvc, importSvc, runner, fsys.Opener{}, DefaultPlans(), nopLogger{})
	_, outcomes, err := svc.Run(context.Background(), fsysRepo, []string{"semgrep"})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Tool != "semgrep" {
		t.Fatalf("only-filter should run just semgrep, got %+v", outcomes)
	}
}
