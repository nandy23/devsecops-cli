package tool

import (
	"context"
	"testing"

	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

type fakeRunner struct {
	available map[string]bool
	lastCmd   port.Command
	exit      int
}

func (f *fakeRunner) Look(bin string) (string, bool) {
	if f.available[bin] {
		return "/usr/bin/" + bin, true
	}
	return "", false
}

func (f *fakeRunner) Run(_ context.Context, c port.Command) (port.CommandResult, error) {
	f.lastCmd = c
	return port.CommandResult{ExitCode: f.exit}, nil
}

func specs() map[string]Spec {
	return map[string]Spec{
		"vault": {Bin: "vault", Env: []string{"VAULT_ADDR=https://v.example.com"}},
		"trivy": {Bin: "trivy"},
	}
}

func TestTool_RejectsNonAllowlisted(t *testing.T) {
	s := New(&fakeRunner{available: map[string]bool{}}, specs())
	if _, err := s.Run(context.Background(), "rm", []string{"-rf", "/"}, nil, nil, nil); err == nil {
		t.Fatal("expected non-allow-listed tool to be rejected")
	}
}

func TestTool_ErrorsWhenNotInstalled(t *testing.T) {
	s := New(&fakeRunner{available: map[string]bool{}}, specs())
	if _, err := s.Run(context.Background(), "vault", []string{"status"}, nil, nil, nil); err == nil {
		t.Fatal("expected error when binary is not installed")
	}
}

func TestTool_InjectsEnvAndPassesArgs(t *testing.T) {
	fr := &fakeRunner{available: map[string]bool{"vault": true}, exit: 0}
	s := New(fr, specs())
	code, err := s.Run(context.Background(), "vault", []string{"status"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("want exit 0, got %d", code)
	}
	if len(fr.lastCmd.Args) != 1 || fr.lastCmd.Args[0] != "status" {
		t.Fatalf("args not passed through: %+v", fr.lastCmd.Args)
	}
	if len(fr.lastCmd.Env) != 1 || fr.lastCmd.Env[0] != "VAULT_ADDR=https://v.example.com" {
		t.Fatalf("env not injected: %+v", fr.lastCmd.Env)
	}
}

func TestTool_PropagatesExitCode(t *testing.T) {
	fr := &fakeRunner{available: map[string]bool{"trivy": true}, exit: 5}
	s := New(fr, specs())
	code, err := s.Run(context.Background(), "trivy", []string{"image", "x"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 5 {
		t.Fatalf("want propagated exit code 5, got %d", code)
	}
}
