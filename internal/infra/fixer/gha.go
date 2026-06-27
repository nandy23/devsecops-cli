// Package fixer implements safe, idempotent remediations applied by `devsec
// fix`. Fixers only propose changes; the CLI writes them on --apply.
package fixer

import (
	"context"
	"io/fs"
	"regexp"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// GitHubActions hardens GitHub Actions workflows by ensuring a least-privilege
// top-level permissions block, and granting security-events:write to workflows
// that upload SARIF (required for code scanning).
type GitHubActions struct{}

func (GitHubActions) Name() string { return "github-actions-permissions" }

var rePermissions = regexp.MustCompile(`(?m)^permissions:`)
var reName = regexp.MustCompile(`(?m)^name:.*$`)

func (g GitHubActions) Plan(_ context.Context, fsys port.FileSystem, _ model.Analysis) ([]port.FixAction, error) {
	paths, err := fsys.List()
	if err != nil {
		return nil, err
	}
	var actions []port.FixAction
	for _, p := range paths {
		if !strings.Contains(p, ".github/workflows/") || !(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			continue
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			continue
		}
		content := string(b)
		needsSec := strings.Contains(content, "upload-sarif") || strings.Contains(content, "github/codeql-action")

		if !rePermissions.MatchString(content) {
			// No permissions block at all → add a least-privilege one.
			block := "permissions:\n  contents: read\n"
			if needsSec {
				block += "  security-events: write\n"
			}
			newContent := insertAfterName(content, block)
			actions = append(actions, port.FixAction{
				File:        p,
				Description: "add least-privilege top-level permissions" + secNote(needsSec),
				NewContent:  newContent,
			})
			continue
		}
		// Has permissions but uploads SARIF without security-events.
		if needsSec && !strings.Contains(content, "security-events:") {
			newContent := rePermissions.ReplaceAllString(content, "permissions:\n  security-events: write")
			actions = append(actions, port.FixAction{
				File:        p,
				Description: "grant security-events: write for SARIF upload",
				NewContent:  newContent,
			})
		}
	}
	return actions, nil
}

func secNote(needsSec bool) string {
	if needsSec {
		return " (incl. security-events: write for SARIF upload)"
	}
	return ""
}

// insertAfterName inserts block after the top-level `name:` line, or at the top
// if there is none. The block is surrounded by blank lines for readability.
func insertAfterName(content, block string) string {
	loc := reName.FindStringIndex(content)
	if loc == nil {
		return block + "\n" + content
	}
	end := loc[1]
	// advance past the newline after the name line
	if nl := strings.IndexByte(content[end:], '\n'); nl >= 0 {
		end += nl + 1
	}
	return content[:end] + "\n" + block + content[end:]
}
