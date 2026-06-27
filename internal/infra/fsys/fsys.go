// Package fsys provides a filesystem adapter over a repository root that
// honors ignore globs and caps file sizes. It implements port.FileSystem.
package fsys

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Repo is a read-only view of a repository rooted at a directory.
type Repo struct {
	root   string
	fsys   fs.FS
	ignore []string
}

var defaultIgnore = []string{
	".git", "node_modules", "vendor", "dist", "build", ".idea", ".vscode",
	"target", "__pycache__", ".venv", "venv",
}

// Opener implements port.RepoOpener, building a FileSystem over any directory.
type Opener struct{}

// OpenDir opens a directory as a read-only FileSystem (no extra ignores).
func (Opener) OpenDir(path string) (port.FileSystem, error) { return New(path, nil) }

// New opens a repository at root with optional extra ignore directory names.
func New(root string, extraIgnore []string) (*Repo, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	ignore := append([]string{}, defaultIgnore...)
	ignore = append(ignore, extraIgnore...)
	return &Repo{root: abs, fsys: os.DirFS(abs), ignore: ignore}, nil
}

// Open implements fs.FS.
func (r *Repo) Open(name string) (fs.File, error) { return r.fsys.Open(name) }

// Root returns the absolute repository root.
func (r *Repo) Root() string { return r.root }

// List walks the tree and returns repo-relative file paths, skipping ignored
// directories.
func (r *Repo) List() ([]string, error) {
	var out []string
	err := fs.WalkDir(r.fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // fail-soft per entry
		}
		if p == "." {
			return nil
		}
		base := filepath.Base(p)
		if d.IsDir() {
			if r.isIgnored(base) {
				return fs.SkipDir
			}
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

func (r *Repo) isIgnored(base string) bool {
	for _, ig := range r.ignore {
		if strings.EqualFold(base, ig) {
			return true
		}
	}
	return false
}
