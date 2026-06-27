package detector

import (
	"path/filepath"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// scan walks the repo once and returns the list of relative paths plus a set of
// basenames for quick membership tests.
func scan(fsys port.FileSystem) (paths []string, bases map[string]string, err error) {
	paths, err = fsys.List()
	if err != nil {
		return nil, nil, err
	}
	bases = make(map[string]string, len(paths))
	for _, p := range paths {
		bases[strings.ToLower(filepath.Base(p))] = p
	}
	return paths, bases, nil
}

// readSnippet reads the first n bytes of a file for evidence, fail-soft.
func readSnippet(fsys port.FileSystem, path string, n int) string {
	f, err := fsys.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	read, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:read]))
}

// hasExt reports whether any path has the given extension.
func hasExt(paths []string, ext string) (string, bool) {
	for _, p := range paths {
		if strings.EqualFold(filepath.Ext(p), ext) {
			return p, true
		}
	}
	return "", false
}

// hasGlob reports whether any path matches the shell glob against its basename.
func hasGlob(paths []string, pattern string) (string, bool) {
	for _, p := range paths {
		if ok, _ := filepath.Match(pattern, filepath.Base(p)); ok {
			return p, true
		}
	}
	return "", false
}

func tech(kind model.TechKind, name string, conf float64, path, reason string) model.Technology {
	return model.Technology{
		Kind:       kind,
		Name:       name,
		Confidence: conf,
		Evidence:   []model.Evidence{{Path: path, Reason: reason}},
	}
}
