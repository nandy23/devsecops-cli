package detector

import (
	"regexp"

	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Version-extraction regexes per ecosystem.
var (
	reGoVersion    = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)`)
	reNodeEngines  = regexp.MustCompile(`"node"\s*:\s*"([^"]+)"`)
	rePyRequires   = regexp.MustCompile(`requires-python\s*=\s*"([^"]+)"`)
	reMavenSource  = regexp.MustCompile(`<maven\.compiler\.source>([^<]+)</maven\.compiler\.source>`)
	reMavenRelease = regexp.MustCompile(`<maven\.compiler\.release>([^<]+)</maven\.compiler\.release>`)
	reJavaVersion  = regexp.MustCompile(`<java\.version>([^<]+)</java\.version>`)
	rePhpRequires  = regexp.MustCompile(`"php"\s*:\s*"([^"]+)"`)
	reRustEdition  = regexp.MustCompile(`(?m)^edition\s*=\s*"([^"]+)"`)
	reGemRuby      = regexp.MustCompile(`(?m)^ruby\s+["']([^"']+)["']`)
	reFirstSemver  = regexp.MustCompile(`(\d+(?:\.\d+){0,2})`)
)

// langVersion extracts a best-effort language/runtime version for a detected
// language, reading the manifest plus common version-pin files.
func langVersion(fsys port.FileSystem, lang, manifestPath string, bases map[string]string) string {
	content := readSnippet(fsys, manifestPath, 8192)
	switch lang {
	case "Go":
		return firstGroup(reGoVersion, content)
	case "NodeJS":
		if v := firstGroup(reNodeEngines, content); v != "" {
			return v
		}
		if p, ok := bases[".nvmrc"]; ok {
			return cleanSemver(readSnippet(fsys, p, 64))
		}
		if p, ok := bases[".node-version"]; ok {
			return cleanSemver(readSnippet(fsys, p, 64))
		}
	case "Python":
		if v := firstGroup(rePyRequires, content); v != "" {
			return v
		}
		if p, ok := bases[".python-version"]; ok {
			return cleanSemver(readSnippet(fsys, p, 64))
		}
		if p, ok := bases["runtime.txt"]; ok {
			return cleanSemver(readSnippet(fsys, p, 64))
		}
	case "Java":
		for _, re := range []*regexp.Regexp{reMavenRelease, reMavenSource, reJavaVersion} {
			if v := firstGroup(re, content); v != "" {
				return v
			}
		}
	case "PHP":
		return firstGroup(rePhpRequires, content)
	case "Rust":
		return firstGroup(reRustEdition, content)
	case "Ruby":
		return firstGroup(reGemRuby, content)
	}
	return ""
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// cleanSemver pulls the first semver-like token out of a short file (e.g. .nvmrc
// may contain "v20.11.0" or "lts/iron").
func cleanSemver(s string) string {
	return firstGroup(reFirstSemver, s)
}
