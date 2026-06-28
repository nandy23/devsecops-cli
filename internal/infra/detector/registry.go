package detector

import "github.com/nandy23/devsecops-cli/internal/domain/port"

// Builtin returns the default set of detectors shipped with devsec, ordered by
// descending priority. Plugins can append to this list via the DI container.
func Builtin() []port.Detector {
	return []port.Detector{
		LanguageDetector{},
		ContainerDetector{},
		InfraDetector{},
		CIDetector{},
		LintDetector{},
	}
}
