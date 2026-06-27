// Package knowledge defines the tool knowledge entity used by `devsec explain`.
package knowledge

import "github.com/nandy23/devsecops-cli/internal/domain/model"

// Tool describes a security tool the CLI can recommend and explain.
type Tool struct {
	Name         string                 `yaml:"name" json:"name"`
	Category     model.SecurityCategory `yaml:"category" json:"category"`
	Purpose      string                 `yaml:"purpose" json:"purpose"`
	Advantages   []string               `yaml:"advantages" json:"advantages"`
	WhenToUse    string                 `yaml:"when_to_use" json:"when_to_use"`
	Alternatives []string               `yaml:"alternatives" json:"alternatives"`
	Stage        string                 `yaml:"stage" json:"stage"`
	License      string                 `yaml:"license" json:"license"`
	Links        []string               `yaml:"links" json:"links"`
}
