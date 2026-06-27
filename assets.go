// Package assets embeds the default rules, knowledge base and pipeline
// templates into the binary so devsec is fully self-contained yet overridable
// by local or remote sources at runtime.
package assets

import "embed"

//go:embed rules/*.yaml
var Rules embed.FS

//go:embed knowledge/*.yaml
var Knowledge embed.FS

//go:embed templates
var Templates embed.FS
