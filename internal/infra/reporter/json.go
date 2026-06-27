// Package reporter renders an analysis and score into output formats.
package reporter

import (
	"context"
	"encoding/json"
	"io"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/scoring"
)

// JSON renders the full analysis + score as a stable JSON document.
type JSON struct{}

func (JSON) Format() string { return "json" }

type jsonDoc struct {
	SchemaVersion string         `json:"schema_version"`
	Analysis      model.Analysis `json:"analysis"`
	Score         scoring.Report `json:"score"`
}

func (JSON) Render(_ context.Context, a model.Analysis, s scoring.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonDoc{SchemaVersion: "1.0", Analysis: a, Score: s})
}
