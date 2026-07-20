package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Syft imports SBOM documents produced by Syft (`syft . -o spdx-json` or
// `-o cyclonedx-json`). Category: sbom. An SBOM is an artifact, not a list of
// problems, so a parsed document credits SBOM coverage and records a single
// informational finding summarizing how many components it inventories.
type Syft struct{}

func (Syft) Tool() string { return "syft" }

type sbomDoc struct {
	// SPDX marker + packages.
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		Name string `json:"name"`
	} `json:"packages"`
	// CycloneDX marker + components.
	BOMFormat  string `json:"bomFormat"`
	Components []struct {
		Name string `json:"name"`
	} `json:"components"`
}

func (s Syft) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"sbom.spdx.json", "sbom.cdx.json", "sbom.json", "bom.json"},
		[]string{".spdx.json", ".cdx.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var doc sbomDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			continue
		}
		var format string
		var count int
		switch {
		case doc.SPDXVersion != "":
			format, count = "SPDX", len(doc.Packages)
		case doc.BOMFormat == "CycloneDX":
			format, count = "CycloneDX", len(doc.Components)
		default:
			continue // not an SBOM we recognize
		}
		res := model.ScanResult{
			Tool:   s.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatSBOM},
			Findings: []model.Finding{
				finding(s.Tool(), path, model.CatSBOM, model.SevInfo,
					fmt.Sprintf("%s SBOM present, inventorying %d components", format, count), path),
			},
		}
		out = append(out, res)
	}
	return out, nil
}
