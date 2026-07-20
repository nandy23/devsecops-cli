package scanner

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Cosign imports the JSON output of `cosign verify <image> -o json`, which lists
// the verified signatures for an image. Category: signing. A parsed report with
// at least one verified signature proves image signing is in place and credits
// the signing category.
type Cosign struct{}

func (Cosign) Tool() string { return "cosign" }

type cosignVerification struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

func (c Cosign) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"cosign.json", "cosign-verify.json", "cosign-report.json"},
		[]string{".cosign.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		verifications := parseCosign(data)
		if len(verifications) == 0 {
			continue // not a cosign verify report / no verified signatures
		}
		res := model.ScanResult{
			Tool:   c.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatSigning},
		}
		for _, v := range verifications {
			ref := v.Critical.Identity.DockerReference
			if d := v.Critical.Image.DockerManifestDigest; d != "" {
				ref += "@" + d
			}
			res.Findings = append(res.Findings, finding(c.Tool(), path,
				model.CatSigning, model.SevInfo, "verified signature ("+v.Critical.Type+")", ref))
		}
		out = append(out, res)
	}
	return out, nil
}

// parseCosign accepts either a JSON array (the usual form) or a single object,
// and keeps only entries that structurally look like a cosign verification.
func parseCosign(data []byte) []cosignVerification {
	trimmed := strings.TrimSpace(string(data))
	var records []cosignVerification
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &records); err != nil {
			return nil
		}
	} else {
		var one cosignVerification
		if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
			return nil
		}
		records = []cosignVerification{one}
	}
	var valid []cosignVerification
	for _, r := range records {
		if r.Critical.Type != "" || r.Critical.Image.DockerManifestDigest != "" {
			valid = append(valid, r)
		}
	}
	return valid
}
