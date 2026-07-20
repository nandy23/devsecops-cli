package scanner

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
)

func TestSyft_SPDX(t *testing.T) {
	js := `{"spdxVersion":"SPDX-2.3","name":"app","packages":[
		{"name":"lodash"},{"name":"express"},{"name":"react"}
	]}`
	fsys := memFS{fstest.MapFS{"sbom.spdx.json": {Data: []byte(js)}}}
	res, _ := Syft{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatSBOM {
		t.Fatalf("want sbom coverage, got %+v", res)
	}
	if len(res[0].Findings) != 1 || !strings.Contains(res[0].Findings[0].Message, "SPDX") ||
		!strings.Contains(res[0].Findings[0].Message, "3 components") {
		t.Fatalf("want an SPDX summary with 3 components, got %+v", res[0].Findings)
	}
}

func TestSyft_CycloneDX(t *testing.T) {
	js := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"foo"},{"name":"bar"}]}`
	fsys := memFS{fstest.MapFS{"sbom.cdx.json": {Data: []byte(js)}}}
	res, _ := Syft{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatSBOM {
		t.Fatalf("want sbom coverage, got %+v", res)
	}
	if !strings.Contains(res[0].Findings[0].Message, "CycloneDX") {
		t.Fatalf("want a CycloneDX summary, got %q", res[0].Findings[0].Message)
	}
}

func TestSyft_UnrelatedJSONNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"sbom.json": {Data: []byte(`{"foo":"bar"}`)}}}
	res, _ := Syft{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("json without an SBOM marker should produce no result, got %+v", res)
	}
}

func TestCosign_VerifiedSignature(t *testing.T) {
	js := `[{"critical":{"identity":{"docker-reference":"ghcr.io/org/app"},
		"image":{"docker-manifest-digest":"sha256:abc123"},
		"type":"cosign container image signature"},"optional":{"Issuer":"https://token.actions.githubusercontent.com"}}]`
	fsys := memFS{fstest.MapFS{"cosign.json": {Data: []byte(js)}}}
	res, _ := Cosign{}.Import(context.Background(), fsys)
	if len(res) != 1 || res[0].Covers[0] != model.CatSigning {
		t.Fatalf("want signing coverage, got %+v", res)
	}
	if len(res[0].Findings) != 1 || !strings.Contains(res[0].Findings[0].Location, "ghcr.io/org/app@sha256:abc123") {
		t.Fatalf("want a verified-signature finding for the image, got %+v", res[0].Findings)
	}
}

func TestCosign_UnrelatedJSONNoResult(t *testing.T) {
	fsys := memFS{fstest.MapFS{"cosign.json": {Data: []byte(`[{"foo":"bar"}]`)}}}
	res, _ := Cosign{}.Import(context.Background(), fsys)
	if len(res) != 0 {
		t.Fatalf("array without a cosign 'critical' block should produce no result, got %+v", res)
	}
}
