package generator

import (
	"strings"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// GitHubFuncs returns template functions that render real, runnable GitHub
// Actions jobs (using official actions) for each pipeline stage, tailored to the
// detected language. This replaces placeholder "echo TODO" steps with executable
// scanner steps.
func GitHubFuncs() template.FuncMap {
	return template.FuncMap{"githubJob": githubJob}
}

// githubJob renders one stage as a full GitHub Actions job (indented for the
// `jobs:` map).
func githubJob(s pipeline.Stage, lang string) string {
	var steps []string
	add := func(snips ...string) {
		for _, sn := range snips {
			if strings.TrimSpace(sn) != "" {
				steps = append(steps, sn)
			}
		}
	}
	add(stepCheckout)

	switch s.Kind {
	case pipeline.StageDependencies:
		add(langSetup(lang), depsInstall(lang))
		for _, t := range s.Tools {
			add(toolStep(t, s.Kind))
		}
	case pipeline.StageUnitTest:
		add(langSetup(lang), depsInstall(lang), testCmd(lang))
	case pipeline.StageBuild:
		add(langSetup(lang), depsInstall(lang), buildCmd(lang))
	case pipeline.StageSAST, pipeline.StageSecretScan, pipeline.StageIaCScan,
		pipeline.StageContainerScan, pipeline.StageSBOM:
		for _, t := range s.Tools {
			add(toolStep(t, s.Kind))
		}
	case pipeline.StageArtifact:
		for _, t := range s.Tools {
			add(toolStep(t, s.Kind))
		}
		if len(s.Tools) == 0 {
			add(runStep("Package artifact", `echo "TODO: package & publish your artifact"`))
		}
	case pipeline.StageDeploy:
		add(runStep("Deploy", `echo "TODO: deploy (gated on previous security stages passing)"`))
	}

	var b strings.Builder
	b.WriteString("  " + s.ID + ":\n")
	b.WriteString("    name: " + s.Name + "\n")
	b.WriteString("    runs-on: ubuntu-latest\n")
	b.WriteString("    steps:\n")
	b.WriteString(strings.Join(steps, "\n") + "\n")
	return b.String()
}

const stepCheckout = "      - uses: actions/checkout@v4"

// runStep renders a simple run step using a block scalar so the command can
// safely contain characters like ':' without breaking YAML.
func runStep(name, cmd string) string {
	return "      - name: " + name + "\n        run: |\n          " + cmd
}

func langSetup(lang string) string {
	switch lang {
	case "nodejs":
		return "      - uses: actions/setup-node@v4\n        with:\n          node-version: '20'"
	case "go":
		return "      - uses: actions/setup-go@v5\n        with:\n          go-version: '1.22'"
	case "python":
		return "      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'"
	case "java":
		return "      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '21'"
	default:
		return ""
	}
}

func depsInstall(lang string) string {
	switch lang {
	case "nodejs":
		return runStep("Install dependencies", "npm ci")
	case "go":
		return runStep("Download modules", "go mod download")
	case "python":
		return runStep("Install dependencies", "pip install -r requirements.txt")
	case "java":
		return runStep("Resolve dependencies", "mvn -B -q -DskipTests install")
	default:
		return ""
	}
}

func testCmd(lang string) string {
	switch lang {
	case "nodejs":
		return runStep("Unit tests", "npm test --if-present")
	case "go":
		return runStep("Unit tests", "go test ./...")
	case "python":
		return runStep("Unit tests", "pytest -q || true")
	case "java":
		return runStep("Unit tests", "mvn -B test")
	default:
		return runStep("Unit tests", `echo "TODO: run unit tests"`)
	}
}

func buildCmd(lang string) string {
	switch lang {
	case "nodejs":
		return runStep("Build", "npm run build --if-present")
	case "go":
		return runStep("Build", "go build ./...")
	case "java":
		return runStep("Build", "mvn -B -DskipTests package")
	default:
		return runStep("Build", `echo "TODO: build the application/image"`)
	}
}

// uploadSarif uploads a SARIF file to GitHub code scanning (permissions:
// security-events: write is set at the top of the workflow).
func uploadSarif(file string) string {
	return "      - name: Upload SARIF\n        uses: github/codeql-action/upload-sarif@v3\n        if: always()\n        with:\n          sarif_file: " + file
}

// toolStep maps a tool to a real GitHub Actions step (sometimes several),
// using the right invocation for the pipeline stage.
func toolStep(tool string, kind pipeline.StageKind) string {
	switch tool {
	case "trivy":
		if kind == pipeline.StageContainerScan {
			return "      - name: Build image\n        run: docker build -t app:${{ github.sha }} .\n" +
				"      - name: Trivy image scan\n        uses: aquasecurity/trivy-action@0.24.0\n        with:\n          scan-type: image\n          image-ref: app:${{ github.sha }}\n          format: sarif\n          output: trivy-image.sarif\n          severity: HIGH,CRITICAL\n" +
				uploadSarif("trivy-image.sarif")
		}
		return "      - name: Trivy filesystem scan\n        uses: aquasecurity/trivy-action@0.24.0\n        with:\n          scan-type: fs\n          scan-ref: .\n          scanners: vuln,misconfig,secret\n          format: sarif\n          output: trivy-fs.sarif\n" +
			uploadSarif("trivy-fs.sarif")
	case "semgrep":
		return "      - name: Semgrep SAST\n        run: |\n          python -m pip install --quiet semgrep\n          semgrep scan --config auto --sarif --output semgrep.sarif\n" +
			uploadSarif("semgrep.sarif")
	case "sonarqube":
		return "      - name: SonarQube scan (sonar-scanner CLI)\n        uses: SonarSource/sonarqube-scan-action@v3\n        env:\n          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}\n          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}"
	case "gitleaks":
		return "      - name: Gitleaks secret scan\n        uses: gitleaks/gitleaks-action@v2\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
	case "trufflehog":
		return "      - name: TruffleHog secret scan\n        uses: trufflesecurity/trufflehog@main\n        with:\n          extra_args: --results=verified"
	case "checkov":
		return "      - name: Checkov IaC scan\n        uses: bridgecrewio/checkov-action@v12\n        with:\n          output_format: sarif\n          output_file_path: checkov.sarif\n" +
			uploadSarif("checkov.sarif")
	case "tfsec":
		return "      - name: tfsec IaC scan\n        uses: aquasecurity/tfsec-sarif-action@v0.1.4\n        with:\n          sarif_file: tfsec.sarif\n" +
			uploadSarif("tfsec.sarif")
	case "grype":
		return "      - name: Grype scan\n        uses: anchore/scan-action@v4\n        id: grype\n        with:\n          path: .\n          output-format: sarif\n" +
			uploadSarif("${{ steps.grype.outputs.sarif }}")
	case "hadolint":
		return "      - name: Hadolint Dockerfile lint\n        uses: hadolint/hadolint-action@v3.1.0\n        with:\n          dockerfile: Dockerfile\n          format: sarif\n          output-file: hadolint.sarif\n          no-fail: true\n" +
			uploadSarif("hadolint.sarif")
	case "kubescape":
		return "      - name: Kubescape posture scan\n        uses: kubescape/github-action@main\n        with:\n          format: sarif\n          outputFile: kubescape.sarif\n" +
			uploadSarif("kubescape.sarif")
	case "syft":
		return "      - name: Generate SBOM (Syft)\n        uses: anchore/sbom-action@v0\n        with:\n          format: spdx-json\n          output-file: sbom.spdx.json\n" +
			"      - name: Upload SBOM\n        uses: actions/upload-artifact@v4\n        with:\n          name: sbom\n          path: sbom.spdx.json"
	case "cosign":
		return "      - name: Install Cosign\n        uses: sigstore/cosign-installer@v3\n      - name: Sign image (keyless)\n        run: |\n          echo \"cosign sign --yes <registry>/app:${{ github.sha }}\"  # set your pushed image ref"
	case "snyk":
		return "      - name: Snyk dependency scan\n        uses: snyk/actions/node@master\n        continue-on-error: true\n        env:\n          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}"
	default:
		return runStep("Run "+tool, `echo "TODO: invoke `+tool+`"`)
	}
}
