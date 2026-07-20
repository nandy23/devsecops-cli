package generator

import "github.com/nandy23/devsecops-cli/internal/domain/pipeline"

// This file holds platform-agnostic shell commands and container images for each
// tool/stage, reused by the GitLab, Azure DevOps and Jenkins generators (the
// GitHub generator uses richer Actions instead).

// toolShell returns the shell command(s) that actually run a security tool.
func toolShell(tool string, kind pipeline.StageKind) []string {
	switch tool {
	case "trivy":
		if kind == pipeline.StageContainerScan {
			return []string{"trivy image --format json --output trivy-image.json --severity HIGH,CRITICAL \"$IMAGE\""}
		}
		return []string{"trivy fs --scanners vuln,misconfig,secret --format json --output trivy.json ."}
	case "semgrep":
		return []string{"semgrep scan --config auto --json --output semgrep.json"}
	case "sonarqube":
		return []string{`sonar-scanner -Dsonar.host.url="$SONAR_HOST_URL" -Dsonar.login="$SONAR_TOKEN"`}
	case "gitleaks":
		return []string{"gitleaks detect --source . --report-format json --report-path gitleaks.json --no-banner || true"}
	case "trufflehog":
		return []string{"trufflehog filesystem . --json > trufflehog.json || true"}
	case "checkov":
		return []string{"checkov -d . -o json > checkov.json || true"}
	case "tfsec":
		return []string{"tfsec . --format json --out tfsec.json || true"}
	case "grype":
		return []string{"grype dir:. -o json > grype.json || true"}
	case "hadolint":
		return []string{"hadolint Dockerfile -f json > hadolint.json || true"}
	case "kubescape":
		return []string{"kubescape scan . --format json --output kubescape.json || true"}
	case "syft":
		return []string{"syft . -o spdx-json=sbom.spdx.json"}
	case "cosign":
		return []string{`echo "cosign sign --yes <registry>/app:$CI_COMMIT_SHA  # set your pushed image"`}
	case "snyk":
		return []string{"snyk test --json > snyk.json || true"}
	case "owasp-dependency-check":
		// --nvdApiKey avoids severe NVD rate limiting; set NVD_API_KEY in CI.
		// --data caches the NVD DB between runs so it is not re-downloaded.
		return []string{`dependency-check --scan . --format JSON --out . --nvdApiKey "$NVD_API_KEY" --data .dependency-check`}
	default:
		return []string{"echo \"TODO: run " + tool + "\""}
	}
}

// toolImage returns a container image that ships the tool (for GitLab/Azure
// container jobs). Empty means use the default/job image.
func toolImage(tool string) string {
	switch tool {
	case "trivy":
		return "aquasec/trivy:latest"
	case "semgrep":
		return "semgrep/semgrep:latest"
	case "sonarqube":
		return "sonarsource/sonar-scanner-cli:latest"
	case "gitleaks":
		return "zricethezav/gitleaks:latest"
	case "checkov":
		return "bridgecrew/checkov:latest"
	case "tfsec":
		return "aquasec/tfsec:latest"
	case "grype":
		return "anchore/grype:latest"
	case "hadolint":
		return "hadolint/hadolint:latest-debian"
	case "syft":
		return "anchore/syft:latest"
	case "owasp-dependency-check":
		return "owasp/dependency-check:latest"
	default:
		return ""
	}
}

// langImage returns the container image for structural (build/test) jobs.
func langImage(lang string) string {
	switch lang {
	case "nodejs":
		return "node:20"
	case "go":
		return "golang:1.22"
	case "python":
		return "python:3.12"
	case "java":
		return "maven:3.9-eclipse-temurin-21"
	default:
		return "ubuntu:24.04"
	}
}

// langInstall / langTest / langBuild return shell commands per language.
func langInstall(lang string) []string {
	switch lang {
	case "nodejs":
		return []string{"npm ci"}
	case "go":
		return []string{"go mod download"}
	case "python":
		return []string{"pip install -r requirements.txt"}
	case "java":
		return []string{"mvn -B -q -DskipTests install"}
	default:
		return []string{`echo "TODO: install dependencies"`}
	}
}

func langTest(lang string) []string {
	switch lang {
	case "nodejs":
		return []string{"npm test --if-present"}
	case "go":
		return []string{"go test ./..."}
	case "python":
		return []string{"pytest -q || true"}
	case "java":
		return []string{"mvn -B test"}
	default:
		return []string{`echo "TODO: run unit tests"`}
	}
}

func langBuild(lang string) []string {
	switch lang {
	case "nodejs":
		return []string{"npm run build --if-present"}
	case "go":
		return []string{"go build ./..."}
	case "java":
		return []string{"mvn -B -DskipTests package"}
	default:
		return []string{`echo "TODO: build the application/image"`}
	}
}

// structuralCmds returns the language commands for a structural stage kind.
func structuralCmds(kind pipeline.StageKind, lang string) []string {
	switch kind {
	case pipeline.StageDependencies:
		return langInstall(lang)
	case pipeline.StageUnitTest:
		return append(langInstall(lang), langTest(lang)...)
	case pipeline.StageBuild:
		return append(langInstall(lang), langBuild(lang)...)
	case pipeline.StageArtifact:
		return []string{`echo "TODO: package & publish your artifact"`}
	case pipeline.StageDeploy:
		return []string{`echo "TODO: deploy (gated on previous security stages)"`}
	default:
		return []string{`echo "checkout"`}
	}
}
