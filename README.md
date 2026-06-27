<h1 align="center">devsec</h1>

<p align="center">
  <b>The Open Source DevSecOps Assistant</b><br>
  Analyze repositories · audit CI/CD pipelines · recommend security tooling · score maturity · generate secure pipelines
</p>

<p align="center">
  <a href="https://github.com/nandy23/devsecops-cli/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/nandy23/devsecops-cli/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Go" src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey">
</p>

---

`devsec` aims to be the `kubectl` / `terraform` of DevSecOps: simple commands, powerful functionality. It **orchestrates** security tools — it never replaces or bundles them.

```
$ devsec detect -p .
Detected technologies:
  • container      Docker              98%
  • iac            Terraform           97%
  • language       Go                  99%

Recommendations:
  [HIGH] container_scan → trivy     Images can ship known CVEs...
  [HIGH] iac_scan       → checkov   Terraform can provision insecure infra...
```

> New here? Read the **[Getting Started guide](docs/GETTING_STARTED.md)** — what
> to prepare, install steps, and how each command works.

## Install

```bash
# from source (Go 1.26+)
make build           # produces ./bin/devsec
# or
go install github.com/nandy23/devsecops-cli/cmd/devsec@latest
```

## Commands

| Command | Description |
|---------|-------------|
| `devsec detect`  | Detect languages, frameworks, containers, IaC and CI platforms; print recommendations. |
| `devsec doctor`  | Audit existing CI/CD pipelines for missing security stages. |
| `devsec score`   | Output a 0–100 security maturity score (`--min-score` gates CI). |
| `devsec init`    | Generate a secure CI/CD pipeline (`--platform github\|gitlab\|azure\|jenkins`, `--dry-run`). |
| `devsec explain <tool>` | Explain a tool: purpose, advantages, when to use, alternatives, stage. |
| `devsec report`  | Produce a Markdown / HTML / JSON / SARIF report (`-f`, `-o`). |
| `devsec graph`   | Render the recommended pipeline as a Mermaid diagram. |
| `devsec connect` | Query enterprise connectors (e.g. SonarQube) and collect their findings. |
| `devsec scan`    | Run locally-installed scanners (gitleaks, semgrep, snyk, trivy, checkov) and ingest results. |
| `devsec tool`    | Passthrough to an allow-listed CLI with config injected (`devsec tool vault -- status`). |
| `devsec fix`     | Preview/apply safe remediations (e.g. least-privilege workflow permissions, SARIF upload perms). |

Global flags: `-p/--path`, `-c/--config`, `-v/--verbose`, `--json`.

Planned: `migrate`, `plugin`, `update`.

## Quickstart

```bash
make build
./bin/devsec detect  -p examples/sample-app
./bin/devsec doctor  -p examples/sample-app
./bin/devsec score   -p examples/sample-app --min-score 80
./bin/devsec init    -p examples/sample-app --platform github --dry-run
./bin/devsec report  -p examples/sample-app -f html -o report.html
./bin/devsec explain trivy
```

## Architecture

Clean Architecture with a strict inward dependency rule. Every command transforms a single immutable `Analysis` aggregate produced by the detector engine. Rules, tool knowledge and pipeline templates are **data** (embedded YAML/templates, overridable locally), not code.

```
CLI ─▶ Application services ─▶ Domain (model, rules, scoring, IR)
                                   ▲
        Infrastructure adapters ───┘  (detectors, rule engine, auditors,
                                        generators, reporters, knowledge base)
```

See [docs/](docs/) — including the [Getting Started guide](docs/GETTING_STARTED.md) — for setup and usage details.

### Layout

```
cmd/devsec        entrypoint
internal/cli      Cobra commands (no business logic)
internal/app      use-case services (detect, doctor, score, init, report, graph, explain)
internal/domain   pure model, ports (interfaces), rule AST, scoring, pipeline IR
internal/infra    adapters: detectors, rule engine, auditors, generators, reporters, config
internal/di       composition root (the only package that wires everything)
pkg/pluginsdk     stable public contract for third-party plugins
rules/ knowledge/ templates/   embedded, overridable data
```

## Enterprise connectors

devsec can pull findings from external platforms and fold them into the unified
score/report. Supported today (more planned):

| Connector | Reads | Credits category |
|-----------|-------|------------------|
| **SonarQube** | quality gate, measures, open vulnerabilities | `sast` |
| **Harbor** | per-artifact Trivy scan overview (critical/high counts, unscanned images) | `container_scan` |
| **Nexus IQ** | latest policy evaluation, component vulnerabilities & violations | `dependency_scan` |
| **Vault** | health, seal state and KV secret engines (operational = secret posture) | `secret_scan` |
| **Dependency-Track** | project SBOM analysis: components & vulnerabilities | `sbom` |
| **JFrog Xray** | security/license violations for a watch | `dependency_scan`, `container_scan` |
| **DefectDojo** | active findings, mapped to categories by tag | _multi_ (by tag) |
| **Kyverno / K8s** | PolicyReport pass/fail from the cluster | `policy` |
| **Falco** | Falco DaemonSet readiness in the cluster | `runtime` |
| **Sigstore / Rekor** | transparency-log entries for a signer/artifact | `signing` |
| **Jenkins** | last build result + security stages in the job config | _multi_ (detected) |

With connectors covering all nine categories, devsec can compute a full
**0–100 maturity score entirely from enterprise platforms** — or any mix of
pipeline audit, scanner imports and connectors.

```bash
# SonarQube
export DEVSEC_SONAR_URL=https://sonarqube.example.com
export DEVSEC_SONAR_PROJECT=my-project-key
export DEVSEC_SONAR_TOKEN=...         # never commit tokens

# Harbor
export DEVSEC_HARBOR_URL=https://harbor.example.com
export DEVSEC_HARBOR_PROJECT=my-project
export DEVSEC_HARBOR_USERNAME='robot$ci'
export DEVSEC_HARBOR_SECRET=...

# Nexus IQ
export DEVSEC_NEXUS_URL=https://nexus-iq.example.com
export DEVSEC_NEXUS_APP=demo-app
export DEVSEC_NEXUS_USERNAME=admin
export DEVSEC_NEXUS_SECRET=...

# Vault
export DEVSEC_VAULT_URL=https://vault.example.com:8200
export DEVSEC_VAULT_TOKEN=...

devsec connect                       # collect from all enabled connectors
devsec score                         # external coverage feeds the maturity score
```

Each connector follows a `Connect → Validate → Collect → Disconnect` lifecycle
and declares which security categories it `Covers`, so scoring stays honest.

## Importing scanner results

devsec **orchestrates scanners, it never runs them**. Instead it ingests the
reports your CI already produces and folds the findings into the unified
score/report. A successfully parsed report credits its category — even with zero
findings, because a clean scan still proves the scan runs.

| Scanner | Report files (auto-discovered) | Credits |
|---------|-------------------------------|---------|
| **gitleaks** | `gitleaks.json`, `gitleaks-report.json`, `*.gitleaks.json` | `secret_scan` |
| **trufflehog** | `trufflehog.json`, `*.trufflehog.json` (NDJSON) | `secret_scan` |
| **semgrep** | `semgrep.json`, `*.semgrep.json` | `sast` |
| **snyk** | `snyk.json`, `*.snyk.json` | `dependency_scan` |
| **grype** | `grype.json`, `*.grype.json` | `container_scan` |
| **hadolint** | `hadolint.json`, `*.hadolint.json` | `container_scan` |
| **tfsec** | `tfsec.json`, `*.tfsec.json` | `iac_scan` |
| **kubescape** | `kubescape.json`, `*.kubescape.json` | `policy` |
| **any SARIF** | `*.sarif` (mapped by tool driver name) | by tool |

```bash
gitleaks detect -f json -r gitleaks.json   # your CI produces the report
semgrep --json -o semgrep.json
snyk test --json > snyk.json

devsec doctor      # ingests the reports, shows findings, recomputes the score
```

### Running the scanners for you

`devsec scan` closes the loop: it resolves the scanners on your `PATH`, runs the
ones present, and ingests their output automatically. It **never bundles or
installs** the tools — missing ones are skipped, not installed for you.

```bash
devsec scan                  # run every available scanner, then score
devsec scan --tools semgrep  # just one
devsec scan --min-score 60   # gate CI on the result
```

### Wrapping any tool: `devsec tool`

A thin, allow-listed passthrough that injects devsec config (Vault address,
SonarQube host…) into the wrapped CLI and forwards its exit code:

```bash
devsec tool vault -- status          # VAULT_ADDR/VAULT_TOKEN injected from config
devsec tool trivy -- image alpine:3  # flags after -- go straight to the tool
devsec tool sonar-scanner            # SONAR_HOST_URL/SONAR_TOKEN injected
```

Only vetted tools are allowed (gitleaks, semgrep, snyk, trivy, checkov,
terrascan, grype, syft, cosign, kubescape, trufflehog, vault, sonar-scanner) so
`devsec tool` can't be used to run arbitrary commands.

## Profiles

A profile selects how opinionated the recommendations are. Set `profile:` in
config or `DEVSEC_PROFILE=…`:

| Profile | Recommends | For |
|---------|-----------|-----|
| `minimal` | gitleaks, semgrep, trivy (secret/SAST/container/deps) | the non-negotiable basics |
| `balanced` *(default)* | + syft (SBOM), cosign (signing), checkov (IaC) | the common starter pack |
| `strict` | + kyverno (policy), falco (runtime), snyk (extra SCA) | mature teams |

```bash
DEVSEC_PROFILE=strict devsec detect
```

Rules are tagged with `profiles:` in `rules/*.yaml`; a rule with no `profiles`
applies to every profile.

## One tool, many categories (Trivy)

Trivy is multi-purpose, so `devsec scan` runs it with
`--scanners vuln,misconfig,secret` and a single `trivy.json` credits
**dependency_scan, iac_scan and secret_scan** at once (mapped from Trivy's
result `Class`). `trivy image` reports additionally credit `container_scan`.

## Extending

- **Add a rule:** drop a YAML file in `./rules` (or `~/.devsec/rules`). No Go needed.
- **Add a tool to `explain`:** add an entry to `knowledge/tools.yaml`.
- **Add a detector / generator / connector:** implement an interface from `pkg/pluginsdk`.

## Development

```bash
make fmt vet test   # format, vet, run unit tests
make run            # detect on the sample app
```

## License

MIT — see [LICENSE](LICENSE).
