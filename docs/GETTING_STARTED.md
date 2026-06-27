# Getting Started with devsec

This guide explains what devsec is, what you need before using it, how to
install it, and how each command works.

---

## 1. What is devsec?

**devsec is a DevSecOps assistant CLI.** It looks at a repository and answers:

- *What technologies do we use?* (languages, Docker, Terraform, Kubernetes, CI…)
- *Which security tools should we run?* (Trivy, Semgrep, gitleaks, Cosign…)
- *How mature is our security?* (a 0–100 score across 9 categories)
- *What's missing and how do we fix it?*

**Key idea: devsec orchestrates, it does NOT replace security tools.** It never
bundles or installs scanners. Instead it:

1. **Detects** your stack and **recommends** the right tools.
2. **Runs** scanners you already installed (`devsec scan`) or **ingests** the
   reports your CI already produced (`devsec doctor`).
3. **Queries** enterprise platforms via their APIs (`devsec connect`).
4. **Scores** your security maturity and **generates** secure pipelines.

The 9 scored categories: SAST, Secret Scan, Dependency Scan, IaC Scan, SBOM,
Container Scan, Signing, Policy, Runtime.

---

## 2. Prerequisites

| To do this… | You need… |
|-------------|-----------|
| **Build / install devsec** | Go 1.26+ (`go version`) |
| `detect`, `score`, `explain`, `report`, `graph`, `init`, `doctor`, `fix` | nothing else — works offline |
| `devsec scan` | the scanner binaries you want to run, on your `PATH` (see §5) |
| `devsec connect` | network access + credentials to your platforms (see §6) |

devsec is a single static binary. It works on Linux, macOS, and Windows.

---

## 3. Install

### Option A — from source (recommended while developing)

```bash
git clone <repo-url> devsecops-cli
cd devsecops-cli
make build            # produces ./bin/devsec
./bin/devsec --version
```

Put it on your PATH:

```bash
sudo mv ./bin/devsec /usr/local/bin/      # macOS/Linux
# or add ./bin to your PATH
```

### Option B — go install

```bash
go install github.com/nandy23/devsecops-cli/cmd/devsec@latest
# binary lands in $(go env GOPATH)/bin — make sure that's on your PATH
```

### Verify

```bash
devsec --version
devsec --help
```

---

## 4. First run (no extra tools needed)

```bash
# point at any repository
devsec detect  -p .          # technologies + recommended tools
devsec score   -p .          # 0–100 maturity score
devsec doctor  -p .          # audit CI/CD pipelines + ingest any scan reports
devsec explain trivy         # what a tool is, when to use it, alternatives
devsec init    -p . --platform github --dry-run   # preview a secure pipeline
devsec report  -p . -f html -o report.html        # shareable report
devsec graph   -p .          # Mermaid diagram of the recommended pipeline
devsec fix     -p .          # preview safe remediations (add --apply to write)
```

Useful global flags: `-p/--path`, `-c/--config`, `--json`, `-v/--verbose`.

Pick how opinionated recommendations are with a profile:

```bash
DEVSEC_PROFILE=minimal  devsec detect   # essentials only
DEVSEC_PROFILE=strict   devsec detect    # everything
```

---

## 5. Using real scanners (`devsec scan`)

devsec runs scanners that are **already installed** and ingests their output.
Install only the ones you want — missing ones are skipped, not installed for you.

```bash
devsec scan -p .                 # run every available scanner, then score
devsec scan -p . --tools trivy   # just one
devsec scan -p . --min-score 60  # gate CI (exit code 2 if below)
```

### Installing the scanners (macOS via Homebrew shown; see each tool's docs for Linux/Windows)

| Tool | Category | Install |
|------|----------|---------|
| **trivy** | container/iac/deps/secret | `brew install trivy` |
| **gitleaks** | secrets | `brew install gitleaks` |
| **trufflehog** | secrets | `brew install trufflehog` |
| **semgrep** | SAST | `brew install semgrep` or `pip install semgrep` |
| **snyk** | dependencies | `npm install -g snyk` (then `snyk auth`) |
| **grype** | container/deps | `brew install grype` |
| **hadolint** | Dockerfile | `brew install hadolint` |
| **checkov** | IaC | `pip install checkov` |
| **tfsec** | IaC (Terraform) | `brew install tfsec` |
| **kubescape** | K8s policy | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| bash` |
| **syft** | SBOM | `brew install syft` |
| **cosign** | signing | `brew install cosign` |

> Already have reports from CI instead? Just drop them in the repo
> (`gitleaks.json`, `semgrep.json`, `trivy.json`, `*.sarif`, …) and run
> `devsec doctor` — it ingests them automatically.

### Wrapping a tool directly

```bash
devsec tool trivy -- image alpine:3      # devsec passes args straight through
devsec tool vault -- status              # with config (VAULT_ADDR) injected
```

---

## 6. Connecting enterprise platforms (`devsec connect`)

Connectors pull findings from platforms via their REST APIs and fold them into
the same score/report. **Secrets must come from environment variables — never
commit a token.** Enable a connector by setting its env vars (or `enabled: true`
in `devsec.yaml`).

```bash
# SonarQube → sast
export DEVSEC_SONAR_URL=https://sonarqube.example.com
export DEVSEC_SONAR_PROJECT=my-key
export DEVSEC_SONAR_TOKEN=...

devsec connect      # show what each connector reports
devsec score        # external coverage now feeds the score
```

What you need to prepare per connector:

| Connector | Prepare | Credits |
|-----------|---------|---------|
| SonarQube | server URL, project key, user token | sast |
| Nexus IQ | URL, app public id, user + token | dependency_scan |
| Harbor | URL, project, robot account + secret | container_scan |
| Vault | URL, token | secret_scan |
| Dependency-Track | URL, project, API key | sbom |
| JFrog Xray | URL, watch name, access token | dep + container |
| DefectDojo | URL, product, API token | by finding tag |
| Kyverno / Falco | kube-apiserver URL + service-account token | policy / runtime |
| Sigstore Rekor | Rekor URL + signer email/hash | signing |
| Jenkins | URL, job, user + API token | detected stages |

See [`configs/devsec.yaml`](../configs/devsec.yaml) for every option and the
matching `DEVSEC_*` environment variables.

---

## 7. Configuration

devsec reads, in order of precedence: **CLI flags > `DEVSEC_*` env vars >
`devsec.yaml` > built-in defaults**.

Create `devsec.yaml` in your repo root (copy from `configs/devsec.yaml`) to set a
profile, ignore paths, score weights, enabled connectors, and report format.

---

## 8. Typical workflows

**Local check before a PR:**
```bash
devsec scan -p . --min-score 70
```

**In CI (reports already produced by other steps):**
```bash
devsec doctor -p . --json > devsec.json
devsec report -p . -f sarif -o devsec.sarif   # upload to GitHub code scanning
```

**Adopting DevSecOps on a new repo:**
```bash
devsec detect -p .                       # see what's recommended
devsec init   -p . --platform github     # generate a secure pipeline
devsec fix    -p . --apply               # harden existing workflows
```

---

## 9. Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | runtime error |
| 2 | `--min-score` threshold not met (policy gate) |
| other | for `devsec tool`, the wrapped tool's own exit code |
