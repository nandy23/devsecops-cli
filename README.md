<h1 align="center">devsec</h1>

<p align="center"><b>The Open Source DevSecOps Assistant</b><br>
Analyze a repo · run/ingest security scanners · score maturity (0–100) · generate secure pipelines.</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

> **devsec orchestrates security tools — it never bundles or replaces them.**

## Install

```bash
make build           # → ./bin/devsec
# or
go install github.com/nandy23/devsecops-cli/cmd/devsec@latest
```

## Commands

| Command | What it does |
|---------|--------------|
| `detect`  | Detect languages/versions, frameworks, Docker, IaC, CI + recommend tools |
| `doctor`  | Audit pipelines, ingest scanner reports, score |
| `score`   | Security maturity 0–100 across 9 categories |
| `scan`    | Run locally-installed scanners (trivy, gitleaks, semgrep, snyk…) + ingest |
| `init`    | Generate a real pipeline (GitHub / GitLab / Azure / Jenkins) |
| `tool`    | Wrap a CLI with config injected (`devsec tool sonar-scanner -- ...`) |
| `connect` | Pull findings from platforms (SonarQube, Harbor, Vault…) |
| `explain` | Explain a tool (purpose, when to use, alternatives) |
| `report`  | Markdown / HTML / JSON / SARIF |
| `fix`     | Preview/apply safe pipeline hardening |

## Quickstart

```bash
devsec detect -p .                       # what's in this repo
devsec doctor -p .                       # audit + score
devsec init   -p . --platform github     # generate a secure pipeline
```

## Docs

See **[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** for setup, scanner
install, connectors and full usage.

## License

MIT — see [LICENSE](LICENSE).
