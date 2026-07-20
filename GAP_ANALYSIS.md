# DevSec — Gap Analysis & Roadmap

> Perbandingan antara **visi** (`PRODUCT.md` / `ROADMAP.md` / `ARCHITECTURE.md`) dan
> **implementasi nyata** di kode. Disusun dari penelusuran source pada **2026-07-19**.
> Cakupan: scope **DevOps** dan **DevSecOps**.

## Legend

| Simbol | Arti |
|--------|------|
| ✅ | Sudah diimplement & jalan |
| 🟡 | Parsial / hanya di knowledge base / belum tuntas |
| ❌ | Belum ada |

---

## 1. Sudah ke-cover (baseline kuat)

| Area | Implementasi nyata |
|------|--------------------|
| **Scanner** (14) | SAST `semgrep` · secret `gitleaks` + `trufflehog` · deps `trivy` / `snyk` / `owaspdc` / `grype` / `depaudit` · IaC `tfsec` · Dockerfile `hadolint` · K8s `kubescape` + `k8smanifest` |
| **Connector** (12) | `sonarqube`, `jenkins`, `harbor`, `nexus`, `vault`, `xray`, `dtrack`, `defectdojo`, `kyverno`, `falco`, `rekor`, `k8s` |
| **Detektor bahasa** (8) | Go, Java, Kotlin, NodeJS, PHP, Python, Ruby, Rust |
| **Detektor IaC** (7) | Terraform, Kubernetes, Helm, Ansible, Packer, Pulumi, Bicep |
| **Detektor CI** (5) | GitHub, GitLab, Azure, Jenkins, CircleCI |
| **Pipeline generator** (4) | Azure DevOps, GitHub Actions, GitLab CI, Jenkins |
| **Reporter** | Markdown, HTML, JSON, SARIF + scoring 0–100 |

---

## 2. Gap — Scope DevSecOps (keamanan)

| # | Gap | Status | Dampak | Prioritas |
|---|-----|--------|--------|-----------|
| S1 | **SBOM generation (`syft`)** — disebut di PRODUCT & knowledge, scanner belum ada | ❌ | Stage SBOM punya rule tapi kosong runner | 🔴 High |
| S2 | **Image signing (`cosign`)** — rule stage `artifact` ada, runner belum ada | ❌ | Klaim signing belum terbukti | 🔴 High |
| S3 | **IaC selain Terraform (`checkov` / `terrascan`)** — hanya `tfsec` | ❌ | K8s/Helm/CloudFormation/ARM belum benar-benar di-scan | 🔴 High |
| S4 | ~~**DAST** (ZAP / Nuclei / Dastardly / Nikto)~~ | ✅ **DONE** | Importer `zap`, `nuclei`, `dastardly`, `nikto`; kategori `dast` (weight 5); rule `dast-zap` (strict); knowledge lengkap | — |
| S4b | ~~**TLS/transport testing** (sslyze / testssl)~~ | ✅ **DONE** | Importer `sslyze` (JSON) + `testssl` (flat JSON); kategori `dast`; rule `dast-tls` (strict); knowledge `sslyze`/`testssl` | — |
| S9 | ~~**Recon / attack surface** (Nmap)~~ | ✅ **DONE** | Kategori baru `recon` (weight 5); importer `nmap` (XML, open ports + NSE vuln scripts); rule `recon-nmap` (strict); knowledge `nmap` | — |
| S5 | **CodeQL** — hanya di knowledge base | 🟡 | Deep taint analysis belum tersedia | 🟠 Med |
| S6 | ~~**Generator config file** (`sonar-project.properties`, `trivy.yaml`, `.checkov.yaml`, `.gitleaks.toml`, `syft.yaml`, `.hadolint.yaml`, `.ansible-lint`)~~ | ✅ **DONE** | Command `devsec config` — generate config scanner dari hasil detect; preview `--dry-run`, idempotent (skip existing, `--force`); tanpa secret | — |
| S7 | **Compliance mapping** (CIS / PCI / SOC2 / OWASP ASVS) | ❌ | Skor per-kategori saja, belum dipetakan ke standar | 🟠 Med |
| S8 | ~~**License compliance** dependency~~ | ✅ **DONE** | Kategori baru `license` (weight 5); Trivy importer parse `Licenses` (`--scanners license`); rule `license-trivy` (strict); dedup tool per stage di BuildSpec | — |

---

## 3. Gap — Scope DevOps (lebih luas)

| # | Gap | Status | Dampak | Prioritas |
|---|-----|--------|--------|-----------|
| D1 | **Deteksi framework aplikasi** (Express, Spring, Django, Rails, React, Next) | ❌ | Baru bahasa + linter; rekomendasi kurang kontekstual | 🔴 High |
| D2 | **Bahasa tambahan** — .NET/C#, TypeScript eksplisit, Scala, Elixir, C/C++, Dart/Flutter | ❌ | Repo non-listed tidak terdeteksi | 🟠 Med |
| D3 | **Connector platform Git** — GitHub / GitLab / Azure DevOps (hanya Jenkins) | ❌ | Tidak bisa audit branch policy / PR gate / Actions | 🔴 High |
| D4 | **Artifactory** connector (baru JFrog Xray) | ❌ | Registry Artifactory belum tercakup | 🟢 Low |
| D5 | ~~**CI generator tambahan** — Bitbucket, CircleCI~~ (Travis, Tekton, ArgoCD, Drone menyusul) | ✅ **DONE** | Generator `bitbucket` (`bitbucket-pipelines.yml`) + `circleci` (`.circleci/config.yml`); reuse shell steps; output tervalidasi YAML | 🟠 (sisa) |
| D6 | **Deteksi cloud** (AWS / GCP / Azure resources) — disebut di ARCHITECTURE | ❌ | Konteks cloud belum masuk rekomendasi | 🟠 Med |
| D7 | **GitOps / deploy** (ArgoCD, Flux, Helm release) | ❌ | Stage deploy belum lengkap | 🟢 Low |
| D8 | **CloudFormation** detection di infra | ❌ | IaC AWS-native belum dikenali | 🟢 Low |

---

## 4. Gap — Kematangan produk (dari ROADMAP)

| # | Gap | Status | Roadmap |
|---|-----|--------|---------|
| P1 | **Plugin SDK** baru kerangka (`pkg/pluginsdk`), marketplace belum | 🟡 | v0.8 |
| P2 | **Remote rules / remote knowledge base** | ❌ | v1.0 |
| P3 | **`devsec inventory`** command | ❌ | v0.9 (yang jadi: `graph`, `explain`) |
| P4 | **Rule engine masih tipis** — hanya 10 rule di `rules/core.yaml` | 🟡 | — |
| P5 | **PDF report** | ❌ | Future |
| P6 | **Enterprise Profiles / Multi-Cloud / Signed Releases** | ❌ | v1.0 |

---

## 5. Prioritas rekomendasi (urutan eksekusi)

1. **`syft` (SBOM) + `cosign` (signing)** — S1, S2 → melengkapi stage yang sudah ada rule-nya tapi kosong runner.
2. **`checkov`** — S3 → IaC tidak lagi Terraform-only.
3. **Generator config file** (`sonar-project.properties` dll) — S6 → mengotomasi yang sekarang masih dibuat manual.
4. **Connector GitHub / GitLab / Azure DevOps** — D3 → audit pipeline & branch policy, bukan hanya Jenkins.
5. **DAST (ZAP/Nuclei)** — S4 → menutup lubang konsep paling terlihat untuk klaim "DevSecOps lengkap".
6. **Deteksi framework** — D1 → rekomendasi lebih kontekstual per stack.

---

## 6. Ringkasan

- **Fondasi kuat**: shift-left security (SAST, secret, deps, container, IaC-Terraform, K8s) + 12 connector enterprise + 4 pipeline generator.
- **Lubang paling nyata**: **DAST** (nol), **SBOM/signing** (rule ada, runner kosong), **IaC non-Terraform**, dan **generator config file** yang dijanjikan tapi belum ada.
- **Scope DevOps** masih fokus ke security; deteksi framework, cloud, dan connector platform Git belum ada.
