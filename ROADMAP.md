# DevSec Roadmap

## v0.1 Foundation

Goal

Build the project skeleton.

Features

* Cobra CLI
* Configuration
* Logging
* Dependency Injection
* Repository Detection
* Rule Engine
* Recommendation Engine

---

## v0.2 Repository Analysis

Support detection for:

* Go
* Java
* Python
* Node
* Docker
* Kubernetes
* Terraform
* Helm
* Ansible

Output

Technology Inventory

---

## v0.3 DevSec Doctor

Commands

```
devsec doctor
```

Audit

* Repository
* Pipeline
* Security
* IaC

Generate

Security Score

Recommendations

---

## v0.4 Pipeline Generator

Generate

* Azure DevOps
* GitHub
* GitLab
* Jenkins

Generate configuration files.

---

## v0.5 Enterprise Connectors

Support

* SonarQube
* Jenkins
* Azure DevOps

Merge findings into one report.

---

## v0.6 Enterprise+

Support

* Harbor
* Nexus
* Artifactory
* Vault

---

## v0.7 Reports

Support

* HTML
* Markdown
* JSON
* Mermaid

---

## v0.8 Plugin SDK

Allow third-party plugins.

Plugin Types

* Detector
* Connector
* Reporter
* Rule Provider

---

## v0.9 Advanced Features

Implement

* devsec graph
* devsec explain
* devsec inventory

---

## v1.0 Stable Release

Features

* Plugin Marketplace
* Remote Rules
* Remote Knowledge Base
* Enterprise Profiles
* Multi-Cloud Support
* Signed Releases
* SBOM
* Production Documentation

---

# Future Vision

```
Repository
        │
        ▼
Repository Analysis
        │
        ▼
Enterprise Connectors

SonarQube

Jenkins

Azure DevOps

Harbor

Vault

GitHub

GitLab

        │
        ▼
Recommendation Engine
        │
        ▼
Unified Security Report
        │
        ▼
Pipeline Generation
        │
        ▼
Continuous Improvement
```

The long-term objective is to make DevSec the open-source control plane for DevSecOps and Platform Engineering, capable of orchestrating repository analysis, security tooling, CI/CD systems, and enterprise integrations through a single extensible CLI.
