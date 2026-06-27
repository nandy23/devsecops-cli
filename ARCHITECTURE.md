# Architecture

## Overview

DevSec follows Clean Architecture.

```
CLI
 │
 ▼
Application Layer
 │
 ▼
Domain Layer
 │
 ▼
Infrastructure Layer
 │
 ▼
Connectors / Plugins
```

---

# Core Components

```
devsec

├── CLI
├── Detector Engine
├── Rule Engine
├── Recommendation Engine
├── Pipeline Engine
├── Connector Engine
├── Knowledge Base
├── Reporting Engine
├── Plugin SDK
```

---

# Detector Engine

Responsible for detecting:

* Languages
* Frameworks
* Containers
* Infrastructure
* Cloud
* CI/CD
* Security tools

Produces a single immutable Analysis object.

---

# Rule Engine

Rules are YAML-based.

Example:

```
Dockerfile

↓

Recommend Trivy
```

Rules are loaded from:

* Embedded
* Local
* Remote (future)

---

# Recommendation Engine

Consumes:

* Analysis
* Rules
* Connectors

Produces:

* Recommendations
* Missing Controls
* Security Findings

---

# Connector Engine

First-class connectors:

* SonarQube
* Jenkins
* Azure DevOps
* GitHub
* GitLab
* Harbor
* Nexus
* Vault

Each connector implements:

```
Connect()

Validate()

Collect()

Disconnect()
```

---

# Pipeline Engine

Produces platform-specific pipelines.

Supported

* Azure DevOps
* GitHub
* GitLab
* Jenkins

Generated dynamically.

Never uses one fixed template.

---

# Reporting Engine

Produces

Markdown

HTML

JSON

Future

SARIF

PDF

---

# Knowledge Base

Contains metadata for:

* scanners
* platforms
* best practices
* pipeline stages
* remediation

Everything is explainable.

---

# Plugin SDK

Supports

Detector Plugins

Connector Plugins

Reporter Plugins

Rule Providers

Knowledge Providers

Cloud Providers

Pipeline Providers

---

# Enterprise Integrations

```
Repository
      │
      ▼
Detector
      │
      ▼
Rule Engine
      │
      ▼
Connectors

SonarQube
Jenkins
Azure DevOps
Harbor
Vault

      │
      ▼
Recommendation Engine
      │
      ▼
Unified Report
```

---

# Design Goals

* Modular
* Testable
* Extensible
* Enterprise Ready
* Community Friendly
