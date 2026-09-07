# Container Misconfiguration Audit Tool (`container-audit`)

[![CI Security Scan](https://github.com/security/container-misconfiguration-auditor/actions/workflows/security-scan.yml/badge.svg)](.github/workflows/security-scan.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: pytest](https://img.shields.io/badge/tests-pytest-blueviolet.svg)](https://docs.pytest.org/)

An automated static security analysis and DevSecOps auditing tool designed to detect, classify, score, and remediate security misconfigurations across **Dockerfiles**, **Docker Compose files**, **Kubernetes YAML manifests**, and **Container images**.

Aligned with **CIS Docker Benchmark v1.6.0** and **CIS Kubernetes Benchmark v1.8.0** recommendations and industry container security best practices.

---

> [!IMPORTANT]
> **Academic & Security Disclaimer**:
> This tool is a security auditing aid for DevSecOps pipelines, developer workstations, and educational environments. It does not replace a comprehensive manual security assessment, threat modeling, or penetration test. CIS mappings provided are reference alignments and do not constitute formal CIS certification.

---

## Table of Contents

1. [Key Features](#key-features)
2. [Architecture & Workflow](#architecture--workflow)
3. [Technology Stack](#technology-stack)
4. [Installation & Setup](#installation--setup)
5. [CLI Usage & Examples](#cli-usage--examples)
6. [Supported File Types & Automatic Detection](#supported-file-types--automatic-detection)
7. [Comprehensive Rule Catalog](#comprehensive-rule-catalog)
   - [Dockerfile Rules (D001–D010)](#dockerfile-rules)
   - [Docker Compose Rules (C001–C012)](#docker-compose-rules)
   - [Kubernetes Rules (K001–K015)](#kubernetes-rules)
8. [Scoring & Severity Calculation](#scoring--severity-calculation)
9. [CIS Benchmark Mapping Methodology](#cis-benchmark-mapping-methodology)
10. [Rule Confidence & Finding Suppression](#rule-confidence--finding-suppression)
11. [Multi-Format Reporting](#multi-format-reporting)
12. [Trivy External Scanner Integration](#trivy-external-scanner-integration)
13. [Test Data Environments](#test-data-environments)
14. [Automated Testing](#automated-testing)
15. [GitHub Actions CI/CD Integration](#github-actions-cicd-integration)
16. [Docker Container Usage](#docker-container-usage)
17. [Limitations & Future Roadmap](#limitations--future-roadmap)

---

## 1. Key Features

- **Multi-Format Auditing**: Evaluates Dockerfiles, multi-service Docker Compose files, multi-document Kubernetes YAML resources, and container images.
- **Pinpoint AST Line Tracking**: Preserves exact source code line numbers for detected issues using AST line loaders.
- **Automated Secret Redaction**: Detects exposed API keys, tokens, passwords, and private keys while strictly redacting cleartext secrets in all logs, terminal, and report outputs (`*** [REDACTED]`).
- **Configurable Scoring Engine**: Calculates an intuitive 0–100 security score with custom deduction weights.
- **Rule Confidence Ratings**: Classifies detections as `HIGH` (deterministic AST checks) or `MEDIUM`/`LOW` (heuristic pattern matching).
- **Rule Suppression**: Flexible exception management via `--ignore <RULE_IDS>` or `.auditignore` configuration files.
- **Multi-Output Reporting**: Produces styled Rich terminal dashboards, machine-readable JSON for pipelines, interactive Jinja2 HTML reports, and industry-standard SARIF v2.1.0 reports for GitHub Security Scanning.
- **Graceful Trivy Integration**: Automatically detects and invokes Aqua Security Trivy for container image CVEs and misconfiguration scanning with seamless fallback.

---

## 2. Architecture & Workflow

```
                               +-----------------------------------+
                               |          CLI Entry Point          |
                               |  container-audit scan | dockerfile|
                               |  compose | kubernetes | image     |
                               +-----------------+-----------------+
                                                 |
                                                 v
                               +-----------------------------------+
                               |        Scanner Orchestrator       |
                               |  (Auto-detection & .auditignore)  |
                               +-----------------+-----------------+
                                                 |
                +--------------------------------+--------------------------------+
                |                                |                                |
                v                                v                                v
     +--------------------+            +--------------------+            +--------------------+
     | Dockerfile Scanner |            |  Compose Scanner   |            | Kubernetes Scanner |
     |  (D001 - D010)     |            |   (C001 - C012)    |            |   (K001 - K015)    |
     +----------+---------+            +----------+---------+            +----------+---------+
                |                                |                                |
                +--------------------------------+--------------------------------+
                                                 |
                                                 +--------------------------------+
                                                 | (Optional image scan)          v
                                                 |                    +-----------------------+
                                                 |                    | Trivy Scanner Runner  |
                                                 |                    | & Finding Normalizer  |
                                                 |                    +-----------+-----------+
                                                 v                                |
                               +-----------------------------------+              |
                               |    Finding Normalization Model    |<-------------+
                               | (Severity, Confidence, Category)  |
                               +-----------------+-----------------+
                                                 |
                        +------------------------+------------------------+
                        |                        |                        |
                        v                        v                        v
             +--------------------+   +--------------------+   +--------------------+
             |     CIS Mapper     |   | Remediation Engine |   |   Scoring Engine   |
             | (Verified controls)|   | (Guidance & Code)  |   | (Baseline 100 - W) |
             +----------+---------+   +----------+---------+   +----------+---------+
                        |                        |                        |
                        +------------------------+------------------------+
                                                 |
                                                 v
                               +-----------------------------------+
                               |     Multi-Format Report Engine    |
                               |  - Terminal (Rich UI)             |
                               |  - JSON (Structured CI output)    |
                               |  - HTML (Jinja2 Dashboard)        |
                               |  - SARIF (GitHub Code Scanning)   |
                               +-----------------+-----------------+
                                                 |
                                                 v
                               +-----------------------------------+
                               |  Exit Code / Security Threshold   |
                               |   (--fail-on LOW|MED|HIGH|CRIT)   |
                               +-----------------------------------+
```

---

## 3. Technology Stack

- **Core**: Python 3.11+
- **CLI Framework**: Typer & Click
- **Terminal UI**: Rich (color-coded gauges, panels, and tables)
- **YAML & AST Engine**: PyYAML with custom line-preserving constructors
- **Templating**: Jinja2 for responsive HTML reports
- **Data Modeling**: Pydantic v2
- **Image Scanning**: Aqua Security Trivy CLI integration
- **Testing**: pytest & pytest-cov
- **CI/CD**: GitHub Actions & SARIF 2.1.0 upload

---

## 4. Installation & Setup

### Local Installation (Pip / Virtual Environment)

```bash
# Clone the repository
git clone https://github.com/security/container-misconfiguration-auditor.git
cd container-misconfiguration-auditor

# Create and activate a virtual environment
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Install dependencies and the CLI tool in editable mode
pip install -r requirements.txt
pip install -e .
```

Verify the installation:
```bash
container-audit --help
```

---

## 5. CLI Usage & Examples

### 1. Scan Any Directory or File (Automatic Detection)
```bash
# Scan current directory
container-audit scan .

# Scan specific directory and output HTML report
container-audit scan ./test-data/vulnerable --format html --output reports/vuln-report.html

# Scan with strict security gate (fail CI on HIGH or CRITICAL findings)
container-audit scan ./test-data/vulnerable --fail-on HIGH

# Scan and ignore specific findings
container-audit scan . --ignore K001,D004
```

### 2. Audit a Single Dockerfile
```bash
container-audit dockerfile ./Dockerfile
container-audit dockerfile ./Dockerfile --format json --output docker-report.json
```

### 3. Audit a Docker Compose File
```bash
container-audit compose ./docker-compose.yml
```

### 4. Audit a Kubernetes Manifest
```bash
container-audit kubernetes ./deployment.yaml --format terminal
```

### 5. Audit a Container Image (via Trivy)
```bash
container-audit image nginx:latest
```

---

## 6. Supported File Types & Automatic Detection

When running `container-audit scan <path>`, the tool inspects and classifies:
- **Dockerfiles**: Files named `Dockerfile`, `Containerfile`, `*.dockerfile`, or `Dockerfile.*`.
- **Docker Compose**: Files named `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml` or containing top-level `services:`.
- **Kubernetes Manifests**: YAML files containing `apiVersion` and valid Kubernetes `kind` (Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Services, ConfigMaps, etc.), including **multi-document YAML streams** (`---`).

---

## 7. Comprehensive Rule Catalog

### Dockerfile Rules

| Rule ID | Title | Severity | Confidence | CIS Reference | Description |
|---|---|---|---|---|---|
| **D001** | Explicit Root User | `HIGH` | `HIGH` | CIS Docker 4.1 | Explicitly sets `USER root` or `USER 0`. |
| **D002** | Base Image Uses 'latest' Tag | `MEDIUM` | `HIGH` | CIS Docker 4.3 | FROM instruction uses mutable `:latest` tag or lacks tag. |
| **D003** | Missing Non-Root USER | `HIGH` | `HIGH` | CIS Docker 4.1 | No non-root USER instruction configured in final image stage. |
| **D004** | Embedded Secrets | `CRITICAL` | `MEDIUM` | CIS Docker 4.4 | Hardcoded passwords, API keys, tokens, or private keys detected. |
| **D005** | SSH Server Installed | `MEDIUM` | `HIGH` | CIS Docker 4.5 | Installation of `openssh-server` or SSH daemons in container. |
| **D006** | Dangerous System Modification | `HIGH` | `HIGH` | Best Practice | Risky modifications like `chmod 777` on system paths or `/etc/shadow`. |
| **D007** | ADD Instead of COPY | `LOW` | `HIGH` | CIS Docker 4.9 | ADD instruction used when standard COPY is safer. |
| **D008** | Unsafe Package Practice | `LOW` | `HIGH` | Best Practice | Unverified scripts (`curl \| bash`) or `--allow-unauthenticated`. |
| **D009** | Missing HEALTHCHECK | `LOW` | `HIGH` | CIS Docker 4.6 | No HEALTHCHECK instruction defined in final stage. |
| **D010** | Unpinned Floating Tag | `MEDIUM` | `HIGH` | CIS Docker 4.3 | Base image uses floating branch/major tag (e.g. `alpine`). |

---

### Docker Compose Rules

| Rule ID | Title | Severity | Confidence | CIS Reference | Description |
|---|---|---|---|---|---|
| **C001** | Privileged Container | `CRITICAL` | `HIGH` | CIS Docker 5.4 | Service sets `privileged: true`. |
| **C002** | Host Network Mode | `HIGH` | `HIGH` | CIS Docker 5.9 | Service sets `network_mode: host`. |
| **C003** | Host PID Shared | `HIGH` | `HIGH` | CIS Docker 5.15 | Service sets `pid: host`. |
| **C004** | Host IPC Shared | `HIGH` | `HIGH` | CIS Docker 5.16 | Service sets `ipc: host`. |
| **C005** | Host Root Filesystem Mount | `CRITICAL` | `HIGH` | CIS Docker 5.5 | Volume mount specifies host root directory (`/`). |
| **C006** | Sensitive Host Path Mounted | `CRITICAL` | `HIGH` | CIS Docker 5.31 | Mounting `/var/run/docker.sock`, `/etc`, `/root`, `/proc`, etc. |
| **C007** | Excessive Capabilities (ALL) | `CRITICAL` | `HIGH` | CIS Docker 5.3 | Service sets `cap_add: [ALL]`. |
| **C008** | AppArmor/Seccomp Disabled | `HIGH` | `HIGH` | CIS Docker 5.1 | Sets `seccomp:unconfined` or `apparmor:unconfined`. |
| **C009** | Secret in Environment | `CRITICAL` | `MEDIUM` | CIS Docker 5.14 | Plaintext credentials in environment variables. |
| **C010** | Image Uses 'latest' Tag | `MEDIUM` | `HIGH` | CIS Docker 4.3 | Service image uses mutable `:latest` tag. |
| **C011** | Missing Resource Limits | `MEDIUM` | `HIGH` | CIS Docker 5.10 | No memory and CPU limits defined. |
| **C012** | Dangerous Port Exposure | `HIGH` | `HIGH` | CIS Docker 5.13 | Sensitive ports (22, 2375, 3306, 5432, 6379, 27017) bound to `0.0.0.0`. |

---

### Kubernetes Rules

| Rule ID | Title | Severity | Confidence | CIS Reference | Description |
|---|---|---|---|---|---|
| **K001** | Privileged Container | `CRITICAL` | `HIGH` | CIS K8s 5.2.1 | Container sets `securityContext.privileged: true`. |
| **K002** | runAsNonRoot Not Enabled | `HIGH` | `HIGH` | CIS K8s 5.2.6 | Container lacks `runAsNonRoot: true` or sets `runAsUser: 0`. |
| **K003** | allowPrivilegeEscalation Enabled/Unspecified | `HIGH` | `HIGH` | CIS K8s 5.2.5 | Container enables or fails to explicitly disable privilege escalation. |
| **K004** | hostNetwork Enabled | `HIGH` | `HIGH` | CIS K8s 5.2.4 | Pod sets `hostNetwork: true`. |
| **K005** | hostPID Enabled | `HIGH` | `HIGH` | CIS K8s 5.2.3 | Pod sets `hostPID: true`. |
| **K006** | hostIPC Enabled | `HIGH` | `HIGH` | CIS K8s 5.2.2 | Pod sets `hostIPC: true`. |
| **K007** | Dangerous hostPath Volume | `CRITICAL` | `HIGH` | CIS K8s 5.2.8 | Pod mounts host root, docker socket, or `/etc`. |
| **K008** | Image Uses 'latest' Tag | `MEDIUM` | `HIGH` | CIS K8s 5.7.4 | Container image uses `:latest` or missing tag. |
| **K009** | Excessive Added Capabilities (ALL) | `CRITICAL` | `HIGH` | CIS K8s 5.2.7 | SecurityContext `capabilities.add` contains `ALL`. |
| **K010** | Dangerous Capabilities Added | `HIGH` | `HIGH` | CIS K8s 5.2.7 | Adds `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `DAC_OVERRIDE`, etc. |
| **K011** | readOnlyRootFilesystem Disabled/Missing | `MEDIUM` | `HIGH` | CIS K8s 5.2.9 | Root filesystem is writable. |
| **K012** | Missing Resource Limits/Requests | `MEDIUM` | `HIGH` | CIS K8s 5.7.1 | Lacks CPU and Memory requests and limits. |
| **K013** | Missing Seccomp Profile | `MEDIUM` | `HIGH` | CIS K8s 5.7.2 | SecurityContext does not set `RuntimeDefault` seccomp profile. |
| **K014** | Container securityContext Missing | `MEDIUM` | `HIGH` | CIS K8s 5.7.3 | Container has no `securityContext` block defined. |
| **K015** | Embedded Secrets in Manifest | `CRITICAL` | `MEDIUM` | CIS K8s 5.4.1 | Plaintext secret values in env variables or ConfigMaps. |

---

## 8. Scoring & Severity Calculation

The tool starts with a baseline **Security Score of 100/100**. For each detected misconfiguration, points are deducted based on severity weights:

$$\text{Score} = \max\left(0, 100 - \sum (20 \cdot N_{\text{CRITICAL}} + 10 \cdot N_{\text{HIGH}} + 5 \cdot N_{\text{MEDIUM}} + 2 \cdot N_{\text{LOW}})\right)$$

| Severity | Deduction Weight | Example Impact |
|---|---|---|
| **CRITICAL** | -20 pts | `privileged: true`, host root mount, embedded secret |
| **HIGH** | -10 pts | `hostNetwork: true`, missing non-root user, dangerous ports |
| **MEDIUM** | -5 pts | `latest` image tag, missing resource limits, missing seccomp |
| **LOW** | -2 pts | Missing `HEALTHCHECK`, `ADD` instead of `COPY` |
| **INFO** | 0 pts | Informational notices |

The score is clamped at `0` and will never be negative.

---

## 9. CIS Benchmark Mapping Methodology

All CIS benchmark references correspond strictly to verified controls from:
- **CIS Docker Benchmark v1.6.0** (Controls 4.1, 4.3, 4.4, 4.5, 4.6, 4.9, 5.1, 5.3, 5.4, 5.5, 5.9, 5.10, 5.13, 5.14, 5.15, 5.16, 5.31)
- **CIS Kubernetes Benchmark v1.8.0** (Controls 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.4.1, 5.7.1, 5.7.2, 5.7.3, 5.7.4)

When an exact official benchmark control cannot be established with high confidence, the tool explicitly outputs:
`Best Practice — CIS mapping requires verification`
rather than fabricating arbitrary IDs.

---

## 10. Rule Confidence & Finding Suppression

### Finding Confidence
- `HIGH`: Deterministic AST and configuration checks (e.g. `privileged: true`).
- `MEDIUM`: Heuristic pattern matching (e.g. regex-based credential and token matching).
- `LOW`: Broad heuristic indicators.

### Finding Suppression
Suppress intentional or accepted findings using:
1. **CLI Flag**: `--ignore <RULE_IDS>`
   ```bash
   container-audit scan . --ignore K001,D004,C001
   ```
2. **Local Configuration File (`.auditignore`)**:
   Create a `.auditignore` file in your scan root:
   ```ini
   # Ignore specific intentional rules
   K001
   D009
   C012
   ```

---

## 11. Multi-Format Reporting

### 1. Terminal (Rich Console)
```bash
container-audit scan ./test-data/vulnerable
```
Displays interactive color badges, security score gauge, location tracking, and code recommendations.

### 2. JSON (Pipeline Automation)
```bash
container-audit scan ./test-data/vulnerable --format json --output reports/audit.json
```

### 3. HTML (Interactive Dashboard)
```bash
container-audit scan ./test-data/vulnerable --format html --output reports/audit.html
```

### 4. SARIF 2.1.0 (GitHub Code Scanning)
```bash
container-audit scan ./test-data/vulnerable --format sarif --output reports/audit.sarif
```

---

## 12. Trivy External Scanner Integration

When auditing container images:
```bash
container-audit image nginx:latest
```
1. The tool detects if `trivy` is installed in `PATH`.
2. If Trivy is missing, a helpful installation guide is printed without crashing.
3. If Trivy is installed, it runs `trivy image --format json <image>` and unifies all CVE vulnerabilities and misconfigurations into the standard `Finding` model.

---

## 13. Test Data Environments

Two complete test environments are provided in `test-data/`:
- `test-data/vulnerable/`: Contains intentionally insecure Dockerfiles, Compose setups, and Kubernetes manifests (produces Score < 50, Status: FAIL).
- `test-data/secure/`: Hardened configurations implementing non-root execution, dropped capabilities, pinned digests, seccomp, and resource limits (produces Score: 100, Status: PASS).

---

## 14. Automated Testing

Run the full test suite with coverage:
```bash
pytest -v
```
All 50 unit and integration tests validate Dockerfile parsing, Compose scanning, Kubernetes multi-doc AST evaluation, scoring clamping, secret masking, and report generation.

---

## 15. GitHub Actions CI/CD Integration

The tool includes a ready-to-use GitHub Actions workflow at `.github/workflows/security-scan.yml`. It:
1. Installs Python, dependencies, and Trivy.
2. Runs the unit test suite.
3. Performs automated misconfiguration audits on every commit and pull request.
4. Uploads SARIF results directly to GitHub Security Code Scanning.
5. Fails the build if any `HIGH` or `CRITICAL` findings are detected (`--fail-on HIGH`).

---

## 16. Docker Container Usage

Build the tool container:
```bash
docker build -t container-audit .
```

### Run on Linux / macOS
```bash
docker run --rm -v "$(pwd):/target" container-audit scan /target
```

### Run on Windows PowerShell
```powershell
docker run --rm -v "${PWD}:/target" container-audit scan /target
```

---

## 17. Limitations & Future Roadmap

### Current Limitations
- Dynamic runtime container behavior (e.g. syscall monitoring via eBPF) is out of scope for this static analysis tool.
- Secret detection relies on heuristic regex entropy matching; encrypted or hashed secrets might not be identified.

### Future Roadmap
- [ ] Web-based graphical dashboard (FastAPI + React).
- [ ] OPA / Rego policy engine plugin support.
- [ ] Real-time Helm chart and Kustomize rendering engine.
- [ ] Automated remediation pull request generator (`--fix`).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
