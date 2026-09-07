"""
Scanner Orchestrator.
Dispatches audit jobs to appropriate scanners, handles file discovery, and aggregates findings.
"""

from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import os
import json

from app.models import Finding, ScanResult, ScanSummary, Severity, Confidence
from app.parser import FileClassifier
from app.scoring import ScoringEngine
from app.scanners.dockerfile_scanner import DockerfileScanner
from app.scanners.compose_scanner import ComposeScanner
from app.scanners.kubernetes_scanner import KubernetesScanner
from app.scanners.image_scanner import ImageScanner

IGNORED_DIRECTORIES = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
    "reports",
}


def load_auditignore(target_dir: str) -> List[str]:
    """Look for .auditignore in target directory and load rule IDs to suppress."""
    ignore_path = Path(target_dir) / ".auditignore"
    ignored: List[str] = []
    if ignore_path.is_file():
        try:
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ignored.append(line.upper())
        except Exception:
            pass
    return ignored


class ScannerOrchestrator:
    """Coordinates multi-file scanning, rule suppression, and scoring."""

    def __init__(
        self,
        ignore_rules: Optional[List[str]] = None,
        enable_trivy: bool = True,
        scoring_engine: Optional[ScoringEngine] = None,
    ):
        self.ignore_rules = set(r.upper() for r in (ignore_rules or []))
        self.enable_trivy = enable_trivy
        self.scoring_engine = scoring_engine or ScoringEngine()

    def scan_path(self, target_path_str: str) -> ScanResult:
        """Scan a file or directory recursively."""
        target_path = Path(target_path_str)

        # Merge .auditignore if scanning a directory
        if target_path.is_dir():
            file_ignores = load_auditignore(target_path_str)
            self.ignore_rules.update(file_ignores)

        if not target_path.exists():
            return ScanResult(
                target=target_path_str,
                summary=ScanSummary(score=0, passed=False),
                errors=[f"Target path does not exist: {target_path_str}"],
            )

        if target_path.is_file():
            return self._scan_single_file(str(target_path))

        # Discover all relevant files in directory
        discovered_files = self._discover_files(target_path)
        all_findings: List[Finding] = []
        scanned_files_list: List[str] = []
        errors: List[str] = []
        container_count = 0

        for file_path, file_type in discovered_files:
            try:
                scanned_files_list.append(file_path)
                file_findings = self._dispatch_scan(file_path, file_type)
                all_findings.extend(file_findings)
                # Count containers found
                container_count += len(set(f.container for f in file_findings if f.container))
            except Exception as e:
                errors.append(f"Error scanning {file_path}: {str(e)}")

        # Deduplicate findings
        unique_findings = self._deduplicate_findings(all_findings)

        # Calculate score and build summary
        summary = self.scoring_engine.summarize(
            unique_findings,
            files_scanned=len(scanned_files_list),
            containers_scanned=container_count,
        )

        return ScanResult(
            target=target_path_str,
            score=summary.score,
            summary=summary,
            findings=unique_findings,
            files_scanned=scanned_files_list,
            errors=errors,
        )

    def scan_dockerfile(self, file_path: str) -> ScanResult:
        """Explicitly audit a single Dockerfile."""
        scanner = DockerfileScanner(file_path, ignore_rules=list(self.ignore_rules))
        try:
            findings = scanner.scan()
            errors = []
        except Exception as e:
            findings = []
            errors = [f"Failed to scan Dockerfile {file_path}: {str(e)}"]

        summary = self.scoring_engine.summarize(findings, files_scanned=1, containers_scanned=1)
        return ScanResult(
            target=file_path,
            score=summary.score,
            summary=summary,
            findings=findings,
            files_scanned=[file_path],
            errors=errors,
        )

    def scan_compose(self, file_path: str) -> ScanResult:
        """Explicitly audit a Docker Compose file."""
        scanner = ComposeScanner(file_path, ignore_rules=list(self.ignore_rules))
        try:
            findings = scanner.scan()
            errors = []
        except Exception as e:
            findings = []
            errors = [f"Failed to scan Compose file {file_path}: {str(e)}"]

        containers = len(set(f.resource for f in findings if f.resource))
        summary = self.scoring_engine.summarize(findings, files_scanned=1, containers_scanned=containers)
        return ScanResult(
            target=file_path,
            score=summary.score,
            summary=summary,
            findings=findings,
            files_scanned=[file_path],
            errors=errors,
        )

    def scan_kubernetes(self, file_path: str) -> ScanResult:
        """Explicitly audit a Kubernetes YAML manifest."""
        scanner = KubernetesScanner(file_path, ignore_rules=list(self.ignore_rules))
        try:
            findings = scanner.scan()
            errors = []
        except Exception as e:
            findings = []
            errors = [f"Failed to scan Kubernetes manifest {file_path}: {str(e)}"]

        containers = len(set(f.container for f in findings if f.container))
        summary = self.scoring_engine.summarize(findings, files_scanned=1, containers_scanned=containers)
        return ScanResult(
            target=file_path,
            score=summary.score,
            summary=summary,
            findings=findings,
            files_scanned=[file_path],
            errors=errors,
        )

    def scan_image(self, image_name: str) -> ScanResult:
        """Scan a container image using Trivy integration."""
        scanner = ImageScanner(image_name, ignore_rules=list(self.ignore_rules))
        findings, errors, trivy_available = scanner.scan()

        summary = self.scoring_engine.summarize(findings, files_scanned=0, containers_scanned=1)
        return ScanResult(
            target=image_name,
            score=summary.score,
            summary=summary,
            findings=findings,
            files_scanned=[],
            errors=errors,
            metadata={"trivy_available": trivy_available, "image": image_name},
        )

    def _scan_single_file(self, file_path: str) -> ScanResult:
        """Determine type and scan single file."""
        file_type = FileClassifier.classify_file(file_path)
        if file_type == "dockerfile":
            return self.scan_dockerfile(file_path)
        elif file_type == "compose":
            return self.scan_compose(file_path)
        elif file_type == "kubernetes":
            return self.scan_kubernetes(file_path)
        else:
            return ScanResult(
                target=file_path,
                summary=ScanSummary(score=100, passed=True, files_scanned=1),
                files_scanned=[file_path],
                errors=[f"File '{file_path}' is not a recognized Dockerfile, Compose, or Kubernetes file."],
            )

    def _discover_files(self, directory: Path) -> List[tuple[str, str]]:
        """Recursively discover files and classify their type."""
        discovered: List[tuple[str, str]] = []

        for root, dirs, files in os.walk(directory):
            # Prune ignored directories in-place
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]

            for file_name in files:
                file_path = str(Path(root) / file_name)
                f_type = FileClassifier.classify_file(file_path)
                if f_type in {"dockerfile", "compose", "kubernetes"}:
                    discovered.append((file_path, f_type))

        return discovered

    def _dispatch_scan(self, file_path: str, file_type: str) -> List[Finding]:
        """Dispatch scan to appropriate engine."""
        if file_type == "dockerfile":
            return DockerfileScanner(file_path, ignore_rules=list(self.ignore_rules)).scan()
        elif file_type == "compose":
            return ComposeScanner(file_path, ignore_rules=list(self.ignore_rules)).scan()
        elif file_type == "kubernetes":
            return KubernetesScanner(file_path, ignore_rules=list(self.ignore_rules)).scan()
        return []

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings based on ID, file, line, and container."""
        seen: Set[str] = set()
        unique: List[Finding] = []

        for f in findings:
            key = f"{f.id}::{f.file}::{f.line}::{f.container or ''}::{f.resource or ''}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
