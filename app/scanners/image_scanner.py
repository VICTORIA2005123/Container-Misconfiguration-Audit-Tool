"""
Trivy external scanner integration for container image and extended configuration auditing.
Detects Trivy availability, parses JSON output, and normalizes into standard Finding models.
"""

from typing import List, Tuple, Optional, Dict, Any
import subprocess
import shutil
import json
import logging

from app.models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


def is_trivy_installed() -> bool:
    """Check if trivy CLI binary is present in system PATH."""
    return shutil.which("trivy") is not None


def map_trivy_severity(sev_str: str) -> Severity:
    """Normalize Trivy severity string into Severity enum."""
    s = (sev_str or "").strip().upper()
    if s == "CRITICAL":
        return Severity.CRITICAL
    elif s == "HIGH":
        return Severity.HIGH
    elif s == "MEDIUM":
        return Severity.MEDIUM
    elif s == "LOW":
        return Severity.LOW
    else:
        return Severity.INFO


class ImageScanner:
    """Invokes external Trivy scanner and normalizes results."""

    def __init__(self, image_name: str, ignore_rules: Optional[List[str]] = None):
        self.image_name = image_name
        self.ignore_rules = set(r.upper() for r in (ignore_rules or []))

    def scan(self) -> Tuple[List[Finding], List[str], bool]:
        """
        Scan image with Trivy.
        Returns: (findings, errors, trivy_available)
        """
        if not is_trivy_installed():
            msg = (
                "Trivy is not installed. Install Trivy to enable container image "
                "and extended misconfiguration scanning (https://aquasecurity.github.io/trivy/)."
            )
            return [], [msg], False

        try:
            cmd = [
                "trivy",
                "image",
                "--format", "json",
                "--quiet",
                self.image_name,
            ]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if process.returncode != 0 and not process.stdout.strip():
                err_msg = f"Trivy scan failed with exit code {process.returncode}: {process.stderr.strip()}"
                return [], [err_msg], True

            findings = self._parse_trivy_json(process.stdout)
            return findings, [], True

        except subprocess.TimeoutExpired:
            return [], [f"Trivy scan timed out for image '{self.image_name}'."], True
        except Exception as e:
            return [], [f"Failed executing Trivy scan: {str(e)}"], True

    def _parse_trivy_json(self, raw_json: str) -> List[Finding]:
        """Parse Trivy JSON report and convert to Finding models."""
        if not raw_json.strip():
            return []

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        findings: List[Finding] = []
        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", self.image_name)
            
            # Vulnerabilities
            vulns = result.get("Vulnerabilities", [])
            for vuln in vulns:
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN_CVE")
                if vuln_id.upper() in self.ignore_rules:
                    continue

                pkg_name = vuln.get("PkgName", "unknown-package")
                installed_ver = vuln.get("InstalledVersion", "unknown")
                fixed_ver = vuln.get("FixedVersion", "N/A")
                title = vuln.get("Title") or f"Vulnerability in {pkg_name}"
                desc = vuln.get("Description", f"Vulnerability {vuln_id} detected in {pkg_name} {installed_ver}.")
                severity = map_trivy_severity(vuln.get("Severity", "UNKNOWN"))

                remediation = f"Upgrade {pkg_name} from version {installed_ver} to fixed version {fixed_ver}." if fixed_ver != "N/A" else f"Mitigate or monitor {pkg_name} version {installed_ver}."

                findings.append(
                    Finding(
                        id=vuln_id,
                        title=f"[{pkg_name}] {title[:80]}",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        category="VULNERABILITY",
                        description=desc,
                        risk=f"Known CVE {vuln_id} with severity {severity.value}. May lead to remote code execution, privilege escalation, or DoS.",
                        file=self.image_name,
                        resource=target,
                        container=self.image_name,
                        remediation=remediation,
                        source="trivy",
                    )
                )

            # Misconfigurations
            misconfigs = result.get("Misconfigurations", [])
            for mis in misconfigs:
                rule_id = mis.get("ID", "TRV_MISCONFIG")
                if rule_id.upper() in self.ignore_rules:
                    continue

                title = mis.get("Title", "Container Misconfiguration")
                desc = mis.get("Description", "")
                msg = mis.get("Message", "")
                combined_desc = f"{desc} {msg}".strip()
                severity = map_trivy_severity(mis.get("Severity", "UNKNOWN"))
                resolution = mis.get("Resolution", "Follow container security hardening guidelines.")

                findings.append(
                    Finding(
                        id=rule_id,
                        title=title,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        category="MISCONFIGURATION",
                        description=combined_desc or title,
                        risk="Security misconfiguration detected by Trivy engine.",
                        file=self.image_name,
                        resource=target,
                        container=self.image_name,
                        remediation=resolution,
                        source="trivy",
                    )
                )

        return findings
