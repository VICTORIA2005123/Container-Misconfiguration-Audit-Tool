"""
Dockerfile Security Scanner.
Audits Dockerfiles for security misconfigurations, credential leaks, and CIS recommendations.
"""

from typing import List, Dict, Any, Optional
import re
from pathlib import Path

from app.models import Finding, Severity, Confidence
from app.parser import DockerfileParser, DockerfileInstruction
from app.cis_mapper import get_cis_reference
from app.remediation import get_remediation_details


# Secret detection regex patterns
SECRET_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{3,})['\"]?", "password"),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", "api_key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", "secret"),
    (r"(?i)(auth[_-]?token|access[_-]?token|bearer[_-]?token|token)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", "token"),
    (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", "private_key"),
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----", "private_key_header"),
    (r"(?i)aws[_-]?(?:access|secret)[_-]?key[_-]?id?\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", "aws_key"),
]

# SSH package names
SSH_PACKAGES = [
    "openssh-server",
    "openssh",
    "dropbear",
    "sshd",
]

# Dangerous system modification patterns
DANGEROUS_MOD_PATTERNS = [
    (r"(?i)chmod\s+(?:-R\s+)?(?:777|a\+[rwx]{3}|u?g?o\+[rwx]{3})\s+(?:/|/etc|/root|/var|/usr|/bin|/sbin)", "chmod 777 on sensitive system path"),
    (r"(?i)(?:echo|cat|sed|tee|printf|cp|mv)\s+.*(?:/etc/shadow|/etc/gshadow|/etc/sudoers)", "direct manipulation of authentication databases"),
    (r"(?i)chmod\s+(?:-R\s+)?(?:[uUgGoOaA\+\-]*s|[0-7]?[42][0-7]{3})\s+", "setting setuid/setgid bits on binaries"),
    (r"(?i)echo\s+['\"][^'\"]*ALL=\(ALL(?::ALL)?\)\s+NOPASSWD:\s*ALL['\"]\s*>>?\s*/etc/sudoers", "passwordless sudo all configuration"),
]

# Unsafe installation patterns
UNSAFE_INSTALL_PATTERNS = [
    (r"(?i)(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh|zsh)", "piping unverified remote script directly to shell execution"),
    (r"(?i)--allow-unauthenticated", "disabling package signature authentication in apt"),
    (r"(?i)--no-check-certificate", "disabling SSL certificate verification in wget"),
    (r"(?i)curl\s+-[a-zA-Z]*k|curl\s+--insecure", "insecure SSL curl execution"),
    (r"(?i)pip\s+install\s+.*--trusted-host", "bypassing TLS verification in pip package installer"),
]


def mask_secret(value: str) -> str:
    """Mask secret value preserving only first 2 and last 1 characters if long enough."""
    val = value.strip().strip("'\"")
    if len(val) <= 4:
        return "*** [REDACTED]"
    return f"{val[:2]}***{val[-1]} [REDACTED]"


class DockerfileScanner:
    """Scans parsed Dockerfiles for security misconfigurations."""

    def __init__(self, file_path: str, ignore_rules: Optional[List[str]] = None):
        self.file_path = file_path
        self.ignore_rules = set(r.upper() for r in (ignore_rules or []))

    def scan(self, content: Optional[str] = None) -> List[Finding]:
        """Perform full security scan on Dockerfile."""
        if content is not None:
            instructions = DockerfileParser.parse_content(content)
        else:
            instructions = DockerfileParser.parse_file(self.file_path)

        if not instructions:
            return []

        findings: List[Finding] = []

        # Find all FROM stages
        stages: Dict[int, List[DockerfileInstruction]] = {}
        for inst in instructions:
            stages.setdefault(inst.stage_index, []).append(inst)

        # Audit all instructions for individual rule violations
        for inst in instructions:
            # Rule D001: Explicit Root User
            if inst.instruction == "USER":
                user_arg = inst.arguments.strip().lower()
                if user_arg in {"root", "0", "0:0", "root:root"}:
                    findings.append(self._create_finding(
                        rule_id="D001",
                        title="Explicit Root User Configured",
                        description=f"Dockerfile explicitly configures execution user as '{inst.arguments}'.",
                        line=inst.line_number,
                    ))

            # Rule D002 & D010: Base image tag validation
            if inst.instruction == "FROM":
                self._check_base_image(inst, findings)

            # Rule D004: Secrets embedded in instructions (ENV, ARG, RUN, etc.)
            self._check_secrets(inst, findings)

            # Rule D005: SSH server installation
            if inst.instruction == "RUN":
                self._check_ssh_installation(inst, findings)
                self._check_dangerous_modifications(inst, findings)
                self._check_unsafe_installations(inst, findings)

            # Rule D007: ADD instead of COPY
            if inst.instruction == "ADD":
                self._check_add_instruction(inst, findings)

        # Multi-instruction & Stage-level rules (evaluated on the final stage)
        final_stage_idx = max(stages.keys()) if stages else 1
        final_instructions = stages.get(final_stage_idx, [])

        # Rule D003: Missing Non-Root USER in final stage
        self._check_missing_user(final_instructions, findings)

        # Rule D009: Missing HEALTHCHECK instruction in final stage
        self._check_healthcheck(final_instructions, findings)

        # Filter ignored rules
        return [f for f in findings if f.id.upper() not in self.ignore_rules]

    def _check_base_image(self, inst: DockerfileInstruction, findings: List[Finding]):
        """Check for latest or unpinned floating image tags in FROM instruction."""
        # Argument format: FROM [--platform=...] <image>[:<tag>] [@<digest>] [AS <name>]
        args = inst.arguments
        # Remove flags like --platform=...
        args_clean = re.sub(r"--[a-z]+=[^\s]+\s*", "", args).strip()
        parts = args_clean.split()
        if not parts:
            return

        image_part = parts[0]
        if image_part.lower() == "scratch":
            return

        # Check for digest
        has_digest = "@sha256:" in image_part

        if not has_digest:
            if ":" not in image_part:
                # No tag specified at all (defaults to latest)
                findings.append(self._create_finding(
                    rule_id="D002",
                    title="Base Image Uses Implicit 'latest' Tag",
                    description=f"Base image '{image_part}' does not specify a version tag and defaults to 'latest'.",
                    line=inst.line_number,
                ))
            else:
                image_name, tag = image_part.split(":", 1)
                tag_lower = tag.lower()

                if tag_lower in {"latest", "stable", "edge"}:
                    findings.append(self._create_finding(
                        rule_id="D002",
                        title="Base Image Uses 'latest' Tag",
                        description=f"Base image specifies mutable tag '{tag}'.",
                        line=inst.line_number,
                    ))
                elif re.match(r"^[a-zA-Z]+$", tag) or (tag.isdigit() and len(tag) <= 2):
                    # Single major version or generic branch name (e.g. node:20 or alpine:edge or python:3)
                    findings.append(self._create_finding(
                        rule_id="D010",
                        title="Unpinned Base Image Floating Tag",
                        description=f"Base image specifies broad floating tag '{tag}' instead of a pinned version or digest.",
                        line=inst.line_number,
                    ))

    def _check_secrets(self, inst: DockerfileInstruction, findings: List[Finding]):
        """Search for hardcoded secrets in Dockerfile instructions."""
        text = f"{inst.instruction} {inst.arguments}"
        for pattern, secret_type in SECRET_PATTERNS:
            match = re.search(pattern, text)
            if match:
                # If matched group 2 (the secret value), mask it
                masked_note = ""
                if match.groups():
                    val = match.groups()[-1]
                    masked_note = f" Detected value: '{mask_secret(val)}'."

                findings.append(self._create_finding(
                    rule_id="D004",
                    title="Secrets Embedded in Dockerfile",
                    description=f"Potential hardcoded credential/secret ({secret_type}) detected.{masked_note}",
                    line=inst.line_number,
                    confidence=Confidence.MEDIUM,
                ))
                break

    def _check_ssh_installation(self, inst: DockerfileInstruction, findings: List[Finding]):
        """Detect installation of SSH servers."""
        run_args = inst.arguments.lower()
        for pkg in SSH_PACKAGES:
            pattern = rf"(?:apt-get|apt|apk|yum|dnf|zypper|pacman)\s+.*install.*(?:\s+|=){pkg}(?:\s+|$)"
            if re.search(pattern, run_args) or f"install {pkg}" in run_args or f"add {pkg}" in run_args:
                findings.append(self._create_finding(
                    rule_id="D005",
                    title="SSH Server Installed in Container",
                    description=f"Instruction installs SSH server package '{pkg}'.",
                    line=inst.line_number,
                ))
                break

    def _check_dangerous_modifications(self, inst: DockerfileInstruction, findings: List[Finding]):
        """Detect dangerous filesystem permission alterations."""
        run_args = inst.arguments
        for pattern, reason in DANGEROUS_MOD_PATTERNS:
            if re.search(pattern, run_args):
                findings.append(self._create_finding(
                    rule_id="D006",
                    title="Dangerous System Modification",
                    description=f"Instruction performs risky system permission or config modification: {reason}.",
                    line=inst.line_number,
                ))
                break

    def _check_unsafe_installations(self, inst: DockerfileInstruction, findings: List[Finding]):
        """Detect unsafe flags and pipe-to-shell patterns."""
        run_args = inst.arguments
        for pattern, reason in UNSAFE_INSTALL_PATTERNS:
            if re.search(pattern, run_args):
                findings.append(self._create_finding(
                    rule_id="D008",
                    title="Unsafe Package Installation Practice",
                    description=f"Instruction uses unsafe package installation pattern: {reason}.",
                    line=inst.line_number,
                    confidence=Confidence.HIGH,
                ))
                break

    def _check_add_instruction(self, inst: DockerfileInstruction, findings: List[Finding]):
        """Check for ADD instruction used when COPY is preferred."""
        arg = inst.arguments.strip()
        # If it's a URL or an archive intended for decompression, ADD might be intentional, but flag general local ADDs
        is_url = arg.startswith("http://") or arg.startswith("https://")
        is_tar = arg.endswith(".tar") or arg.endswith(".tar.gz") or arg.endswith(".tgz")

        if not is_url and not is_tar:
            findings.append(self._create_finding(
                rule_id="D007",
                title="ADD Instruction Used Instead of COPY",
                description="The ADD instruction was used to copy local files. COPY is safer and preferred.",
                line=inst.line_number,
            ))

    def _check_missing_user(self, final_instructions: List[DockerfileInstruction], findings: List[Finding]):
        """Check if final stage has a non-root USER instruction configured."""
        user_insts = [i for i in final_instructions if i.instruction == "USER"]
        if not user_insts:
            last_line = final_instructions[-1].line_number if final_instructions else 1
            findings.append(self._create_finding(
                rule_id="D003",
                title="Missing Non-Root USER Instruction",
                description="The Dockerfile does not specify any non-root USER instruction. The container will run as root.",
                line=last_line,
            ))
        else:
            # Check the last USER instruction in the stage
            last_user = user_insts[-1].arguments.strip().lower()
            if last_user in {"root", "0", "0:0", "root:root"}:
                # Handled by D001
                pass

    def _check_healthcheck(self, final_instructions: List[DockerfileInstruction], findings: List[Finding]):
        """Check if HEALTHCHECK instruction is present in the final stage."""
        has_healthcheck = any(i.instruction == "HEALTHCHECK" for i in final_instructions)
        if not has_healthcheck:
            last_line = final_instructions[-1].line_number if final_instructions else 1
            findings.append(self._create_finding(
                rule_id="D009",
                title="Missing HEALTHCHECK Instruction",
                description="No HEALTHCHECK instruction was defined in the final container image stage.",
                line=last_line,
            ))

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        line: Optional[int] = None,
        confidence: Confidence = Confidence.HIGH,
    ) -> Finding:
        """Helper to create standard Finding instance."""
        remediation_meta = get_remediation_details(rule_id)
        cis_ref = get_cis_reference(rule_id)

        # Determine severity from rule ID
        severity_map = {
            "D001": Severity.HIGH,
            "D002": Severity.MEDIUM,
            "D003": Severity.HIGH,
            "D004": Severity.CRITICAL,
            "D005": Severity.MEDIUM,
            "D006": Severity.HIGH,
            "D007": Severity.LOW,
            "D008": Severity.LOW,
            "D009": Severity.LOW,
            "D010": Severity.MEDIUM,
        }

        category_map = {
            "D001": "ACCESS_CONTROL",
            "D002": "IMAGE_INTEGRITY",
            "D003": "ACCESS_CONTROL",
            "D004": "SECRETS",
            "D005": "ATTACK_SURFACE",
            "D006": "PRIVILEGE_ESCALATION",
            "D007": "BEST_PRACTICE",
            "D008": "BEST_PRACTICE",
            "D009": "HARDENING",
            "D010": "IMAGE_INTEGRITY",
        }

        return Finding(
            id=rule_id,
            title=title,
            severity=severity_map.get(rule_id, Severity.MEDIUM),
            confidence=confidence,
            category=category_map.get(rule_id, "SECURITY"),
            description=description,
            risk=remediation_meta["risk"],
            file=self.file_path,
            line=line,
            cis_reference=cis_ref,
            remediation=remediation_meta["remediation"],
            secure_example=remediation_meta.get("secure_example"),
            source="custom",
        )
