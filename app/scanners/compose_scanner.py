"""
Docker Compose Security Scanner.
Audits docker-compose configurations for privilege escalations, dangerous mounts, and CIS recommendations.
"""

from typing import List, Dict, Any, Optional
import re
from pathlib import Path

from app.models import Finding, Severity, Confidence
from app.parser import YamlParser, get_line_number
from app.cis_mapper import get_cis_reference
from app.remediation import get_remediation_details
from app.scanners.dockerfile_scanner import mask_secret, SECRET_PATTERNS

# Sensitive host paths that should never be mounted directly into containers
SENSITIVE_HOST_PATHS = {
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
}

# Sensitive ports commonly abused if exposed to 0.0.0.0
SENSITIVE_PORTS = {
    22: "SSH",
    2375: "Docker Daemon (unencrypted)",
    2376: "Docker Daemon TLS",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Store",
    27017: "MongoDB Database",
    9200: "Elasticsearch",
    11211: "Memcached",
}


class ComposeScanner:
    """Scans Docker Compose files for security misconfigurations."""

    def __init__(self, file_path: str, ignore_rules: Optional[List[str]] = None):
        self.file_path = file_path
        self.ignore_rules = set(r.upper() for r in (ignore_rules or []))

    def scan(self, content: Optional[str] = None) -> List[Finding]:
        """Perform security scan on Docker Compose file."""
        if content is not None:
            documents = YamlParser.parse_content(content)
        else:
            documents = YamlParser.parse_file(self.file_path)

        if not documents:
            return []

        findings: List[Finding] = []

        for doc in documents:
            services = doc.get("services", {})
            if not isinstance(services, dict):
                continue

            for service_name, service_config in services.items():
                if not isinstance(service_config, dict):
                    continue

                line = get_line_number(service_config, default=1)
                self._audit_service(service_name, service_config, line, findings)

        # Filter suppressed rules
        return [f for f in findings if f.id.upper() not in self.ignore_rules]

    def _audit_service(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        service_line: int,
        findings: List[Finding],
    ):
        """Audit an individual service definition."""
        # Rule C001: privileged: true
        if service_config.get("privileged") is True:
            findings.append(self._create_finding(
                rule_id="C001",
                title="Privileged Container Enabled",
                description=f"Service '{service_name}' has 'privileged: true' enabled.",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))

        # Rule C002: network_mode: host
        net_mode = str(service_config.get("network_mode", "")).strip().lower()
        if net_mode == "host":
            findings.append(self._create_finding(
                rule_id="C002",
                title="Host Network Mode Enabled",
                description=f"Service '{service_name}' shares the host network namespace via 'network_mode: host'.",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))

        # Rule C003: pid: host
        pid_mode = str(service_config.get("pid", "")).strip().lower()
        if pid_mode == "host":
            findings.append(self._create_finding(
                rule_id="C003",
                title="Host PID Namespace Shared",
                description=f"Service '{service_name}' shares the host PID namespace ('pid: host').",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))

        # Rule C004: ipc: host
        ipc_mode = str(service_config.get("ipc", "")).strip().lower()
        if ipc_mode == "host":
            findings.append(self._create_finding(
                rule_id="C004",
                title="Host IPC Namespace Shared",
                description=f"Service '{service_name}' shares the host IPC namespace ('ipc: host').",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))

        # Volume mounts checks (C005, C006)
        volumes = service_config.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                self._check_volume_mount(service_name, vol, service_line, findings)

        # Rule C007: cap_add: ALL
        cap_adds = service_config.get("cap_add", [])
        if isinstance(cap_adds, list):
            caps_upper = [str(c).upper() for c in cap_adds]
            if "ALL" in caps_upper:
                findings.append(self._create_finding(
                    rule_id="C007",
                    title="Excessive Linux Capabilities (cap_add: ALL)",
                    description=f"Service '{service_name}' adds ALL Linux capabilities.",
                    resource=service_name,
                    container=service_name,
                    line=service_line,
                ))

        # Rule C008: apparmor / seccomp disabled
        security_opts = service_config.get("security_opt", [])
        if isinstance(security_opts, list):
            for opt in security_opts:
                opt_str = str(opt).lower()
                if "seccomp:unconfined" in opt_str or "apparmor:unconfined" in opt_str:
                    findings.append(self._create_finding(
                        rule_id="C008",
                        title="AppArmor or Seccomp Disabled",
                        description=f"Service '{service_name}' disables security confinement ({opt}).",
                        resource=service_name,
                        container=service_name,
                        line=service_line,
                    ))

        # Rule C009: Secrets in environment variables
        self._check_environment_secrets(service_name, service_config, service_line, findings)

        # Rule C010: Image uses latest tag
        image_str = str(service_config.get("image", "")).strip()
        if image_str:
            self._check_image_tag(service_name, image_str, service_line, findings)

        # Rule C011: Missing resource limits
        self._check_resource_limits(service_name, service_config, service_line, findings)

        # Rule C012: Dangerous port exposure
        ports = service_config.get("ports", [])
        if isinstance(ports, list):
            self._check_ports(service_name, ports, service_line, findings)

    def _check_volume_mount(
        self,
        service_name: str,
        vol_entry: Any,
        service_line: int,
        findings: List[Finding],
    ):
        """Check volume mount string or dict for host root or sensitive paths."""
        host_path = ""
        if isinstance(vol_entry, str):
            # Formats: host_path:container_path[:mode]
            parts = vol_entry.split(":")
            if len(parts) >= 2:
                host_path = parts[0].strip()
        elif isinstance(vol_entry, dict):
            host_path = str(vol_entry.get("source", "")).strip()

        if not host_path:
            return

        # Normalize path
        norm_path = host_path.rstrip("/\\")
        if norm_path == "" and (host_path == "/" or host_path == "\\"):
            norm_path = "/"

        # Rule C005: Host root filesystem mount
        if norm_path == "/" or norm_path == "\\":
            findings.append(self._create_finding(
                rule_id="C005",
                title="Host Root Filesystem Mounted",
                description=f"Service '{service_name}' mounts the host root filesystem ('{host_path}').",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))
            return

        # Rule C006: Sensitive host paths
        for sensitive in SENSITIVE_HOST_PATHS:
            if norm_path == sensitive or norm_path.startswith(sensitive + "/"):
                findings.append(self._create_finding(
                    rule_id="C006",
                    title="Sensitive Host Path Mounted",
                    description=f"Service '{service_name}' mounts sensitive host path '{host_path}'.",
                    resource=service_name,
                    container=service_name,
                    line=service_line,
                ))
                break

    def _check_environment_secrets(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        service_line: int,
        findings: List[Finding],
    ):
        """Check environment variables for hardcoded secrets."""
        env = service_config.get("environment")
        env_items = []
        if isinstance(env, list):
            env_items = [str(x) for x in env]
        elif isinstance(env, dict):
            env_items = [f"{k}={v}" for k, v in env.items()]

        for item in env_items:
            for pattern, secret_type in SECRET_PATTERNS:
                match = re.search(pattern, item)
                if match:
                    masked_val = ""
                    if match.groups():
                        val = match.groups()[-1]
                        masked_val = f" Detected value: '{mask_secret(val)}'."

                    findings.append(self._create_finding(
                        rule_id="C009",
                        title="Hardcoded Secret in Environment Variable",
                        description=f"Service '{service_name}' defines potential plaintext secret ({secret_type}) in environment.{masked_val}",
                        resource=service_name,
                        container=service_name,
                        line=service_line,
                        confidence=Confidence.MEDIUM,
                    ))
                    break

    def _check_image_tag(
        self,
        service_name: str,
        image_str: str,
        service_line: int,
        findings: List[Finding],
    ):
        """Check if image uses latest tag or is untagged."""
        if "@sha256:" in image_str:
            return

        if ":" not in image_str:
            findings.append(self._create_finding(
                rule_id="C010",
                title="Image Uses Implicit 'latest' Tag",
                description=f"Service '{service_name}' image '{image_str}' has no tag and defaults to 'latest'.",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))
        else:
            _, tag = image_str.split(":", 1)
            if tag.lower() in {"latest", "stable", "edge"}:
                findings.append(self._create_finding(
                    rule_id="C010",
                    title="Image Uses 'latest' Tag",
                    description=f"Service '{service_name}' image specifies mutable tag '{tag}'.",
                    resource=service_name,
                    container=service_name,
                    line=service_line,
                ))

    def _check_resource_limits(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        service_line: int,
        findings: List[Finding],
    ):
        """Check if memory and cpu limits are configured."""
        deploy = service_config.get("deploy", {})
        resources = deploy.get("resources", {}) if isinstance(deploy, dict) else {}
        limits = resources.get("limits", {}) if isinstance(resources, dict) else {}

        has_mem_limit = "mem_limit" in service_config or ("memory" in limits)
        has_cpu_limit = "cpus" in service_config or ("cpus" in limits)

        if not (has_mem_limit and has_cpu_limit):
            findings.append(self._create_finding(
                rule_id="C011",
                title="Missing Resource Limits",
                description=f"Service '{service_name}' does not configure both CPU and Memory limits.",
                resource=service_name,
                container=service_name,
                line=service_line,
            ))

    def _check_ports(
        self,
        service_name: str,
        ports: List[Any],
        service_line: int,
        findings: List[Finding],
    ):
        """Check for dangerous ports exposed on all interfaces (0.0.0.0)."""
        for p in ports:
            port_str = str(p).strip()
            # Formats: "5432:5432", "0.0.0.0:5432:5432", "127.0.0.1:5432:5432", "5432"
            parts = port_str.split(":")
            host_ip = "0.0.0.0"
            container_port: Optional[int] = None

            if len(parts) == 1:
                # e.g. "5432" -> exposed publicly
                if parts[0].isdigit():
                    container_port = int(parts[0])
            elif len(parts) == 2:
                # e.g. "5432:5432" -> host port 5432 exposed publicly
                if parts[0].isdigit():
                    container_port = int(parts[0])
            elif len(parts) == 3:
                # e.g. "0.0.0.0:5432:5432" or "127.0.0.1:5432:5432"
                host_ip = parts[0]
                if parts[1].isdigit():
                    container_port = int(parts[1])

            if container_port in SENSITIVE_PORTS:
                # If host_ip is not restricted to localhost
                if host_ip in {"0.0.0.0", "", "*", "::"}:
                    service_desc = SENSITIVE_PORTS[container_port]
                    findings.append(self._create_finding(
                        rule_id="C012",
                        title="Dangerous Port Exposure",
                        description=f"Service '{service_name}' exposes sensitive administrative/database port {container_port} ({service_desc}) on public interfaces ({host_ip or '0.0.0.0'}).",
                        resource=service_name,
                        container=service_name,
                        line=service_line,
                    ))

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        resource: Optional[str] = None,
        container: Optional[str] = None,
        line: Optional[int] = None,
        confidence: Confidence = Confidence.HIGH,
    ) -> Finding:
        """Create standard Finding instance for Compose rules."""
        remediation_meta = get_remediation_details(rule_id)
        cis_ref = get_cis_reference(rule_id)

        severity_map = {
            "C001": Severity.CRITICAL,
            "C002": Severity.HIGH,
            "C003": Severity.HIGH,
            "C004": Severity.HIGH,
            "C005": Severity.CRITICAL,
            "C006": Severity.CRITICAL,
            "C007": Severity.CRITICAL,
            "C008": Severity.HIGH,
            "C009": Severity.CRITICAL,
            "C010": Severity.MEDIUM,
            "C011": Severity.MEDIUM,
            "C012": Severity.HIGH,
        }

        category_map = {
            "C001": "PRIVILEGE_ESCALATION",
            "C002": "NETWORK_SECURITY",
            "C003": "PRIVILEGE_ESCALATION",
            "C004": "ACCESS_CONTROL",
            "C005": "PRIVILEGE_ESCALATION",
            "C006": "PRIVILEGE_ESCALATION",
            "C007": "PRIVILEGE_ESCALATION",
            "C008": "HARDENING",
            "C009": "SECRETS",
            "C010": "IMAGE_INTEGRITY",
            "C011": "HARDENING",
            "C012": "NETWORK_SECURITY",
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
            resource=resource,
            container=container,
            line=line,
            cis_reference=cis_ref,
            remediation=remediation_meta["remediation"],
            secure_example=remediation_meta.get("secure_example"),
            source="custom",
        )
