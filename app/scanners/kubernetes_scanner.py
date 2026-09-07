"""
Kubernetes Manifest Security Scanner.
Audits multi-document Kubernetes YAML resources (Pods, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs)
for security misconfigurations and CIS Kubernetes Benchmark recommendations.
"""

from typing import List, Dict, Any, Optional, Tuple
import re
from pathlib import Path

from app.models import Finding, Severity, Confidence
from app.parser import YamlParser, get_line_number
from app.cis_mapper import get_cis_reference
from app.remediation import get_remediation_details
from app.scanners.dockerfile_scanner import mask_secret, SECRET_PATTERNS

DANGEROUS_K8S_CAPS = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_OVERRIDE",
    "SYS_RAWIO",
    "NET_RAW",
    "SYS_CHROOT",
}

SENSITIVE_K8S_HOST_PATHS = {
    "/",
    "/etc",
    "/root",
    "/var/run",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc",
    "/sys",
    "/dev",
}


class KubernetesScanner:
    """Scans Kubernetes YAML manifests for security misconfigurations."""

    def __init__(self, file_path: str, ignore_rules: Optional[List[str]] = None):
        self.file_path = file_path
        self.ignore_rules = set(r.upper() for r in (ignore_rules or []))

    def scan(self, content: Optional[str] = None) -> List[Finding]:
        """Perform security scan on Kubernetes manifest file or content."""
        if content is not None:
            documents = YamlParser.parse_content(content)
        else:
            documents = YamlParser.parse_file(self.file_path)

        if not documents:
            return []

        findings: List[Finding] = []

        for doc in documents:
            if not isinstance(doc, dict):
                continue
            self._audit_document(doc, findings)

        # Filter suppressed rules
        return [f for f in findings if f.id.upper() not in self.ignore_rules]

    def _audit_document(self, doc: Dict[str, Any], findings: List[Finding]):
        """Audit a single Kubernetes YAML document."""
        kind = doc.get("kind", "Unknown")
        metadata = doc.get("metadata", {})
        resource_name = metadata.get("name", "unnamed-resource") if isinstance(metadata, dict) else "unnamed-resource"
        doc_line = get_line_number(doc, default=1)

        pod_spec, spec_line = self._extract_pod_spec(doc)
        if pod_spec is None:
            # If not a pod-like resource, check ConfigMaps/Secrets/other for raw secrets (K015)
            self._check_manifest_secrets(doc, resource_name, doc_line, findings)
            return

        # 1. Pod-level checks
        self._audit_pod_spec(pod_spec, resource_name, kind, spec_line, findings)

        # 2. Container-level checks
        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])
        all_containers: List[Tuple[str, Dict[str, Any]]] = []

        if isinstance(containers, list):
            for c in containers:
                if isinstance(c, dict):
                    all_containers.append(("container", c))

        if isinstance(init_containers, list):
            for c in init_containers:
                if isinstance(c, dict):
                    all_containers.append(("initContainer", c))

        for c_type, container in all_containers:
            container_name = container.get("name", "unnamed-container")
            c_line = get_line_number(container, default=spec_line)
            self._audit_container(container, container_name, resource_name, kind, pod_spec, c_line, findings)

    def _extract_pod_spec(self, doc: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int]:
        """Extract pod specification from various Kubernetes resource types."""
        kind = doc.get("kind", "")
        spec = doc.get("spec")
        if not isinstance(spec, dict):
            return None, 1

        if kind == "Pod":
            return spec, get_line_number(spec, default=1)

        if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
            template = spec.get("template", {})
            if isinstance(template, dict):
                t_spec = template.get("spec", {})
                if isinstance(t_spec, dict):
                    return t_spec, get_line_number(t_spec, default=get_line_number(template, 1))

        if kind == "CronJob":
            job_template = spec.get("jobTemplate", {})
            if isinstance(job_template, dict):
                j_spec = job_template.get("spec", {})
                if isinstance(j_spec, dict):
                    t_spec = j_spec.get("template", {}).get("spec", {})
                    if isinstance(t_spec, dict):
                        return t_spec, get_line_number(t_spec, default=1)

        # Direct containers in spec
        if "containers" in spec and isinstance(spec["containers"], list):
            return spec, get_line_number(spec, default=1)

        return None, 1

    def _audit_pod_spec(
        self,
        pod_spec: Dict[str, Any],
        resource_name: str,
        kind: str,
        line: int,
        findings: List[Finding],
    ):
        """Audit pod-level security parameters."""
        # Rule K004: hostNetwork
        if pod_spec.get("hostNetwork") is True:
            findings.append(self._create_finding(
                rule_id="K004",
                title="hostNetwork Enabled",
                description=f"{kind} '{resource_name}' has 'hostNetwork: true' enabled.",
                resource=resource_name,
                line=line,
            ))

        # Rule K005: hostPID
        if pod_spec.get("hostPID") is True:
            findings.append(self._create_finding(
                rule_id="K005",
                title="hostPID Enabled",
                description=f"{kind} '{resource_name}' has 'hostPID: true' enabled.",
                resource=resource_name,
                line=line,
            ))

        # Rule K006: hostIPC
        if pod_spec.get("hostIPC") is True:
            findings.append(self._create_finding(
                rule_id="K006",
                title="hostIPC Enabled",
                description=f"{kind} '{resource_name}' has 'hostIPC: true' enabled.",
                resource=resource_name,
                line=line,
            ))

        # Rule K007: Dangerous hostPath volumes
        volumes = pod_spec.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                if not isinstance(vol, dict):
                    continue
                host_path_dict = vol.get("hostPath")
                if isinstance(host_path_dict, dict):
                    h_path = str(host_path_dict.get("path", "")).strip()
                    v_name = vol.get("name", "unnamed-vol")
                    v_line = get_line_number(vol, default=line)

                    norm_path = h_path.rstrip("/\\")
                    if norm_path == "" and (h_path == "/" or h_path == "\\"):
                        norm_path = "/"

                    is_dangerous = (
                        norm_path in SENSITIVE_K8S_HOST_PATHS
                        or any(norm_path.startswith(sp + "/") for sp in SENSITIVE_K8S_HOST_PATHS if sp != "/")
                    )

                    if is_dangerous or norm_path == "/":
                        findings.append(self._create_finding(
                            rule_id="K007",
                            title="Dangerous hostPath Volume Mount",
                            description=f"{kind} '{resource_name}' mounts sensitive hostPath volume '{v_name}' -> '{h_path}'.",
                            resource=resource_name,
                            line=v_line,
                        ))

        # Rule K013: Pod-level seccomp profile
        pod_sec_ctx = pod_spec.get("securityContext", {})
        pod_has_seccomp = False
        if isinstance(pod_sec_ctx, dict):
            seccomp = pod_sec_ctx.get("seccompProfile", {})
            if isinstance(seccomp, dict) and seccomp.get("type") in {"RuntimeDefault", "Localhost"}:
                pod_has_seccomp = True

        # Store in pod spec for container inheritance check
        pod_spec["__has_pod_seccomp__"] = pod_has_seccomp
        pod_spec["__pod_run_as_non_root__"] = (
            isinstance(pod_sec_ctx, dict) and pod_sec_ctx.get("runAsNonRoot") is True
        )

    def _audit_container(
        self,
        container: Dict[str, Any],
        container_name: str,
        resource_name: str,
        kind: str,
        pod_spec: Dict[str, Any],
        line: int,
        findings: List[Finding],
    ):
        """Audit container-level security configurations."""
        sec_ctx = container.get("securityContext")

        # Rule K014: container securityContext missing
        if sec_ctx is None or not isinstance(sec_ctx, dict):
            findings.append(self._create_finding(
                rule_id="K014",
                title="Container securityContext Missing",
                description=f"{kind} '{resource_name}' container '{container_name}' has no securityContext defined.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))
            sec_ctx = {}

        # Rule K001: privileged container
        if sec_ctx.get("privileged") is True:
            findings.append(self._create_finding(
                rule_id="K001",
                title="Privileged Container Enabled",
                description=f"{kind} '{resource_name}' container '{container_name}' runs in privileged mode.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))

        # Rule K002: runAsNonRoot not enabled or root UID
        c_non_root = sec_ctx.get("runAsNonRoot")
        p_non_root = pod_spec.get("__pod_run_as_non_root__", False)
        run_as_user = sec_ctx.get("runAsUser")

        if run_as_user == 0:
            findings.append(self._create_finding(
                rule_id="K002",
                title="Container Configured Explicitly as Root (runAsUser: 0)",
                description=f"{kind} '{resource_name}' container '{container_name}' explicitly sets runAsUser: 0.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))
        elif not (c_non_root is True or (c_non_root is None and p_non_root)):
            findings.append(self._create_finding(
                rule_id="K002",
                title="runAsNonRoot Not Enabled",
                description=f"{kind} '{resource_name}' container '{container_name}' does not enforce runAsNonRoot.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))

        # Rule K003: allowPrivilegeEscalation
        allow_priv_esc = sec_ctx.get("allowPrivilegeEscalation")
        if allow_priv_esc is True:
            findings.append(self._create_finding(
                rule_id="K003",
                title="allowPrivilegeEscalation Enabled",
                description=f"{kind} '{resource_name}' container '{container_name}' explicitly enables allowPrivilegeEscalation.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))
        elif allow_priv_esc is None and not sec_ctx.get("privileged"):
            findings.append(self._create_finding(
                rule_id="K003",
                title="allowPrivilegeEscalation Not Explicitly Disabled",
                description=f"{kind} '{resource_name}' container '{container_name}' does not explicitly set allowPrivilegeEscalation: false.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))

        # Rule K008: Image latest tag
        image_str = str(container.get("image", "")).strip()
        if image_str:
            self._check_image_tag(image_str, resource_name, container_name, kind, line, findings)

        # Linux Capabilities (K009, K010)
        caps = sec_ctx.get("capabilities", {})
        if isinstance(caps, dict):
            add_caps = caps.get("add", [])
            if isinstance(add_caps, list):
                caps_upper = [str(c).upper() for c in add_caps]
                if "ALL" in caps_upper:
                    findings.append(self._create_finding(
                        rule_id="K009",
                        title="Excessive Added Capabilities (ALL)",
                        description=f"{kind} '{resource_name}' container '{container_name}' adds 'ALL' capabilities.",
                        resource=resource_name,
                        container=container_name,
                        line=line,
                    ))
                for cap in caps_upper:
                    if cap in DANGEROUS_K8S_CAPS:
                        findings.append(self._create_finding(
                            rule_id="K010",
                            title=f"Dangerous Capability Added: {cap}",
                            description=f"{kind} '{resource_name}' container '{container_name}' adds dangerous capability '{cap}'.",
                            resource=resource_name,
                            container=container_name,
                            line=line,
                        ))

        # Rule K011: readOnlyRootFilesystem
        ro_root = sec_ctx.get("readOnlyRootFilesystem")
        if ro_root is False:
            findings.append(self._create_finding(
                rule_id="K011",
                title="readOnlyRootFilesystem Explicitly Disabled",
                description=f"{kind} '{resource_name}' container '{container_name}' explicitly sets readOnlyRootFilesystem: false.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))
        elif ro_root is None:
            findings.append(self._create_finding(
                rule_id="K011",
                title="readOnlyRootFilesystem Not Enabled",
                description=f"{kind} '{resource_name}' container '{container_name}' does not configure readOnlyRootFilesystem: true.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))

        # Rule K012: Resource requests and limits
        resources = container.get("resources", {})
        requests = resources.get("requests", {}) if isinstance(resources, dict) else {}
        limits = resources.get("limits", {}) if isinstance(resources, dict) else {}

        has_cpu_req = "cpu" in requests
        has_mem_req = "memory" in requests
        has_cpu_lim = "cpu" in limits
        has_mem_lim = "memory" in limits

        if not (has_cpu_req and has_mem_req and has_cpu_lim and has_mem_lim):
            findings.append(self._create_finding(
                rule_id="K012",
                title="Missing Resource Requests and Limits",
                description=f"{kind} '{resource_name}' container '{container_name}' lacks full CPU/Memory requests and limits.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))

        # Rule K013: Seccomp profile check
        c_seccomp = sec_ctx.get("seccompProfile", {})
        c_has_seccomp = isinstance(c_seccomp, dict) and c_seccomp.get("type") in {"RuntimeDefault", "Localhost"}
        p_has_seccomp = pod_spec.get("__has_pod_seccomp__", False)

        if not (c_has_seccomp or p_has_seccomp):
            findings.append(self._create_finding(
                rule_id="K013",
                title="Missing Seccomp Profile",
                description=f"{kind} '{resource_name}' container '{container_name}' does not configure RuntimeDefault seccomp profile.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))

        # Rule K015: Secrets in container environment
        env = container.get("env", [])
        if isinstance(env, list):
            for env_var in env:
                if not isinstance(env_var, dict):
                    continue
                var_name = str(env_var.get("name", ""))
                var_val = env_var.get("value")
                if var_val is not None:
                    var_str = f"{var_name}={var_val}"
                    for pattern, secret_type in SECRET_PATTERNS:
                        if re.search(pattern, var_str):
                            masked_note = f" Detected value: '{mask_secret(str(var_val))}'."
                            findings.append(self._create_finding(
                                rule_id="K015",
                                title="Secrets Embedded Directly in Manifest",
                                description=f"{kind} '{resource_name}' container '{container_name}' embeds plaintext secret ({secret_type}) in env var '{var_name}'.{masked_note}",
                                resource=resource_name,
                                container=container_name,
                                line=get_line_number(env_var, default=line),
                                confidence=Confidence.MEDIUM,
                            ))
                            break

    def _check_image_tag(
        self,
        image_str: str,
        resource_name: str,
        container_name: str,
        kind: str,
        line: int,
        findings: List[Finding],
    ):
        """Check container image tag."""
        if "@sha256:" in image_str:
            return

        if ":" not in image_str:
            findings.append(self._create_finding(
                rule_id="K008",
                title="Container Image Uses Implicit 'latest' Tag",
                description=f"{kind} '{resource_name}' container '{container_name}' image '{image_str}' has no tag.",
                resource=resource_name,
                container=container_name,
                line=line,
            ))
        else:
            _, tag = image_str.split(":", 1)
            if tag.lower() in {"latest", "stable", "edge"}:
                findings.append(self._create_finding(
                    rule_id="K008",
                    title="Container Image Uses 'latest' Tag",
                    description=f"{kind} '{resource_name}' container '{container_name}' image specifies mutable tag '{tag}'.",
                    resource=resource_name,
                    container=container_name,
                    line=line,
                ))

    def _check_manifest_secrets(
        self,
        doc: Dict[str, Any],
        resource_name: str,
        line: int,
        findings: List[Finding],
    ):
        """Audit non-pod manifests (e.g. ConfigMaps) for accidental secret leaks."""
        data = doc.get("data", {})
        if isinstance(data, dict):
            for k, v in data.items():
                v_str = f"{k}={v}"
                for pattern, secret_type in SECRET_PATTERNS:
                    if re.search(pattern, v_str):
                        masked_note = f" Detected value: '{mask_secret(str(v))}'."
                        findings.append(self._create_finding(
                            rule_id="K015",
                            title="Secrets Embedded Directly in Manifest",
                            description=f"Resource '{resource_name}' ({doc.get('kind')}) contains potential plaintext secret ({secret_type}) in key '{k}'.{masked_note}",
                            resource=resource_name,
                            line=line,
                            confidence=Confidence.MEDIUM,
                        ))
                        break

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
        """Create standard Finding instance for Kubernetes rules."""
        remediation_meta = get_remediation_details(rule_id)
        cis_ref = get_cis_reference(rule_id)

        severity_map = {
            "K001": Severity.CRITICAL,
            "K002": Severity.HIGH,
            "K003": Severity.HIGH,
            "K004": Severity.HIGH,
            "K005": Severity.HIGH,
            "K006": Severity.HIGH,
            "K007": Severity.CRITICAL,
            "K008": Severity.MEDIUM,
            "K009": Severity.CRITICAL,
            "K010": Severity.HIGH,
            "K011": Severity.MEDIUM,
            "K012": Severity.MEDIUM,
            "K013": Severity.MEDIUM,
            "K014": Severity.MEDIUM,
            "K015": Severity.CRITICAL,
        }

        category_map = {
            "K001": "PRIVILEGE_ESCALATION",
            "K002": "ACCESS_CONTROL",
            "K003": "PRIVILEGE_ESCALATION",
            "K004": "NETWORK_SECURITY",
            "K005": "PRIVILEGE_ESCALATION",
            "K006": "ACCESS_CONTROL",
            "K007": "PRIVILEGE_ESCALATION",
            "K008": "IMAGE_INTEGRITY",
            "K009": "PRIVILEGE_ESCALATION",
            "K010": "PRIVILEGE_ESCALATION",
            "K011": "HARDENING",
            "K012": "HARDENING",
            "K013": "HARDENING",
            "K014": "HARDENING",
            "K015": "SECRETS",
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
