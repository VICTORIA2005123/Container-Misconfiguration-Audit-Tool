"""
CIS Benchmark mapping layer.
Maps security audit rules to official CIS Docker & Kubernetes Benchmark controls where verified.
"""

from typing import Optional, Dict


# Verified CIS Docker Benchmark v1.6.0 & CIS Kubernetes Benchmark v1.8.0 mappings
CIS_MAPPINGS: Dict[str, Dict[str, str]] = {
    # Dockerfile Rules
    "D001": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.1",
        "title": "Ensure a user for the container has been created",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.1",
    },
    "D002": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.3",
        "title": "Ensure that containers use specific tags instead of 'latest'",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.3",
    },
    "D003": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.1",
        "title": "Ensure a user for the container has been created",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.1",
    },
    "D004": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.4",
        "title": "Ensure images are scanned and secrets are not included in Dockerfiles",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.4",
    },
    "D005": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.5",
        "title": "Ensure SSH is not run inside containers",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.5",
    },
    "D006": {
        "benchmark": "Best Practice",
        "control": "N/A",
        "title": "Avoid dangerous system modifications and excessive file permissions",
        "reference": "Best Practice - CIS mapping requires verification",
    },
    "D007": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.9",
        "title": "Ensure COPY is used instead of ADD in Dockerfiles",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.9",
    },
    "D008": {
        "benchmark": "Best Practice",
        "control": "N/A",
        "title": "Ensure safe package installation practices",
        "reference": "Best Practice - CIS mapping requires verification",
    },
    "D009": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.6",
        "title": "Ensure HEALTHCHECK instructions have been added to the container image",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.6",
    },
    "D010": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.3",
        "title": "Ensure unpinned base image floating tags are avoided",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.3",
    },

    # Docker Compose Rules
    "C001": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.4",
        "title": "Ensure privileged containers are not used",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.4",
    },
    "C002": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.9",
        "title": "Ensure the host's network namespace is not shared",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.9",
    },
    "C003": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.15",
        "title": "Ensure the host's process namespace is not shared",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.15",
    },
    "C004": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.16",
        "title": "Ensure the host's IPC namespace is not shared",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.16",
    },
    "C005": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.5",
        "title": "Ensure sensitive host system directories are not mounted",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.5",
    },
    "C006": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.31",
        "title": "Ensure the Docker socket is not mounted inside containers",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.31",
    },
    "C007": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.3",
        "title": "Ensure Linux capabilities are restricted and not set to ALL",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.3",
    },
    "C008": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.1",
        "title": "Ensure AppArmor / Seccomp profiles are enabled",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.1",
    },
    "C009": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.14",
        "title": "Ensure environment variables do not contain raw secrets",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.14",
    },
    "C010": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "4.3",
        "title": "Ensure images use immutable version tags",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 4.3",
    },
    "C011": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.10",
        "title": "Ensure memory usage for container is limited",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.10",
    },
    "C012": {
        "benchmark": "CIS Docker Benchmark v1.6.0",
        "control": "5.13",
        "title": "Ensure incoming traffic is bound to a specific host interface",
        "reference": "CIS Docker Benchmark v1.6.0 - Control 5.13",
    },

    # Kubernetes Rules
    "K001": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.1",
        "title": "Minimize the admission of privileged containers",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.1",
    },
    "K002": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.6",
        "title": "Minimize the admission of root containers (runAsNonRoot)",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.6",
    },
    "K003": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.5",
        "title": "Minimize the admission of containers with allowPrivilegeEscalation",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.5",
    },
    "K004": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.4",
        "title": "Minimize the admission of hostNetwork containers",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.4",
    },
    "K005": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.3",
        "title": "Minimize the admission of hostPID containers",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.3",
    },
    "K006": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.2",
        "title": "Minimize the admission of hostIPC containers",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.2",
    },
    "K007": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.8",
        "title": "Minimize the admission of containers with dangerous hostPath volumes",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.8",
    },
    "K008": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.7.4",
        "title": "Ensure container images do not use the 'latest' tag",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.7.4",
    },
    "K009": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.7",
        "title": "Minimize the admission of containers with added capabilities (ALL)",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.7",
    },
    "K010": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.7",
        "title": "Minimize the admission of containers with NET_ADMIN/SYS_ADMIN capabilities",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.7",
    },
    "K011": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.2.9",
        "title": "Minimize the admission of containers with readOnlyRootFilesystem disabled",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.2.9",
    },
    "K012": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.7.1",
        "title": "Ensure CPU and memory limits are set for containers",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.7.1",
    },
    "K013": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.7.2",
        "title": "Ensure Seccomp profile is set to RuntimeDefault",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.7.2",
    },
    "K014": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.7.3",
        "title": "Ensure container securityContext is explicitly configured",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.7.3",
    },
    "K015": {
        "benchmark": "CIS Kubernetes Benchmark v1.8.0",
        "control": "5.4.1",
        "title": "Prefer using Secrets over environment variables or ConfigMaps for sensitive data",
        "reference": "CIS Kubernetes Benchmark v1.8.0 - Control 5.4.1",
    },
}


def get_cis_reference(rule_id: str) -> str:
    """Return verified CIS benchmark reference string or fallback disclaimer."""
    mapping = CIS_MAPPINGS.get(rule_id.upper())
    if mapping and mapping.get("reference"):
        return mapping["reference"]
    return "Best Practice - CIS mapping requires verification"


def get_cis_details(rule_id: str) -> Optional[Dict[str, str]]:
    """Return dictionary with detailed CIS benchmark data."""
    return CIS_MAPPINGS.get(rule_id.upper())
