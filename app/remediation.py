"""
Remediation Engine for Container Misconfiguration Audit Tool.
Provides clear, educational explanations and secure snippet examples for container security findings.
"""

from typing import Dict, Any, Optional

REMEDIATIONS: Dict[str, Dict[str, str]] = {
    # Dockerfile Rules
    "D001": {
        "risk": "Running as root gives any process inside the container full root privileges on the container filesystem and potentially on the host if container isolation is compromised.",
        "remediation": "Explicitly define a non-root user using 'USER <username_or_uid>' instead of USER root or USER 0.",
        "secure_example": "RUN groupadd -r appuser && useradd -r -g appuser -u 10001 appuser\nUSER appuser",
    },
    "D002": {
        "risk": "The 'latest' tag is mutable and dynamic. Builds using 'latest' can introduce untested breaking changes, dependency regressions, or unforeseen vulnerabilities.",
        "remediation": "Pin container base images to an exact immutable version tag or image digest (SHA256).",
        "secure_example": "FROM python:3.12.3-slim-bookworm\n# Or with digest:\n# FROM python@sha256:abc123456789...",
    },
    "D003": {
        "risk": "When no USER instruction is specified, the container defaults to executing processes as the root user (UID 0).",
        "remediation": "Create a dedicated system user and group within the image and switch execution context using the USER instruction before CMD/ENTRYPOINT.",
        "secure_example": "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser\nCMD [\"node\", \"server.js\"]",
    },
    "D004": {
        "risk": "Hardcoded secrets (passwords, tokens, API keys, private keys) are baked into Docker image layers and can be retrieved by anyone with image pull or inspect access.",
        "remediation": "Remove hardcoded credentials from the Dockerfile. Use Docker build secrets (--mount=type=secret) or runtime environment injection via secret managers.",
        "secure_example": "# Docker BuildKit secret mount:\nRUN --mount=type=secret,id=api_key cat /run/secrets/api_key",
    },
    "D005": {
        "risk": "Running an SSH daemon inside a container increases the attack surface, violates single-responsibility container principles, and often leads to weak key management.",
        "remediation": "Remove openssh-server from the container. Use container native exec commands (e.g. 'docker exec' or 'kubectl exec') for debugging.",
        "secure_example": "# Do not install openssh-server in RUN commands.\n# Use application logs and metrics for observability.",
    },
    "D006": {
        "risk": "Excessive permissions (such as chmod 777) or manipulating /etc/shadow directly allows unprivileged local processes to tamper with system binaries or escalate privileges.",
        "remediation": "Apply the principle of least privilege. Grant minimal permissions (e.g., chmod 750/640) only to application directories.",
        "secure_example": "RUN chown -R appuser:appgroup /app && chmod 750 /app",
    },
    "D007": {
        "risk": "The ADD instruction supports remote URL fetching and automatic tar archive unpacking, which can lead to unintentional remote code execution or zip slip attacks.",
        "remediation": "Use COPY instead of ADD for copying local files and directories into the container image.",
        "secure_example": "COPY package*.json ./",
    },
    "D008": {
        "risk": "Piping unverified curl/wget web scripts directly into shell execution (curl | bash) or using --allow-unauthenticated bypasses package integrity and signature validation.",
        "remediation": "Verify package checksums and cryptographic signatures before execution, and download scripts locally before auditing and executing.",
        "secure_example": "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \\\n    && curl -fsSL https://example.com/install.sh -o install.sh \\\n    && sha256sum -c install.sh.sha256 \\\n    && sh install.sh \\\n    && rm -rf /var/lib/apt/lists/*",
    },
    "D009": {
        "risk": "Without a HEALTHCHECK instruction, the container runtime cannot automatically detect hung or deadlocked processes, preventing self-healing restarts.",
        "remediation": "Define a HEALTHCHECK instruction with reasonable interval, timeout, and retries.",
        "secure_example": "HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\\n  CMD curl -f http://localhost:8080/health || exit 1",
    },
    "D010": {
        "risk": "Unpinned or floating base image tags (e.g., 'alpine' or 'node') change automatically over time, resulting in non-deterministic builds and security regressions.",
        "remediation": "Specify a full semantic version tag (e.g., 'node:20.12.2-alpine3.19') or image digest.",
        "secure_example": "FROM node:20.12.2-alpine3.19",
    },

    # Docker Compose Rules
    "C001": {
        "risk": "Privileged containers disable all Linux security boundaries (AppArmor, Seccomp, Capabilities, cgroups), providing near-root access to the host kernel and devices.",
        "remediation": "Remove 'privileged: true'. If specific privileges are needed, selectively grant individual capabilities using 'cap_add'.",
        "secure_example": "services:\n  web:\n    image: myapp:1.0.0\n    privileged: false\n    cap_drop:\n      - ALL",
    },
    "C002": {
        "risk": "Using host networking ('network_mode: host') breaks network namespace isolation, exposing container services directly on host network interfaces.",
        "remediation": "Use bridge or user-defined overlay networks and expose only specific required application ports.",
        "secure_example": "services:\n  web:\n    image: myapp:1.0.0\n    networks:\n      - app-net\nnetworks:\n  app-net:\n    driver: bridge",
    },
    "C003": {
        "risk": "Sharing the host PID namespace ('pid: host') enables the container to see and send signals to all host processes.",
        "remediation": "Remove 'pid: host' to isolate container processes within their own PID namespace.",
        "secure_example": "services:\n  web:\n    image: myapp:1.0.0\n    # pid: host (removed)",
    },
    "C004": {
        "risk": "Sharing the host IPC namespace ('ipc: host') allows processes inside the container to access host shared memory (POSIX/SysV IPC).",
        "remediation": "Remove 'ipc: host' to keep IPC isolated.",
        "secure_example": "services:\n  web:\n    image: myapp:1.0.0\n    # ipc: host (removed)",
    },
    "C005": {
        "risk": "Mounting the host root filesystem ('/') directly into a container allows container processes to modify host system binaries, configuration, and security settings.",
        "remediation": "Never mount host root. Mount only specific non-sensitive application data directories.",
        "secure_example": "volumes:\n  - ./data:/var/lib/myapp:ro",
    },
    "C006": {
        "risk": "Mounting sensitive paths like '/var/run/docker.sock', '/etc', or '/root' provides full control over the host Docker daemon and sensitive host configuration.",
        "remediation": "Remove sensitive mounts. Avoid mounting the Docker socket unless running a trusted CI agent with dedicated protections.",
        "secure_example": "volumes:\n  - app-data:/var/app/data\nvolumes:\n  app-data:",
    },
    "C007": {
        "risk": "Granting 'cap_add: ALL' gives the container full kernel capabilities, substantially increasing the risk of kernel exploitation and container breakout.",
        "remediation": "Drop all capabilities and add only the exact minimal capabilities required by the workload.",
        "secure_example": "cap_drop:\n  - ALL\ncap_add:\n  - NET_BIND_SERVICE",
    },
    "C008": {
        "risk": "Disabling AppArmor or Seccomp ('unconfined') eliminates default syscall filtering and mandatory access controls.",
        "remediation": "Remove 'seccomp:unconfined' and 'apparmor:unconfined'. Utilize Docker default or custom seccomp profiles.",
        "secure_example": "security_opt:\n  - no-new-privileges:true",
    },
    "C009": {
        "risk": "Placing plaintext secrets in Compose files exposes credentials in version control and container inspection.",
        "remediation": "Use Docker secrets or environment variables loaded from a secure external vault.",
        "secure_example": "secrets:\n  - db_password\nsecrets:\n  db_password:\n    file: ./secrets/db_password.txt",
    },
    "C010": {
        "risk": "Images with 'latest' tag or missing tags introduce untracked changes into environments.",
        "remediation": "Specify an immutable semantic version tag for each service image.",
        "secure_example": "services:\n  web:\n    image: nginx:1.25.5-alpine",
    },
    "C011": {
        "risk": "Without memory and CPU limits, a compromised or runaway container can cause denial-of-service (DoS) on host resources.",
        "remediation": "Set resource limits under deploy.resources.limits or mem_limit/cpus.",
        "secure_example": "deploy:\n  resources:\n    limits:\n      cpus: '0.50'\n      memory: 512M",
    },
    "C012": {
        "risk": "Exposing sensitive administrative services (SSH, database, Redis, Docker socket) on 0.0.0.0 exposes them to the entire network or internet.",
        "remediation": "Bind port mappings to 127.0.0.1 for local services or use private internal networks.",
        "secure_example": "ports:\n  - \"127.0.0.1:5432:5432\"",
    },

    # Kubernetes Rules
    "K001": {
        "risk": "Privileged Kubernetes pods have unrestricted access to all host kernel features, devices, and can easily escape container confinement.",
        "remediation": "Set 'securityContext.privileged: false' in container specifications.",
        "secure_example": "securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false",
    },
    "K002": {
        "risk": "Running containers as root (UID 0) gives processes maximum in-container privileges.",
        "remediation": "Enforce 'runAsNonRoot: true' and define 'runAsUser: 10001' in pod or container securityContext.",
        "secure_example": "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001\n  runAsGroup: 10001",
    },
    "K003": {
        "risk": "Allowing privilege escalation permits a child process to gain more privileges than its parent (e.g. through setuid binaries).",
        "remediation": "Explicitly set 'allowPrivilegeEscalation: false' in the container securityContext.",
        "secure_example": "securityContext:\n  allowPrivilegeEscalation: false",
    },
    "K004": {
        "risk": "Setting 'hostNetwork: true' shares the host network namespace, allowing pods to sniff host traffic and access loopback services.",
        "remediation": "Disable hostNetwork (set to false or remove) and use Kubernetes Services and Ingress.",
        "secure_example": "spec:\n  hostNetwork: false",
    },
    "K005": {
        "risk": "Setting 'hostPID: true' shares the host process namespace, exposing all host processes to container inspection and signals.",
        "remediation": "Disable hostPID in the pod specification.",
        "secure_example": "spec:\n  hostPID: false",
    },
    "K006": {
        "risk": "Setting 'hostIPC: true' allows access to the host's inter-process communication mechanisms (shared memory).",
        "remediation": "Disable hostIPC in the pod specification.",
        "secure_example": "spec:\n  hostIPC: false",
    },
    "K007": {
        "risk": "Mounting hostPath volumes (especially '/', '/var/run', '/etc') allows direct modification of host files and privilege escalation.",
        "remediation": "Use PersistentVolumeClaims (PVCs), ConfigMaps, or emptyDir volumes instead of hostPath.",
        "secure_example": "volumes:\n  - name: data\n    emptyDir: {}",
    },
    "K008": {
        "risk": "Using 'latest' tag or omitting tags can lead to unexpected image changes, caching anomalies, and inability to trace deployed versions.",
        "remediation": "Pin container image tags to specific semantic versions or immutable image digests.",
        "secure_example": "image: registry.k8s.io/pause:3.9@sha256:7031c1b25...",
    },
    "K009": {
        "risk": "Adding 'ALL' capabilities provides the container with full Linux capability privileges, breaking isolation.",
        "remediation": "Drop ALL capabilities and selectively add only specifically needed capabilities.",
        "secure_example": "securityContext:\n  capabilities:\n    drop:\n      - ALL",
    },
    "K010": {
        "risk": "Capabilities such as SYS_ADMIN, NET_ADMIN, and SYS_PTRACE provide near-root control over kernel subsystems.",
        "remediation": "Audit and remove dangerous capabilities. Rely on unprivileged application architectures.",
        "secure_example": "securityContext:\n  capabilities:\n    drop:\n      - ALL\n    add:\n      - NET_BIND_SERVICE",
    },
    "K011": {
        "risk": "A writable root filesystem allows attackers to persist malware, download payloads, and modify binaries inside the container.",
        "remediation": "Set 'readOnlyRootFilesystem: true' and mount temporary writable directories using emptyDir.",
        "secure_example": "securityContext:\n  readOnlyRootFilesystem: true\nvolumeMounts:\n  - name: tmp\n    mountPath: /tmp",
    },
    "K012": {
        "risk": "Containers without resource requests/limits can consume unbounded CPU and Memory, risking node instability (OOM kills).",
        "remediation": "Define both requests and limits for CPU and memory.",
        "secure_example": "resources:\n  requests:\n    memory: \"64Mi\"\n    cpu: \"250m\"\n  limits:\n    memory: \"128Mi\"\n    cpu: \"500m\"",
    },
    "K013": {
        "risk": "Running without a seccomp profile allows containers to invoke any system call, broadening kernel exploit attack surfaces.",
        "remediation": "Configure seccompProfile type to 'RuntimeDefault'.",
        "secure_example": "securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
    },
    "K014": {
        "risk": "Missing container securityContext leaves security settings at permissive defaults.",
        "remediation": "Explicitly configure a hardened securityContext for all containers in the pod.",
        "secure_example": "securityContext:\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true\n  runAsNonRoot: true\n  runAsUser: 10001\n  capabilities:\n    drop:\n      - ALL\n  seccompProfile:\n    type: RuntimeDefault",
    },
    "K015": {
        "risk": "Hardcoded credentials in manifest environment variables or ConfigMaps expose sensitive data in version control and manifests.",
        "remediation": "Reference Kubernetes Secret resources via secretKeyRef or secret volumes with RBAC restrictions.",
        "secure_example": "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: app-secrets\n        key: db-password",
    },
}


def get_remediation_details(rule_id: str) -> Dict[str, str]:
    """Return remediation metadata dictionary for a rule."""
    default_remediation = {
        "risk": "Misconfiguration may compromise container isolation or host integrity.",
        "remediation": "Review container security best practices and apply principle of least privilege.",
        "secure_example": None,
    }
    return REMEDIATIONS.get(rule_id.upper(), default_remediation)
