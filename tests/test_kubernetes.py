"""
Tests for Kubernetes manifest security scanner.
"""

from app.scanners.kubernetes_scanner import KubernetesScanner
from app.models import Severity


def test_k001_privileged_container():
    content = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: vulnerable-deployment
    spec:
      replicas: 1
      template:
        spec:
          containers:
          - name: web
            image: nginx:1.25.5-alpine
            securityContext:
              privileged: true
    """
    scanner = KubernetesScanner("deployment.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K001" in rule_ids
    assert any(f.severity == Severity.CRITICAL for f in findings if f.id == "K001")


def test_k002_run_as_non_root():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: root-pod
    spec:
      containers:
      - name: app
        image: node:20.12.2-alpine
        securityContext:
          runAsUser: 0
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K002" in rule_ids


def test_k003_allow_privilege_escalation():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: priv-esc-pod
    spec:
      containers:
      - name: app
        image: node:20.12.2-alpine
        securityContext:
          allowPrivilegeEscalation: true
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K003" in rule_ids


def test_k004_k005_k006_host_namespaces():
    content = """
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      name: host-ns-ds
    spec:
      template:
        spec:
          hostNetwork: true
          hostPID: true
          hostIPC: true
          containers:
          - name: agent
            image: agent:1.0.0
    """
    scanner = KubernetesScanner("daemonset.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K004" in rule_ids
    assert "K005" in rule_ids
    assert "K006" in rule_ids


def test_k007_dangerous_hostpath():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: hostpath-pod
    spec:
      volumes:
      - name: host-root
        hostPath:
          path: /
      containers:
      - name: web
        image: nginx:1.25.5-alpine
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K007" in rule_ids
    assert any(f.severity == Severity.CRITICAL for f in findings if f.id == "K007")


def test_k008_latest_image_tag():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: latest-pod
    spec:
      containers:
      - name: web
        image: nginx:latest
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K008" in rule_ids


def test_k009_k010_capabilities():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: cap-pod
    spec:
      containers:
      - name: web
        image: nginx:1.25.5-alpine
        securityContext:
          capabilities:
            add:
              - ALL
              - SYS_ADMIN
              - NET_ADMIN
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K009" in rule_ids
    assert "K010" in rule_ids


def test_k011_readonly_rootfs():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: rootfs-pod
    spec:
      containers:
      - name: web
        image: nginx:1.25.5-alpine
        securityContext:
          readOnlyRootFilesystem: false
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K011" in rule_ids


def test_k012_missing_resources():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: res-pod
    spec:
      containers:
      - name: web
        image: nginx:1.25.5-alpine
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K012" in rule_ids


def test_k013_missing_seccomp():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: seccomp-pod
    spec:
      containers:
      - name: web
        image: nginx:1.25.5-alpine
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K013" in rule_ids


def test_k014_missing_security_context():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: bare-pod
    spec:
      containers:
      - name: web
        image: nginx:1.25.5-alpine
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K014" in rule_ids


def test_k015_embedded_secrets():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: secret-pod
    spec:
      containers:
      - name: web
        image: nginx:1.25.5-alpine
        env:
        - name: DATABASE_PASSWORD
          value: SuperTopSecretDbPass999!
    """
    scanner = KubernetesScanner("pod.yaml")
    findings = scanner.scan(content)
    secret_findings = [f for f in findings if f.id == "K015"]
    assert len(secret_findings) == 1
    assert "SuperTopSecretDbPass999!" not in secret_findings[0].description
    assert "[REDACTED]" in secret_findings[0].description


import textwrap

def test_multi_document_manifest():
    content = textwrap.dedent("""
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: web-app
    spec:
      template:
        spec:
          containers:
          - name: nginx
            image: nginx:1.25.5-alpine
            securityContext:
              privileged: true
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: web-service
    spec:
      ports:
      - port: 80
    """).strip()
    scanner = KubernetesScanner("multi.yaml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "K001" in rule_ids

