"""
Test initial setup and baseline models.
"""

from app.models import Finding, Severity, Confidence, ScanSummary
from app.scoring import ScoringEngine
from app.cis_mapper import get_cis_reference
from app.remediation import get_remediation_details
from app.parser import DockerfileParser, YamlParser, FileClassifier


def test_models():
    finding = Finding(
        id="D001",
        title="Explicit Root User",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="ACCESS_CONTROL",
        description="Testing description",
        risk="Testing risk",
        file="Dockerfile",
        line=5,
        cis_reference="CIS Docker Benchmark v1.6.0 — Control 4.1",
        remediation="Set non-root user",
        secure_example="USER appuser",
    )
    assert finding.id == "D001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH


def test_scoring():
    engine = ScoringEngine()
    findings = [
        Finding(
            id="D001",
            title="Explicit Root User",
            severity=Severity.HIGH,
            category="ACCESS_CONTROL",
            description="desc",
            risk="risk",
            file="Dockerfile",
            remediation="remedy",
        ),
        Finding(
            id="C001",
            title="Privileged Container",
            severity=Severity.CRITICAL,
            category="PRIVILEGE_ESCALATION",
            description="desc",
            risk="risk",
            file="compose.yml",
            remediation="remedy",
        ),
    ]
    # Score should be 100 - (10 + 20) = 70
    score = engine.calculate_score(findings)
    assert score == 70

    summary = engine.summarize(findings, files_scanned=2)
    assert summary.critical == 1
    assert summary.high == 1
    assert summary.score == 70
    assert summary.files_scanned == 2


def test_cis_mapper():
    ref = get_cis_reference("D001")
    assert "CIS Docker Benchmark" in ref
    ref_k8s = get_cis_reference("K001")
    assert "CIS Kubernetes Benchmark" in ref_k8s
    ref_unknown = get_cis_reference("UNKNOWN999")
    assert "Best Practice" in ref_unknown


def test_remediation():
    rem = get_remediation_details("K001")
    assert "privileged: false" in rem["remediation"] or "privileged: false" in rem["secure_example"]


def test_dockerfile_parser():
    content = """
    FROM ubuntu:22.04
    RUN apt-get update && \\
        apt-get install -y curl
    USER 10001
    CMD ["bash"]
    """
    instructions = DockerfileParser.parse_content(content)
    assert len(instructions) == 4
    assert instructions[0].instruction == "FROM"
    assert instructions[1].instruction == "RUN"
    assert instructions[2].instruction == "USER"
    assert instructions[3].instruction == "CMD"
    assert instructions[2].arguments == "10001"


def test_yaml_parser():
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: test-pod
    spec:
      containers:
      - name: web
        image: nginx:latest
    """
    docs = YamlParser.parse_content(content)
    assert len(docs) == 1
    assert docs[0]["kind"] == "Pod"
    assert FileClassifier.is_kubernetes_manifest(docs[0]) is True
    assert FileClassifier.is_docker_compose(docs[0]) is False
