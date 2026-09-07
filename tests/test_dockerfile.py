"""
Tests for Dockerfile security scanner.
"""

from app.scanners.dockerfile_scanner import DockerfileScanner, mask_secret
from app.models import Severity, Confidence


def test_mask_secret():
    assert mask_secret("123") == "*** [REDACTED]"
    masked = mask_secret("SuperSecretPassword123!")
    assert "SuperSecretPassword123!" not in masked
    assert "Su***!" in masked or "Su***" in masked


def test_d001_explicit_root_user():
    content = """
    FROM ubuntu:22.04
    USER root
    CMD ["bash"]
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D001" in rule_ids
    assert "D003" not in rule_ids  # Should NOT duplicate with D003


def test_d002_latest_image_tag():
    content = """
    FROM ubuntu:latest
    USER appuser
    HEALTHCHECK CMD curl -f http://localhost/ || exit 1
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D002" in rule_ids


def test_d003_missing_non_root_user():
    content = """
    FROM alpine:3.19.1
    RUN apk add --no-cache curl
    HEALTHCHECK CMD curl -f http://localhost/ || exit 1
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D003" in rule_ids
    assert "D001" not in rule_ids


def test_d004_secret_detection_and_masking():
    raw_secret = "ghp_VerySecretGitHubToken9999"
    content = f"""
    FROM python:3.12.3-slim
    ENV API_KEY="{raw_secret}"
    USER 10001
    HEALTHCHECK CMD exit 0
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    secret_findings = [f for f in findings if f.id == "D004"]
    assert len(secret_findings) == 1
    assert secret_findings[0].severity == Severity.CRITICAL
    assert raw_secret not in secret_findings[0].description
    assert "[REDACTED]" in secret_findings[0].description


def test_d005_ssh_server_detection():
    content = """
    FROM debian:12.5-slim
    RUN apt-get update && apt-get install -y openssh-server
    USER appuser
    HEALTHCHECK CMD exit 0
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D005" in rule_ids


def test_d006_dangerous_system_modification():
    content = """
    FROM debian:12.5-slim
    RUN chmod -R 777 /etc
    USER appuser
    HEALTHCHECK CMD exit 0
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D006" in rule_ids


def test_d007_add_instead_of_copy():
    content = """
    FROM alpine:3.19.1
    ADD ./source.js /app/source.js
    USER appuser
    HEALTHCHECK CMD exit 0
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D007" in rule_ids


def test_d008_unsafe_install_pipe_to_shell():
    content = """
    FROM alpine:3.19.1
    RUN curl -fsSL https://get.docker.com | sh
    USER appuser
    HEALTHCHECK CMD exit 0
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D008" in rule_ids


def test_d009_missing_healthcheck():
    content = """
    FROM python:3.12.3-slim
    USER appuser
    CMD ["python", "app.py"]
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D009" in rule_ids


def test_d010_unpinned_floating_tag():
    content = """
    FROM node:20
    USER appuser
    HEALTHCHECK CMD exit 0
    """
    scanner = DockerfileScanner("Dockerfile")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D010" in rule_ids


def test_rule_suppression():
    content = """
    FROM python:3.12.3-slim
    USER appuser
    CMD ["python", "app.py"]
    """
    scanner = DockerfileScanner("Dockerfile", ignore_rules=["D009"])
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "D009" not in rule_ids
