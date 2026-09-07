"""
Tests for Docker Compose security scanner.
"""

from app.scanners.compose_scanner import ComposeScanner
from app.models import Severity


def test_c001_privileged():
    content = """
    version: '3.8'
    services:
      web:
        image: nginx:1.25.5
        privileged: true
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C001" in rule_ids
    assert any(f.severity == Severity.CRITICAL for f in findings if f.id == "C001")


def test_c002_network_mode_host():
    content = """
    services:
      app:
        image: node:20.12.2
        network_mode: host
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C002" in rule_ids


def test_c003_pid_host():
    content = """
    services:
      app:
        image: node:20.12.2
        pid: host
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C003" in rule_ids


def test_c004_ipc_host():
    content = """
    services:
      app:
        image: node:20.12.2
        ipc: host
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C004" in rule_ids


def test_c005_host_root_filesystem_mount():
    content = """
    services:
      app:
        image: node:20.12.2
        volumes:
          - /:/host
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C005" in rule_ids


def test_c006_docker_socket_mount():
    content = """
    services:
      agent:
        image: agent:1.0
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C006" in rule_ids


def test_c007_cap_add_all():
    content = """
    services:
      app:
        image: node:20.12.2
        cap_add:
          - ALL
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C007" in rule_ids


def test_c008_seccomp_unconfined():
    content = """
    services:
      app:
        image: node:20.12.2
        security_opt:
          - seccomp:unconfined
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C008" in rule_ids


def test_c009_secrets_in_env():
    content = """
    services:
      db:
        image: postgres:16.2
        environment:
          - POSTGRES_PASSWORD=UltraSecretDbPassword999!
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    secret_findings = [f for f in findings if f.id == "C009"]
    assert len(secret_findings) == 1
    assert "UltraSecretDbPassword999!" not in secret_findings[0].description
    assert "[REDACTED]" in secret_findings[0].description


def test_c010_latest_tag():
    content = """
    services:
      web:
        image: nginx:latest
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C010" in rule_ids


def test_c011_missing_resource_limits():
    content = """
    services:
      web:
        image: nginx:1.25.5-alpine
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C011" in rule_ids


def test_c012_dangerous_port_exposure():
    content = """
    services:
      database:
        image: postgres:16.2-alpine
        ports:
          - "5432:5432"
    """
    scanner = ComposeScanner("docker-compose.yml")
    findings = scanner.scan(content)
    rule_ids = [f.id for f in findings]
    assert "C012" in rule_ids
