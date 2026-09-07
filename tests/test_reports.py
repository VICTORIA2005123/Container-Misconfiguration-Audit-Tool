"""
Tests for report generation (Terminal, JSON, HTML, SARIF).
"""

import json
from pathlib import Path
from app.models import ScanResult, ScanSummary, Finding, Severity, Confidence
from app.report import ReportGenerator


def get_mock_scan_result():
    findings = [
        Finding(
            id="K001",
            title="Privileged Container",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="PRIVILEGE_ESCALATION",
            description="Container runs in privileged mode.",
            risk="Full kernel access.",
            file="deployment.yaml",
            resource="web-deploy",
            container="nginx",
            line=12,
            cis_reference="CIS Kubernetes Benchmark v1.8.0 — Control 5.2.1",
            remediation="Set privileged: false.",
            secure_example="securityContext:\n  privileged: false",
        ),
        Finding(
            id="D004",
            title="Secret Leak",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            category="SECRETS",
            description="Detected hardcoded secret: 'ghp_*** [REDACTED]'.",
            risk="Credentials baked into image layers.",
            file="Dockerfile",
            line=8,
            cis_reference="CIS Docker Benchmark v1.6.0 — Control 4.4",
            remediation="Use build secrets.",
            secure_example="# Use build secrets",
        ),
    ]

    summary = ScanSummary(
        critical=2,
        high=0,
        medium=0,
        low=0,
        info=0,
        total=2,
        score=60,
        files_scanned=2,
        containers_scanned=2,
        passed=False,
    )

    return ScanResult(
        target="./test-dir",
        score=60,
        summary=summary,
        findings=findings,
        files_scanned=["Dockerfile", "deployment.yaml"],
    )


def test_json_report_generation(tmp_path):
    result = get_mock_scan_result()
    reporter = ReportGenerator(result)
    output_path = tmp_path / "report.json"

    reporter.render(format="json", output_file=str(output_path))
    assert output_path.exists()

    with open(output_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["scan"]["score"] == 60
    assert data["summary"]["critical"] == 2
    assert len(data["findings"]) == 2
    assert data["findings"][0]["id"] == "K001"


def test_html_report_generation(tmp_path):
    result = get_mock_scan_result()
    reporter = ReportGenerator(result)
    output_path = tmp_path / "report.html"

    reporter.render(format="html", output_file=str(output_path))
    assert output_path.exists()

    html_content = output_path.read_text(encoding="utf-8")
    assert "Container Misconfiguration Audit Report" in html_content
    assert "K001" in html_content
    assert "60/100" in html_content


def test_sarif_report_generation(tmp_path):
    result = get_mock_scan_result()
    reporter = ReportGenerator(result)
    output_path = tmp_path / "report.sarif"

    reporter.render(format="sarif", output_file=str(output_path))
    assert output_path.exists()

    with open(output_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == 2


def test_fail_on_thresholds():
    result = get_mock_scan_result()
    reporter = ReportGenerator(result)

    assert reporter.should_fail("CRITICAL") is True
    assert reporter.should_fail("HIGH") is True
    assert reporter.should_fail("LOW") is True
