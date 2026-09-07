"""
Tests for scoring engine algorithms.
"""

from app.scoring import ScoringEngine
from app.models import Finding, Severity, Confidence


def test_scoring_weights_and_deductions():
    engine = ScoringEngine()
    findings = [
        Finding(
            id="D004",
            title="Secret Leak",
            severity=Severity.CRITICAL,
            description="desc",
            risk="risk",
            file="Dockerfile",
            remediation="remedy",
        ),  # -20
        Finding(
            id="K001",
            title="Privileged Container",
            severity=Severity.CRITICAL,
            description="desc",
            risk="risk",
            file="deployment.yaml",
            remediation="remedy",
        ),  # -20
        Finding(
            id="C002",
            title="Host Network",
            severity=Severity.HIGH,
            description="desc",
            risk="risk",
            file="compose.yml",
            remediation="remedy",
        ),  # -10
        Finding(
            id="D002",
            title="Latest Tag",
            severity=Severity.MEDIUM,
            description="desc",
            risk="risk",
            file="Dockerfile",
            remediation="remedy",
        ),  # -5
        Finding(
            id="D009",
            title="Missing Healthcheck",
            severity=Severity.LOW,
            description="desc",
            risk="risk",
            file="Dockerfile",
            remediation="remedy",
        ),  # -2
    ]

    # Total deduction: 20 + 20 + 10 + 5 + 2 = 57 -> Score = 43
    score = engine.calculate_score(findings)
    assert score == 43


def test_scoring_clamping_at_zero():
    engine = ScoringEngine()
    # 6 Critical findings = 6 * 20 = 120 deduction. Score must not fall below 0.
    findings = [
        Finding(
            id=f"C00{i}",
            title="Critical",
            severity=Severity.CRITICAL,
            description="desc",
            risk="risk",
            file="file.yaml",
            remediation="remedy",
        )
        for i in range(6)
    ]
    score = engine.calculate_score(findings)
    assert score == 0


def test_custom_scoring_weights():
    custom_weights = {
        Severity.CRITICAL: 50,
        Severity.HIGH: 25,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }
    engine = ScoringEngine(weights=custom_weights)
    findings = [
        Finding(
            id="C001",
            title="Privileged",
            severity=Severity.CRITICAL,
            description="desc",
            risk="risk",
            file="compose.yml",
            remediation="remedy",
        )
    ]
    assert engine.calculate_score(findings) == 50
