"""
Configurable security scoring engine for container misconfiguration audits.
"""

from typing import List, Dict, Optional
from app.models import Finding, Severity, ScanSummary


class ScoringEngine:
    """Configurable scoring engine calculating security score from findings."""

    DEFAULT_WEIGHTS: Dict[Severity, int] = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    def __init__(
        self,
        base_score: int = 100,
        weights: Optional[Dict[Severity, int]] = None,
        min_score: int = 0,
        max_score: int = 100,
    ):
        self.base_score = base_score
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        self.min_score = min_score
        self.max_score = max_score

    def calculate_deduction(self, finding: Finding) -> int:
        """Get deduction weight for a single finding."""
        return self.weights.get(finding.severity, 0)

    def calculate_score(self, findings: List[Finding]) -> int:
        """Calculate aggregate security score given a list of findings."""
        total_deduction = sum(self.calculate_deduction(f) for f in findings)
        score = self.base_score - total_deduction
        return max(self.min_score, min(self.max_score, score))

    def summarize(
        self,
        findings: List[Finding],
        files_scanned: int = 0,
        containers_scanned: int = 0,
        fail_threshold: Optional[Severity] = None,
    ) -> ScanSummary:
        """Generate a complete ScanSummary instance from findings."""
        counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for f in findings:
            sev_str = f.severity.value
            if sev_str in counts:
                counts[sev_str] += 1

        score = self.calculate_score(findings)

        # Determine pass/fail based on fail threshold
        passed = True
        if fail_threshold:
            threshold_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            min_idx = threshold_order.index(fail_threshold)
            for sev in threshold_order[min_idx:]:
                if counts[sev.value] > 0:
                    passed = False
                    break

        return ScanSummary(
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
            info=counts["INFO"],
            total=len(findings),
            score=score,
            files_scanned=files_scanned,
            containers_scanned=containers_scanned,
            passed=passed,
        )
