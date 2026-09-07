from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field




class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Point deductions for scoring."""
        weights = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        return weights.get(self, 0)

    @property
    def color(self) -> str:
        """Rich color tag for terminal output."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
        }
        return colors.get(self, "white")

    @property
    def badge_color(self) -> str:
        """Hex color for HTML badges."""
        colors = {
            Severity.CRITICAL: "#e53e3e",
            Severity.HIGH: "#dd6b20",
            Severity.MEDIUM: "#d69e2e",
            Severity.LOW: "#3182ce",
            Severity.INFO: "#718096",
        }
        return colors.get(self, "#718096")


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(BaseModel):
    """Normalized finding representation for all scanner outputs."""
    id: str = Field(..., description="Unique rule ID, e.g., D001, C001, K001, TRV001")
    title: str = Field(..., description="Short descriptive title of the finding")
    severity: Severity = Field(..., description="Severity level")
    confidence: Confidence = Field(default=Confidence.HIGH, description="Confidence of detection (deterministic vs heuristic)")
    category: str = Field(default="SECURITY", description="Security category or domain")
    description: str = Field(..., description="Detailed description of the detected issue")
    risk: str = Field(..., description="Explanation of the security impact and risk")
    file: str = Field(..., description="Path to the affected file")
    resource: Optional[str] = Field(default=None, description="Resource name (e.g. Deployment name, service name)")
    container: Optional[str] = Field(default=None, description="Container name within the resource")
    line: Optional[int] = Field(default=None, description="Line number where issue originates")
    cis_reference: Optional[str] = Field(default=None, description="Applicable CIS Benchmark recommendation or Best Practice statement")
    remediation: str = Field(..., description="Actionable step-by-step guidance to fix the issue")
    secure_example: Optional[str] = Field(default=None, description="Secure code/configuration snippet demonstrating proper setup")
    source: str = Field(default="custom", description="Finding source: 'custom' or 'trivy'")


class RuleDefinition(BaseModel):
    """Metadata for a scanner rule loaded from YAML or python."""
    id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.HIGH
    category: str
    description: str
    risk: str
    cis_reference: Optional[str] = None
    remediation: str
    secure_example: Optional[str] = None


class ScanSummary(BaseModel):
    """Statistical summary of a scan run."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    score: int = 100
    files_scanned: int = 0
    containers_scanned: int = 0
    passed: bool = True


class ScanResult(BaseModel):
    """Root model for an entire security audit scan."""
    tool_name: str = "Container Misconfiguration Audit Tool"
    version: str = "1.0.0"
    target: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    score: int = 100
    summary: ScanSummary
    findings: List[Finding] = Field(default_factory=list)
    files_scanned: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
