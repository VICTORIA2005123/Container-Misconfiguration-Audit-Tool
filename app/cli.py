"""
CLI Interface for the Container Misconfiguration Audit Tool.
"""

from enum import Enum
from pathlib import Path
from typing import Optional, List
import sys
import typer
from rich.console import Console

app = typer.Typer(
    name="container-audit",
    help="Automated Security Auditing Tool for Dockerfiles, Docker Compose, Kubernetes, and Container Images.",
    add_completion=False,
)

console = Console()


class OutputFormat(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


class FailOnSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def parse_ignore_list(ignore_str: Optional[str]) -> List[str]:
    """Parse comma-separated ignore rule IDs."""
    if not ignore_str:
        return []
    return [item.strip().upper() for item in ignore_str.split(",") if item.strip()]


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to file or directory to scan"),
    format: OutputFormat = typer.Option(OutputFormat.TERMINAL, "--format", "-f", help="Output format: terminal, json, html, sarif"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (for json, html, sarif)"),
    fail_on: Optional[FailOnSeverity] = typer.Option(None, "--fail-on", help="Fail with exit code 1 if findings at or above this severity exist"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated list of rule IDs to ignore (e.g. K001,D001)"),
    trivy: bool = typer.Option(True, "--trivy/--no-trivy", help="Enable or disable external Trivy image/config scanning"),
):
    """Scan a directory or file for container and Kubernetes misconfigurations."""
    from app.scanner import ScannerOrchestrator
    from app.report import ReportGenerator

    orchestrator = ScannerOrchestrator(
        ignore_rules=parse_ignore_list(ignore),
        enable_trivy=trivy,
    )
    result = orchestrator.scan_path(str(path))
    
    reporter = ReportGenerator(result)
    reporter.render(format=format.value, output_file=str(output) if output else None)

    if fail_on and reporter.should_fail(fail_on.value):
        sys.exit(1)


@app.command()
def dockerfile(
    path: Path = typer.Argument(..., help="Path to Dockerfile to scan"),
    format: OutputFormat = typer.Option(OutputFormat.TERMINAL, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on: Optional[FailOnSeverity] = typer.Option(None, "--fail-on", help="Fail-on threshold"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated list of rule IDs to ignore"),
):
    """Audit a single Dockerfile."""
    from app.scanner import ScannerOrchestrator
    from app.report import ReportGenerator

    orchestrator = ScannerOrchestrator(ignore_rules=parse_ignore_list(ignore), enable_trivy=False)
    result = orchestrator.scan_dockerfile(str(path))
    
    reporter = ReportGenerator(result)
    reporter.render(format=format.value, output_file=str(output) if output else None)

    if fail_on and reporter.should_fail(fail_on.value):
        sys.exit(1)


@app.command()
def compose(
    path: Path = typer.Argument(..., help="Path to docker-compose.yml to scan"),
    format: OutputFormat = typer.Option(OutputFormat.TERMINAL, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on: Optional[FailOnSeverity] = typer.Option(None, "--fail-on", help="Fail-on threshold"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated list of rule IDs to ignore"),
):
    """Audit a Docker Compose file."""
    from app.scanner import ScannerOrchestrator
    from app.report import ReportGenerator

    orchestrator = ScannerOrchestrator(ignore_rules=parse_ignore_list(ignore), enable_trivy=False)
    result = orchestrator.scan_compose(str(path))
    
    reporter = ReportGenerator(result)
    reporter.render(format=format.value, output_file=str(output) if output else None)

    if fail_on and reporter.should_fail(fail_on.value):
        sys.exit(1)


@app.command()
def kubernetes(
    path: Path = typer.Argument(..., help="Path to Kubernetes YAML manifest to scan"),
    format: OutputFormat = typer.Option(OutputFormat.TERMINAL, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on: Optional[FailOnSeverity] = typer.Option(None, "--fail-on", help="Fail-on threshold"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated list of rule IDs to ignore"),
):
    """Audit a Kubernetes YAML manifest."""
    from app.scanner import ScannerOrchestrator
    from app.report import ReportGenerator

    orchestrator = ScannerOrchestrator(ignore_rules=parse_ignore_list(ignore), enable_trivy=False)
    result = orchestrator.scan_kubernetes(str(path))
    
    reporter = ReportGenerator(result)
    reporter.render(format=format.value, output_file=str(output) if output else None)

    if fail_on and reporter.should_fail(fail_on.value):
        sys.exit(1)


@app.command()
def image(
    image_name: str = typer.Argument(..., help="Container image name (e.g. nginx:latest)"),
    format: OutputFormat = typer.Option(OutputFormat.TERMINAL, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on: Optional[FailOnSeverity] = typer.Option(None, "--fail-on", help="Fail-on threshold"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated list of rule IDs to ignore"),
):
    """Audit a container image using external Trivy scanner integration."""
    from app.scanner import ScannerOrchestrator
    from app.report import ReportGenerator

    orchestrator = ScannerOrchestrator(ignore_rules=parse_ignore_list(ignore), enable_trivy=True)
    result = orchestrator.scan_image(image_name)
    
    reporter = ReportGenerator(result)
    reporter.render(format=format.value, output_file=str(output) if output else None)

    if fail_on and reporter.should_fail(fail_on.value):
        sys.exit(1)


def main():
    app()


if __name__ == "__main__":
    main()
