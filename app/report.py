"""
Report generator for terminal, JSON, HTML, and SARIF output formats.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
import json
import sys
from jinja2 import Environment, FileSystemLoader

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from app.models import ScanResult, Severity, Finding


class ReportGenerator:
    """Renders scan results in Terminal, JSON, HTML, or SARIF format."""

    def __init__(self, result: ScanResult):
        self.result = result
        self.console = Console()

    def should_fail(self, fail_on_severity_str: str) -> bool:
        """Determine whether the scan should return exit code 1 based on threshold."""
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        try:
            threshold = Severity(fail_on_severity_str.upper())
        except ValueError:
            return False

        if threshold not in order:
            return False

        min_idx = order.index(threshold)
        qualifying_severities = set(s.value for s in order[min_idx:])

        for f in self.result.findings:
            if f.severity.value in qualifying_severities:
                return True
        return False

    def render(self, format: str = "terminal", output_file: Optional[str] = None):
        """Render report in the specified format."""
        fmt = (format or "terminal").lower()

        if fmt == "terminal":
            self._render_terminal()
            if output_file:
                # If output file specified for terminal, save text representation
                with open(output_file, "w", encoding="utf-8") as f:
                    file_console = Console(file=f, force_terminal=False)
                    self._render_terminal(console=file_console)
        elif fmt == "json":
            json_output = self._render_json()
            if output_file:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(json_output)
                self.console.print(f"[green][+][/green] JSON report saved to: [bold]{output_file}[/bold]")
            else:
                print(json_output)
        elif fmt == "html":
            html_output = self._render_html()
            out_path = output_file or "report.html"
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_output)
            self.console.print(f"[green][+][/green] HTML report saved to: [bold]{out_path}[/bold]")
        elif fmt == "sarif":
            sarif_output = self._render_sarif()
            if output_file:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(sarif_output)
                self.console.print(f"[green][+][/green] SARIF report saved to: [bold]{output_file}[/bold]")
            else:
                print(sarif_output)
        else:
            self.console.print(f"[red]Error: Unknown format '{format}'[/red]")

    def _render_terminal(self, console: Optional[Console] = None):
        """Render beautiful terminal output with Rich."""
        c = console or self.console

        c.print("=" * 60, style="bold cyan")
        c.print("CONTAINER MISCONFIGURATION AUDITOR", style="bold white on blue", justify="center")
        c.print("=" * 60, style="bold cyan")

        c.print(f"\n[bold]Target:[/bold] {self.result.target}")
        
        # Color-coded score
        score = self.result.score
        score_color = "bold green" if score >= 80 else ("bold yellow" if score >= 50 else "bold red")
        c.print(f"[bold]Security Score:[/bold] [{score_color}]{score}/100[/{score_color}]\n")

        # Summary breakdown
        c.print(f"[bold red]CRITICAL:[/bold red] {self.result.summary.critical}")
        c.print(f"[red]HIGH:[/red]     {self.result.summary.high}")
        c.print(f"[yellow]MEDIUM:[/yellow]   {self.result.summary.medium}")
        c.print(f"[blue]LOW:[/blue]      {self.result.summary.low}")
        if self.result.summary.info > 0:
            c.print(f"[cyan]INFO:[/cyan]     {self.result.summary.info}")

        if not self.result.findings:
            c.print("\n[bold green][PASS] No security misconfigurations detected![/bold green]\n")
        else:
            # Group findings by severity
            sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            for current_sev in sev_order:
                matching = [f for f in self.result.findings if f.severity == current_sev]
                if not matching:
                    continue

                c.print(f"\n--- [bold {current_sev.color}]{current_sev.value} FINDINGS[/bold {current_sev.color}] ({len(matching)}) ---")

                for finding in matching:
                    loc = f"{finding.file}"
                    if finding.line:
                        loc += f":{finding.line}"

                    res_str = ""
                    if finding.resource or finding.container:
                        res_parts = []
                        if finding.resource:
                            res_parts.append(f"Resource: {finding.resource}")
                        if finding.container:
                            res_parts.append(f"Container: {finding.container}")
                        res_str = f"\n[dim]{' | '.join(res_parts)}[/dim]"

                    conf_tag = f" [dim]({finding.confidence.value} confidence)[/dim]"
                    c.print(f"\n[[bold {current_sev.color}]{finding.id}[/bold {current_sev.color}]] [bold]{finding.title}[/bold]{conf_tag}")
                    c.print(f"Location: [cyan]{loc}[/cyan]{res_str}")
                    c.print(f"Risk: {finding.risk}")
                    if finding.cis_reference:
                        c.print(f"CIS / Standard: [magenta]{finding.cis_reference}[/magenta]")
                    c.print(f"Remediation: [green]{finding.remediation}[/green]")

                    if finding.secure_example:
                        c.print("Secure example:")
                        for line in finding.secure_example.strip().splitlines():
                            t = Text(f"  {line}", style="dim cyan")
                            c.print(t)



        # Footer
        c.print("\n" + "=" * 60, style="dim")
        c.print("[bold]Scan completed.[/bold]")
        c.print(f"Files scanned: {self.result.summary.files_scanned}")
        c.print(f"Containers/images scanned: {self.result.summary.containers_scanned}")
        c.print(f"Findings: {self.result.summary.total}")

        has_high_or_crit = (self.result.summary.critical + self.result.summary.high) > 0
        status_text = "[bold red]FAIL[/bold red]" if has_high_or_crit else "[bold green]PASS[/bold green]"
        c.print(f"Exit status: {status_text}\n")

    def _render_json(self) -> str:
        """Generate structured JSON report representation."""
        data = {
            "tool_name": self.result.tool_name,
            "version": self.result.version,
            "scan": {
                "target": self.result.target,
                "timestamp": self.result.timestamp,
                "score": self.result.score,
            },
            "summary": {
                "critical": self.result.summary.critical,
                "high": self.result.summary.high,
                "medium": self.result.summary.medium,
                "low": self.result.summary.low,
                "info": self.result.summary.info,
                "total": self.result.summary.total,
                "files_scanned": self.result.summary.files_scanned,
                "containers_scanned": self.result.summary.containers_scanned,
                "passed": self.result.summary.passed,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "category": f.category,
                    "description": f.description,
                    "risk": f.risk,
                    "file": f.file,
                    "resource": f.resource,
                    "container": f.container,
                    "line": f.line,
                    "cis_reference": f.cis_reference,
                    "remediation": f.remediation,
                    "secure_example": f.secure_example,
                    "source": f.source,
                }
                for f in self.result.findings
            ],
            "files_scanned": self.result.files_scanned,
            "errors": self.result.errors,
        }
        return json.dumps(data, indent=2)

    def _render_html(self) -> str:
        """Render HTML report via Jinja2."""
        template_dir = Path(__file__).resolve().parent.parent / "templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
        template = env.get_template("report.html")
        return template.render(result=self.result)

    def _render_sarif(self) -> str:
        """Generate SARIF 2.1.0 report for GitHub Security Scanning."""
        rules_dict: Dict[str, Any] = {}
        results_list: List[Dict[str, Any]] = []

        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        for f in self.result.findings:
            if f.id not in rules_dict:
                rules_dict[f.id] = {
                    "id": f.id,
                    "name": f.title.replace(" ", ""),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {
                        "text": f"{f.remediation}\n\nRisk: {f.risk}\nCIS Reference: {f.cis_reference or 'N/A'}"
                    },
                    "defaultConfiguration": {
                        "level": level_map.get(f.severity, "warning")
                    },
                    "properties": {
                        "category": f.category,
                        "confidence": f.confidence.value,
                    }
                }

            start_line = f.line if f.line and f.line > 0 else 1
            result_item = {
                "ruleId": f.id,
                "level": level_map.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": Path(f.file).as_posix() if f.file else "unknown"
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": 1,
                            }
                        }
                    }
                ]
            }
            results_list.append(result_item)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.result.tool_name,
                            "version": self.result.version,
                            "informationUri": "https://github.com/security/container-misconfiguration-auditor",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results_list,
                }
            ]
        }
        return json.dumps(sarif_data, indent=2)
