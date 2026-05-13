"""CLI for safeworkflow."""

import json
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from .sanitizer import sanitize
from .scanner import scan, scan_file
from .types import ScanResult

app = typer.Typer(help="Prompt injection and supply-chain risk protection")
console = Console()


@app.command()
def scan_cmd(
    source: str = typer.Argument(..., help="File or text to scan"),
    fail_on: str = typer.Option("high", "--fail-on", "-f", help="Fail on risk level"),
    format: str = typer.Option("text", "--format", help="Output format: text, json"),
    max_score: int = typer.Option(100, "--max-score", help="Maximum risk score"),
) -> int:
    """Scan content or file for security risks."""
    path = Path(source)

    if path.exists():
        result = scan_file(str(path), fail_on=fail_on)
    else:
        result = scan(source, fail_on=fail_on, max_score=max_score)

    if format == "json":
        output = {
            "score": result.score,
            "risk_level": result.risk_level.value,
            "is_safe": result.is_safe,
            "issue_count": len(result.issues),
            "issues": [
                {
                    "line": i.line,
                    "column": i.column,
                    "message": i.message,
                    "risk_level": i.risk_level.value,
                    "pattern": i.pattern_name,
                }
                for i in result.issues
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        _print_result(result)

    return 1 if not result.is_safe else 0


@app.command("sanitize")
def sanitize_cmd(
    source: str = typer.Argument(..., help="File or text to sanitize"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file"),
    replacement: str = typer.Option(
        "[REDACTED]", "--replacement", "-r", help="Replacement text"
    ),
) -> None:
    """Sanitize content by removing security risks."""
    path = Path(source)
    content = path.read_text(encoding="utf-8") if path.exists() else source
    result = sanitize(content, replacement=replacement)

    if output:
        Path(output).write_text(result, encoding="utf-8")
        rprint(f"[green]Sanitized output written to {output}[/green]")
    else:
        print(result)


def _print_result(result: ScanResult) -> None:
    """Print scan result in human-readable format."""
    rprint(f"\n[bold]Risk Score:[/bold] {result.score}/100")
    rprint(f"[bold]Risk Level:[/bold] {result.risk_level.value.upper()}")
    status = "[green]SAFE[/green]" if result.is_safe else "[red]UNSAFE[/red]"
    rprint(f"[bold]Status:[/bold] {status}")

    if result.issues:
        table = Table(title="Detected Issues")
        table.add_column("Line", style="cyan")
        table.add_column("Pattern", style="magenta")
        table.add_column("Message", style="yellow")
        table.add_column("Risk", style="red")

        for issue in result.issues:
            table.add_row(
                str(issue.line),
                issue.pattern_name,
                issue.message[:50],
                issue.risk_level.value.upper(),
            )
        rprint(table)


if __name__ == "__main__":
    app()
