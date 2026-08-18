"""
API Server command - Start the ERREETOOL REST API server.
"""

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()


def run(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", help="Port to bind to"),
    reload: bool = typer.Option(
        False, "--reload", help="Enable auto-reload (dev mode)"
    ),
    workers: int = typer.Option(
        1, "--workers", help="Number of worker processes"
    ),
) -> None:
    """
    Start the ERREETOOL REST API server.

    The API provides programmatic access to:
    - Run assessments
    - Manage campaigns
    - Execute skills
    - Access memory
    - Generate reports
    """
    console.print(
        Panel(
            f"[bold cyan]Starting ERREETOOL API Server[/bold cyan]\n"
            f"Host: {host}\n"
            f"Port: {port}\n"
            f"Workers: {workers}\n"
            f"Reload: {reload}"
        )
    )

    try:
        from erreetool.api.server import run_server

        run_server(host=host, port=port, reload=reload, workers=workers)
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Server failed: {e}[/bold red]")
        raise
