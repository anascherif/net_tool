import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _to_mbps(bits_per_second: float) -> str:
    return f"{bits_per_second / 1_000_000:.2f} Mbps"


def run(
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
) -> None:
    try:
        import speedtest
    except ImportError:
        console.print(Panel("[bold red]speedtest-cli is not installed.[/bold red]"))
        return

    console.print(Panel("[bold cyan]Running speed test...[/bold cyan]"))
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = st.download()
        upload = st.upload()
        ping_ms = st.results.ping
        server = st.results.server.get("name", "-")
    except (speedtest.SpeedtestException, OSError) as exc:
        console.print(Panel(f"[bold red]Speedtest failed: {exc}[/bold red]"))
        return

    table = Table(title="Internet Speed Test")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Download", _to_mbps(download))
    table.add_row("Upload", _to_mbps(upload))
    table.add_row("Ping", f"{ping_ms:.2f} ms")
    table.add_row("Server", server)

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("speedtest")
