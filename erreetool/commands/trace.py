import re

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from erreetool.utils import is_windows, run_command

console = Console()


def _parse_tracert(output: str) -> list:
    hops = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line[0].isdigit():
            continue
        parts = re.split(r"\s+", line)
        hop = parts[0]
        ip = parts[-1]
        latency = " ".join(parts[1:-1])
        hops.append((hop, ip, latency))
    return hops


def run(
    target: str = typer.Argument(..., help="Target hostname or IP address."),
) -> None:
    cmd = ["tracert", target] if is_windows() else ["traceroute", target]
    code, stdout, stderr = run_command(cmd)
    if code != 0 and not stdout:
        console.print(Panel(f"[bold red]{stderr.strip()}[/bold red]"))
        return

    hops = _parse_tracert(stdout)
    if not hops:
        console.print(Panel("[bold yellow]No traceroute data found.[/bold yellow]"))
        console.print(stdout)
        return

    table = Table(title=f"Traceroute: {target}")
    table.add_column("Hop", style="cyan", justify="right")
    table.add_column("IP/Host", style="green")
    table.add_column("Latency", style="yellow")

    for hop, ip, latency in hops:
        table.add_row(hop, ip, latency)

    console.print(table)
