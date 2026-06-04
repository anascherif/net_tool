import re

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from erreetool.utils import is_windows, run_command

console = Console()


def _parse_windows_ping(output: str) -> dict:
    stats = {}
    packet_match = re.search(
        r"Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)",
        output,
    )
    if packet_match:
        stats["sent"] = int(packet_match.group(1))
        stats["received"] = int(packet_match.group(2))
        stats["lost"] = int(packet_match.group(3))
        stats["loss_pct"] = int(packet_match.group(4))

    time_match = re.search(
        r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms",
        output,
    )
    if time_match:
        stats["min_ms"] = int(time_match.group(1))
        stats["max_ms"] = int(time_match.group(2))
        stats["avg_ms"] = int(time_match.group(3))
    return stats


def _parse_unix_ping(output: str) -> dict:
    stats = {}
    packet_match = re.search(
        r"(\d+) packets transmitted, (\d+) received,.*?(\d+)% packet loss",
        output,
    )
    if packet_match:
        stats["sent"] = int(packet_match.group(1))
        stats["received"] = int(packet_match.group(2))
        stats["loss_pct"] = int(packet_match.group(3))
        stats["lost"] = stats["sent"] - stats["received"]

    time_match = re.search(r"min/avg/max.*?= ([\d\.]+)/([\d\.]+)/([\d\.]+)", output)
    if time_match:
        stats["min_ms"] = float(time_match.group(1))
        stats["avg_ms"] = float(time_match.group(2))
        stats["max_ms"] = float(time_match.group(3))
    return stats


def run(
    target: str = typer.Argument(..., help="Target hostname or IP address."),
    count: int = typer.Option(4, "--count", "-c", help="Number of echo requests."),
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
) -> None:
    if is_windows():
        cmd = ["ping", "-n", str(count), "-w", "1000", target]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", target]

    code, stdout, stderr = run_command(cmd)
    if code != 0 and not stdout:
        console.print(Panel(f"[bold red]{stderr.strip()}[/bold red]"))
        return

    stats = _parse_windows_ping(stdout) if is_windows() else _parse_unix_ping(stdout)
    if not stats:
        console.print(Panel("[bold yellow]Unable to parse ping output.[/bold yellow]"))
        console.print(stdout)
        return

    table = Table(title=f"Ping Results: {target}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Packets Sent", str(stats.get("sent", "-")))
    table.add_row("Packets Received", str(stats.get("received", "-")))
    table.add_row("Packets Lost", str(stats.get("lost", "-")))
    table.add_row("Packet Loss", f"{stats.get('loss_pct', '-')}" + "%")
    table.add_row("Minimum Latency (ms)", str(stats.get("min_ms", "-")))
    table.add_row("Average Latency (ms)", str(stats.get("avg_ms", "-")))
    table.add_row("Maximum Latency (ms)", str(stats.get("max_ms", "-")))

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("ping")
