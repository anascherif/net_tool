import socket
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scapy.all import ARP, Ether, srp  # type: ignore

from erreetool.utils import is_admin

console = Console()


def _resolve_hostname(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return "-"


def _calc_rtt_ms(sent_pkt, recv_pkt) -> Optional[float]:
    sent_time = getattr(sent_pkt, "sent_time", None)
    if sent_time is None:
        sent_time = getattr(sent_pkt, "time", None)
    recv_time = getattr(recv_pkt, "time", None)
    if sent_time is None or recv_time is None:
        return None
    return round((recv_time - sent_time) * 1000, 2)


def run(
    target: str = typer.Argument(..., help="Target network in CIDR format."),
    timeout: float = typer.Option(2.0, help="ARP response timeout in seconds."),
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
) -> None:
    if not is_admin():
        console.print(
            Panel(
                "[bold red]Admin privileges are required for ARP scanning.[/bold red]\n"
                "Run the tool as Administrator.",
                title="Permission Required",
            )
        )
        return

    console.print(Panel(f"[bold cyan]Scanning {target}[/bold cyan]"))
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except (PermissionError, OSError) as exc:
        console.print(Panel(f"[bold red]Scan failed: {exc}[/bold red]"))
        return

    if not answered:
        console.print(Panel("[bold yellow]No active hosts found.[/bold yellow]"))
        return

    table = Table(title="Active Hosts")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="magenta")
    table.add_column("Hostname", style="green")
    table.add_column("Response Time (ms)", style="yellow", justify="right")

    for sent, received in answered:
        ip_addr = received.psrc
        mac_addr = received.hwsrc
        hostname = _resolve_hostname(ip_addr)
        rtt = _calc_rtt_ms(sent, received)
        rtt_display = f"{rtt:.2f}" if rtt is not None else "-"
        table.add_row(ip_addr, mac_addr, hostname, rtt_display)

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("scan", f"Scanned {target}")
