import re
import typer

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from erreetool.utils import is_windows, run_command

console = Console()


def _extract_value(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else "-"


def run(
    explain: bool = typer.Option(False, "--explain", help="Show human-friendly explanation."),
) -> None:
    if not is_windows():
        console.print(
            Panel("[bold yellow]Wi-Fi details are currently supported on Windows only.[/bold yellow]")
        )
        return

    code, wlan_out, wlan_err = run_command(["netsh", "wlan", "show", "interfaces"])
    if code != 0:
        console.print(Panel(f"[bold red]{wlan_err.strip()}[/bold red]"))
        return

    code, ip_out, ip_err = run_command(["ipconfig", "/all"])
    if code != 0:
        console.print(Panel(f"[bold red]{ip_err.strip()}[/bold red]"))
        return

    ssid = _extract_value(r"^\s*SSID\s*:\s*(.+)$", wlan_out)
    bssid = _extract_value(r"^\s*BSSID\s*:\s*(.+)$", wlan_out)
    signal = _extract_value(r"^\s*Signal\s*:\s*(.+)$", wlan_out)
    radio = _extract_value(r"^\s*Radio type\s*:\s*(.+)$", wlan_out)

    ipv4 = _extract_value(r"IPv4 Address.*?:\s*([0-9\.]+)", ip_out)
    gateway = _extract_value(r"Default Gateway.*?:\s*([0-9\.]+)", ip_out)
    dns = _extract_value(r"DNS Servers.*?:\s*([0-9\.]+)", ip_out)
    mac = _extract_value(r"Physical Address.*?:\s*([0-9A-Fa-f\-]+)", ip_out)

    table = Table(title="Wi-Fi / Network Interface Info")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("SSID", ssid)
    table.add_row("BSSID", bssid)
    table.add_row("Signal", signal)
    table.add_row("Radio Type", radio)
    table.add_row("Local IPv4", ipv4)
    table.add_row("Gateway", gateway)
    table.add_row("DNS", dns)
    table.add_row("MAC Address", mac)

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("wifi")
