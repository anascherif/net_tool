import platform
import socket
import sys
from typing import List, Tuple
import shutil
import typer

from rich.console import Console
from rich.table import Table

from erreetool.utils import is_admin

console = Console()


def _check_internet() -> bool:
    try:
        sock = socket.create_connection(("1.1.1.1", 53), timeout=2)
        sock.close()
        return True
    except OSError:
        return False


def _check_package(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


def _status_label(ok: bool, warn: bool = False) -> Tuple[str, str]:
    if ok:
        return "PASS", "green"
    if warn:
        return "WARN", "yellow"
    return "FAIL", "red"


def run(
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
) -> None:
    checks: List[Tuple[str, bool, str, bool]] = []
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python >= 3.10", py_ok, sys.version.split()[0], False))

    checks.append(("Admin privileges", is_admin(), "Required for ARP scan", True))

    internet_ok = _check_internet()
    checks.append(("Internet connectivity", internet_ok, "1.1.1.1:53", False))

    os_name = platform.system()
    os_ok = os_name.lower() == "windows"
    checks.append(("OS compatibility", os_ok, os_name, True))

    nmap_ok = shutil.which("nmap") is not None
    checks.append(("Nmap installed", nmap_ok, "nmap binary", True))

    checks.append(("typer installed", _check_package("typer"), "package", False))
    checks.append(("rich installed", _check_package("rich"), "package", False))
    checks.append(("scapy installed", _check_package("scapy"), "package", False))
    checks.append(("dnspython installed", _check_package("dns"), "package", False))
    checks.append(("python-nmap installed", _check_package("nmap"), "package", True))
    checks.append(("speedtest-cli installed", _check_package("speedtest"), "package", True))

    table = Table(title="ERREETOOL Doctor")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details", style="green")

    for label, ok, details, warn in checks:
        status, color = _status_label(ok, warn=warn)
        table.add_row(label, f"[{color}]{status}[/{color}]", details)

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("doctor")
