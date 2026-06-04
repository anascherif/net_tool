import socket
import shutil
from typing import Iterable, List

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


def _default_ports() -> List[int]:
    return [
        21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 139, 143, 161, 389, 443,
        445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
    ]


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _nmap_available() -> bool:
    try:
        import nmap  # noqa: F401
    except ImportError:
        return False
    return shutil.which("nmap") is not None


def _scan_with_nmap(target: str, full: bool) -> List[tuple]:
    import nmap

    scanner = nmap.PortScanner()
    if full:
        arguments = "-sV -T4 -p-"
    else:
        arguments = "-sV -T4 --top-ports 1000"

    scanner.scan(hosts=target, arguments=arguments)
    results = []
    if target not in scanner.all_hosts():
        return results
    tcp_data = scanner[target].get("tcp", {})
    for port, data in tcp_data.items():
        if data.get("state") == "open":
            service = data.get("name", "unknown")
            product = data.get("product") or ""
            detail = f"{service} {product}".strip()
            results.append((port, detail or service))
    return results


def _scan_with_socket(target: str, ports: Iterable[int]) -> List[tuple]:
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Scanning ports...", total=None)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                if sock.connect_ex((target, port)) == 0:
                    results.append((port, _service_name(port)))
            finally:
                sock.close()
            progress.advance(task)
    return results


def run(
    target: str = typer.Argument(..., help="Target host or IP address."),
    full: bool = typer.Option(False, "--full", is_flag=True, help="Scan all ports (1-65535)."),
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
) -> None:
    console.print(Panel(f"[bold cyan]Port scan for {target}[/bold cyan]"))

    if _nmap_available():
        try:
            import nmap

            results = _scan_with_nmap(target, full)
        except (nmap.PortScannerError, OSError) as exc:
            console.print(
                Panel(
                    f"[bold yellow]Nmap scan failed: {exc}[/bold yellow]\n"
                    "Falling back to socket scanning."
                )
            )
            ports = range(1, 65536) if full else _default_ports()
            results = _scan_with_socket(target, ports)
    else:
        ports = range(1, 65536) if full else _default_ports()
        results = _scan_with_socket(target, ports)

    if not results:
        console.print(Panel("[bold yellow]No open ports found.[/bold yellow]"))
        return

    table = Table(title="Open Ports")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")

    for port, service in sorted(results, key=lambda item: item[0]):
        table.add_row(str(port), service)

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("ports")
