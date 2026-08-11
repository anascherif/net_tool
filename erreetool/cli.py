import shlex
import click
import typer
from typer.main import get_command as _typer_get_command
from rich.console import Console
from rich.panel import Panel

from erreetool.commands import (
    scan,
    ports,
    dns,
    ping,
    trace,
    wifi,
    speedtest,
    doctor,
    assess,
    memory,
)

app = typer.Typer(
    name="erreetool",
    help="ERREETOOL | Advanced Networking Toolkit",
    add_completion=False,
)

console = Console()


app.command("scan")(scan.run)
app.command("ports")(ports.run)
app.command("dns")(dns.run)
app.command("ping")(ping.run)
app.command("trace")(trace.run)
app.command("wifi")(wifi.run)
app.command("speedtest")(speedtest.run)
app.command("doctor")(doctor.run)
app.command("assess")(assess.run)
app.command("memory")(memory.run)


def get_command(app):
    cmd = _typer_get_command(app)
    if hasattr(cmd, "commands"):
        for sub in cmd.commands.values():
            for param in sub.params:
                if isinstance(param, click.Option) and param.is_flag:
                    # Fix for Click 8.1+ / Typer 0.12.3 compatibility
                    if param.flag_value is None:
                        param.flag_value = True
                    # Also handle case where flag_value is not set
                    elif param.flag_value is True:
                        # Already set, nothing to do
                        pass
    return cmd


def get_command_list():
    return [
        ("scan", "ARP network scan in CIDR format"),
        ("ports", "Port scanning with service detection"),
        ("dns", "DNS record lookup (A/AAAA/MX/TXT/NS)"),
        ("ping", "ICMP echo test with statistics"),
        ("trace", "Traceroute to target host"),
        ("wifi", "Display Wi-Fi/network interface info"),
        ("speedtest", "Internet bandwidth speed test"),
        ("doctor", "Diagnostic health check"),
        ("assess", "AI-assisted vulnerability triage report"),
        ("memory", "Manage agent persistent memory"),
    ]


def run_from_menu(command_line: str) -> None:
    cleaned = command_line.strip()
    if not cleaned:
        console.print(Panel("[bold yellow]No ERREETOOL command provided.[/bold yellow]"))
        return

    args = shlex.split(cleaned)
    cmd_list = get_command_list()
    
    # Translate numeric choice to command string
    if args and args[0].isdigit():
        idx = int(args[0]) - 1
        if 0 <= idx < len(cmd_list):
            args[0] = cmd_list[idx][0]
        else:
            console.print(Panel(f"[bold red]Invalid option: {args[0]}[/bold red]"))
            return

    command = get_command(app)
    try:
        command.main(args=args, prog_name="erreetool", standalone_mode=False)
    except SystemExit as exc:
        if exc.code not in (0, None):
            console.print(
                Panel(
                    f"[bold red]ERREETOOL exited with code {exc.code}.[/bold red]",
                )
            )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
