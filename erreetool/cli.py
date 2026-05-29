import shlex
import typer
from typer.main import get_command
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


def run_from_menu(command_line: str) -> None:
    cleaned = command_line.strip()
    if not cleaned:
        console.print(Panel("[bold yellow]No ERREETOOL command provided.[/bold yellow]"))
        return

    args = shlex.split(cleaned)
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
