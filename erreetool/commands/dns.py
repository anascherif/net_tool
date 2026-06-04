import dns.resolver
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def run(
    target: str = typer.Argument(..., help="Domain name to resolve."),
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
) -> None:
    record_types = ["A", "AAAA", "MX", "TXT", "NS"]
    table = Table(title=f"DNS Lookup: {target}")
    table.add_column("Type", style="cyan")
    table.add_column("Answer", style="green")

    any_answer = False
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            for answer in answers:
                table.add_row(rtype, str(answer))
                any_answer = True
        except dns.resolver.NoAnswer:
            table.add_row(rtype, "-")
        except dns.resolver.NXDOMAIN:
            console.print(Panel(f"[bold red]Domain not found: {target}[/bold red]"))
            return
        except dns.exception.DNSException as exc:
            console.print(Panel(f"[bold red]DNS error: {exc}[/bold red]"))
            return

    if not any_answer:
        console.print(Panel("[bold yellow]No DNS records found.[/bold yellow]"))
        return

    console.print(table)

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("dns")
