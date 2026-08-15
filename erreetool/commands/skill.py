"""
Skill CLI commands for managing pentest skills.
"""

import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from erreetool.agent.skills import skill_loader, skill_registry
from erreetool.agent.skills.schema import Skill

console = Console()


def run(
    subcommand: str = typer.Argument("list", help="Subcommand: list, show, validate"),
    name: str = typer.Option(None, "--name", "-n", help="Skill name for show command"),
    file: str = typer.Option(None, "--file", "-f", help="Skill YAML file for validate"),
    tag: str = typer.Option(None, "--tag", "-t", help="Filter by tag"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Manage pentest skills.

    Commands:
      list       List all available skills
      show       Show skill details (requires --name)
      validate   Validate a skill YAML file (requires --file)
    """
    skill_loader.load_all()

    if subcommand == "list":
        _list_skills(tag, verbose)
    elif subcommand == "show":
        if not name:
            console.print("[red]Error:[/red] --name required for show command")
            console.print("Usage: erreetool skill show --name <skill-name>")
            return
        _show_skill(name)
    elif subcommand == "validate":
        if not file:
            console.print("[red]Error:[/red] --file required for validate command")
            return
        _validate_skill(file)
    else:
        console.print(f"[red]Unknown subcommand: {subcommand}[/red]")
        console.print("Available: list, show, validate")


def _list_skills(tag: Optional[str] = None, verbose: bool = False):
    """List all available skills."""
    if tag:
        skills = skill_loader.list_by_tag(tag)
        if not skills:
            console.print(f"[yellow]No skills found with tag: {tag}[/yellow]")
            return
    else:
        skills = skill_loader.list_all()

    if not skills:
        console.print("[yellow]No skills loaded[/yellow]")
        return

    table = Table(title=f"Available Skills ({len(skills)} total)")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Tags", style="green")
    table.add_column("Tools", style="yellow")
    table.add_column("Description", style="white")

    for skill in skills:
        tags_str = ", ".join(skill.tags)
        tools_str = ", ".join(skill.requires_tools)
        desc = skill.description[:60] + "..." if len(skill.description) > 60 else skill.description
        table.add_row(skill.name, tags_str, tools_str, desc)

    console.print(table)


def _show_skill(name: str):
    """Show detailed skill information."""
    skill = skill_loader.get(name)
    if not skill:
        console.print(f"[red]Skill not found: {name}[/red]")
        available = [s.name for s in skill_loader.list_all()]
        if available:
            console.print(f"Available: {', '.join(available)}")
        return

    # Basic info
    console.print(Panel(
        f"[bold]Name:[/bold] {skill.name}\n"
        f"[bold]Description:[/bold] {skill.description}\n"
        f"[bold]Version:[/bold] {skill.version}\n"
        f"[bold]Author:[/bold] {skill.author}\n"
        f"[bold]Tags:[/bold] {', '.join(skill.tags) or 'none'}\n"
        f"[bold]Requires:[/bold] {', '.join(skill.requires_tools) or 'none'}\n"
        f"[bold]Phases:[/bold] {len(skill.phases)}\n"
        f"[bold]Gates:[/bold] {len(skill.gates)}",
        title=f"Skill: {skill.name}",
        border_style="cyan"
    ))

    # Phases
    for i, phase in enumerate(skill.phases, 1):
        cond = f" (if: {phase.condition})" if phase.condition else ""
        console.print(f"\n[bold cyan]Phase {i}: {phase.name}[/bold cyan]{cond}")
        console.print(f"  {phase.description}")

        for step in phase.steps:
            args_str = ", ".join(f"{k}={v}" for k, v in step.args.items())
            if args_str:
                args_str = f" ({args_str})"
            console.print(f"  [green]->[/green] {step.name}: {step.tool}{args_str}")
            if step.extract_facts:
                for fe in step.extract_facts:
                    console.print(f"    [dim]Fact: {fe.fact_template} (type: {fe.fact_type})[/dim]")

    # Gates
    if skill.gates:
        console.print("\n[bold]Verification Gates:[/bold]")
        for gate in skill.gates:
            sev_color = {"error": "red", "warning": "yellow", "info": "blue"}.get(gate.severity, "white")
            console.print(f"  [{sev_color}]{gate.severity.upper()}[/{sev_color}] {gate.name}: {gate.condition}")
            if gate.on_fail:
                console.print(f"    [dim]On fail: {gate.on_fail}[/dim]")


def _validate_skill(file_path: str):
    """Validate a skill YAML file."""
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        return

    try:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)

        from erreetool.agent.skills.schema import parse_skill
        skill = parse_skill(data, source_file=str(path))

        console.print(Panel(
            f"[green]OK Valid skill: {skill.name}[/green]\n"
            f"  Phases: {len(skill.phases)}\n"
            f"  Steps: {sum(len(p.steps) for p in skill.phases)}\n"
            f"  Gates: {len(skill.gates)}\n"
            f"  Tools: {', '.join(skill.requires_tools) or 'none'}",
            title="Validation Success",
            border_style="green"
        ))

    except Exception as e:
        console.print(Panel(
            f"[red]Invalid skill: {e}[/red]",
            title="Validation Failed",
            border_style="red"
        ))


if __name__ == "__main__":
    typer.run(run)