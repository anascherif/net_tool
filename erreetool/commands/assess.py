"""
Assess command - AI-assisted vulnerability triage using autonomous agent.

New implementation using the agent loop with evidence-based reasoning.
Supports both LLM-driven and skill-driven modes.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from erreetool.agent.loop import AgentConfig, AgentLoop
from erreetool.agent.providers import MultiProvider
from erreetool.agent.skills import skill_registry
from erreetool.agent.state import AgentState
from erreetool.reporting.generator import ReportGenerator

console = Console()

# Only scan systems you own or are explicitly authorized to test.


def run(
    target: str = typer.Argument(None, help="Target host or IP address."),
    full: bool = typer.Option(
        False, "--full", help="Full assessment (all tools, deep scan)."
    ),
    quick: bool = typer.Option(
        False, "--quick", help="Quick assessment (essential tools only)."
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Offline mode - no LLM calls (demo)."
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Interactive REPL mode."
    ),
    explain: bool = typer.Option(False, "--explain", help="Show AI explanation."),
    max_steps: int = typer.Option(30, "--max-steps", help="Maximum agent steps (legacy rounds mode)."),
    max_turns: int = typer.Option(240, "--max-turns", help="Maximum solve engine turns (safety budget)."),
    goal: str = typer.Option(None, "--goal", help="Specific assessment goal."),
    skill: str = typer.Option(
        None, "--skill", help="Run specific skill(s) by name (comma-separated)."
    ),
    list_skills: bool = typer.Option(
        False, "--list-skills", help="List available skills and exit."
    ),
    skill_mode: str = typer.Option(
        "auto", "--skill-mode", help="Skill selection mode: auto, quick, full."
    ),
    engine: str = typer.Option(
        "solve", "--engine", help="Engine mode: solve (model-driven), rounds (legacy), skill."
    ),
    no_report: bool = typer.Option(
        False, "--no-report", help="Disable automatic report generation."
    ),
) -> None:
    """
    AI-assisted vulnerability triage assessment.

    Runs an autonomous agent that:
    1. Scans target for open ports and services
    2. Identifies technologies and vulnerabilities
    3. Performs targeted enumeration
    4. Generates evidence-based triage report

    Skill-driven mode (--skill or default):
    - Executes structured YAML skills deterministically
    - More reliable than LLM tool calling
    - Use --skill quick-triage for quick end-to-end scan
    """
    # List skills and exit (no target needed)
    if list_skills:
        skill_registry.print_skills_table(show_all=True)
        return

    # Target is required for actual assessment
    if target is None:
        console.print(
            Panel(
                "[bold red]Error:[/bold red] Target is required",
                title="Missing Argument",
            )
        )
        return

    console.print(Panel(f"[bold cyan]Security Assessment for {target}[/bold cyan]"))

    # Handle Typer/Click bug: boolean flags may come as strings
    full = bool(full)
    quick = bool(quick)
    offline = bool(offline)
    interactive = bool(interactive)
    explain = bool(explain)
    list_skills = bool(list_skills)

    # List skills and exit
    if list_skills:
        skill_registry.print_skills_table(show_all=True)
        return

    # Check for LLM provider (not needed for skill-only offline mode)
    provider = None
    if not offline:
        try:
            provider = MultiProvider.from_env()
            provider_names = [p.__class__.__name__ for p in provider.providers]
            console.print(
                f"[green]OK[/green] LLM providers: {', '.join(provider_names)}"
            )
        except ValueError as e:
            console.print(
                Panel(
                    f"[bold red]{e}[/bold red]\n"
                    "Use --offline for demo mode or set OPENROUTER_API_KEY/NVIDIA_NIM_API_KEY",
                    title="Configuration Required",
                )
            )
            return
    else:
        console.print("[yellow]Offline mode - skipping LLM calls[/yellow]")

# Initialize agent state
    state = AgentState()
    state.context.target = target
    state.context.goals.append(goal or f"Penetration test on {target}")
    
    # Handle Typer/Click bug: boolean flags may come as strings
    full = bool(full)
    quick = bool(quick)
    offline = bool(offline)
    interactive = bool(interactive)
    explain = bool(explain)
    list_skills = bool(list_skills)
    no_report = bool(no_report)
    
    # Validate engine
    if engine not in ("solve", "rounds", "skill"):
        console.print(Panel(f"[bold red]Invalid engine: {engine}. Must be solve, rounds, or skill[/bold red]"))
        return
    
    # Determine mode
    use_skill_mode = skill is not None or engine == "skill" or (provider is None and not offline and quick)
    
    # Configure agent
    config = AgentConfig(
        max_steps=max_steps,
        max_turns=max_turns,
        evidence_gate_required=not offline,
        show_reasoning=explain,
        auto_report=not no_report,
        engine=engine,
        skill_mode=use_skill_mode,
        skill_names=skill or "",
        skill_mode_type=skill_mode,
    )

    # Create agent loop
    loop = AgentLoop(state, provider, config) if provider or use_skill_mode else None

    if interactive:
        # Launch REPL
        console.print("[cyan]Starting interactive mode...[/cyan]")
        from erreetool.interfaces.repl import run_repl

        run_repl(target=target, config=config)
        return
    
    # Handle offline mode with solve engine
    if not provider and engine == "solve":
        console.print("[yellow]Solve engine requires LLM provider, falling back to rounds mode[/yellow]")
        config.engine = "rounds"
        if provider is None:
            loop = AgentLoop(state, None, config) if use_skill_mode else None
        else:
            loop = AgentLoop(state, provider, config)
    elif not provider and not use_skill_mode:
        loop = None

    if interactive:
        # Launch REPL
        console.print("[cyan]Starting interactive mode...[/cyan]")
        from erreetool.interfaces.repl import run_repl

        run_repl(target=target, config=config)
        return

    # Quick mode: limit tools (for LLM mode)
    if quick and not use_skill_mode:
        console.print("[cyan]Quick mode: essential tools only[/cyan]")
        # The agent will self-limit based on goals

    # Run assessment
    console.print("[cyan]Starting assessment...[/cyan]")
    if goal:
        console.print(f"Goal: {goal}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("Running autonomous agent...", total=None)

            if loop:
                final_state = loop.run(goal)
            else:
                # Offline mode - just run basic tools
                final_state = _run_offline_assessment(state, target, quick)

            progress.update(task, description="Generating report...")

            # Generate report
            generator = ReportGenerator()
            report_path = generator.generate(final_state, format="markdown")

            progress.update(task, description="Complete!")

        # Display summary
        _display_summary(final_state, report_path)

        if explain:
            _show_explanation(final_state)

    except KeyboardInterrupt:
        console.print("\n[yellow]Assessment interrupted by user.[/yellow]")
        state.save()
        console.print(f"Session saved to {state.output_dir}")
    except Exception as e:
        console.print(f"[bold red]Assessment failed: {e}[/bold red]")
        state.save()
        console.print(f"Session saved to {state.output_dir}")


def _run_offline_assessment(state: AgentState, target: str, quick: bool) -> AgentState:
    """Run basic assessment without LLM."""
    from erreetool.agent.tools import tool_registry

    console.print("[dim]Running offline tools...[/dim]")

    # Run nmap
    nmap = tool_registry.get("nmap")
    if nmap and nmap.is_available():
        console.print("  [cyan]Running nmap...[/cyan]")
        result = nmap.run(target=target, ports="top-100" if quick else "top-1000")
        if result.success:
            state.add_evidence(
                "tool_output",
                "nmap",
                result.output,
                {"command": result.command, "duration": result.duration},
            )
            _extract_nmap_facts(state, result.output)

    # Run whatweb for web targets
    if _has_web_ports(state):
        whatweb = tool_registry.get("whatweb")
        if whatweb and whatweb.is_available():
            console.print("  [cyan]Running whatweb...[/cyan]")
            result = whatweb.run(target=target)
            if result.success:
                state.add_evidence(
                    "tool_output",
                    "whatweb",
                    result.output,
                    {"command": result.command, "duration": result.duration},
                )

    # Run nuclei
    nuclei = tool_registry.get("nuclei")
    if nuclei and nuclei.is_available():
        console.print("  [cyan]Running nuclei...[/cyan]")
        result = nuclei.run(target=target, severity="critical,high" if quick else None)
        if result.success:
            state.add_evidence(
                "tool_output",
                "nuclei",
                result.output,
                {"command": result.command, "duration": result.duration},
            )
            _extract_nuclei_facts(state, result.output)

    # Generate basic report
    state.context.current_phase = "complete"
    state.save()

    return state


def _has_web_ports(state: AgentState) -> bool:
    """Check if any web ports found."""
    for ev in state.evidence_log:
        if (
            "80/tcp" in ev.content
            or "443/tcp" in ev.content
            or "8080/tcp" in ev.content
        ):
            return True
    return False


def _extract_nmap_facts(state: AgentState, output: str):
    """Extract facts from nmap output."""
    import re

    for match in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)", output):
        port, service = match.groups()
        state.add_high_signal_fact(f"Port {port}/tcp open: {service}")


def _extract_nuclei_facts(state: AgentState, output: str):
    """Extract facts from nuclei output."""
    import re

    for match in re.finditer(r"CVE-\d{4}-\d{4,7}", output):
        state.add_high_signal_fact(f"Vulnerability: {match.group()}")


def _display_summary(state: AgentState, report_path):
    """Display assessment summary."""
    summary = state.get_summary()

    table = Table(title="Assessment Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    for k, v in summary.items():
        table.add_row(k.replace("_", " ").title(), str(v))

    console.print(table)

    # High-signal facts
    if state.context.high_signal_facts:
        console.print("\n[bold]Key Findings:[/bold]")
        for fact in state.context.high_signal_facts[-15:]:
            console.print(f"  - {fact}")

    console.print(f"\n[green]OK[/green] Report saved: {report_path}")
    console.print(f"[dim]Session: {state.output_dir}[/dim]")


def _show_explanation(state: AgentState):
    """Show explanation panel."""
    try:
        from erreetool.utils.explanations import show_explanation

        show_explanation("assess", f"Assessed {state.context.target}")
    except ImportError:
        console.print(
            "[yellow]Explanation feature not available (requires old explanation system)[/yellow]"
        )
