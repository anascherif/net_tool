"""
REPL (Read-Eval-Print Loop) interface for interactive agent usage.

Provides an interactive terminal for controlling the autonomous agent.
"""

import cmd
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erreetool.agent.loop import AgentConfig, AgentLoop
from erreetool.agent.providers import MultiProvider
from erreetool.agent.state import AgentState
from erreetool.agent.tools.base import tool_registry

console = Console()


class ErreetoolREPL(cmd.Cmd):
    """Interactive REPL for erreetool agent."""

    intro = ""
    prompt = " erreetool> "

    def __init__(self, target: str = None, config: AgentConfig = None):
        super().__init__()
        self.target = target
        self.config = config or AgentConfig()
        self.state: AgentState | None = None
        self.loop: AgentLoop | None = None
        self.provider: MultiProvider | None = None

        # Initialize provider
        self._init_provider()

        # If target provided, initialize state
        if target:
            self._init_session(target)

    def _init_provider(self):
        """Initialize LLM provider from environment."""
        try:
            self.provider = MultiProvider.from_env()
            provider_names = [p.__class__.__name__ for p in self.provider.providers]
            console.print(
                f"[green]OK[/green] LLM providers loaded: {', '.join(provider_names)}"
            )
        except ValueError as e:
            console.print(f"[red]FAIL[/red] {e}")
            console.print(
                "[yellow]Set OPENROUTER_API_KEY or NVIDIA_NIM_API_KEY in .env[/yellow]"
            )
            self.provider = None

    def _init_session(self, target: str):
        """Initialize agent state for target."""
        self.state = AgentState()
        self.state.context.target = target
        self.state.context.goals.append(f"Penetration test on {target}")
        self.loop = AgentLoop(self.state, self.provider, self.config)
        console.print(f"[green]OK[/green] Session initialized for target: {target}")

    def preloop(self):
        """Print welcome message."""
        self._print_banner()
        if not self.target:
            console.print(
                "[yellow]No target set. Use 'target <IP>' to set target.[/yellow]"
            )

    def _print_banner(self):
        """Print welcome banner."""
        banner = Text()
        banner.append(" ", style="bold red")
        banner.append("erreetool ", style="bold cyan")
        banner.append("AI Penetration Testing Agent", style="white")
        console.print(Panel(banner, border_style="cyan"))
        console.print("Type [bold]help[/bold] for commands.\n")

    # ---- Commands ----

    def do_target(self, arg):
        """Set target: target <IP_or_hostname>"""
        if not arg:
            console.print("[red]Usage: target <IP_or_hostname>[/red]")
            return

        self.target = arg.strip()
        self._init_session(self.target)

    def do_run(self, arg):
        """Run autonomous agent: run [goal]"""
        if not self.state:
            console.print("[red]No target set. Use 'target <IP>' first.[/red]")
            return

        if not self.provider:
            console.print("[red]No LLM provider configured.[/red]")
            return

        goal = arg.strip() if arg else f"Full penetration test on {self.target}"
        console.print(f"[cyan]Starting autonomous assessment: {goal}[/cyan]")

        try:
            self.state.context.goals.append(goal)
            self.loop.run(goal)
            console.print("[green]OK[/green] Assessment complete!")
            self._show_summary()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def do_step(self, arg):
        """Execute single step: step <tool> [args...]"""
        if not self.state or not self.loop:
            console.print("[red]No active session.[/red]")
            return

        parts = arg.split()
        if not parts:
            console.print("[red]Usage: step <tool> [args...][/red]")
            return

        tool_name = parts[0]
        # Parse remaining as key=value
        kwargs = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                kwargs[k] = v

        executor = self.loop.tool_executors.get(f"run_{tool_name}")
        if not executor:
            console.print(f"[red]Unknown tool: {tool_name}[/red]")
            console.print(f"Available: {list(self.loop.tool_executors.keys())}")
            return

        try:
            result = executor(**kwargs)
            if result.success:
                console.print(
                    f"[green]OK[/green] {tool_name} completed in {result.duration:.1f}s"
                )
                console.print(result.stdout[:2000])
            else:
                console.print(f"[red]FAIL[/red] {tool_name} failed: {result.stderr}")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def do_evidence(self, arg):
        """Show evidence: evidence [search_term] [--type TYPE] [--limit N]"""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        parts = arg.split()
        search = ""
        ev_type = None
        limit = 10

        i = 0
        while i < len(parts):
            if parts[i] == "--type":
                ev_type = parts[i + 1]
                i += 2
            elif parts[i] == "--limit":
                limit = int(parts[i + 1])
                i += 2
            else:
                search = parts[i]
                i += 1

        from erreetool.agent.state import EvidenceType

        etype = EvidenceType(ev_type) if ev_type else None

        results = self.state.search_evidence(search, type=etype, limit=limit)

        if not results:
            console.print("[yellow]No evidence found.[/yellow]")
            return

        table = Table(title=f"Evidence ({len(results)} results)")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Source", style="green")
        table.add_column("Preview", style="white")

        for ev in results:
            table.add_row(ev.id, ev.type.value, ev.source, ev.preview(100))

        console.print(table)

    def do_show(self, arg):
        """Show evidence details: show <evidence_id>"""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        ev = self.state.get_evidence(arg.strip())
        if not ev:
            console.print(f"[red]Evidence not found: {arg}[/red]")
            return

        console.print(
            Panel(
                ev.content,
                title=f"[{ev.id}] {ev.type.value} from {ev.source}",
                border_style="cyan",
            )
        )

    def do_context(self, arg):
        """Show current context."""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        ctx = self.state.context
        console.print(
            Panel(
                f"Target: {ctx.target}\n"
                f"Phase: {ctx.current_phase}\n"
                f"Goals: {len(ctx.goals)}\n"
                f"High-signal facts: {len(ctx.high_signal_facts)}\n"
                f"Completed skills: {len(ctx.completed_skills)}\n"
                f"Steps: {len(self.state.steps)}\n"
                f"Evidence: {len(self.state.evidence_log)}",
                title="Agent Context",
                border_style="cyan",
            )
        )

        if ctx.high_signal_facts:
            console.print("\n[bold]High-signal facts:[/bold]")
            for fact in ctx.high_signal_facts[-20:]:
                console.print(f"  • {fact}")

    def do_goals(self, arg):
        """Manage goals: goals [add|remove|list] [goal_text]"""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        parts = arg.split(maxsplit=1)
        action = parts[0] if parts else "list"
        text = parts[1] if len(parts) > 1 else ""

        if action == "add" and text:
            self.state.context.goals.append(text)
            console.print(f"[green]Added goal:[/green] {text}")
        elif action == "remove" and text:
            try:
                idx = int(text)
                removed = self.state.context.goals.pop(idx)
                console.print(f"[green]Removed goal:[/green] {removed}")
            except (ValueError, IndexError):
                console.print("[red]Invalid goal index.[/red]")
        else:
            console.print("[bold]Current goals:[/bold]")
            for i, goal in enumerate(self.state.context.goals):
                console.print(f"  {i}: {goal}")

    def do_facts(self, arg):
        """Manage high-signal facts: facts [add|remove|list] [fact_text]"""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        parts = arg.split(maxsplit=1)
        action = parts[0] if parts else "list"
        text = parts[1] if len(parts) > 1 else ""

        if action == "add" and text:
            self.state.add_high_signal_fact(text)
            console.print(f"[green]Added fact:[/green] {text}")
        elif action == "remove" and text:
            try:
                idx = int(text)
                removed = self.state.context.high_signal_facts.pop(idx)
                console.print(f"[green]Removed fact:[/green] {removed}")
            except (ValueError, IndexError):
                console.print("[red]Invalid fact index.[/red]")
        else:
            console.print("[bold]High-signal facts:[/bold]")
            for i, fact in enumerate(self.state.context.high_signal_facts):
                console.print(f"  {i}: {fact}")

    def do_verify(self, arg):
        """Verify a claim against evidence: verify <claim>"""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        if not arg:
            console.print("[red]Usage: verify <claim>[/red]")
            return

        verified, matches = self.state.verify_claim(arg)
        if verified:
            console.print(f"[green]OK VERIFIED[/green]: {arg}")
            for m in matches:
                console.print(f"  Evidence: [{m.id}] {m.source}")
        else:
            console.print(f"[red]FAIL UNVERIFIED[/red]: {arg}")

    def do_tools(self, arg):
        """List available tools and their status."""
        status = tool_registry.get_status()

        table = Table(title="Available Tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Binary", style="yellow")

        for name, available in status.items():
            tool = tool_registry.get(name)
            binary = tool.binary if tool else "N/A"
            status_str = (
                "[green]OK Available[/green]"
                if available
                else "[red]FAIL Not found[/red]"
            )
            table.add_row(name, status_str, binary)

        console.print(table)

    def do_report(self, arg):
        """Generate report from current session."""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        from erreetool.reporting.generator import ReportGenerator

        generator = ReportGenerator()
        report_path = generator.generate(self.state)
        console.print(f"[green]OK[/green] Report generated: {report_path}")

    def do_save(self, arg):
        """Save session state."""
        if not self.state:
            console.print("[red]No active session.[/red]")
            return

        self.state.save()
        console.print(f"[green]OK[/green] Session saved to {self.state.state_file}")

    def do_load(self, arg):
        """Load session: load <state_file>"""
        if not arg:
            console.print("[red]Usage: load <state_file>[/red]")
            return

        try:
            self.state = AgentState.load(Path(arg.strip()))
            self.loop = AgentLoop(self.state, self.provider, self.config)
            console.print(f"[green]OK[/green] Session loaded: {self.state.session_id}")
        except Exception as e:
            console.print(f"[red]Error loading session: {e}[/red]")

    def do_clear(self, arg):
        """Clear screen."""
        console.clear()
        self._print_banner()

    def do_history(self, arg):
        """Show command history."""
        console.print("[bold]Recent steps:[/bold]")
        for step in self.state.steps[-20:] if self.state else []:
            status_icon = {
                "completed": "[green]OK[/green]",
                "failed": "[red]FAIL[/red]",
                "running": "[yellow]⟳[/yellow]",
            }.get(step.status.value, "?")
            console.print(
                f"  {status_icon} {step.id}: {step.description} ({step.tool})"
            )

    def do_exit(self, arg):
        """Exit REPL."""
        if self.state:
            self.state.save()
            console.print("[yellow]Session saved. Goodbye![/yellow]")
        return True

    def do_quit(self, arg):
        """Exit REPL."""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        """Exit on Ctrl+D."""
        return self.do_exit(arg)

    def _show_summary(self):
        """Show assessment summary."""
        if not self.state:
            return

        summary = self.state.get_summary()

        table = Table(title="Assessment Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        for k, v in summary.items():
            table.add_row(k.replace("_", " ").title(), str(v))

        console.print(table)

    def default(self, line):
        """Handle unknown commands as natural language to agent."""
        if self.state and self.loop and self.provider:
            # Send as user input to agent
            self.state.add_evidence("user_input", "user", line, {"interactive": True})
            console.print("[dim]Processing...[/dim]")
            # Could trigger agent step here
        else:
            console.print(f"[red]Unknown command: {line}[/red]")
            console.print("Type 'help' for available commands.")


def run_repl(target: str = None, config: AgentConfig = None):
    """Entry point for REPL."""
    repl = ErreetoolREPL(target=target, config=config)
    repl.cmdloop()


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else None
    run_repl(target=target)
