"""
TUI Main Application - Textual-based terminal workspace.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, Input, Select, 
    Tree, Log, TabbedContent, TabPane, Label, Checkbox,
    RichLog, DataTable, Collapsible
)
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets.tree import TreeNode
from rich.text import Text
from rich.syntax import Syntax

from erreetool.agent.state import AgentState, AgentContext, EvidenceType
from erreetool.agent.loop import AgentLoop, AgentConfig
from erreetool.agent.providers import MultiProvider
from erreetool.agent.skills import skill_registry
from erreetool.config import get_output_dir


@dataclass
class TargetScope:
    """Target scope configuration."""
    hosts: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)
    max_depth: int = 3
    rate_limit: int = 100


class ScopeConfigScreen(Screen):
    """Screen for configuring target scope."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("enter", "save_scope", "Save"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Label("Target Scope Configuration", classes="title"),
                Label("Hosts (one per line):"),
                Input(placeholder="192.168.1.0/24", id="hosts_input"),
                Label("Ports (comma-separated):"),
                Input(placeholder="80,443,8080", id="ports_input"),
                Label("Paths (one per line):"),
                Input(placeholder="/admin, /api", id="paths_input"),
                Label("Allowed Actions:"),
                Checkbox("Reconnaissance", id="allow_recon"),
                Checkbox("Vulnerability Scanning", id="allow_vuln"),
                Checkbox("Exploitation", id="allow_exploit"),
                Checkbox("Post-Exploitation", id="allow_post"),
                Label("Denied Actions:"),
                Checkbox("DoS/DDoS", id="deny_dos"),
                Checkbox("Data Exfiltration", id="deny_exfil"),
                Checkbox("Lateral Movement", id="deny_lateral"),
                Button("Save Scope", variant="primary", id="save_btn"),
                classes="scope_container"
            ),
            id="scope_screen"
        )
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_btn":
            self.save_scope()
    
    def save_scope(self):
        hosts = self.query_one("#hosts_input", Input).value.splitlines()
        ports = [int(p.strip()) for p in self.query_one("#ports_input", Input).value.split(",") if p.strip()]
        paths = self.query_one("#paths_input", Input).value.splitlines()
        
        allowed = []
        if self.query_one("#allow_recon", Checkbox).value:
            allowed.append("recon")
        if self.query_one("#allow_vuln", Checkbox).value:
            allowed.append("vuln_scan")
        if self.query_one("#allow_exploit", Checkbox).value:
            allowed.append("exploit")
        if self.query_one("#allow_post", Checkbox).value:
            allowed.append("post_exploit")
        
        denied = []
        if self.query_one("#deny_dos", Checkbox).value:
            denied.append("dos")
        if self.query_one("#deny_exfil", Checkbox).value:
            denied.append("exfiltration")
        if self.query_one("#deny_lateral", Checkbox).value:
            denied.append("lateral")
        
        self.app.target_scope = TargetScope(
            hosts=hosts,
            ports=ports,
            paths=paths,
            allowed_actions=allowed,
            denied_actions=denied
        )
        
        self.app.pop_screen()
        self.app.notify("Scope saved", severity="information")
    
    def action_go_back(self):
        self.app.pop_screen()


class DryRunPreviewScreen(Screen):
    """Screen showing dry-run preview of assessment plan."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("enter", "start_assessment", "Start"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Label("Dry-Run Preview", classes="title"),
                RichLog(id="preview_log", highlight=True, markup=True),
                Button("Start Assessment", variant="primary", id="start_btn"),
                Button("Back", variant="default", id="back_btn"),
                classes="preview_container"
            ),
            id="preview_screen"
        )
        yield Footer()
    
    def on_mount(self):
        self.update_preview()
    
    def update_preview(self):
        log = self.query_one("#preview_log", RichLog)
        scope = self.app.target_scope
        
        log.write("[bold cyan]Assessment Plan Preview[/bold cyan]\n")
        log.write(f"[bold]Engine:[/bold] {self.app.agent_config.engine}\n")
        log.write(f"[bold]Mode:[/bold] {'Skill-driven' if self.app.agent_config.skill_mode else 'Model-driven'}\n\n")
        
        log.write("[bold]Target Scope:[/bold]")
        for host in scope.hosts:
            log.write(f"  • {host}")
        log.write("")
        
        if scope.ports:
            log.write(f"[bold]Ports:[/bold] {', '.join(str(p) for p in scope.ports)}")
        else:
            log.write("[bold]Ports:[/bold] All (top 1000)")
        
        if scope.paths:
            log.write(f"[bold]Paths:[/bold] {', '.join(scope.paths)}")
        
        log.write(f"\n[bold]Allowed Actions:[/bold] {', '.join(scope.allowed_actions) if scope.allowed_actions else 'All'}")
        log.write(f"[bold]Denied Actions:[/bold] {', '.join(scope.denied_actions) if scope.denied_actions else 'None'}")
        
        if self.app.agent_config.skill_mode:
            skills = skill_registry.select_skills(
                AgentState(), 
                mode=self.app.agent_config.skill_mode_type,
                requested=self.app.agent_config.skill_names
            )
            log.write(f"\n[bold]Selected Skills:[/bold]")
            for skill in skills:
                log.write(f"  • {skill.name} - {skill.description[:60]}...")
    
    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "start_btn":
            self.app.start_assessment()
        elif event.button.id == "back_btn":
            self.app.pop_screen()
    
    def action_go_back(self):
        self.app.pop_screen()
    
    def action_start_assessment(self):
        self.app.start_assessment()


class EvidencePanel(Static):
    """Live evidence panel showing recent findings."""
    
    def __init__(self, state: AgentState):
        super().__init__()
        self.state = state
    
    def compose(self) -> ComposeResult:
        yield RichLog(id="evidence_log", highlight=True, markup=True, auto_scroll=True)
    
    def on_mount(self):
        self.update_evidence()
        self.set_interval(2.0, self.update_evidence)
    
    def update_evidence(self):
        log = self.query_one("#evidence_log", RichLog)
        log.clear()
        
        # Show high-signal facts
        if self.state.context.high_signal_facts:
            log.write("[bold cyan]High-Signal Facts[/bold cyan]")
            for fact in self.state.context.high_signal_facts[-10:]:
                log.write(f"  [green]✓[/green] {fact}")
            log.write("")
        
        # Show recent evidence
        recent_evidence = self.state.evidence_log[-20:]
        for ev in reversed(recent_evidence):
            color = "green" if ev.type.value == "tool_output" else "red" if ev.type.value == "tool_error" else "yellow"
            log.write(f"  [{color}]{ev.id}[/{color}] {ev.type.value} from {ev.source}")
            preview = ev.preview(120)
            for line in preview.splitlines():
                log.write(f"    {line}")


class ToolOutputPanel(Static):
    """Live tool output streaming panel."""
    
    def __init__(self, state: AgentState):
        super().__init__()
        self.state = state
    
    def compose(self) -> ComposeResult:
        yield RichLog(id="tool_log", highlight=True, markup=True, auto_scroll=True)
    
    def on_mount(self):
        self.update_tools()
        self.set_interval(1.0, self.update_tools)
    
    def update_tools(self):
        log = self.query_one("#tool_log", RichLog)
        # Clear and show recent tool activity
        if self.state.steps:
            recent_steps = self.state.steps[-5:]
            log.clear()
            log.write("[bold cyan]Recent Tool Activity[/bold cyan]")
            for step in reversed(recent_steps):
                status_color = "green" if step.status.value == "completed" else "red"
                log.write(f"  [{status_color}]▶[/{status_color}] {step.tool} - {step.description}")
                if step.error:
                    log.write(f"    [red]Error:[/red] {step.error}")


class AttackGraphPanel(Static):
    """Attack graph visualization panel."""
    
    def __init__(self, state: AgentState):
        super().__init__()
        self.state = state
    
    def compose(self) -> ComposeResult:
        yield Tree("Attack Graph", id="attack_tree")
    
    def on_mount(self):
        self.update_graph()
        self.set_interval(5.0, self.update_graph)
    
    def update_graph(self):
        tree = self.query_one("#attack_tree", Tree)
        tree.clear()
        
        if not self.state.context.high_signal_facts:
            tree.root.add_leaf("[dim]No attack graph data yet[/dim]")
            return
        
        # Build simple tree from high-signal facts
        host_node = tree.root.add("🎯 " + (self.state.context.target or "Unknown Target"))
        
        for fact in self.state.context.high_signal_facts:
            fact_lower = fact.lower()
            if "port" in fact_lower and "open" in fact_lower:
                host_node.add_leaf(f"🔌 {fact}")
            elif "cve" in fact_lower:
                host_node.add_leaf(f"💥 {fact}")
            elif "form" in fact_lower or "endpoint" in fact_lower:
                host_node.add_leaf(f"📝 {fact}")
            elif "sink" in fact_lower:
                host_node.add_leaf(f"⚠️ {fact}")
            elif "sql" in fact_lower or "inject" in fact_lower:
                host_node.add_leaf(f"💉 {fact}")
            else:
                host_node.add_leaf(f"📋 {fact}")


class AssessmentRunningScreen(Screen):
    """Main assessment running screen with live panels."""
    
    BINDINGS = [
        Binding("ctrl+c", "stop_assessment", "Stop"),
        Binding("f1", "toggle_evidence", "Evidence"),
        Binding("f2", "toggle_tools", "Tools"),
        Binding("f3", "toggle_graph", "Graph"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Horizontal(
                Vertical(
                    EvidencePanel(self.app.agent_state),
                    ToolOutputPanel(self.app.agent_state),
                    id="left_panel"
                ),
                AttackGraphPanel(self.app.agent_state),
                id="main_panels"
            ),
            id="running_screen"
        )
        yield Footer()
    
    def action_stop_assessment(self):
        self.app.stop_assessment()
    
    def action_toggle_evidence(self):
        self.app.notify("Evidence panel toggled", severity="information")
    
    def action_toggle_tools(self):
        self.app.notify("Tools panel toggled", severity="information")
    
    def action_toggle_graph(self):
        self.app.notify("Graph panel toggled", severity="information")


class ERREETOOLApp(App):
    """Main TUI Application."""
    
    CSS = """
    .title {
        text-align: center;
        text-style: bold;
        color: cyan;
        margin: 1;
    }
    .scope_container {
        width: 80;
        height: auto;
        padding: 1;
        border: solid cyan;
    }
    .preview_container {
        width: 100;
        height: auto;
        padding: 1;
        border: solid cyan;
    }
    .preview_container RichLog {
        height: 40;
    }
    #running_screen {
        height: 100%;
    }
    #main_panels {
        height: 100%;
    }
    #left_panel {
        width: 60%;
    }
    #left_panel RichLog {
        height: 50%;
    }
    #left_panel Tree {
        height: 50%;
    }
    RichLog {
        border: solid cyan;
        padding: 1;
    }
    Tree {
        border: solid cyan;
        padding: 1;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+s", "configure_scope", "Scope"),
        Binding("ctrl+d", "dry_run", "Dry Run"),
    ]
    
    def __init__(self):
        super().__init__()
        self.target_scope = TargetScope()
        self.agent_config = AgentConfig()
        self.agent_state: Optional[AgentState] = None
        self.agent_loop: Optional[AgentLoop] = None
        self.provider: Optional[MultiProvider] = None
        self.assessment_task: Optional[asyncio.Task] = None
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Label("ERREETOOL TUI - Penetration Testing Workspace", classes="title"),
                Label("Press Ctrl+S to configure scope, Ctrl+D for dry-run, Ctrl+Q to quit"),
                Button("Configure Scope (Ctrl+S)", id="scope_btn", variant="primary"),
                Button("Dry-Run Preview (Ctrl+D)", id="dryrun_btn", variant="default"),
                Button("Start Assessment", id="start_btn", variant="success"),
                id="main_menu"
            ),
            id="main_container"
        )
        yield Footer()
    
    def on_mount(self):
        self.title = "ERREETOOL TUI"
        self.sub_title = "Penetration Testing Workspace"
    
    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "scope_btn":
            self.push_screen(ScopeConfigScreen())
        elif event.button.id == "dryrun_btn":
            self.push_screen(DryRunPreviewScreen())
        elif event.button.id == "start_btn":
            self.start_assessment()
    
    def action_configure_scope(self):
        self.push_screen(ScopeConfigScreen())
    
    def action_dry_run(self):
        self.push_screen(DryRunPreviewScreen())
    
    def start_assessment(self):
        """Start the assessment."""
        if not self.target_scope.hosts:
            self.notify("No targets configured. Press Ctrl+S to configure scope.", severity="warning")
            return
        
        # Initialize agent state
        self.agent_state = AgentState()
        self.agent_state.context.target = self.target_scope.hosts[0]
        self.agent_state.context.goals.append("Full penetration test")
        
        # Configure agent
        self.agent_config.engine = "solve"
        self.agent_config.solve_max_turns = 240
        
        # Initialize provider
        try:
            self.provider = MultiProvider.from_env()
        except ValueError:
            self.notify("No LLM provider configured. Running in offline mode.", severity="warning")
            self.provider = None
        
        # Create agent loop
        self.agent_loop = AgentLoop(self.agent_state, self.provider, self.agent_config)
        
        # Switch to running screen
        self.push_screen(AssessmentRunningScreen())
        
        # Start assessment in background
        self.assessment_task = asyncio.create_task(self._run_assessment())
    
    async def _run_assessment(self):
        """Run assessment in background."""
        try:
            if self.agent_loop:
                self.agent_loop.run()
        except Exception as e:
            self.notify(f"Assessment error: {e}", severity="error")
        finally:
            self.notify("Assessment completed", severity="information")
    
    def stop_assessment(self):
        """Stop the running assessment."""
        if self.assessment_task:
            self.assessment_task.cancel()
            self.notify("Assessment stopped", severity="warning")
    
    def action_configure_scope(self):
        self.push_screen(ScopeConfigScreen())
    
    def action_dry_run(self):
        self.push_screen(DryRunPreviewScreen())
    
    def action_quit(self):
        self.stop_assessment()
        self.exit()


def run_tui(target: str = None, config: AgentConfig = None, **kwargs):
    """Run the TUI application."""
    app = ERREETOOLApp()
    
    if target:
        app.target_scope.hosts = [target]
    
    if config:
        app.agent_config = config
    
    # Apply any additional kwargs
    for key, value in kwargs.items():
        if hasattr(app.agent_config, key):
            setattr(app.agent_config, key, value)
    
    app.run()


if __name__ == "__main__":
    run_tui()