"""
SkillRegistry - manages loaded skills, selects relevant skills based on
context (target facts, open ports, available tools), and runs them via
the SkillExecutor.
"""

from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.table import Table

from erreetool.agent.state import AgentState
from erreetool.agent.skills.loader import SkillLoader
from erreetool.agent.skills.executor import SkillExecutor
from erreetool.agent.skills.schema import Skill, SkillResult
from erreetool.agent.tools.base import tool_registry

console = Console()


@dataclass
class SelectionReason:
    """Why a skill was selected."""
    skill_name: str
    score: float
    reasons: list[str] = field(default_factory=list)


class SkillRegistry:
    """
    Manages skill discovery, selection, and execution.

    Selection heuristics:
    1. If user requested a specific skill name -> use it
    2. If a skill's required tools are all available -> boost score
    3. If high-signal facts match a skill's tags (e.g., 'smb' tag, fact mentions port 445) -> boost score
    4. 'quick' / 'full' modes select tagged skills
    """

    def __init__(self, loader: SkillLoader = None):
        self.loader = loader or SkillLoader()
        self.executor: Optional[SkillExecutor] = None

    def refresh(self):
        """Force reload all skills from disk."""
        self.loader.load_all(force=True)

    def list_skills(self) -> list[Skill]:
        """Get all loaded skills."""
        return self.loader.list_all()

    def get(self, name: str) -> Optional[Skill]:
        """Get a skill by name."""
        return self.loader.get(name)

    def is_runnable(self, skill: Skill) -> bool:
        """Check if all required tools for a skill are installed."""
        if not skill.requires_tools:
            return True
        for tool_name in skill.requires_tools:
            tool = tool_registry.get(tool_name)
            if tool is None or not tool.is_available():
                return False
        return True

    def select_skills(
        self,
        state: AgentState,
        mode: str = "auto",
        requested: str = None,
        max_skills: int = 10,
    ) -> list[Skill]:
        """
        Select skills to run based on context and mode.

        Args:
            state: Current agent state (for facts/target).
            mode: 'auto', 'quick', 'full'.
            requested: Optional skill name(s) to force run (comma-separated).
            max_skills: Maximum number of skills to select.
        """
        all_skills = self.list_skills()

        # Handle explicit user request
        if requested:
            names = [n.strip() for n in requested.split(",") if n.strip()]
            selected = []
            for name in names:
                skill = self.loader.get(name)
                if skill:
                    selected.append(skill)
                else:
                    console.print(f"[yellow]Skill not found: {name}[/yellow]")
            return selected

        # Score each skill
        scored = []
        for skill in all_skills:
            score, reasons = self._score_skill(skill, state, mode)
            if score > 0:
                scored.append(SelectionReason(skill.name, score, reasons))

        # Sort by score descending
        scored.sort(key=lambda x: x.score, reverse=True)

        # Filter runnable skills (all required tools available)
        runnable = []
        skipped = []
        for sel in scored:
            skill = self.loader.get(sel.skill_name)
            if self.is_runnable(skill):
                runnable.append(skill)
            else:
                skipped.append(sel)

        if skipped:
            console.print(
                f"[dim]Skipped {len(skipped)} skill(s) due to missing tools: "
                f"{', '.join(s.skill_name for s in skipped)}[/dim]"
            )

        return runnable[:max_skills]

    def _score_skill(self, skill: Skill, state: AgentState, mode: str) -> tuple[float, list[str]]:
        """Score a skill for relevance given current context."""
        score = 0.0
        reasons = []

        # Mode-based selection
        if mode == "quick" and "quick" in skill.tags:
            score += 5.0
            reasons.append("tagged 'quick'")
        if mode == "full" and "full" in skill.tags:
            score += 5.0
            reasons.append("tagged 'full'")

        # Always include core recon
        if "recon" in skill.tags and not state.context.high_signal_facts:
            score += 3.0
            reasons.append("recon tag + no facts yet")

        # Match tags against high-signal facts
        facts_blob = " ".join(state.context.high_signal_facts).lower()
        for tag in skill.tags:
            tag_lower = tag.lower()
            # Direct tag match in facts
            if tag_lower in facts_blob:
                score += 4.0
                reasons.append(f"tag '{tag}' matched in facts")
            # Port-based heuristics for common services
            if tag_lower == "smb" and ("445" in facts_blob or "smb" in facts_blob):
                score += 5.0
                reasons.append("port 445/smb detected")
            if tag_lower == "web" and ("80/tcp" in facts_blob or "443/tcp" in facts_blob or "8080" in facts_blob):
                score += 5.0
                reasons.append("web port detected")
            if tag_lower == "sqli" and "sql" in facts_blob:
                score += 4.0
                reasons.append("SQL-related fact detected")

        # Tool availability bonus (prefer skills whose tools are installed)
        if skill.requires_tools and self.is_runnable(skill):
            score += 1.0
            reasons.append("required tools available")

        # Demote skills already completed (but allow re-runs)
        if skill.name in state.context.completed_skills:
            score *= 0.3
            reasons.append("already completed (demoted)")

        return score, reasons

    def run_skill(self, skill: Skill, state: AgentState, tool_override: dict = None) -> SkillResult:
        """Execute a single skill and record results in state."""
        executor = SkillExecutor(state, tool_override=tool_override)
        self.executor = executor

        console.print(f"[cyan]Running skill:[/cyan] [bold]{skill.name}[/bold]")
        if skill.description:
            console.print(f"[dim]{skill.description}[/dim]")

        result = executor.execute(skill)
        self._print_result(result)
        return result
    
    def _print_result(self, result: SkillResult):
        """Print skill result summary."""
        status = "[green]SUCCESS[/green]" if result.success else "[red]FAILED[/red]"
        console.print(f"  {status} | Phases: {result.phases_executed} | Steps: {result.steps_executed} | Facts: {result.facts_extracted} | Gates: {result.gates_passed}/{result.gates_passed + result.gates_failed}")
        if result.error:
            console.print(f"  [red]Error:[/red] {result.error}")

    def run_skills(
        self,
        skills: list[Skill],
        state: AgentState,
        tool_override: dict = None,
    ) -> list[SkillResult]:
        """Execute multiple skills sequentially."""
        results = []
        for skill in skills:
            try:
                result = self.run_skill(skill, state, tool_override=tool_override)
                results.append(result)
            except KeyboardInterrupt:
                console.print("[yellow]Skill execution interrupted by user.[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Skill '{skill.name}' failed: {e}[/red]")
                results.append(SkillResult(
                    skill_name=skill.name,
                    success=False,
                    error=str(e),
                ))
        return results

    def print_skills_table(self, show_all: bool = False):
        """Print a Rich table of available skills."""
        skills = self.list_skills()

        table = Table(title="Available Skills")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Tags", style="yellow")
        table.add_column("Tools", style="green")
        table.add_column("Runnable", style="magenta")

        for skill in skills:
            runnable = self.is_runnable(skill)
            if not show_all and not runnable:
                continue
            table.add_row(
                skill.name,
                skill.description[:60] + ("..." if len(skill.description) > 60 else ""),
                ", ".join(skill.tags),
                ", ".join(skill.requires_tools) if skill.requires_tools else "-",
                "Yes" if runnable else "No",
            )

        console.print(table)


# Global registry instance
skill_registry = SkillRegistry()
