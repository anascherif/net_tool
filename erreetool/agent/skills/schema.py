"""
Skill schema - dataclasses for structured pentest skills.

A Skill is a collection of phases, each containing steps that call tools,
extract facts, and run evidence gates. Skills are deterministic, YAML-defined,
and platform-independent.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FactExtraction:
    """Regex pattern to extract a high-signal fact from tool output."""
    pattern: str
    fact_template: str  # e.g., "Port {1}/tcp open: {2}" - {1}, {2} are group matches
    fact_type: str = "high_signal"  # high_signal | observation | finding


@dataclass
class SkillStep:
    """A single step in a skill phase - calls one tool."""
    name: str
    tool: str
    args: dict = field(default_factory=dict)
    save_as: str = ""  # Named evidence key (queryable later via evidence_get)
    extract_facts: list[FactExtraction] = field(default_factory=list)
    on_error: str = "continue"  # continue | abort | skip_phase
    description: str = ""
    timeout: Optional[int] = None


@dataclass
class SkillPhase:
    """A phase in a skill - contains steps and an optional condition."""
    name: str
    description: str = ""
    condition: str = ""  # Python expression evaluated by restricted evaluator
    steps: list[SkillStep] = field(default_factory=list)


@dataclass
class SkillGate:
    """Post-execution verification gate."""
    name: str
    condition: str  # Python expression
    on_fail: str = ""  # Message logged if gate fails
    severity: str = "warning"  # warning | error | info


@dataclass
class Skill:
    """A structured pentest skill loaded from YAML."""
    name: str
    description: str
    tags: list[str] = field(default_factory=list)
    author: str = "erreetool"
    version: str = "1.0"
    requires_tools: list[str] = field(default_factory=list)
    phases: list[SkillPhase] = field(default_factory=list)
    gates: list[SkillGate] = field(default_factory=list)
    source_file: str = ""  # Path to YAML file

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "author": self.author,
            "version": self.version,
            "requires_tools": self.requires_tools,
            "phases": [
                {
                    "name": p.name,
                    "description": p.description,
                    "condition": p.condition,
                    "steps": [
                        {
                            "name": s.name,
                            "tool": s.tool,
                            "args": s.args,
                            "save_as": s.save_as,
                            "extract_facts": [
                                {"pattern": f.pattern, "fact_template": f.fact_template, "fact_type": f.fact_type}
                                for f in s.extract_facts
                            ],
                            "on_error": s.on_error,
                            "description": s.description,
                            "timeout": s.timeout,
                        }
                        for s in p.steps
                    ],
                }
                for p in self.phases
            ],
            "gates": [
                {"name": g.name, "condition": g.condition, "on_fail": g.on_fail, "severity": g.severity}
                for g in self.gates
            ],
            "source_file": self.source_file,
        }


@dataclass
class SkillResult:
    """Result of executing a skill."""
    skill_name: str
    success: bool
    phases_executed: int = 0
    phases_skipped: int = 0
    steps_executed: int = 0
    steps_failed: int = 0
    facts_extracted: int = 0
    gates_passed: int = 0
    gates_failed: int = 0
    error: str = ""
    duration: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "skill_name": self.skill_name,
            "success": self.success,
            "phases_executed": self.phases_executed,
            "phases_skipped": self.phases_skipped,
            "steps_executed": self.steps_executed,
            "steps_failed": self.steps_failed,
            "facts_extracted": self.facts_extracted,
            "gates_passed": self.gates_passed,
            "gates_failed": self.gates_failed,
            "error": self.error,
            "duration": self.duration,
            "evidence_ids": self.evidence_ids,
        }


# -- YAML parsing helpers ----------------------------------------------

def parse_fact_extraction(data: dict) -> FactExtraction:
    """Parse a fact extraction entry from YAML dict."""
    return FactExtraction(
        pattern=data["pattern"],
        fact_template=data.get("fact", data.get("fact_template", "")),
        fact_type=data.get("type", "high_signal"),
    )


def parse_step(data: dict) -> SkillStep:
    """Parse a step from YAML dict."""
    extract_facts = [parse_fact_extraction(f) for f in data.get("extract_facts", [])]
    return SkillStep(
        name=data["name"],
        tool=data["tool"],
        args=data.get("args", {}),
        save_as=data.get("save_as", ""),
        extract_facts=extract_facts,
        on_error=data.get("on_error", "continue"),
        description=data.get("description", ""),
        timeout=data.get("timeout"),
    )


def parse_phase(data: dict) -> SkillPhase:
    """Parse a phase from YAML dict."""
    steps = [parse_step(s) for s in data.get("steps", [])]
    return SkillPhase(
        name=data["name"],
        description=data.get("description", ""),
        condition=data.get("condition", ""),
        steps=steps,
    )


def parse_gate(data: dict) -> SkillGate:
    """Parse a gate from YAML dict."""
    return SkillGate(
        name=data["name"],
        condition=data["condition"],
        on_fail=data.get("on_fail", ""),
        severity=data.get("severity", "warning"),
    )


def parse_skill(data: dict, source_file: str = "") -> Skill:
    """Parse a full skill from a YAML dict."""
    phases = [parse_phase(p) for p in data.get("phases", [])]
    gates = [parse_gate(g) for g in data.get("gates", [])]
    return Skill(
        name=data["name"],
        description=data.get("description", ""),
        tags=data.get("tags", []),
        author=data.get("author", "erreetool"),
        version=data.get("version", "1.0"),
        requires_tools=data.get("requires_tools", []),
        phases=phases,
        gates=gates,
        source_file=source_file,
    )
