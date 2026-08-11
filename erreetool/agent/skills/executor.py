"""
SkillExecutor - runs skills deterministically, calling tools, evaluating
conditions, extracting facts, and writing evidence.

Includes a restricted Python expression evaluator for skill conditions
(no builtins, no imports, only safe data-access functions).
"""

import re
import time
import fnmatch
from typing import Any

from rich.console import Console

from erreetool.agent.state import AgentState, EvidenceType
from erreetool.agent.tools.base import tool_registry, ToolResult
from erreetool.agent.skills.schema import (
    Skill,
    SkillPhase,
    SkillStep,
    SkillResult,
    FactExtraction,
)

console = Console()


class ConditionEvaluator:
    """
    Restricted Python expression evaluator for skill conditions.

    Provides safe data-access functions to condition expressions:
    - evidence_contains(name, text) -> bool
    - evidence_get(name) -> str
    - fact_count(pattern) -> int
    - has_fact(text) -> bool
    - target -> str (from context)

    Blocks all builtins, imports, attribute access on dangerous objects.
    """

    # Forbidden patterns even within allowed names (defense in depth)
    _FORBIDDEN_TOKENS = (
        "__import__", "__builtins__", "eval", "exec", "compile",
        "open", "os.", "sys.", "subprocess", "globals", "locals",
        "getattr", "setattr", "delattr", "class", "mro", " subclasses",
    )

    @staticmethod
    def _make_safe_globals(context: dict) -> dict:
        """Build the restricted namespace exposed to eval()."""
        state: AgentState = context["state"]
        named_evidence: dict[str, str] = context.get("named_evidence", {})

        def evidence_contains(name: str, text: str) -> bool:
            content = named_evidence.get(name, "")
            return text.lower() in content.lower()

        def evidence_get(name: str) -> str:
            return named_evidence.get(name, "")

        def fact_count(pattern: str) -> int:
            count = 0
            # Convert glob pattern to regex (* -> .*)
            regex = fnmatch.translate(pattern)
            compiled = re.compile(regex, re.IGNORECASE)
            for fact in state.context.high_signal_facts:
                if compiled.search(fact):
                    count += 1
            return count

        def has_fact(text: str) -> bool:
            for fact in state.context.high_signal_facts:
                if text.lower() in fact.lower():
                    return True
            return False

        safe_names = {
            "evidence_contains": evidence_contains,
            "evidence_get": evidence_get,
            "fact_count": fact_count,
            "has_fact": has_fact,
            "target": state.context.target,
            "facts": state.context.high_signal_facts,
            "len": len,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "any": any,
            "all": all,
            "True": True,
            "False": False,
            "None": None,
        }
        return {"__builtins__": {}}, safe_names

    @classmethod
    def evaluate(cls, expression: str, context: dict) -> bool:
        """
        Safely evaluate a condition expression.

        Returns True if expression is empty/None or evaluates truthy.
        Returns False if it evaluates falsy or raises an error.
        """
        if not expression or not expression.strip():
            return True

        # Defense in depth: reject suspicious tokens
        for token in cls._FORBIDDEN_TOKENS:
            if token in expression:
                console.print(
                    f"[red]Rejected condition with forbidden token '{token}': {expression}[/red]"
                )
                return False

        try:
            safe_globals, safe_locals = cls._make_safe_globals(context)
            result = eval(expression, safe_globals, safe_locals)
            return bool(result)
        except Exception as e:
            console.print(
                f"[yellow]Condition eval failed for '{expression}': {e}[/yellow]"
            )
            return False


class SkillExecutor:
    """
    Executes a Skill phase-by-phase against an AgentState.

    For each phase:
      1. Evaluate phase condition (skip if False)
      2. For each step:
         a. Resolve template args ({target}, {named_evidence})
         b. Call the registered tool
         c. Store output as evidence (with save_as name if provided)
         d. Extract facts via regex patterns
         e. Apply on_error policy
      3. After all phases, run gates
    """

    # Mapping from step.tool -> executor method name in loop.py
    # (Used to allow loop's executors that wrap tools with extra logic)
    # If a tool_name is in tool_registry, we use that directly.

    def __init__(self, state: AgentState, tool_override: dict = None):
        """
        Args:
            state: AgentState to record evidence/facts into.
            tool_override: optional dict of {tool_name: callable} to bypass
                the global tool_registry (used for testing/mocking).
        """
        self.state = state
        self.tool_override = tool_override or {}
        # Named evidence: stores output keyed by save_as name within this run
        self.named_evidence: dict[str, str] = {}
        # Track the currently executing skill name (for evidence source)
        self._current_skill_name: str = ""

    def execute(self, skill: Skill) -> SkillResult:
        """Execute a skill end-to-end. Returns SkillResult summary."""
        start = time.time()
        self._current_skill_name = skill.name
        self.named_evidence = {}

        result = SkillResult(
            skill_name=skill.name,
            success=True,
        )

        # Mark skill as completed in context
        if skill.name not in self.state.context.completed_skills:
            self.state.context.completed_skills.append(skill.name)

        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "skill",
            f"Starting skill: {skill.name} ({skill.description})",
            {"skill": skill.name, "phase": "start"},
        )

        for phase in skill.phases:
            phase_result = self._execute_phase(phase, skill, result)
            if phase_result == "abort":
                result.success = False
                break

        # Run gates
        for gate in skill.gates:
            passed = self._evaluate_condition(gate.condition)
            if passed:
                result.gates_passed += 1
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "gate",
                    f"Gate PASSED: {gate.name}",
                    {"gate": gate.name, "skill": skill.name, "passed": True},
                )
            else:
                result.gates_failed += 1
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "gate",
                    f"Gate FAILED: {gate.name} - {gate.on_fail}",
                    {
                        "gate": gate.name,
                        "skill": skill.name,
                        "passed": False,
                        "severity": gate.severity,
                        "message": gate.on_fail,
                    },
                )
                if gate.severity == "error":
                    result.success = False

        result.duration = time.time() - start

        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "skill",
            f"Completed skill: {skill.name} (success={result.success}, "
            f"steps={result.steps_executed}, facts={result.facts_extracted})",
            {
                "skill": skill.name,
                "phase": "end",
                "result": result.to_dict(),
            },
        )

        # Record in skill history
        if hasattr(self.state.context, "skill_history"):
            self.state.context.skill_history.append(result.to_dict())

        return result

    def _execute_phase(self, phase: SkillPhase, skill: Skill, result: SkillResult) -> str:
        """Execute a single phase. Returns 'ok', 'skip', or 'abort'."""
        ctx = {
            "state": self.state,
            "named_evidence": self.named_evidence,
        }

        if phase.condition and not self._evaluate_condition(phase.condition, ctx):
            result.phases_skipped += 1
            self.state.add_evidence(
                EvidenceType.OBSERVATION,
                "skill",
                f"Phase '{phase.name}' skipped (condition false)",
                {"skill": skill.name, "phase": phase.name, "skipped": True},
            )
            return "skip"

        result.phases_executed += 1
        self.state.context.current_phase = phase.name

        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "skill",
            f"Phase: {phase.name} - {phase.description}" if phase.description else f"Phase: {phase.name}",
            {"skill": skill.name, "phase": phase.name},
        )

        for step in phase.steps:
            outcome = self._execute_step(step, skill, phase, result)
            if outcome == "abort":
                return "abort"
            elif outcome == "skip_phase":
                return "ok"

        return "ok"

    def _execute_step(self, step: SkillStep, skill: Skill, phase: SkillPhase, result: SkillResult) -> str:
        """Execute a single step. Returns 'ok', 'abort', or 'skip_phase'."""
        # Resolve template variables in args
        try:
            resolved_args = self._resolve_args(step.args)
        except Exception as e:
            result.steps_failed += 1
            self.state.add_evidence(
                EvidenceType.TOOL_ERROR,
                "skill",
                f"Step '{step.name}' arg resolution failed: {e}",
                {"skill": skill.name, "phase": phase.name, "step": step.name},
            )
            return self._handle_error(step, "skip_phase")

        # Get tool
        tool = self.tool_override.get(step.tool) or tool_registry.get(step.tool)
        if tool is None:
            result.steps_failed += 1
            self.state.add_evidence(
                EvidenceType.TOOL_ERROR,
                "skill",
                f"Step '{step.name}': tool '{step.tool}' not registered",
                {"skill": skill.name, "phase": phase.name, "step": step.name, "tool": step.tool},
            )
            return self._handle_error(step, "skip_phase")

        # Check tool availability (unless overridden, e.g., mock)
        if step.tool not in self.tool_override and hasattr(tool, "is_available"):
            if not tool.is_available():
                result.steps_failed += 1
                self.state.add_evidence(
                    EvidenceType.TOOL_ERROR,
                    "skill",
                    f"Step '{step.name}': tool '{step.tool}' not installed",
                    {"skill": skill.name, "phase": phase.name, "step": step.name, "tool": step.tool},
                )
                return self._handle_error(step, "skip_phase")

        # Set timeout if specified
        if step.timeout and hasattr(tool, "timeout"):
            original_timeout = tool.timeout
            tool.timeout = step.timeout
        else:
            original_timeout = None

        # Execute
        result.steps_executed += 1
        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "skill",
            f"Executing: {step.name} (tool={step.tool})",
            {"skill": skill.name, "phase": phase.name, "step": step.name, "tool": step.tool, "args": resolved_args},
        )

        try:
            tool_result = tool.run(**resolved_args)
        except Exception as e:
            result.steps_failed += 1
            self.state.add_evidence(
                EvidenceType.TOOL_ERROR,
                "skill",
                f"Step '{step.name}' raised: {e}",
                {"skill": skill.name, "step": step.name, "tool": step.tool},
            )
            if original_timeout is not None:
                tool.timeout = original_timeout
            return self._handle_error(step, "skip_phase")
        finally:
            if original_timeout is not None and hasattr(tool, "timeout"):
                tool.timeout = original_timeout

        # Store evidence
        ev_type = EvidenceType.TOOL_OUTPUT if tool_result.success else EvidenceType.TOOL_ERROR
        metadata = {
            "skill": skill.name,
            "phase": phase.name,
            "step": step.name,
            "tool": step.tool,
            "command": tool_result.command,
            "duration": tool_result.duration,
            "returncode": tool_result.returncode,
            "success": tool_result.success,
        }
        evidence = self.state.add_evidence(
            ev_type,
            step.tool,
            tool_result.output,
            metadata,
        )
        result.evidence_ids.append(evidence.id)

        # Store as named evidence if save_as is set
        if step.save_as:
            self.named_evidence[step.save_as] = tool_result.output

        # Extract facts
        if tool_result.success and step.extract_facts:
            for fact_ext in step.extract_facts:
                facts = self._extract_facts(tool_result.output, fact_ext)
                for fact in facts:
                    self.state.add_high_signal_fact(fact)
                    result.facts_extracted += 1

        # Handle errors
        if not tool_result.success:
            result.steps_failed += 1
            return self._handle_error(step, "skip_phase")

        return "ok"

    def _handle_error(self, step: SkillStep, default: str) -> str:
        """Map step.on_error to a return code."""
        if step.on_error == "abort":
            return "abort"
        elif step.on_error == "skip_phase":
            return "skip_phase"
        else:  # "continue" or unknown
            return "ok"

    def _resolve_args(self, args: dict) -> dict:
        """Resolve template variables in args dict.

        Supports:
        - {target} -> state.context.target
        - {named:param} -> named_evidence[param]
        - {env:VAR_NAME} -> os.environ[VAR_NAME]
        """
        resolved = {}
        for key, value in args.items():
            resolved[key] = self._resolve_value(value)
        return resolved

    def _resolve_value(self, value):
        """Recursively resolve template strings in any value."""
        if isinstance(value, str):
            return self._resolve_string(value)
        elif isinstance(value, dict):
            return {k: self._resolve_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._resolve_value(v) for v in value]
        return value

    def _resolve_string(self, s: str) -> str:
        """Resolve template variables in a string."""
        # {target}
        s = s.replace("{target}", self.state.context.target or "")
        # {named:NAME}
        for match in re.finditer(r"\{named:([\w-]+)\}", s):
            name = match.group(1)
            s = s.replace(match.group(0), self.named_evidence.get(name, ""))
        # {env:VAR_NAME}
        for match in re.finditer(r"\{env:(\w+)\}", s):
            import os
            var_name = match.group(1)
            s = s.replace(match.group(0), os.environ.get(var_name, ""))
        return s

    def _extract_facts(self, output: str, fact_ext: FactExtraction) -> list[str]:
        """Extract facts from tool output using regex."""
        facts = []
        try:
            for match in re.finditer(fact_ext.pattern, output):
                # Build fact from template, substituting {1}, {2}, etc.
                fact = fact_ext.fact_template
                for i, group in enumerate(match.groups(), start=1):
                    fact = fact.replace("{" + str(i) + "}", group or "")
                # Also replace {0} with full match
                fact = fact.replace("{0}", match.group(0))
                if fact and fact not in facts:
                    facts.append(fact)
        except re.error as e:
            console.print(
                f"[red]Invalid regex in fact extraction '{fact_ext.pattern}': {e}[/red]"
            )
        return facts

    def _evaluate_condition(self, expression: str, ctx: dict = None) -> bool:
        """Evaluate a condition expression using the restricted evaluator."""
        context = ctx or {
            "state": self.state,
            "named_evidence": self.named_evidence,
        }
        return ConditionEvaluator.evaluate(expression, context)
