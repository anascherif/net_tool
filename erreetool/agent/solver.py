"""
SolveEngine - Model-driven autonomous agent loop.

Replaces fixed-step loop with goal-directed execution:
- Agent runs until FINAL, NO_PATH, or ASK_USER
- Evidence gates validate all claims verbatim
- Context auto-compact when approaching token limits
- High-signal facts extracted and pinned to context
"""

import json
import time
import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Literal
from enum import Enum

from rich.console import Console

from erreetool.agent.state import (
    AgentState, AgentContext, EvidenceType, AgentStep, StepStatus, Evidence
)
from erreetool.agent.providers import MultiProvider, LLMMessage, TOOL_DEFINITIONS
from erreetool.agent.tools.base import tool_registry, ToolResult
from erreetool.agent.skills import SkillExecutor, SkillRegistry, skill_registry
from erreetool.agent.memory import memory_retriever, RetrievedContext, memory_store, MemoryType, SessionSummary
from erreetool.agent.safety import SafetyGate, SafetyPolicy, RiskLevel, ApprovalResponse, ApprovalPrompt

console = Console()


class SolveResult(str, Enum):
    """Terminal state of solve loop."""
    FINAL = "final"           # Goal achieved, evidence gate passed
    NO_PATH = "no_path"       # Exhausted high-signal anchors, cannot continue
    ASK_USER = "ask_user"     # Need clarification from human
    MAX_TURNS = "max_turns"   # Safety budget exhausted
    ERROR = "error"           # Unrecoverable error


@dataclass
class SolveConfig:
    """Configuration for the solve engine."""
    max_turns: int = 240              # Safety budget (not a plan - runaway guard)
    auto_report: bool = True          # Generate report on FINAL
    context_auto_compact: bool = True # Compress history when > trigger_ratio
    context_compact_trigger_ratio: float = 0.70  # Compact when context > 70% of model limit
    context_compact_target_ratio: float = 0.55   # Target after compaction
    context_recent_turns: int = 12    # Preserve N recent turn groups during compact
    context_summary_max_tokens: int = 3500       # Budget for long-term summary
    evidence_gate_required: bool = True          # Verify FINAL claims verbatim
    stall_guard_threshold: int = 5    # Max consecutive evidence-only turns
    show_reasoning: bool = True       # Display model reasoning
    use_safety_gate: bool = True      # Classify risky tool calls
    non_interactive: bool = True      # Auto-deny dangerous (CI/CD mode)
    allow_exploitation: bool = False  # Master exploit switch
    human_in_loop: bool = False       # Prompt before every tool call
    use_memory: bool = True           # Load relevant past sessions
    memory_max_sessions: int = 5


@dataclass
class TurnResult:
    """Result of a single solve turn."""
    turn_number: int
    action: str                       # "tool_call", "final", "ask_user", "no_path"
    tool_calls: list[dict] = field(default_factory=list)
    content: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    reasoning: str = ""
    completed: bool = False
    result: Optional[SolveResult] = None


class SolveEngine:
    """
    Model-driven autonomous penetration testing engine.
    
    Flow:
    1. Build context (goals, evidence preview, high-signal facts, tools)
    2. Model decides next action (tool call, FINAL, ASK_USER, NO_PATH)
    3. Execute tool, collect full raw evidence
    4. Extract high-signal facts, update context
    5. Check stall guard, auto-compact if needed
    6. Repeat until terminal state
    7. On FINAL: evidence gate validates all claims verbatim
    """
    
    SYSTEM_PROMPT = """You are an autonomous penetration testing agent. Your goal is to perform comprehensive security assessments on authorized targets.

AVAILABLE TOOLS:
- run_nmap: Port scanning and service detection
- run_nuclei: Vulnerability scanning with 3000+ templates
- run_whatweb: Web technology fingerprinting
- run_gobuster: Directory/file enumeration
- run_sqlmap: SQL injection testing
- run_crypto: Encoding/decoding/crypto operations
- run_shell: Local command execution

EVIDENCE-BASED OPERATION:
- Every tool execution produces evidence (raw output stored permanently)
- Your claims MUST be backed by evidence
- Final conclusions require evidence gate verification
- Anti-hallucination: If you claim something, cite the evidence ID
- You CANNOT make up findings - they must appear verbatim in tool output

WORKFLOW:
1. RECON: Discover open ports, services, technologies
2. ENUMERATE: Deep dive into discovered services
3. VULN SCAN: Check for known vulnerabilities
4. EXPLOIT: Verify exploitable findings (if authorized)
5. REPORT: Summarize findings with evidence citations

TOOL CALLING:
- Use tools to gather evidence. Do not guess.
- Large outputs are truncated in context - use evidence_search/evidence_view to retrieve full content
- High-signal facts (forms, endpoints, sink patterns, source code) are automatically pinned to context

TERMINAL ACTIONS:
- FINAL: "I have achieved the goal. [evidence citations]" - Must pass evidence gate
- NO_PATH: "I have exhausted all high-signal anchors. [reason]" - No more paths to explore
- ASK_USER: "I need clarification: [question]" - Blocked on scope/authorization

EVIDENCE GATE:
- Every claim in FINAL must appear verbatim in tool output OR cite evidence ID
- NO_PATH rejected if high-signal anchors remain unexploited
"""

    def __init__(
        self,
        state: AgentState,
        provider: MultiProvider,
        config: SolveConfig = None
    ):
        self.state = state
        self.provider = provider
        self.config = config or SolveConfig()
        self.turn_count = 0
        self.start_time = time.time()
        
        # Safety gate
        self.safety_gate = None
        if self.config.use_safety_gate:
            self.safety_gate = SafetyGate(
                SafetyPolicy(
                    non_interactive=self.config.non_interactive,
                    auto_approve_below=RiskLevel.MODERATE,
                )
            )
        
        # Tool executor mapping
        self.tool_executors = {
            "run_nmap": self._exec_nmap,
            "run_nuclei": self._exec_nuclei,
            "run_whatweb": self._exec_whatweb,
            "run_gobuster": self._exec_gobuster,
            "run_sqlmap": self._exec_sqlmap,
            "run_crypto": self._exec_crypto,
            "run_shell": self._exec_shell,
        }
        
        # Skill executor (lazy init)
        self._skill_executor = None
        self._skill_registry = None
        
        # Context management
        self._turn_history: list[dict] = []  # For compaction
        self._consecutive_evidence_turns = 0
        self._long_term_summary = ""
        
        # Evidence tools (for model to retrieve full content)
        self._evidence_tools = {
            "evidence_search": self._tool_evidence_search,
            "evidence_view": self._tool_evidence_view,
            "evidence_list": self._tool_evidence_list,
        }
    
    @property
    def skill_executor(self):
        if self._skill_executor is None:
            self._skill_executor = SkillExecutor(self.state)
        return self._skill_executor
    
    @property
    def skill_registry(self):
        if self._skill_registry is None:
            self._skill_registry = SkillRegistry()
        return self._skill_registry
    
    def run(self, goal: str = None) -> AgentState:
        """Run the solve loop until terminal state."""
        if goal:
            self.state.context.goals.append(goal)
        
        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "agent",
            f"Solve session started. Goal: {goal or 'Full penetration test'}",
            {"session_id": self.state.session_id, "engine": "solve"}
        )
        
        # Load relevant memory
        if self.config.use_memory:
            self._load_memory_context(goal)
        
        # Initial context build
        self._build_initial_context()
        
        # Main solve loop
        while True:
            self.turn_count += 1
            
            # Check terminal conditions
            if self.turn_count > self.config.max_turns:
                console.print(f"[yellow]Max turns ({self.config.max_turns}) reached[/yellow]")
                self._handle_terminal(SolveResult.MAX_TURNS, "Safety budget exhausted")
                break
            
            # Check stall guard
            if self._consecutive_evidence_turns >= self.config.stall_guard_threshold:
                console.print(f"[yellow]Stall guard triggered ({self.config.stall_guard_threshold} evidence-only turns)[/yellow]")
                self._handle_terminal(SolveResult.NO_PATH, "Stall guard: too many consecutive evidence-only turns")
                break
            
            # Build messages for LLM
            messages = self._build_messages()
            
            # Get LLM response
            try:
                response = self.provider.chat(
                    messages,
                    temperature=0.3,
                    max_tokens=4000,
                    tools=TOOL_DEFINITIONS + self._get_evidence_tool_definitions(),
                    tool_choice="auto"
                )
            except Exception as e:
                console.print(f"[red]LLM error: {e}[/red]")
                self._handle_terminal(SolveResult.ERROR, f"LLM failed: {e}")
                break
            
            # Process response
            turn_result = self._process_response(response)
            
            if turn_result.completed:
                # Terminal state reached
                if turn_result.result == SolveResult.FINAL:
                    # Evidence gate verification
                    if self.config.evidence_gate_required:
                        if self._verify_final_claims(turn_result.content):
                            console.print("[green]Evidence gate passed[/green]")
                        else:
                            console.print("[yellow]Evidence gate failed - continuing[/yellow]")
                            self._consecutive_evidence_turns = 0
                            continue
                    self._handle_terminal(SolveResult.FINAL, turn_result.content)
                elif turn_result.result == SolveResult.NO_PATH:
                    self._handle_terminal(SolveResult.NO_PATH, turn_result.content)
                elif turn_result.result == SolveResult.ASK_USER:
                    self._handle_terminal(SolveResult.ASK_USER, turn_result.content)
                break
            
            # Check auto-compact
            if self.config.context_auto_compact:
                self._maybe_compact_context()
        
        # Final save
        self._save_session_to_memory()
        self.state.save()
        return self.state
    
    def _process_response(self, response) -> TurnResult:
        """Process LLM response and execute actions."""
        turn = TurnResult(turn_number=self.turn_count)
        
        if response.tool_calls:
            # Tool calls - execute them
            turn.action = "tool_call"
            turn.tool_calls = response.tool_calls
            self._execute_tool_calls(response.tool_calls)
            turn.evidence_ids = self.state.steps[-1].evidence_ids if self.state.steps else []
            self._consecutive_evidence_turns += 1
            
        elif response.content:
            content = response.content.strip()
            
            # Check for terminal markers
            if content.upper().startswith("FINAL"):
                turn.action = "final"
                turn.content = content
                turn.completed = True
                turn.result = SolveResult.FINAL
                turn.reasoning = content
                
            elif content.upper().startswith("NO_PATH"):
                turn.action = "no_path"
                turn.content = content
                turn.completed = True
                turn.result = SolveResult.NO_PATH
                turn.reasoning = content
                
            elif content.upper().startswith("ASK_USER"):
                turn.action = "ask_user"
                turn.content = content
                turn.completed = True
                turn.result = SolveResult.ASK_USER
                turn.reasoning = content
                
            else:
                # Regular reasoning - continue
                turn.action = "reasoning"
                turn.content = content
                turn.reasoning = content
                self.state.add_evidence(
                    EvidenceType.LLM_REASONING,
                    "agent",
                    content,
                    {"turn": self.turn_count, "type": "reasoning"}
                )
                self._consecutive_evidence_turns = 0  # Reset on reasoning
        
        else:
            # Empty response
            turn.action = "empty"
            self.state.add_evidence(
                EvidenceType.LLM_REASONING,
                "agent",
                "LLM returned empty response",
                {"turn": self.turn_count}
            )
            self._consecutive_evidence_turns += 1
        
        # Record turn for compaction
        self._turn_history.append({
            "turn": self.turn_count,
            "action": turn.action,
            "tool_calls": turn.tool_calls,
            "content": turn.content[:500] if turn.content else "",
            "evidence_ids": turn.evidence_ids,
            "timestamp": time.time(),
        })
        
        return turn
    
    def _execute_tool_calls(self, tool_calls: list[dict]):
        """Execute tool calls with safety gate."""
        for tc in tool_calls:
            func_name = tc["function"]["name"]
            func_args = json.loads(tc["function"]["arguments"])
            
            # Safety gate check
            if self.safety_gate:
                allowed, classification, approval = self.safety_gate.check(
                    func_name.replace("run_", ""),
                    func_args
                )
                if not allowed:
                    error = f"Safety gate blocked {func_name}: {classification.reason}"
                    console.print(f"[yellow]{error}[/yellow]")
                    self.state.add_evidence(
                        EvidenceType.OBSERVATION,
                        "safety_gate",
                        error,
                        {"risk": classification.risk.value}
                    )
                    continue
                if approval == ApprovalResponse.ABORT:
                    console.print("[red]User aborted via safety gate[/red]")
                    return
            
            # Create step
            step = self.state.add_step(
                description=f"Execute {func_name}",
                tool=func_name,
                args=func_args
            )
            
            # Execute
            executor = self.tool_executors.get(func_name)
            if not executor:
                error = f"Unknown tool: {func_name}"
                self.state.complete_step(step, error=error)
                self.state.add_evidence(
                    EvidenceType.TOOL_ERROR, "agent", error,
                    {"tool": func_name, "args": func_args}
                )
                continue
            
            try:
                result = executor(**func_args)
                
                # Add evidence (FULL raw output stored)
                ev_type = EvidenceType.TOOL_OUTPUT if result.success else EvidenceType.TOOL_ERROR
                evidence = self.state.add_evidence(
                    ev_type,
                    func_name,
                    result.output,
                    {
                        "command": result.command,
                        "duration": result.duration,
                        "returncode": result.returncode,
                        "metadata": result.metadata,
                    }
                )
                
                self.state.complete_step(step, evidence_ids=[evidence.id], error=result.stderr if not result.success else "")
                
                # Extract high-signal facts
                self._extract_facts(func_name, result.output)
                
            except Exception as e:
                self.state.complete_step(step, error=str(e))
                self.state.add_evidence(
                    EvidenceType.TOOL_ERROR,
                    func_name,
                    f"Execution failed: {e}",
                    {"args": func_args}
                )
    
    def _handle_terminal(self, result: SolveResult, content: str):
        """Handle terminal state."""
        self.state.add_evidence(
            EvidenceType.LLM_REASONING,
            "agent",
            f"TERMINAL: {result.value}\n{content}",
            {"terminal": True, "result": result.value}
        )
        console.print(f"[bold cyan]Solve completed: {result.value}[/bold cyan]")
    
    def _verify_final_claims(self, content: str) -> bool:
        """Evidence gate: verify all claims in FINAL response verbatim."""
        # Extract claims (sentences with technical content)
        import re
        claims = re.findall(
            r'[^.]*?(?:CVE-\d{4}-\d{4,7}|port \d+|vulnerab\w+|exploit\w+|credential\w+|flag|sql inject|xss|rce|shell|root|admin|password|hash|token)[^.]*\.',
            content,
            re.IGNORECASE,
        )
        
        all_verified = True
        for claim in claims:
            claim = claim.strip()
            if not claim:
                continue
            verified, matches = self.state.verify_claim(claim)
            if not verified:
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "gate",
                    f"UNVERIFIED CLAIM: {claim}",
                    {"gate_failed": True, "claim": claim}
                )
                console.print(f"[red]Gate failed: {claim[:100]}[/red]")
                all_verified = False
            else:
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "gate",
                    f"VERIFIED: {claim} (evidence: {', '.join(m.id for m in matches)})",
                    {"gate_passed": True}
                )
        
        return all_verified
    
    def _check_no_path_valid(self, content: str) -> bool:
        """Check if NO_PATH is valid (no high-signal anchors remain)."""
        # Check if any high-signal facts are unexploited
        unexploited = []
        for fact in self.state.context.high_signal_facts:
            fact_lower = fact.lower()
            # Check if fact has been acted upon
            acted = False
            for step in self.state.steps:
                if step.status == StepStatus.COMPLETED:
                    for ev_id in step.evidence_ids:
                        ev = self.state.get_evidence(ev_id)
                        if ev and any(kw in ev.content.lower() for kw in fact_lower.split() if len(kw) > 3):
                            acted = True
                            break
                if acted:
                    break
            if not acted:
                unexploited.append(fact)
        
        if unexploited:
            console.print(f"[yellow]NO_PATH rejected: {len(unexploited)} unexploited anchors[/yellow]")
            for f in unexploited[:5]:
                console.print(f"  - {f}")
            return False
        return True
    
    def _build_initial_context(self):
        """Load memory and build initial context."""
        self._load_memory_context(None)
    
    def _build_messages(self) -> list[LLMMessage]:
        """Build message history for LLM."""
        messages = [LLMMessage(role="system", content=self.SYSTEM_PROMPT)]
        
        # Context summary (compacted or full)
        context_parts = []
        if self._long_term_summary:
            context_parts.append(f"LONG-TERM SUMMARY:\n{self._long_term_summary}")
        
        context_parts.append(self._format_current_context())
        context_parts.append("HIGH-SIGNAL FACTS (pinned):")
        for fact in self.state.context.high_signal_facts[-20:]:
            context_parts.append(f"  - {fact}")
        
        # Recent turn history (post-compaction)
        if self._turn_history:
            context_parts.append("RECENT TURNS:")
            for t in self._turn_history[-self.config.context_recent_turns:]:
                if t["action"] == "tool_call":
                    context_parts.append(f"  T{t['turn']}: TOOL {t['tool_calls'][0]['function']['name'] if t['tool_calls'] else '?'} -> {len(t['evidence_ids'])} evidence")
                elif t["action"] == "reasoning":
                    context_parts.append(f"  T{t['turn']}: REASONING")
                elif t["action"] in ("final", "no_path", "ask_user"):
                    context_parts.append(f"  T{t['turn']}: {t['action'].upper()}")
        
        context_summary = "\n".join(context_parts)
        
        messages.append(LLMMessage(
            role="user",
            content=f"CURRENT CONTEXT:\n{context_summary}\n\nGOALS:\n" + 
            "\n".join(f"- {g}" for g in self.state.context.goals)
        ))
        
        return messages
    
    def _format_current_context(self) -> str:
        """Format current context for LLM."""
        ctx = self.state.context
        parts = [
            f"Target: {ctx.target or 'Not set'}",
            f"Phase: {ctx.current_phase}",
            f"High-signal facts: {len(ctx.high_signal_facts)}",
            f"Completed skills: {len(ctx.completed_skills)}",
        ]
        
        if ctx.findings:
            parts.append("Findings:")
            for k, v in ctx.findings.items():
                parts.append(f"  {k}: {v}")
        
        return "\n".join(parts)
    
    def _maybe_compact_context(self):
        """Compact context if approaching token limit."""
        # Estimate tokens (rough: 1 token ~ 4 chars)
        context_size = len(self._format_current_context()) + len(str(self._turn_history))
        # Model limit estimate (conservative)
        model_limit = 8000  # Adjust based on actual model
        
        if context_size > model_limit * self.config.context_compact_trigger_ratio:
            self._compact_context()
    
    def _compact_context(self):
        """Compress turn history into long-term summary."""
        if len(self._turn_history) <= self.config.context_recent_turns:
            return
        
        # Build summary from older turns
        old_turns = self._turn_history[:-self.config.context_recent_turns]
        
        summary_prompt = f"""Summarize these penetration testing turns for future context.
Focus on: discovered services, vulnerabilities found, credentials, attack paths, failed attempts.
Preserve specific technical details (ports, CVEs, paths, parameters).

TURNS:
{json.dumps(old_turns, indent=2)}

Provide a concise technical summary (<= {self.config.context_summary_max_tokens} tokens)."""
        
        try:
            summary_response = self.provider.chat([
                LLMMessage(role="system", content="You are a penetration testing summarizer."),
                LLMMessage(role="user", content=summary_prompt)
            ], temperature=0.1, max_tokens=self.config.context_summary_max_tokens, tools=None)
            
            if summary_response.content:
                self._long_term_summary = summary_response.content
                # Keep only recent turns
                self._turn_history = self._turn_history[-self.config.context_recent_turns:]
                console.print(f"[dim]Context compacted: {len(old_turns)} turns summarized[/dim]")
        except Exception as e:
            console.print(f"[yellow]Compaction failed: {e}[/yellow]")
    
    def _load_memory_context(self, goal: str = None):
        """Load relevant memory from past sessions."""
        target = self.state.context.target
        if not target:
            return
        
        try:
            retrieved = memory_retriever.get_context_for_assessment(
                target=target,
                state=self.state,
                max_sessions=self.config.memory_max_sessions,
            )
            
            if retrieved.relevant_sessions or retrieved.finding_patterns:
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "memory",
                    f"Loaded relevant context:\n{retrieved.summary}",
                    {
                        "memory_sessions": len(retrieved.relevant_sessions),
                        "memory_patterns": len(retrieved.finding_patterns),
                    }
                )
                
                # Add key findings as high-signal facts
                for session in retrieved.relevant_sessions[:3]:
                    for fact in session.critical_findings[:3]:
                        self.state.add_high_signal_fact(f"[From past session] {fact}")
                    for fact in session.high_findings[:2]:
                        self.state.add_high_signal_fact(f"[From past session] {fact}")
                
                for pattern in retrieved.finding_patterns[:5]:
                    self.state.add_high_signal_fact(
                        f"[Pattern] {pattern.description} (seen {pattern.seen_count}x, {pattern.confidence.value})"
                    )
        except Exception as e:
            console.print(f"[yellow]Memory load failed: {e}[/yellow]")
    
    def _save_session_to_memory(self):
        """Save session summary to memory."""
        if not self.config.use_memory:
            return
        
        try:
            summary = SessionSummary(
                session_id=self.state.session_id,
                target=self.state.context.target,
                timestamp=self.state.created_at,
                duration=time.time() - self.state.created_at,
                skills_run=self.state.context.completed_skills.copy(),
                tools_used=list(set(
                    step.tool.replace("run_", "") for step in self.state.steps
                    if step.tool.startswith("run_")
                )),
                high_signal_facts=self.state.context.high_signal_facts.copy(),
                critical_findings=[
                    f for f in self.state.context.high_signal_facts
                    if any(kw in f.lower() for kw in ['critical', 'cve-', 'exploit', 'rce', 'vulnerab'])
                ],
                high_findings=[
                    f for f in self.state.context.high_signal_facts
                    if any(kw in f.lower() for kw in ['high', 'sql', 'admin', 'credential'])
                ],
                recommendations=[],
                success=len([s for s in self.state.steps if s.status == StepStatus.FAILED]) == 0,
            )
            
            memory_store.add_session_summary(summary)
            self._extract_patterns_from_facts()
            self._update_tool_effectiveness()
        except Exception as e:
            console.print(f"[yellow]Memory save failed: {e}[/yellow]")
    
    def _extract_patterns_from_facts(self):
        """Extract and store finding patterns from current session facts."""
        from erreetool.agent.memory.schema import FindingPattern
        
        facts = self.state.context.high_signal_facts
        port_facts = [f for f in facts if "port" in f.lower() and "open" in f.lower()]
        vuln_facts = [f for f in facts if "cve-" in f.lower()]
        tech_facts = [f for f in facts if any(t in f.lower() for t in ["web server", "cms", "technology"])]
        
        if port_facts:
            pattern = FindingPattern(
                pattern_id=f"port_pattern_{self.state.session_id}",
                pattern_type="port",
                description=f"Common open ports: {', '.join(p.split(':')[-1].strip() for p in port_facts[:5])}",
                indicators=[p.split(':')[-1].strip() for p in port_facts[:5]],
                associated_findings=port_facts,
                seen_count=1,
                last_seen=time.time(),
                confidence="medium",
                example_targets=[self.state.context.target],
                tags=["port", "recon"],
            )
            memory_store.add_finding_pattern(pattern)
        
        if vuln_facts:
            for vuln in vuln_facts:
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', vuln)
                if cve_match:
                    cve_id = cve_match.group()
                    pattern = FindingPattern(
                        pattern_id=f"vuln_{cve_id}_{self.state.session_id}",
                        pattern_type="cve",
                        description=f"CVE pattern: {cve_id}",
                        indicators=[cve_id],
                        associated_findings=[vuln],
                        seen_count=1,
                        last_seen=time.time(),
                        confidence="high",
                        example_targets=[self.state.context.target],
                        tags=["cve", "vuln"],
                    )
                    memory_store.add_finding_pattern(pattern)
    
    def _update_tool_effectiveness(self):
        """Update tool effectiveness records."""
        from erreetool.agent.memory.schema import ToolEffectiveness
        
        tool_stats = {}
        for step in self.state.steps:
            if step.tool.startswith("run_"):
                tool_name = step.tool.replace("run_", "")
                if tool_name not in tool_stats:
                    tool_stats[tool_name] = {"runs": 0, "successes": 0, "findings": 0, "duration": 0.0}
                tool_stats[tool_name]["runs"] += 1
                if step.status == StepStatus.COMPLETED:
                    tool_stats[tool_name]["successes"] += 1
                    tool_stats[tool_name]["findings"] += len(step.evidence_ids)
                    tool_stats[tool_name]["duration"] += step.duration
        
        context_parts = []
        for fact in self.state.context.high_signal_facts:
            fact_lower = fact.lower()
            if "port" in fact_lower and "open" in fact_lower:
                match = re.search(r'port\s+(\d+)/tcp\s+open\s+(\w+)', fact_lower)
                if match:
                    context_parts.append(f"port:{match.group(1)}:{match.group(2)}")
            elif "web server" in fact_lower:
                match = re.search(r'web server:\s+(\w+)', fact_lower)
                if match:
                    context_parts.append(f"web:{match.group(1)}")
        
        if not context_parts:
            return
        
        context_hash = hashlib.md5("|".join(sorted(context_parts)).encode()).hexdigest()[:16]
        
        for tool_name, stats in tool_stats.items():
            effectiveness = ToolEffectiveness(
                tool_name=tool_name,
                context_hash=context_hash,
                runs=stats["runs"],
                successes=stats["successes"],
                findings_generated=stats["findings"],
                avg_duration=stats["duration"] / stats["runs"] if stats["runs"] > 0 else 0,
                last_used=time.time(),
            )
            memory_store.add_tool_effectiveness(effectiveness)
    
    # ===== Evidence Tools (for model to retrieve full content) =====
    
    def _get_evidence_tool_definitions(self) -> list[dict]:
        """Tool definitions for evidence retrieval."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "evidence_search",
                    "description": "Search evidence by keyword. Returns matching evidence IDs and previews.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search term"},
                            "type": {"type": "string", "enum": ["tool_output", "tool_error", "llm_reasoning", "skill_result", "observation"]},
                            "source": {"type": "string", "description": "Tool/source name filter"},
                            "limit": {"type": "integer", "default": 10}
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "evidence_view",
                    "description": "View full content of specific evidence by ID.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "evidence_id": {"type": "string", "description": "Evidence ID (e.g., e0001)"},
                            "max_chars": {"type": "integer", "default": 5000}
                        },
                        "required": ["evidence_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "evidence_list",
                    "description": "List recent evidence with previews.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "default": 20},
                            "type": {"type": "string"}
                        }
                    }
                }
            },
        ]
    
    def _tool_evidence_search(self, query: str, type: str = None, source: str = None, limit: int = 10) -> dict:
        """Search evidence by keyword."""
        ev_type = EvidenceType(type) if type else None
        results = self.state.search_evidence(query, ev_type, source, limit)
        return {
            "results": [
                {"id": ev.id, "type": ev.type.value, "source": ev.source, "preview": ev.preview(200)}
                for ev in results
            ],
            "count": len(results)
        }
    
    def _tool_evidence_view(self, evidence_id: str, max_chars: int = 5000) -> dict:
        """View full evidence content."""
        ev = self.state.get_evidence(evidence_id)
        if not ev:
            return {"error": f"Evidence {evidence_id} not found"}
        return {
            "id": ev.id,
            "type": ev.type.value,
            "source": ev.source,
            "content": ev.content[:max_chars],
            "metadata": ev.metadata,
            "hash": ev.hash,
            "size": ev.size,
            "truncated": len(ev.content) > max_chars
        }
    
    def _tool_evidence_list(self, limit: int = 20, type: str = None) -> dict:
        """List recent evidence."""
        ev_type = EvidenceType(type) if type else None
        results = []
        for ev in reversed(self.state.evidence_log[-limit:]):
            if ev_type and ev.type != ev_type:
                continue
            results.append({
                "id": ev.id,
                "type": ev.type.value,
                "source": ev.source,
                "preview": ev.preview(150),
                "timestamp": ev.timestamp
            })
        return {"results": results, "count": len(results)}
    
    # ===== Tool Executors =====
    
    def _exec_nmap(self, target: str, ports: str = "top-1000", service_detection: bool = True, scripts: str = None, **kwargs) -> ToolResult:
        tool = tool_registry.get("nmap")
        return tool.run(target=target, ports=ports, service_detection=service_detection, scripts=scripts, **kwargs)
    
    def _exec_nuclei(self, target: str, tags: str = None, severity: str = None, **kwargs) -> ToolResult:
        tool = tool_registry.get("nuclei")
        return tool.run(target=target, tags=tags, severity=severity, **kwargs)
    
    def _exec_whatweb(self, target: str, aggression: int = 2, **kwargs) -> ToolResult:
        tool = tool_registry.get("whatweb")
        return tool.run(target=target, aggression=aggression, **kwargs)
    
    def _exec_gobuster(self, target: str, wordlist: str = None, extensions: str = "php,html,txt,js,json", threads: int = 50, **kwargs) -> ToolResult:
        tool = tool_registry.get("gobuster")
        return tool.run(target=target, wordlist=wordlist, extensions=extensions, threads=threads, **kwargs)
    
    def _exec_sqlmap(self, url: str, parameter: str = None, risk: int = 1, level: int = 1, **kwargs) -> ToolResult:
        tool = tool_registry.get("sqlmap")
        return tool.run(url=url, parameter=parameter, risk=risk, level=level, **kwargs)
    
    def _exec_crypto(self, operation: str, data: str, **kwargs) -> ToolResult:
        tool = tool_registry.get("crypto")
        if operation == "auto_decode":
            return tool.auto_decode(data)
        elif operation == "identify_hash":
            return tool.identify_hash(data)
        return tool.run(operation=operation, data=data, **kwargs)
    
    def _exec_shell(self, command: str, timeout: int = 60, **kwargs) -> ToolResult:
        import subprocess
        start = time.time()
        try:
            proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            return ToolResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                command=[command],
                duration=time.time() - start,
                evidence_id=f"shell_{int(start)}",
                tool_name="shell",
            )
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, stdout="", stderr=f"Timeout after {timeout}s", returncode=-1, command=[command], duration=time.time()-start, evidence_id=f"shell_{int(start)}", tool_name="shell")
        except Exception as e:
            return ToolResult(success=False, stdout="", stderr=str(e), returncode=-1, command=[command], duration=time.time()-start, evidence_id=f"shell_{int(start)}", tool_name="shell")
    
    def _extract_facts(self, tool: str, output: str):
        """Extract high-signal facts from tool output."""
        import re
        
        # Generic port findings
        if tool in ("nmap", "shell"):
            for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', output):
                port, service = match.groups()
                self.state.add_high_signal_fact(f"Port {port}/tcp open: {service}")
        
        # Vulnerability findings
        if tool in ("nuclei", "nmap", "shell"):
            for cve in re.findall(r'CVE-\d{4}-\d{4,7}', output):
                self.state.add_high_signal_fact(f"Vulnerability found: {cve}")
        
        # Technology findings
        if tool in ("nmap", "whatweb", "nuclei", "shell"):
            for match in re.finditer(r'(\w+)[/\s]([\d.]+)', output):
                tech, version = match.groups()
                if tech.lower() in {'apache', 'nginx', 'iis', 'tomcat', 'jenkins', 'wordpress', 'drupal', 'joomla'}:
                    self.state.add_high_signal_fact(f"Technology: {tech} {version}")
        
        # Database findings
        if tool in ("nmap", "sqlmap", "shell"):
            db_match = re.search(r'\b(mysql|postgresql|mssql|oracle|mongodb|redis)\b', output, re.IGNORECASE)
            if db_match:
                self.state.add_high_signal_fact(f"Database service detected: {db_match.group(1).lower()}")
        
        # SQLi findings
        if tool == "sqlmap":
            if re.search(r'(injectable|sql injection|vulnerable|back-end DBMS)', output, re.IGNORECASE):
                self.state.add_high_signal_fact("SQL injection vulnerability detected by sqlmap")
        
        # Directory findings
        if tool == "gobuster":
            for match in re.finditer(r'^/(?:Status:\s+\d+\s+\[Size:\s+\d+\]\s+)?\[\s*(\d+)\s*\]\s+(\S+)', output, re.MULTILINE):
                status, path = match.groups()
                if status in ("200", "301", "302", "401", "403"):
                    self.state.add_high_signal_fact(f"Directory found: {path} (HTTP {status})")
        
        # High-signal pattern extraction (forms, endpoints, sinks, source code)
        self._extract_high_signal_patterns(output)
    
    def _extract_high_signal_patterns(self, content: str):
        """Extract high-signal patterns: forms, endpoints, sink patterns, source code blocks."""
        import re
        
        # HTML forms
        for match in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', content, re.IGNORECASE):
            self.state.add_high_signal_fact(f"Form endpoint: {match.group(1)}")
        
        for match in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\']', content, re.IGNORECASE):
            self.state.add_high_signal_fact(f"Form parameter: {match.group(1)}")
        
        # JavaScript endpoints
        for match in re.finditer(r'(?:fetch|axios|\.get|\.post|ajax)\s*\(\s*["\']([^"\']+)["\']', content):
            self.state.add_high_signal_fact(f"JS endpoint: {match.group(1)}")
        
        # PHP/Backend API links
        for match in re.finditer(r'(?:href|action|src)=["\']([^"\']*\.php[^"\']*)["\']', content, re.IGNORECASE):
            self.state.add_high_signal_fact(f"PHP endpoint: {match.group(1)}")
        
        # Dangerous sink patterns
        sink_patterns = [
            (r'eval\s*\(', "eval() sink"),
            (r'exec\s*\(', "exec() sink"),
            (r'system\s*\(', "system() sink"),
            (r'shell_exec\s*\(', "shell_exec() sink"),
            (r'passthru\s*\(', "passthru() sink"),
            (r'unserialize\s*\(', "unserialize() sink"),
            (r'base64_decode\s*\(', "base64_decode() sink"),
        ]
        for pattern, label in sink_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.state.add_high_signal_fact(f"Dangerous sink: {label}")
        
        # Source code blocks (highlight_file, show_source)
        if "highlight_file" in content or "show_source" in content:
            # Extract PHP source between markers
            php_blocks = re.findall(r'<\?php(.*?)\?>', content, re.DOTALL)
            for block in php_blocks[:3]:  # Limit
                if len(block) > 50:
                    self.state.add_high_signal_fact(f"PHP source block ({len(block)} chars)")
        
        # Large source code dumps
        if len(content) > 5000 and ("<html" in content.lower() or "<?php" in content):
            self.state.add_high_signal_fact(f"Large response with source code ({len(content)} chars)")


def run_solve(
    state: AgentState,
    provider: MultiProvider,
    goal: str = None,
    config: SolveConfig = None
) -> AgentState:
    """Entry point to run solve engine."""
    engine = SolveEngine(state, provider, config)
    return engine.run(goal)