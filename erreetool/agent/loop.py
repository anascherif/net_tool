"""
Autonomous agent loop with evidence gates and anti-hallucination.

The agent decides next actions based on context, executes tools,
and validates claims against collected evidence.

Supports two modes:
- LLM-driven (default): LLM decides tool calls
- Skill-driven: Executes structured YAML skills deterministically
"""

import json
import time
import re
import hashlib
from dataclasses import dataclass

from rich.console import Console

from erreetool.agent.state import AgentState, AgentContext, EvidenceType, AgentStep, StepStatus
from erreetool.agent.providers import MultiProvider, LLMMessage, TOOL_DEFINITIONS
from erreetool.agent.tools.base import tool_registry, ToolResult
from erreetool.agent.skills import SkillExecutor, SkillRegistry, skill_registry
from erreetool.agent.memory import memory_retriever, RetrievedContext, memory_store, MemoryType, SessionSummary
from erreetool.agent.safety import SafetyGate, SafetyPolicy, RiskLevel, ApprovalResponse, ApprovalPrompt
from erreetool.agent.solver import SolveConfig, SolveResult, run_solve
from erreetool.agent.tools.http_tools import TrafficStore, register_enhanced_tools

console = Console()


@dataclass
class AgentConfig:
    """Configuration for the autonomous agent."""
    max_steps: int = 50
    max_duration: float = 3600  # 1 hour
    evidence_gate_required: bool = True
    show_reasoning: bool = True
    auto_report: bool = True
    # Engine mode
    engine: str = "solve"  # "solve" (model-driven) | "rounds" (legacy fixed-step) | "skill" (skill-driven)
    # Solve engine config
    solve_max_turns: int = 240
    solve_auto_report: bool = True
    context_auto_compact: bool = True
    context_compact_trigger_ratio: float = 0.70
    context_compact_target_ratio: float = 0.55
    context_recent_turns: int = 12
    context_summary_max_tokens: int = 3500
    stall_guard_threshold: int = 5
    # Skill mode (legacy)
    skill_mode: bool = False  # If True, run skills instead of LLM loop
    skill_names: str = ""  # Comma-separated skill names to run
    skill_mode_type: str = "auto"  # auto, quick, full
    # Memory
    use_memory: bool = True  # Load relevant past sessions
    memory_max_sessions: int = 5
    # Safety gate (Phase 6)
    use_safety_gate: bool = True  # If True, classify and prompt for risky actions
    non_interactive: bool = True  # If True, never prompt - auto-deny dangerous
    # Exploitation verification (Phase 6)
    allow_exploitation: bool = False  # Master switch for exploit verification
    # Human-in-the-loop (Phase 6)
    human_in_loop: bool = False  # If True, prompt before every tool call



class AgentLoop:
    """
    Autonomous agent loop for penetration testing.
    
    Flow:
    1. Model receives context + evidence preview + available tools
    2. Model decides next action (tool call, final answer, ask user)
    3. Execute tool, collect evidence
    4. Update context with findings
    5. Repeat until goal achieved or max steps reached
    6. Evidence gate validates final claims
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
- Every tool execution produces evidence (raw output stored)
- Your claims MUST be backed by evidence
- Final conclusions require evidence gate verification
- Anti-hallucination: If you claim something, cite the evidence ID

WORKFLOW:
1. RECON: Discover open ports, services, technologies
2. ENUMERATE: Deep dive into discovered services
3. VULN SCAN: Check for known vulnerabilities
4. EXPLOIT: Verify exploitable findings (if authorized)
5. REPORT: Summarize findings with evidence citations

SKILL MODE:
- When skill-mode is active, structured YAML skills drive execution.
- Each skill has phases with steps, evidence gates, and optional fact
  extraction. Failed gate checks abort the skill and report why.
- Prefer skill-driven assessment when a skill matches the goal so the
  pipeline is deterministic and reproducible.
- You can still call tools directly for ad-hoc investigation between
  skills.

MEMORY:
- The agent has long-term memory across sessions: similar past targets,
  recurring finding patterns, CVE knowledge, and credential patterns.
- Use retrieved memory context to prioritize tools and avoid repeating
  dead ends. When you reconfirm a known pattern, reference it.

RULES:
- Only use tools on authorized targets
- Cite evidence IDs for all claims (e.g., "[e0001]")
- Be thorough but efficient
- Ask for clarification if scope is unclear
- Stop when assessment is complete"""

    def __init__(
        self,
        state: AgentState,
        provider: MultiProvider,
        config: AgentConfig = None
    ):
        self.state = state
        self.provider = provider
        self.config = config or AgentConfig()
        self.step_count = 0
        self.start_time = time.time()
        
        # Traffic store for HTTP evidence
        self.traffic_store = TrafficStore(state.session_id, state.output_dir)
        
        # Register enhanced tools
        register_enhanced_tools(state, self.traffic_store)
        
        # Safety gate (Phase 6)
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
            # Enhanced tools
            "run_fetch": self._exec_fetch,
            "run_http_probe_batch": self._exec_http_probe_batch,
            "run_source_extract": self._exec_source_extract,
            "run_runtime_diff_probe": self._exec_runtime_diff_probe,
            "run_traffic_list": self._exec_traffic_list,
            "run_traffic_view": self._exec_traffic_view,
        }
        
        # Skill executor (lazy init)
        self._skill_executor = None
        self._skill_registry = None
    
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
        """Run the autonomous agent loop."""
        # Initialize context
        if goal:
            self.state.context.goals.append(goal)
        
        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "agent",
            f"Session started. Goal: {goal or 'Full penetration test'}",
            {"session_id": self.state.session_id, "engine": self.config.engine}
        )
        
        # Load relevant memory from past sessions
        self._load_memory_context(goal)
        
        # Check if skill mode is enabled (legacy)
        if self.config.skill_mode:
            return self._run_skills(goal)
        
        # Check if solve engine mode
        if self.config.engine == "solve":
            return self._run_solve(goal)
        
        # Otherwise, run the legacy LLM-driven loop (rounds mode)
        return self._run_rounds(goal)
    
    def _run_solve(self, goal: str = None) -> AgentState:
        """Run using the solve engine (model-driven)."""
        if not self.provider:
            console.print("[yellow]No LLM provider available for solve engine[/yellow]")
            return self._fallback_assessment(goal)
        
        solve_config = SolveConfig(
            max_turns=self.config.solve_max_turns,
            auto_report=self.config.solve_auto_report,
            context_auto_compact=self.config.context_auto_compact,
            context_compact_trigger_ratio=self.config.context_compact_trigger_ratio,
            context_compact_target_ratio=self.config.context_compact_target_ratio,
            context_recent_turns=self.config.context_recent_turns,
            context_summary_max_tokens=self.config.context_summary_max_tokens,
            stall_guard_threshold=self.config.stall_guard_threshold,
            show_reasoning=self.config.show_reasoning,
            use_safety_gate=self.config.use_safety_gate,
            non_interactive=self.config.non_interactive,
            allow_exploitation=self.config.allow_exploitation,
            human_in_loop=self.config.human_in_loop,
            use_memory=self.config.use_memory,
            memory_max_sessions=self.config.memory_max_sessions,
        )
        
        return run_solve(self.state, self.provider, goal, solve_config)
    
    def _run_rounds(self, goal: str = None) -> AgentState:
        """Run the legacy rounds-based loop."""
        while not self._should_stop():
            self.step_count += 1
            
            # Build messages for LLM
            messages = self._build_messages()
            
            # Get LLM response
            try:
                response = self.provider.chat(
                    messages,
                    temperature=0.3,
                    max_tokens=4000,
                    tools=TOOL_DEFINITIONS,
                    tool_choice="auto"
                )
            except Exception as e:
                # All providers failed - use fallback analysis
                console.print(f"[yellow]LLM unavailable, using built-in analysis: {e}[/yellow]")
                fallback_report = self._fallback_analysis()
                self.state.add_evidence(
                    EvidenceType.LLM_REASONING,
                    "agent",
                    fallback_report,
                    {"fallback": True}
                )
                break
            
            # Process response
            if response.tool_calls:
                self._execute_tool_calls(response.tool_calls)
            elif response.content:
                self._process_final_response(response.content)
                break
            else:
                # No action - continue
                self.state.add_evidence(
                    EvidenceType.LLM_REASONING,
                    "agent",
                    "LLM returned empty response, continuing...",
                    {"step": self.step_count}
                )
        
        # Final evidence gate check
        if self.config.evidence_gate_required:
            self._verify_final_claims()
        
        # Save session to memory for future assessments
        self._save_session_to_memory()
        
        # Save final state
        self.state.save()
        return self.state
    
    def _fallback_assessment(self, goal: str = None) -> AgentState:
        """Run basic assessment without LLM."""
        from erreetool.agent.tools import tool_registry
        
        console.print("[dim]Running offline tools...[/dim]")
        
        # Run nmap
        nmap = tool_registry.get("nmap")
        if nmap and nmap.is_available():
            console.print("  [cyan]Running nmap...[/cyan]")
            result = nmap.run(target=self.state.context.target, ports="top-1000")
            if result.success:
                self.state.add_evidence(
                    EvidenceType.TOOL_OUTPUT, "nmap", result.output,
                    {"command": result.command, "duration": result.duration}
                )
                self._extract_facts("nmap", result.output)
        
        # Run nuclei
        nuclei = tool_registry.get("nuclei")
        if nuclei and nuclei.is_available():
            console.print("  [cyan]Running nuclei...[/cyan]")
            result = nuclei.run(target=self.state.context.target)
            if result.success:
                self.state.add_evidence(
                    EvidenceType.TOOL_OUTPUT, "nuclei", result.output,
                    {"command": result.command, "duration": result.duration}
                )
                self._extract_facts("nuclei", result.output)
        
        # Save session to memory
        self._save_session_to_memory()
        
        # Save final state
        self.state.save()
        return self.state
    
    def _run_skills(self, goal: str = None) -> AgentState:
        """Run skill-driven assessment."""
        console.print(f"[cyan]Skill-driven mode:[/cyan] {self.config.skill_mode_type}")
        
        # Select skills
        skills = self.skill_registry.select_skills(
            self.state,
            mode=self.config.skill_mode_type,
            requested=self.config.skill_names,
        )
        
        if not skills:
            console.print("[yellow]No skills selected. Run with --list-skills to see available.[/yellow]")
            self.state.save()
            return self.state
        
        console.print(f"[cyan]Selected {len(skills)} skill(s):[/cyan] " + ", ".join(s.name for s in skills))
        
        # Run skills
        results = self.skill_registry.run_skills(skills, self.state)
        
        # Summarize
        successful = sum(1 for r in results if r.success)
        total = len(results)
        console.print(f"[cyan]Skill execution complete:[/cyan] {successful}/{total} successful")
        
        # Run final gates if LLM is available
        if self.provider and self.config.evidence_gate_required:
            console.print("[dim]Running final evidence gate...[/dim]")
            self._verify_final_claims()
        
        # Generate final analysis if LLM available
        if self.provider:
            self._run_final_analysis(goal)
        
        # Save session to memory for future assessments
        self._save_session_to_memory()
        
        # Save final state
        self.state.save()
        return self.state
    
    def _run_final_analysis(self, goal: str = None):
        """Run final LLM analysis of collected evidence."""
        messages = [
            LLMMessage(role="system", content=self.SYSTEM_PROMPT),
            LLMMessage(
                role="user",
                content=f"FINAL ANALYSIS REQUESTED\n\nGoal: {goal or 'Full penetration test'}\n"
                f"Target: {self.state.context.target}\n"
                f"Skills completed: {len(self.state.context.completed_skills)}\n"
                f"High-signal facts: {len(self.state.context.high_signal_facts)}\n\n"
                f"EVIDENCE PREVIEW:\n{self.state.get_high_signal_preview()}\n\n"
                "Provide a final vulnerability triage report. Mark with 'FINAL' prefix."
            )
        ]
        
        try:
            response = self.provider.chat(
                messages,
                temperature=0.3,
                max_tokens=4000,
                tools=None,
                tool_choice="none"
            )
            if response.content:
                self._process_final_response(response.content)
        except Exception as e:
            console.print(f"[yellow]Final analysis failed: {e}[/yellow]")
            fallback_report = self._fallback_analysis()
            self.state.add_evidence(
                EvidenceType.LLM_REASONING,
                "agent",
                fallback_report,
                {"fallback": True, "final": True}
            )
    
    def _load_memory_context(self, goal: str = None):
        """Load relevant memory from past sessions."""
        if not self.config.use_memory:
            return
        
        target = self.state.context.target
        if not target:
            return
        
        console.print("[dim]Loading relevant memory from past sessions...[/dim]")
        
        try:
            retrieved = memory_retriever.get_context_for_assessment(
                target=target,
                state=self.state,
                max_sessions=self.config.memory_max_sessions,
            )
            
            if retrieved.relevant_sessions or retrieved.finding_patterns:
                # Add memory summary as evidence
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "memory",
                    f"Loaded relevant context:\n{retrieved.summary}",
                    {
                        "memory_sessions": len(retrieved.relevant_sessions),
                        "memory_patterns": len(retrieved.finding_patterns),
                        "memory_tools": len(retrieved.tool_recommendations),
                        "memory_cves": len(retrieved.cve_knowledge),
                    }
                )
                
                # Add key findings from past sessions as high-signal facts
                for session in retrieved.relevant_sessions[:3]:
                    for fact in session.critical_findings[:3]:
                        self.state.add_high_signal_fact(f"[From past session] {fact}")
                    for fact in session.high_findings[:2]:
                        self.state.add_high_signal_fact(f"[From past session] {fact}")
                
                # Add finding patterns
                for pattern in retrieved.finding_patterns[:5]:
                    self.state.add_high_signal_fact(
                        f"[Pattern] {pattern.description} (seen {pattern.seen_count}x, {pattern.confidence.value})"
                    )
                
                console.print(f"[green]Loaded {len(retrieved.relevant_sessions)} past sessions, {len(retrieved.finding_patterns)} patterns[/green]")
            else:
                console.print("[dim]No relevant past sessions found[/dim]")
                
        except Exception as e:
            console.print(f"[yellow]Memory load failed: {e}[/yellow]")
    
    def _save_session_to_memory(self):
        """Save current session summary to memory for future assessments."""
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
            
            # Also update finding patterns from high-signal facts
            self._extract_patterns_from_facts()
            
            # Update tool effectiveness
            self._update_tool_effectiveness()
            
            console.print(f"[dim]Session saved to memory[/dim]")
            
        except Exception as e:
            console.print(f"[yellow]Memory save failed: {e}[/yellow]")
    
    def _extract_patterns_from_facts(self):
        """Extract and store finding patterns from current session facts."""
        from erreetool.agent.memory.schema import FindingPattern

        facts = self.state.context.high_signal_facts

        # Group facts by type
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
                confidence=ConfidenceLevel.MEDIUM,
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
                        confidence=ConfidenceLevel.HIGH,
                        example_targets=[self.state.context.target],
                        tags=["cve", "vuln"],
                    )
                    memory_store.add_finding_pattern(pattern)

        if tech_facts:
            pattern = FindingPattern(
                pattern_id=f"tech_pattern_{self.state.session_id}",
                pattern_type="technology",
                description=f"Technology stack: {', '.join(tech_facts[:3])}",
                indicators=[f.split(':')[-1].strip() for f in tech_facts],
                associated_findings=tech_facts,
                seen_count=1,
                last_seen=time.time(),
                confidence=ConfidenceLevel.MEDIUM,
                example_targets=[self.state.context.target],
                tags=["technology", "fingerprint"],
            )
            memory_store.add_finding_pattern(pattern)
    
    def _update_tool_effectiveness(self):
        """Update tool effectiveness records from this session."""
        from erreetool.agent.memory.schema import ToolEffectiveness
        
        # Group steps by tool
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
        
        # Build context hash
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
    
    def _should_stop(self) -> bool:
        """Check if agent should stop."""
        if self.step_count >= self.config.max_steps:
            return True
        if time.time() - self.start_time > self.config.max_duration:
            return True
        # Check if final answer was given
        last_step = self.state.steps[-1] if self.state.steps else None
        if last_step and last_step.status == StepStatus.COMPLETED:
            # Check if it was a final answer
            if "FINAL" in last_step.description.upper():
                return True
        return False
    
    def _build_messages(self) -> list[LLMMessage]:
        """Build message history for LLM."""
        messages = [
            LLMMessage(role="system", content=self.SYSTEM_PROMPT)
        ]
        
        # Add context
        context_summary = self._format_context()
        messages.append(LLMMessage(
            role="user",
            content=f"CURRENT CONTEXT:\n{context_summary}\n\nGOALS:\n" + 
            "\n".join(f"- {g}" for g in self.state.context.goals) +
            "\n\nEVIDENCE PREVIEW:\n" + self.state.get_high_signal_preview()
        ))
        
        # Add recent steps as assistant/tool messages
        for step in self.state.steps[-5:]:  # Last 5 steps
            if step.status == StepStatus.COMPLETED:
                # Tool result
                for ev_id in step.evidence_ids:
                    ev = self.state.get_evidence(ev_id)
                    if ev:
                        messages.append(LLMMessage(
                            role="tool",
                            content=ev.preview(1000),
                            tool_call_id=step.id,
                            name=step.tool
                        ))
        
        return messages
    
    def _format_context(self) -> str:
        """Format context for LLM."""
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
        
        if ctx.high_signal_facts:
            parts.append("Verified facts:")
            for fact in ctx.high_signal_facts[-10:]:
                parts.append(f"  - {fact}")
        
        return "\n".join(parts)
    
    def _execute_tool_calls(self, tool_calls: list[dict]):
        """Execute tool calls from LLM."""
        for tc in tool_calls:
            func_name = tc["function"]["name"]
            func_args = json.loads(tc["function"]["arguments"])
            
            # Safety gate check (Phase 6)
            if self.safety_gate:
                allowed, classification, response = self.safety_gate.check(
                    func_name.replace("run_", ""),  # tool name without prefix
                    func_args
                )
                if not allowed:
                    error = f"Safety gate blocked {func_name}: {classification.reason}"
                    console.print(f"[yellow]{error}[/yellow]")
                    self.state.add_evidence(
                        EvidenceType.OBSERVATION,
                        "safety_gate",
                        error,
                        {"risk": classification.risk.value, "response": response.value if response else "auto"}
                    )
                    continue
                if response == ApprovalResponse.ABORT:
                    console.print("[red]User aborted assessment via safety gate.[/red]")
                    return
            
            # Create step
            step = self.state.add_step(
                description=f"Execute {func_name}",
                tool=func_name,
                args=func_args
            )
            
            # Execute tool
            executor = self.tool_executors.get(func_name)
            if not executor:
                error = f"Unknown tool: {func_name}"
                self.state.complete_step(step, error=error)
                self.state.add_evidence(
                    EvidenceType.TOOL_ERROR,
                    "agent",
                    error,
                    {"tool": func_name, "args": func_args}
                )
                continue
            
            try:
                result = executor(**func_args)
                
                # Add evidence
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
                
                # Complete step
                self.state.complete_step(step, evidence_ids=[evidence.id], error=result.stderr if not result.success else "")
                
                # Extract high-signal facts from output
                self._extract_facts(func_name, result.output)
                
            except Exception as e:
                self.state.complete_step(step, error=str(e))
                self.state.add_evidence(
                    EvidenceType.TOOL_ERROR,
                    func_name,
                    f"Execution failed: {e}",
                    {"args": func_args}
                )
    
    def _extract_facts(self, tool: str, output: str):
        """Extract high-signal facts from tool output.

        The `tool` parameter is used to apply tool-specific parsing heuristics
        on top of the generic patterns, so facts carry useful context (which
        tool saw the artifact) and avoid noisy false positives (e.g. we only
        look for web servers in nmap/whatweb output, not sqlmap output).
        """
        import re

        # ----- Generic port findings (nmap primarily) -----
        if tool in ("nmap", "shell"):
            for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', output):
                port, service = match.groups()
                self.state.add_high_signal_fact(
                    f"Port {port}/tcp open: {service}"
                )

        # ----- Vulnerability findings (nuclei, nmap NSE) -----
        if tool in ("nuclei", "nmap", "shell"):
            for cve in re.findall(r'CVE-\d{4}-\d{4,7}', output):
                self.state.add_high_signal_fact(f"Vulnerability found: {cve}")

        # ----- Technology findings -----
        if tool in ("nmap", "whatweb", "nuclei", "shell"):
            for match in re.finditer(r'(\w+)[/\s]([\d.]+)', output):
                tech, version = match.groups()
                if tech.lower() in {
                    'apache', 'nginx', 'iis', 'tomcat',
                    'jenkins', 'wordpress', 'drupal', 'joomla',
                }:
                    self.state.add_high_signal_fact(
                        f"Technology: {tech} {version}"
                    )

        # ----- Database findings -----
        if tool in ("nmap", "sqlmap", "shell"):
            db_match = re.search(
                r'\b(mysql|postgresql|mssql|oracle|mongodb|redis)\b',
                output,
                re.IGNORECASE,
            )
            if db_match:
                self.state.add_high_signal_fact(
                    f"Database service detected: {db_match.group(1).lower()}"
                )

        # ----- SQLi findings (sqlmap) -----
        if tool == "sqlmap":
            if re.search(
                r'(injectable|sql injection|vulnerable|back-end DBMS)',
                output,
                re.IGNORECASE,
            ):
                self.state.add_high_signal_fact(
                    "SQL injection vulnerability detected by sqlmap"
                )

        # ----- Directory findings (gobuster) -----
        if tool == "gobuster":
            for match in re.finditer(r'^/(?:Status:\s+\d+\s+\[Size:\s+\d+\]\s+)?\[\s*(\d+)\s*\]\s+(\S+)', output, re.MULTILINE):
                status, path = match.groups()
                if status in ("200", "301", "302", "401", "403"):
                    self.state.add_high_signal_fact(
                        f"Directory found: {path} (HTTP {status})"
                    )
    
    def _process_final_response(self, content: str):
        """Process final answer from LLM."""
        # Check for FINAL marker
        if "FINAL" in content.upper():
            self.state.add_evidence(
                EvidenceType.LLM_REASONING,
                "agent",
                content,
                {"final": True}
            )
        else:
            # Treat as reasoning
            self.state.add_evidence(
                EvidenceType.LLM_REASONING,
                "agent",
                content,
                {"final": False}
            )
    
    def _verify_final_claims(self) -> bool:
        """Anti-hallucination gate: verify claims in final response."""
        # Get final evidence
        final_evidence = [e for e in self.state.evidence_log 
                         if e.metadata.get("final") and e.type == EvidenceType.LLM_REASONING]
        
        if not final_evidence:
            return True  # No final claim to verify
        
        content = final_evidence[-1].content
        
        # Extract claims (sentences with CVE, port, vulnerability, etc.)
        import re
        claims = re.findall(
            r'[^.]*?(?:CVE-\d{4}-\d{4,7}|port \d+|vulnerab\w+|exploit\w+|credential\w+)[^.]*\.',
            content,
            re.IGNORECASE,
        )
        
        all_verified = True
        for claim in claims:
            verified, matches = self.state.verify_claim(claim)
            if not verified:
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "gate",
                    f"UNVERIFIED CLAIM: {claim.strip()}",
                    {"gate_failed": True}
                )
                all_verified = False
            else:
                self.state.add_evidence(
                    EvidenceType.OBSERVATION,
                    "gate",
                    f"VERIFIED: {claim.strip()} (evidence: {', '.join(m.id for m in matches)})",
                    {"gate_passed": True}
                )
        
        return all_verified
    
    # Tool executors
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
    
    def _exec_fetch(self, **kwargs) -> ToolResult:
        from erreetool.agent.tools.http_tools import FetchTool
        tool = FetchTool(state=self.state, traffic_store=self.traffic_store)
        return tool.run(**kwargs)
    
    def _exec_http_probe_batch(self, **kwargs) -> ToolResult:
        from erreetool.agent.tools.http_tools import HTTPProbeBatchTool
        tool = HTTPProbeBatchTool(state=self.state, traffic_store=self.traffic_store)
        return tool.run(**kwargs)
    
    def _exec_source_extract(self, **kwargs) -> ToolResult:
        from erreetool.agent.tools.http_tools import SourceExtractTool
        tool = SourceExtractTool(state=self.state)
        return tool.run(**kwargs)
    
    def _exec_runtime_diff_probe(self, **kwargs) -> ToolResult:
        from erreetool.agent.tools.http_tools import RuntimeDiffProbeTool
        tool = RuntimeDiffProbeTool(state=self.state)
        return tool.run(**kwargs)
    
    def _exec_traffic_list(self, **kwargs) -> ToolResult:
        from erreetool.agent.tools.http_tools import TrafficListTool
        tool = TrafficListTool(state=self.state, traffic_store=self.traffic_store)
        return tool.run(**kwargs)
    
    def _exec_traffic_view(self, **kwargs) -> ToolResult:
        from erreetool.agent.tools.http_tools import TrafficViewTool
        tool = TrafficViewTool(state=self.state, traffic_store=self.traffic_store)
        return tool.run(**kwargs)
    
    def _fallback_analysis(self) -> str:
        """Generate basic triage report without LLM."""
        ctx = self.state.context
        facts = ctx.high_signal_facts
        
        lines = [
            "# Vulnerability Triage Report (Built-in Analysis)",
            f"",
            f"**Target:** `{ctx.target}`",
            f"**Analysis Mode:** Built-in fallback (no LLM)",
            f"**Facts Analyzed:** {len(facts)}",
            f"",
            "---",
            "",
        ]
        
        if not facts:
            lines.extend([
                "## No High-Signal Facts Found",
                "",
                "The assessment did not discover specific high-signal findings.",
                "This may indicate:",
                "- Target has minimal exposed services",
                "- Services are not revealing version information",
                "- Further manual enumeration may be needed",
                "",
            ])
            return "\n".join(lines)
        
        # Categorize facts
        critical = []
        high = []
        medium = []
        low = []
        
        for fact in facts:
            fact_lower = fact.lower()
            if any(kw in fact_lower for kw in ['cve-', 'vulnerab', 'exploit', 'rce', 'backdoor', 'critical']):
                critical.append(fact)
            elif any(kw in fact_lower for kw in ['port 445', 'smb', 'sql', 'database', 'admin', 'default cred']):
                high.append(fact)
            elif any(kw in fact_lower for kw in ['port 135', 'rpc', 'epmap', 'version', 'apache', 'nginx', 'iis']):
                medium.append(fact)
            else:
                low.append(fact)
        
        def add_section(title, items, icon):
            if items:
                lines.append(f"## {icon} {title}")
                lines.append("")
                for item in items:
                    lines.append(f"- {item}")
                lines.append("")
        
        add_section("CRITICAL", critical, "🔴")
        add_section("HIGH", high, "🟠")
        add_section("MEDIUM", medium, "🟡")
        add_section("LOW / INFO", low, "🔵")
        
        lines.extend([
            "---",
            "",
            "## Recommendations",
            "",
            "1. **Verify findings manually** - Built-in analysis is heuristic-based",
            "2. **Run targeted enumeration** on critical/high findings",
            "3. **Check for patches** on identified CVE references",
            "4. **Validate exploitability** in a controlled environment",
            "",
            "*Note: This is a heuristic analysis. For production use, configure an LLM provider.*",
        ])
        
        return "\n".join(lines)