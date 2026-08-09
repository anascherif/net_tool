"""
Autonomous agent loop with evidence gates and anti-hallucination.

The agent decides next actions based on context, executes tools,
and validates claims against collected evidence.
"""

import json
import time
from typing import Optional, Any
from dataclasses import dataclass

from rich.console import Console

from erreetool.agent.state import AgentState, AgentContext, EvidenceType, AgentStep, StepStatus
from erreetool.agent.providers import MultiProvider, LLMMessage, TOOL_DEFINITIONS
from erreetool.agent.tools.base import tool_registry, ToolResult

console = Console()


@dataclass
class AgentConfig:
    """Configuration for the autonomous agent."""
    max_steps: int = 50
    max_duration: float = 3600  # 1 hour
    evidence_gate_required: bool = True
    show_reasoning: bool = True
    auto_report: bool = True


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
    
    def run(self, goal: str = None) -> AgentState:
        """Run the autonomous agent loop."""
        # Initialize context
        if goal:
            self.state.context.goals.append(goal)
        
        self.state.add_evidence(
            EvidenceType.OBSERVATION,
            "agent",
            f"Session started. Goal: {goal or 'Full penetration test'}",
            {"session_id": self.state.session_id}
        )
        
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
        
        # Save final state
        self.state.save()
        return self.state
    
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
        """Extract high-signal facts from tool output."""
        # Simple pattern-based extraction
        import re
        
        # Port findings
        for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', output):
            port, service = match.groups()
            self.state.add_high_signal_fact(f"Port {port}/tcp open: {service}")
        
        # Vulnerability findings
        if "CVE-" in output:
            for cve in re.findall(r'CVE-\d{4}-\d{4,}', output):
                self.state.add_high_signal_fact(f"Vulnerability found: {cve}")
        
        # Technology findings
        for match in re.finditer(r'(\w+)[/\s]([\d.]+)', output):
            tech, version = match.groups()
            if tech.lower() in ['apache', 'nginx', 'iis', 'tomcat', 'jenkins', 'wordpress', 'drupal', 'joomla']:
                self.state.add_high_signal_fact(f"Technology: {tech} {version}")
        
        # Database findings
        if any(kw in output.lower() for kw in ['mysql', 'postgresql', 'mssql', 'oracle']):
            self.state.add_high_signal_fact(f"Database service detected in output")
    
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
        claims = re.findall(r'[^.]*?(?:CVE-\d{4}-\d{4,}|port \d+|vulnerab\w+|exploit\w+|credential\w+)[^.]*\.', content, re.IGNORECASE)
        
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