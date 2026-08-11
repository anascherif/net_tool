"""
AgentState - Persistent state management for autonomous agent.

Stores evidence, context, step history, and provides anti-hallucination gates.
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional
from enum import Enum


class StepStatus(str, Enum):
    """Status of an agent step."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class EvidenceType(str, Enum):
    """Type of evidence collected."""
    TOOL_OUTPUT = "tool_output"
    TOOL_ERROR = "tool_error"
    LLM_REASONING = "llm_reasoning"
    SKILL_RESULT = "skill_result"
    USER_INPUT = "user_input"
    OBSERVATION = "observation"


@dataclass
class Evidence:
    """A piece of evidence collected during agent execution."""
    id: str
    type: EvidenceType
    source: str  # tool name, skill name, etc.
    content: str
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    hash: str = ""
    size: int = 0
    
    def __post_init__(self):
        import hashlib
        self.hash = hashlib.sha256(self.content.encode()).hexdigest()[:16]
        self.size = len(self.content.encode())
    
    def preview(self, max_chars: int = 500) -> str:
        """Get a preview of the evidence content."""
        if len(self.content) <= max_chars:
            return self.content
        return self.content[:max_chars] + f"\n... [{len(self.content)} chars total]"
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "source": self.source,
            "content": self.content,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "size": self.size,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        return cls(**data)


@dataclass
class AgentStep:
    """A single step in the agent's execution."""
    id: str
    description: str
    tool: str
    args: dict
    status: StepStatus = StepStatus.PENDING
    evidence_ids: list[str] = field(default_factory=list)
    error: str = ""
    start_time: float = 0
    end_time: float = 0
    duration: float = 0
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "tool": self.tool,
            "args": self.args,
            "status": self.status.value,
            "evidence_ids": self.evidence_ids,
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AgentStep":
        step = cls(
            id=data["id"],
            description=data["description"],
            tool=data["tool"],
            args=data["args"],
            status=StepStatus(data["status"]),
            evidence_ids=data.get("evidence_ids", []),
            error=data.get("error", ""),
            start_time=data.get("start_time", 0),
            end_time=data.get("end_time", 0),
            duration=data.get("duration", 0),
        )
        return step


@dataclass
class AgentContext:
    """Current context for the agent (target, constraints, findings)."""
    target: str = ""
    constraints: list[str] = field(default_factory=list)
    goals: list[str] = field(default_factory=list)
    findings: dict = field(default_factory=dict)  # Structured findings
    high_signal_facts: list[str] = field(default_factory=list)  # Fixed facts
    completed_skills: list[str] = field(default_factory=list)
    failed_skills: list[str] = field(default_factory=list)
    skill_history: list[dict] = field(default_factory=list)
    current_phase: str = "recon"
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> "AgentContext":
        return cls(**data)


class AgentState:
    """
    Persistent state for the autonomous agent.
    
    Manages:
    - Evidence log (append-only, JSONL)
    - Step history
    - Context (target, findings, facts)
    - Anti-hallucination gates
    """
    
    def __init__(self, session_id: str = None, output_dir: Path = None):
        self.session_id = session_id or f"session_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        self.output_dir = output_dir or Path.cwd() / "erreetool-output" / self.session_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.evidence_log: list[Evidence] = []
        self.steps: list[AgentStep] = []
        self.context = AgentContext()
        self.created_at = time.time()
        self.updated_at = time.time()
        
        # Evidence index for fast lookup
        self._evidence_index: dict[str, Evidence] = {}
        
        # JSONL file for persistence
        self.evidence_file = self.output_dir / "evidence.jsonl"
        self.state_file = self.output_dir / "state.json"
    
    def add_evidence(
        self,
        type: EvidenceType,
        source: str,
        content: str,
        metadata: dict = None
    ) -> Evidence:
        """Add evidence to the log."""
        evidence = Evidence(
            id=f"e{len(self.evidence_log) + 1:04d}",
            type=type,
            source=source,
            content=content,
            metadata=metadata or {},
        )
        self.evidence_log.append(evidence)
        self._evidence_index[evidence.id] = evidence
        self.updated_at = time.time()
        
        # Persist to JSONL
        self._write_evidence(evidence)
        return evidence
    
    def _write_evidence(self, evidence: Evidence):
        """Write single evidence to JSONL file."""
        with open(self.evidence_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(evidence.to_dict()) + "\n")
    
    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        return self._evidence_index.get(evidence_id)
    
    def search_evidence(
        self,
        query: str,
        type: EvidenceType = None,
        source: str = None,
        limit: int = 10
    ) -> list[Evidence]:
        """Search evidence by content (simple keyword search)."""
        results = []
        query_lower = query.lower()
        
        for ev in reversed(self.evidence_log):  # Most recent first
            if type and ev.type != type:
                continue
            if source and ev.source != source:
                continue
            if query_lower in ev.content.lower():
                results.append(ev)
                if len(results) >= limit:
                    break
        return results
    
    def get_high_signal_preview(self, max_evidence: int = 20, max_chars: int = 3000) -> str:
        """Get high-signal preview of recent evidence for LLM context."""
        # Prioritize: tool outputs > errors > reasoning
        priority = {
            EvidenceType.TOOL_OUTPUT: 0,
            EvidenceType.TOOL_ERROR: 1,
            EvidenceType.SKILL_RESULT: 2,
            EvidenceType.LLM_REASONING: 3,
        }
        
        sorted_ev = sorted(
            self.evidence_log[-max_evidence:],
            key=lambda e: priority.get(e.type, 99)
        )
        
        parts = []
        total_chars = 0
        for ev in sorted_ev:
            preview = ev.preview(max_chars // max_evidence)
            parts.append(f"[{ev.id}] {ev.type.value} from {ev.source}:\n{preview}")
            total_chars += len(preview)
            if total_chars >= max_chars:
                break
        
        return "\n---\n".join(parts) if parts else "No evidence yet."
    
    def add_step(self, description: str, tool: str, args: dict) -> AgentStep:
        """Create and add a new step."""
        step = AgentStep(
            id=f"s{len(self.steps) + 1:04d}",
            description=description,
            tool=tool,
            args=args,
            start_time=time.time(),
        )
        self.steps.append(step)
        self.updated_at = time.time()
        return step
    
    def complete_step(self, step: AgentStep, evidence_ids: list[str] = None, error: str = ""):
        """Mark step as completed."""
        step.status = StepStatus.FAILED if error else StepStatus.COMPLETED
        step.evidence_ids = evidence_ids or []
        step.error = error
        step.end_time = time.time()
        step.duration = step.end_time - step.start_time
        self.updated_at = time.time()
    
    def add_high_signal_fact(self, fact: str):
        """Add a verified high-signal fact that persists in context."""
        if fact not in self.context.high_signal_facts:
            self.context.high_signal_facts.append(fact)
            self.updated_at = time.time()

    def mark_skill_failed(self, skill_name: str, error: str = ""):
        """Record a skill execution failure."""
        if skill_name not in self.context.failed_skills:
            self.context.failed_skills.append(skill_name)
            self.updated_at = time.time()
        if error:
            self.context.skill_history.append({
                "skill_name": skill_name,
                "success": False,
                "error": error,
            })
    
    def verify_claim(self, claim: str, min_matches: int = 1) -> tuple[bool, list[Evidence]]:
        """
        Anti-hallucination gate: verify a claim exists in evidence.
        
        Returns (verified, supporting_evidence)
        """
        claim_lower = claim.lower()
        matches = []
        
        for ev in self.evidence_log:
            if claim_lower in ev.content.lower():
                matches.append(ev)
                if len(matches) >= min_matches:
                    break
        
        return len(matches) >= min_matches, matches
    
    def save(self):
        """Save full state to JSON."""
        state = {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "context": self.context.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "evidence_count": len(self.evidence_log),
        }
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    
    @classmethod
    def load(cls, state_file: Path) -> "AgentState":
        """Load state from JSON file."""
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        state = cls(session_id=data["session_id"], output_dir=state_file.parent)
        state.created_at = data["created_at"]
        state.updated_at = data["updated_at"]
        state.context = AgentContext.from_dict(data["context"])
        state.steps = [AgentStep.from_dict(s) for s in data["steps"]]
        
        # Load evidence from JSONL
        evidence_file = state_file.parent / "evidence.jsonl"
        if evidence_file.exists():
            with open(evidence_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        ev_data = json.loads(line)
                        ev = Evidence.from_dict(ev_data)
                        state.evidence_log.append(ev)
                        state._evidence_index[ev.id] = ev
        
        return state
    
    def get_summary(self) -> dict:
        """Get a summary of the current state."""
        return {
            "session_id": self.session_id,
            "target": self.context.target,
            "phase": self.context.current_phase,
            "steps_total": len(self.steps),
            "steps_completed": sum(1 for s in self.steps if s.status == StepStatus.COMPLETED),
            "steps_failed": sum(1 for s in self.steps if s.status == StepStatus.FAILED),
            "evidence_total": len(self.evidence_log),
            "high_signal_facts": len(self.context.high_signal_facts),
            "duration": time.time() - self.created_at,
        }