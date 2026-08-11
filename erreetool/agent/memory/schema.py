"""
Memory schema - dataclasses for persistent agent memory.

Stores session summaries, finding patterns, and learned knowledge
across assessments for cross-session intelligence.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


class MemoryType(str, Enum):
    """Type of memory entry."""
    SESSION_SUMMARY = "session_summary"
    FINDING_PATTERN = "finding_pattern"
    TOOL_EFFECTIVENESS = "tool_effectiveness"
    TARGET_PROFILE = "target_profile"
    CVE_KNOWLEDGE = "cve_knowledge"
    CREDENTIAL_PATTERN = "credential_pattern"


class ConfidenceLevel(str, Enum):
    """Confidence in a memory entry."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


@dataclass
class SessionSummary:
    """Summary of a completed assessment session."""
    session_id: str
    target: str
    timestamp: float
    duration: float
    skills_run: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    high_signal_facts: list[str] = field(default_factory=list)
    critical_findings: list[str] = field(default_factory=list)
    high_findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "duration": self.duration,
            "skills_run": self.skills_run,
            "tools_used": self.tools_used,
            "high_signal_facts": self.high_signal_facts,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "recommendations": self.recommendations,
            "success": self.success,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionSummary":
        return cls(**{k: v for k, v in data.items() if k != "datetime"})


@dataclass
class FindingPattern:
    """A learned pattern from findings across sessions."""
    pattern_id: str
    pattern_type: str  # "cve", "port", "tech", "credential", "vuln_class"
    description: str
    indicators: list[str] = field(default_factory=list)  # What triggers this pattern
    associated_findings: list[str] = field(default_factory=list)
    seen_count: int = 1
    last_seen: float = 0
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    example_targets: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "description": self.description,
            "indicators": self.indicators,
            "associated_findings": self.associated_findings,
            "seen_count": self.seen_count,
            "last_seen": self.last_seen,
            "confidence": self.confidence.value,
            "example_targets": self.example_targets,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FindingPattern":
        data = dict(data)
        if "confidence" in data:
            data["confidence"] = ConfidenceLevel(data["confidence"])
        return cls(**data)


@dataclass
class ToolEffectiveness:
    """Tracks how effective a tool was in a given context."""
    tool_name: str
    context_hash: str  # Hash of context (e.g., "web:nginx", "smb:windows")
    runs: int = 0
    successes: int = 0
    findings_generated: int = 0
    avg_duration: float = 0.0
    last_used: float = 0
    notes: str = ""

    @property
    def success_rate(self) -> float:
        return self.successes / self.runs if self.runs > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "context_hash": self.context_hash,
            "runs": self.runs,
            "successes": self.successes,
            "findings_generated": self.findings_generated,
            "avg_duration": self.avg_duration,
            "last_used": self.last_used,
            "success_rate": self.success_rate,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ToolEffectiveness":
        return cls(**{k: v for k, v in data.items() if k != "success_rate"})


@dataclass
class TargetProfile:
    """Profile of a target type based on past assessments."""
    profile_id: str
    target_type: str  # "web", "smb", "database", "network", "unknown"
    common_ports: list[int] = field(default_factory=list)
    common_technologies: list[str] = field(default_factory=list)
    common_vulns: list[str] = field(default_factory=list)
    recommended_skills: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    assessment_count: int = 0
    last_assessed: float = 0

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "target_type": self.target_type,
            "common_ports": self.common_ports,
            "common_technologies": self.common_technologies,
            "common_vulns": self.common_vulns,
            "recommended_skills": self.recommended_skills,
            "recommended_tools": self.recommended_tools,
            "assessment_count": self.assessment_count,
            "last_assessed": self.last_assessed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TargetProfile":
        return cls(**data)


@dataclass
class CVEKnowledge:
    """Learned knowledge about a specific CVE."""
    cve_id: str
    description: str
    affected_technologies: list[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_complexity: str = "unknown"  # low, medium, high, unknown
    cvss_score: float = 0.0
    seen_in_targets: list[str] = field(default_factory=list)
    detection_methods: list[str] = field(default_factory=list)
    mitigation_notes: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    last_updated: float = 0

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "affected_technologies": self.affected_technologies,
            "exploit_available": self.exploit_available,
            "exploit_complexity": self.exploit_complexity,
            "cvss_score": self.cvss_score,
            "seen_in_targets": self.seen_in_targets,
            "detection_methods": self.detection_methods,
            "mitigation_notes": self.mitigation_notes,
            "confidence": self.confidence.value,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CVEKnowledge":
        data = dict(data)
        if "confidence" in data:
            data["confidence"] = ConfidenceLevel(data["confidence"])
        return cls(**data)


@dataclass
class CredentialPattern:
    """Pattern for default/common credentials."""
    pattern_id: str
    service: str  # ssh, ftp, smb, rdp, web, database
    username: str
    password: str
    context: str = ""  # e.g., "default", "common", "vendor_specific"
    success_count: int = 0
    attempted_count: int = 0
    last_tried: float = 0
    source: str = "learned"  # learned, wordlist, vendor_doc

    @property
    def success_rate(self) -> float:
        return self.success_count / self.attempted_count if self.attempted_count > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "context": self.context,
            "success_count": self.success_count,
            "attempted_count": self.attempted_count,
            "success_rate": self.success_rate,
            "last_tried": self.last_tried,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CredentialPattern":
        return cls(**{k: v for k, v in data.items() if k != "success_rate"})


# -- Generic Memory Entry wrapper --

@dataclass
class MemoryEntry:
    """Generic wrapper for any memory type with metadata."""
    entry_id: str
    memory_type: MemoryType
    content: dict  # Serialized SessionSummary, FindingPattern, etc.
    created_at: float
    updated_at: float
    tags: list[str] = field(default_factory=list)
    relevance_score: float = 1.0

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "memory_type": self.memory_type.value,
            "content": self.content,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
            "relevance_score": self.relevance_score,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryEntry":
        data = dict(data)
        if "memory_type" in data:
            data["memory_type"] = MemoryType(data["memory_type"])
        return cls(**data)


def generate_entry_id(prefix: str = "mem") -> str:
    """Generate a unique memory entry ID."""
    import uuid
    return f"{prefix}_{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}"