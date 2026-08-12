"""
Memory retriever - smart context retrieval for agent.

Provides relevance-ranked memory entries based on current assessment context.
"""

import re
import hashlib
from typing import Optional
from dataclasses import dataclass

from erreetool.agent.memory.store import memory_store, MemoryStore
from erreetool.agent.memory.schema import (
    MemoryType,
    SessionSummary,
    FindingPattern,
    ToolEffectiveness,
    TargetProfile,
    CVEKnowledge,
    CredentialPattern,
    ConfidenceLevel,
)
from erreetool.agent.state import AgentState


_CONFIDENCE_RANK = {lvl.value: i for i, lvl in enumerate(ConfidenceLevel)}


@dataclass
class RetrievedContext:
    """Context retrieved from memory for current assessment."""
    relevant_sessions: list[SessionSummary] = None
    finding_patterns: list[FindingPattern] = None
    tool_recommendations: list[ToolEffectiveness] = None
    target_profile: Optional[TargetProfile] = None
    cve_knowledge: list[CVEKnowledge] = None
    credential_patterns: list[CredentialPattern] = None
    summary: str = ""

    def __post_init__(self):
        if self.relevant_sessions is None:
            self.relevant_sessions = []
        if self.finding_patterns is None:
            self.finding_patterns = []
        if self.tool_recommendations is None:
            self.tool_recommendations = []
        if self.cve_knowledge is None:
            self.cve_knowledge = []
        if self.credential_patterns is None:
            self.credential_patterns = []


class MemoryRetriever:
    """
    Retrieves relevant memory for current assessment context.
    
    Uses multiple signals:
    - Target similarity (IP, hostname, network)
    - Technology stack overlap
    - Port/service overlap
    - CVE references
    - Skill/tool effectiveness history
    """

    def __init__(self, store: MemoryStore = None):
        self.store = store or memory_store
        # Ensure loaded
        self.store.load()

    def get_context_for_assessment(
        self,
        target: str,
        state: AgentState = None,
        max_sessions: int = 5,
        max_patterns: int = 10,
    ) -> RetrievedContext:
        """Get comprehensive context for a new assessment."""
        context = RetrievedContext()

        # 1. Get recent sessions for similar targets
        context.relevant_sessions = self._find_relevant_sessions(target, max_sessions)

        # 2. Get finding patterns relevant to target
        context.finding_patterns = self._find_relevant_patterns(target, state, max_patterns)

        # 3. Get target profile
        context.target_profile = self._get_target_profile(target, state)

        # 4. Get tool recommendations based on context
        if state:
            context.tool_recommendations = self._get_tool_recommendations(state)

        # 5. Get CVE knowledge for any CVEs found
        if state and state.context.high_signal_facts:
            context.cve_knowledge = self._get_cve_knowledge(state.context.high_signal_facts)

        # 6. Get credential patterns for discovered services
        if state:
            context.credential_patterns = self._get_credential_patterns(state)

        # Generate summary
        context.summary = self._generate_summary(context)

        return context

    def _find_relevant_sessions(self, target: str, limit: int) -> list[SessionSummary]:
        """Find sessions for similar targets."""
        # Extract network prefix for similarity
        target_network = self._get_network_prefix(target)
        
        sessions = self.store.get_recent_sessions(limit * 3)  # Get more, filter
        relevant = []
        
        for session in sessions:
            score = self._target_similarity(target, session.target)
            if score > 0.3:  # Threshold for relevance
                relevant.append((score, session))
        
        # Sort by similarity and recency
        relevant.sort(key=lambda x: (x[0], x[1].timestamp), reverse=True)
        return [s for _, s in relevant[:limit]]

    def _find_relevant_patterns(
        self,
        target: str,
        state: AgentState,
        limit: int
    ) -> list[FindingPattern]:
        """Find finding patterns relevant to current target/context."""
        patterns = []
        
        # Get patterns matching target
        target_patterns = self.store.get_patterns_for_target(target)
        patterns.extend(target_patterns)
        
        # If we have state with facts, match patterns by indicators
        if state and state.context.high_signal_facts:
            facts_blob = " ".join(state.context.high_signal_facts).lower()
            for entry in self.store.get_by_type(MemoryType.FINDING_PATTERN):
                pattern = FindingPattern.from_dict(entry.content)
                # Check indicator match
                for indicator in pattern.indicators:
                    if indicator.lower() in facts_blob:
                        if pattern not in patterns:
                            patterns.append(pattern)
                        break
        
        # Sort by confidence (descending) and seen_count (descending)
        patterns.sort(
            key=lambda p: (_CONFIDENCE_RANK.get(p.confidence.value, 0), p.seen_count),
            reverse=True,
        )

        return patterns[:limit]

    def _get_target_profile(self, target: str, state: AgentState) -> Optional[TargetProfile]:
        """Get or infer target profile."""
        # Try to find existing profile by target type
        profiles = self.store.get_by_type(MemoryType.TARGET_PROFILE)
        
        # Infer target type from state
        target_type = "unknown"
        if state:
            facts = " ".join(state.context.high_signal_facts).lower()
            if any(p in facts for p in ["http", "web", "nginx", "apache", "iis"]):
                target_type = "web"
            elif "445" in facts or "smb" in facts:
                target_type = "smb"
            elif any(p in facts for p in ["mysql", "postgresql", "mssql", "database"]):
                target_type = "database"
            elif any(p in facts for p in ["ssh", "rdp", "telnet"]):
                target_type = "remote_access"
        
        for entry in profiles:
            profile = TargetProfile.from_dict(entry.content)
            if profile.target_type == target_type:
                return profile
        
        return None

    def _get_tool_recommendations(self, state: AgentState) -> list[ToolEffectiveness]:
        """Get tool recommendations based on current context."""
        # Build context hash from known facts
        facts = state.context.high_signal_facts
        context_parts = []
        
        for fact in facts:
            fact_lower = fact.lower()
            if "port" in fact_lower and "open" in fact_lower:
                # Extract service
                match = re.search(r'port\s+(\d+)/tcp\s+open\s+(\w+)', fact_lower)
                if match:
                    context_parts.append(f"port:{match.group(1)}:{match.group(2)}")
            elif "web server" in fact_lower:
                match = re.search(r'web server:\s+(\w+)', fact_lower)
                if match:
                    context_parts.append(f"web:{match.group(1)}")
            elif "cms" in fact_lower:
                match = re.search(r'cms:\s+(\w+)', fact_lower)
                if match:
                    context_parts.append(f"cms:{match.group(1)}")
        
        if not context_parts:
            return []
        
        context_hash = hashlib.md5("|".join(sorted(context_parts)).encode()).hexdigest()[:16]
        return self.store.get_tool_recommendations(context_hash)

    def _get_cve_knowledge(self, facts: list[str]) -> list[CVEKnowledge]:
        """Get CVE knowledge for CVEs mentioned in facts."""
        cves = []
        for fact in facts:
            # Extract CVE IDs
            matches = re.findall(r'CVE-\d{4}-\d{4,7}', fact)
            for cve_id in matches:
                knowledge = self.store.get_cve_knowledge(cve_id)
                if knowledge:
                    cves.append(knowledge)
        return cves

    def _get_credential_patterns(self, state: AgentState) -> list[CredentialPattern]:
        """Get credential patterns for discovered services."""
        patterns: list[CredentialPattern] = []
        facts = " ".join(state.context.high_signal_facts).lower()

        services: list[str] = []
        if "ssh" in facts or "22/tcp" in facts:
            services.append("ssh")
        if "ftp" in facts or "21/tcp" in facts:
            services.append("ftp")
        if "smb" in facts or "445/tcp" in facts:
            services.append("smb")
        if "rdp" in facts or "3389/tcp" in facts:
            services.append("rdp")
        if "mysql" in facts or "3306/tcp" in facts:
            services.append("mysql")
        if "postgresql" in facts or "5432/tcp" in facts:
            services.append("postgresql")
        if "mssql" in facts or "1433/tcp" in facts:
            services.append("mssql")

        for service in services:
            service_patterns = self.store.get_credential_patterns(service)
            # Dedupe by (service, username, password) tuple
            seen = {(p.service, p.username, p.password) for p in patterns}
            for p in service_patterns[:3]:
                key = (p.service, p.username, p.password)
                if key not in seen:
                    patterns.append(p)
                    seen.add(key)

        return patterns

    def _target_similarity(self, target1: str, target2: str) -> float:
        """Calculate similarity between two targets."""
        # Same target
        if target1 == target2:
            return 1.0
        
        # Same network prefix
        net1 = self._get_network_prefix(target1)
        net2 = self._get_network_prefix(target2)
        if net1 and net1 == net2:
            return 0.7
        
        # Both in private ranges
        if self._is_private(target1) and self._is_private(target2):
            return 0.3
        
        return 0.0

    def _get_network_prefix(self, target: str) -> str:
        """Get network prefix (e.g., 192.168.1 for 192.168.1.50)."""
        parts = target.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3])
        return ""

    def _is_private(self, target: str) -> bool:
        """Check if target is in private IP range."""
        try:
            parts = list(map(int, target.split(".")))
            if len(parts) == 4:
                return (parts[0] == 10) or \
                       (parts[0] == 172 and 16 <= parts[1] <= 31) or \
                       (parts[0] == 192 and parts[1] == 168)
        except ValueError:
            pass
        return False

    def _generate_summary(self, context: RetrievedContext) -> str:
        """Generate human-readable summary of retrieved context."""
        lines = []
        
        if context.relevant_sessions:
            lines.append(f"Found {len(context.relevant_sessions)} relevant past session(s)")
            for s in context.relevant_sessions[:3]:
                lines.append(f"  - {s.target} ({len(s.high_signal_facts)} facts, {len(s.critical_findings)} critical)")
        
        if context.finding_patterns:
            lines.append(f"Loaded {len(context.finding_patterns)} relevant finding pattern(s)")
            for p in context.finding_patterns[:3]:
                lines.append(f"  - {p.pattern_type}: {p.description} (seen {p.seen_count}x)")
        
        if context.target_profile:
            lines.append(f"Target profile: {context.target_profile.target_type} ({context.target_profile.assessment_count} assessments)")
        
        if context.tool_recommendations:
            lines.append(f"Tool recommendations: {len(context.tool_recommendations)}")
            for t in context.tool_recommendations[:3]:
                lines.append(f"  - {t.tool_name}: {t.success_rate:.0%} success rate")
        
        if context.cve_knowledge:
            lines.append(f"CVE knowledge: {len(context.cve_knowledge)}")
        
        if context.credential_patterns:
            lines.append(f"Credential patterns: {len(context.credential_patterns)}")
        
        return "\n".join(lines) if lines else "No relevant memory found"


# Global retriever instance
memory_retriever = MemoryRetriever()