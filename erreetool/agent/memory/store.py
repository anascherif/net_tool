"""
Memory store - persistent JSONL storage for agent memory.

Provides append-only storage with indexing for fast retrieval.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Optional
from collections import defaultdict

from erreetool.agent.memory.schema import (
    MemoryEntry,
    MemoryType,
    SessionSummary,
    FindingPattern,
    ToolEffectiveness,
    TargetProfile,
    CVEKnowledge,
    CredentialPattern,
    generate_entry_id,
    ConfidenceLevel,
)


class MemoryStore:
    """
    Persistent memory store using JSONL files.
    
    Stores memory entries by type in separate files for efficient querying.
    Maintains in-memory indexes for fast lookups.
    """

    # File names for each memory type
    TYPE_FILES = {
        MemoryType.SESSION_SUMMARY: "sessions.jsonl",
        MemoryType.FINDING_PATTERN: "patterns.jsonl",
        MemoryType.TOOL_EFFECTIVENESS: "tool_effectiveness.jsonl",
        MemoryType.TARGET_PROFILE: "target_profiles.jsonl",
        MemoryType.CVE_KNOWLEDGE: "cve_knowledge.jsonl",
        MemoryType.CREDENTIAL_PATTERN: "credential_patterns.jsonl",
    }

    def __init__(self, memory_dir: Path = None):
        self.memory_dir = memory_dir or Path.cwd() / "erreetool-memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)

        # In-memory caches
        self._entries: dict[str, MemoryEntry] = {}
        self._by_type: dict[MemoryType, list[MemoryEntry]] = defaultdict(list)
        self._by_tag: dict[str, list[MemoryEntry]] = defaultdict(list)
        self._loaded = False

    def _get_file_path(self, memory_type: MemoryType) -> Path:
        """Get file path for a memory type."""
        return self.memory_dir / self.TYPE_FILES.get(memory_type, f"{memory_type.value}.jsonl")

    def load(self, force: bool = False) -> int:
        """Load all memory entries from disk."""
        if self._loaded and not force:
            return len(self._entries)

        self._entries.clear()
        self._by_type.clear()
        self._by_tag.clear()
        self._loaded = False

        total = 0
        for mem_type, filename in self.TYPE_FILES.items():
            filepath = self.memory_dir / filename
            if not filepath.exists():
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            entry = MemoryEntry.from_dict(data)
                            self._add_to_index(entry)
                            total += 1
                        except Exception:
                            continue
            except Exception:
                continue

        self._loaded = True
        return total

    def _add_to_index(self, entry: MemoryEntry):
        """Add entry to in-memory indexes."""
        self._entries[entry.entry_id] = entry
        self._by_type[entry.memory_type].append(entry)
        for tag in entry.tags:
            self._by_tag[tag].append(entry)

    def _write_entry(self, entry: MemoryEntry):
        """Append entry to its type file."""
        filepath = self._get_file_path(entry.memory_type)
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

    def add(self, entry: MemoryEntry) -> MemoryEntry:
        """Add a new memory entry."""
        self._add_to_index(entry)
        self._write_entry(entry)
        return entry

    def add_session_summary(self, summary: SessionSummary) -> MemoryEntry:
        """Add a session summary."""
        entry = MemoryEntry(
            entry_id=generate_entry_id("session"),
            memory_type=MemoryType.SESSION_SUMMARY,
            content=summary.to_dict(),
            created_at=time.time(),
            updated_at=time.time(),
            tags=["session", summary.target] + summary.skills_run,
        )
        return self.add(entry)

    def add_finding_pattern(self, pattern: FindingPattern) -> MemoryEntry:
        """Add or update a finding pattern."""
        # Check if similar pattern exists
        existing = self.find_similar_pattern(pattern)
        if existing:
            # Update existing
            existing.content["seen_count"] = existing.content.get("seen_count", 0) + 1
            existing.content["last_seen"] = time.time()
            # Merge indicators
            existing_indicators = set(existing.content.get("indicators", []))
            existing_indicators.update(pattern.indicators)
            existing.content["indicators"] = list(existing_indicators)
            # Merge example targets
            existing_targets = set(existing.content.get("example_targets", []))
            existing_targets.update(pattern.example_targets)
            existing.content["example_targets"] = list(existing_targets)
            existing.updated_at = time.time()
            self._rewrite_type_file(MemoryType.FINDING_PATTERN)
            return existing

        entry = MemoryEntry(
            entry_id=generate_entry_id("pattern"),
            memory_type=MemoryType.FINDING_PATTERN,
            content=pattern.to_dict(),
            created_at=time.time(),
            updated_at=time.time(),
            tags=["pattern", pattern.pattern_type] + pattern.tags,
        )
        return self.add(entry)

    def find_similar_pattern(self, pattern: FindingPattern) -> Optional[MemoryEntry]:
        """Find a similar existing pattern."""
        for entry in self._by_type.get(MemoryType.FINDING_PATTERN, []):
            if entry.content.get("pattern_type") == pattern.pattern_type:
                # Check indicator overlap
                existing_indicators = set(entry.content.get("indicators", []))
                new_indicators = set(pattern.indicators)
                if existing_indicators & new_indicators:
                    # Significant overlap
                    overlap = len(existing_indicators & new_indicators)
                    total = len(existing_indicators | new_indicators)
                    if overlap / total > 0.5:  # 50% Jaccard similarity
                        return entry
        return None

    def add_tool_effectiveness(self, effectiveness: ToolEffectiveness) -> MemoryEntry:
        """Add or update tool effectiveness."""
        key = f"{effectiveness.tool_name}:{effectiveness.context_hash}"
        existing = None
        for entry in self._by_type.get(MemoryType.TOOL_EFFECTIVENESS, []):
            if entry.content.get("tool_name") == effectiveness.tool_name and \
               entry.content.get("context_hash") == effectiveness.context_hash:
                existing = entry
                break

        if existing:
            existing.content["runs"] = existing.content.get("runs", 0) + effectiveness.runs
            existing.content["successes"] = existing.content.get("successes", 0) + effectiveness.successes
            existing.content["findings_generated"] = existing.content.get("findings_generated", 0) + effectiveness.findings_generated
            existing.content["avg_duration"] = (
                (existing.content.get("avg_duration", 0) * (existing.content.get("runs", 1) - effectiveness.runs)
                 + effectiveness.avg_duration * effectiveness.runs
                ) / existing.content["runs"]
            )
            existing.content["last_used"] = time.time()
            existing.content["notes"] = effectiveness.notes
            existing.updated_at = time.time()
            self._rewrite_type_file(MemoryType.TOOL_EFFECTIVENESS)
            return existing

        entry = MemoryEntry(
            entry_id=generate_entry_id("tool"),
            memory_type=MemoryType.TOOL_EFFECTIVENESS,
            content=effectiveness.to_dict(),
            created_at=time.time(),
            updated_at=time.time(),
            tags=["tool", effectiveness.tool_name, effectiveness.context_hash],
        )
        return self.add(entry)

    def add_target_profile(self, profile: TargetProfile) -> MemoryEntry:
        """Add or update target profile."""
        existing = None
        for entry in self._by_type.get(MemoryType.TARGET_PROFILE, []):
            if entry.content.get("target_type") == profile.target_type:
                existing = entry
                break

        if existing:
            # Merge data
            for field in ["common_ports", "common_technologies", "common_vulns",
                          "recommended_skills", "recommended_tools"]:
                existing_set = set(existing.content.get(field, []))
                existing_set.update(getattr(profile, field))
                existing.content[field] = list(existing_set)
            existing.content["assessment_count"] = existing.content.get("assessment_count", 0) + 1
            existing.content["last_assessed"] = time.time()
            existing.updated_at = time.time()
            self._rewrite_type_file(MemoryType.TARGET_PROFILE)
            return existing

        entry = MemoryEntry(
            entry_id=generate_entry_id("profile"),
            memory_type=MemoryType.TARGET_PROFILE,
            content=profile.to_dict(),
            created_at=time.time(),
            updated_at=time.time(),
            tags=["profile", profile.target_type],
        )
        return self.add(entry)

    def add_cve_knowledge(self, cve: CVEKnowledge) -> MemoryEntry:
        """Add or update CVE knowledge."""
        existing = None
        for entry in self._by_type.get(MemoryType.CVE_KNOWLEDGE, []):
            if entry.content.get("cve_id") == cve.cve_id:
                existing = entry
                break

        if existing:
            # Update with new info
            for field in ["affected_technologies", "detection_methods", "seen_in_targets"]:
                existing_set = set(existing.content.get(field, []))
                existing_set.update(getattr(cve, field))
                existing.content[field] = list(existing_set)
            # Update other fields if provided
            if cve.exploit_available:
                existing.content["exploit_available"] = True
            if cve.cvss_score > existing.content.get("cvss_score", 0):
                existing.content["cvss_score"] = cve.cvss_score
            if cve.mitigation_notes:
                existing.content["mitigation_notes"] = cve.mitigation_notes
            existing.content["confidence"] = max(
                ConfidenceLevel(existing.content.get("confidence", "low")).value,
                cve.confidence.value,
                key=lambda x: ["low", "medium", "high", "verified"].index(x)
            )
            existing.content["last_updated"] = time.time()
            existing.updated_at = time.time()
            self._rewrite_type_file(MemoryType.CVE_KNOWLEDGE)
            return existing

        entry = MemoryEntry(
            entry_id=generate_entry_id("cve"),
            memory_type=MemoryType.CVE_KNOWLEDGE,
            content=cve.to_dict(),
            created_at=time.time(),
            updated_at=time.time(),
            tags=["cve", cve.cve_id] + cve.affected_technologies,
        )
        return self.add(entry)

    def add_credential_pattern(self, pattern: CredentialPattern) -> MemoryEntry:
        """Add or update credential pattern."""
        existing = None
        for entry in self._by_type.get(MemoryType.CREDENTIAL_PATTERN, []):
            if (entry.content.get("service") == pattern.service and
                entry.content.get("username") == pattern.username and
                entry.content.get("password") == pattern.password):
                existing = entry
                break

        if existing:
            existing.content["attempted_count"] = existing.content.get("attempted_count", 0) + pattern.attempted_count
            existing.content["success_count"] = existing.content.get("success_count", 0) + pattern.success_count
            existing.content["last_tried"] = time.time()
            existing.updated_at = time.time()
            self._rewrite_type_file(MemoryType.CREDENTIAL_PATTERN)
            return existing

        entry = MemoryEntry(
            entry_id=generate_entry_id("cred"),
            memory_type=MemoryType.CREDENTIAL_PATTERN,
            content=pattern.to_dict(),
            created_at=time.time(),
            updated_at=time.time(),
            tags=["credential", pattern.service, pattern.context],
        )
        return self.add(entry)

    def _rewrite_type_file(self, memory_type: MemoryType):
        """Rewrite entire type file from memory (for updates)."""
        filepath = self._get_file_path(memory_type)
        entries = self._by_type.get(memory_type, [])
        with open(filepath, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry.to_dict()) + "\n")

    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """Get entry by ID."""
        if not self._loaded:
            self.load()
        return self._entries.get(entry_id)

    def get_by_type(self, memory_type: MemoryType, limit: int = 100) -> list[MemoryEntry]:
        """Get entries by type, most recent first."""
        if not self._loaded:
            self.load()
        entries = self._by_type.get(memory_type, [])
        return sorted(entries, key=lambda e: e.updated_at, reverse=True)[:limit]

    def get_by_tag(self, tag: str, limit: int = 100) -> list[MemoryEntry]:
        """Get entries by tag."""
        if not self._loaded:
            self.load()
        entries = self._by_tag.get(tag, [])
        return sorted(entries, key=lambda e: e.updated_at, reverse=True)[:limit]

    def search(self, query: str, memory_type: MemoryType = None, limit: int = 50) -> list[MemoryEntry]:
        """Simple keyword search across memory entries."""
        if not self._loaded:
            self.load()
        
        query_lower = query.lower()
        results = []
        
        entries = self._by_type.get(memory_type, []) if memory_type else self._entries.values()
        
        for entry in entries:
            # Search in tags
            if any(query_lower in tag.lower() for tag in entry.tags):
                results.append(entry)
                continue
            # Search in content (shallow)
            content_str = json.dumps(entry.content).lower()
            if query_lower in content_str:
                results.append(entry)
                if len(results) >= limit:
                    break
        
        return sorted(results, key=lambda e: e.updated_at, reverse=True)[:limit]

    def get_recent_sessions(self, limit: int = 10) -> list[SessionSummary]:
        """Get recent session summaries."""
        entries = self.get_by_type(MemoryType.SESSION_SUMMARY, limit)
        return [SessionSummary.from_dict(e.content) for e in entries]

    def get_patterns_for_target(self, target: str, pattern_type: str = None) -> list[FindingPattern]:
        """Get finding patterns relevant to a target."""
        if not self._loaded:
            self.load()
        
        results = []
        for entry in self._by_type.get(MemoryType.FINDING_PATTERN, []):
            pattern = FindingPattern.from_dict(entry.content)
            if pattern_type and pattern.pattern_type != pattern_type:
                continue
            # Check if target matches any example target or indicator
            for example in pattern.example_targets:
                if target in example or example in target:
                    results.append(pattern)
                    break
            # Check indicators
            for indicator in pattern.indicators:
                if indicator.lower() in target.lower():
                    results.append(pattern)
                    break
        
        return sorted(results, key=lambda p: p.seen_count, reverse=True)

    def get_tool_recommendations(self, context_hash: str) -> list[ToolEffectiveness]:
        """Get tool effectiveness for a context."""
        if not self._loaded:
            self.load()
        
        results = []
        for entry in self._by_type.get(MemoryType.TOOL_EFFECTIVENESS, []):
            if entry.content.get("context_hash") == context_hash:
                results.append(ToolEffectiveness.from_dict(entry.content))
        
        return sorted(results, key=lambda t: t.success_rate, reverse=True)

    def get_cve_knowledge(self, cve_id: str) -> Optional[CVEKnowledge]:
        """Get knowledge about a specific CVE."""
        if not self._loaded:
            self.load()
        
        for entry in self._by_type.get(MemoryType.CVE_KNOWLEDGE, []):
            if entry.content.get("cve_id") == cve_id:
                return CVEKnowledge.from_dict(entry.content)
        return None

    def get_credential_patterns(self, service: str = None) -> list[CredentialPattern]:
        """Get credential patterns, optionally filtered by service."""
        if not self._loaded:
            self.load()
        
        results = []
        for entry in self._by_type.get(MemoryType.CREDENTIAL_PATTERN, []):
            pattern = CredentialPattern.from_dict(entry.content)
            if service and pattern.service != service:
                continue
            results.append(pattern)
        
        return sorted(results, key=lambda p: p.success_rate, reverse=True)

    def get_stats(self) -> dict:
        """Get memory store statistics."""
        if not self._loaded:
            self.load()
        
        return {
            "total_entries": len(self._entries),
            "by_type": {mt.value: len(entries) for mt, entries in self._by_type.items()},
            "tags": {tag: len(entries) for tag, entries in self._by_tag.items()},
            "memory_dir": str(self.memory_dir),
        }

    def clear(self, memory_type: MemoryType = None):
        """Clear memory (all or specific type)."""
        if memory_type:
            # Clear specific type
            for entry in self._by_type.get(memory_type, []):
                self._entries.pop(entry.entry_id, None)
                for tag in entry.tags:
                    if entry in self._by_tag[tag]:
                        self._by_tag[tag].remove(entry)
            self._by_type[memory_type].clear()
            # Rewrite file
            filepath = self._get_file_path(memory_type)
            if filepath.exists():
                filepath.unlink()
        else:
            # Clear all
            self._entries.clear()
            self._by_type.clear()
            self._by_tag.clear()
            for filepath in self.memory_dir.glob("*.jsonl"):
                filepath.unlink()


# Global memory store instance
memory_store = MemoryStore()