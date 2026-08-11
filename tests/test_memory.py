"""Unit tests for memory system: schema, store, retriever."""

import tempfile
import time
from pathlib import Path

import pytest

from erreetool.agent.memory.schema import (
    MemoryEntry,
    MemoryType,
    SessionSummary,
    FindingPattern,
    ToolEffectiveness,
    TargetProfile,
    CVEKnowledge,
    CredentialPattern,
    ConfidenceLevel,
    generate_entry_id,
)
from erreetool.agent.memory.store import MemoryStore
from erreetool.agent.memory.retriever import MemoryRetriever, RetrievedContext
from erreetool.agent.state import AgentState, AgentContext, EvidenceType


# ===== Fixtures =====

@pytest.fixture
def temp_memory_dir():
    """Create a temp directory for memory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def store(temp_memory_dir):
    """Create a fresh MemoryStore for each test."""
    return MemoryStore(memory_dir=temp_memory_dir)


@pytest.fixture
def retriever(store):
    """Create a MemoryRetriever for each test."""
    return MemoryRetriever(store=store)


@pytest.fixture
def state():
    """Create a fresh AgentState for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state = AgentState(output_dir=Path(tmpdir))
        state.context.target = "192.168.1.100"
        yield state


# ===== Schema Tests =====

def test_generate_entry_id():
    """Test entry ID generation."""
    id1 = generate_entry_id("test")
    id2 = generate_entry_id("test")
    assert id1 != id2
    assert id1.startswith("test_")
    assert len(id1) > 10


def test_session_summary_serialization():
    """Test SessionSummary to/from dict."""
    summary = SessionSummary(
        session_id="test_123",
        target="10.0.0.1",
        timestamp=time.time(),
        duration=60.0,
        skills_run=["nmap-recon", "web-enum"],
        tools_used=["nmap", "whatweb"],
        high_signal_facts=["Port 80 open", "CVE-2021-44228"],
        critical_findings=["CVE-2021-44228"],
        high_findings=["Port 80 open"],
        success=True,
    )
    data = summary.to_dict()
    assert data["session_id"] == "test_123"
    assert data["target"] == "10.0.0.1"
    
    restored = SessionSummary.from_dict(data)
    assert restored.session_id == summary.session_id
    assert restored.target == summary.target
    assert restored.skills_run == summary.skills_run


def test_finding_pattern_serialization():
    """Test FindingPattern to/from dict."""
    pattern = FindingPattern(
        pattern_id="pat_1",
        pattern_type="port",
        description="Common web ports",
        indicators=["80", "443", "8080"],
        associated_findings=["Port 80 open", "Port 443 open"],
        seen_count=5,
        last_seen=time.time(),
        confidence=ConfidenceLevel.HIGH,
        example_targets=["192.168.1.1"],
        tags=["web", "port"],
    )
    data = pattern.to_dict()
    assert data["pattern_type"] == "port"
    assert data["confidence"] == "high"
    
    restored = FindingPattern.from_dict(data)
    assert restored.pattern_type == pattern.pattern_type
    assert restored.confidence == ConfidenceLevel.HIGH


def test_tool_effectiveness():
    """Test ToolEffectiveness calculations."""
    eff = ToolEffectiveness(
        tool_name="nmap",
        context_hash="abc123",
        runs=10,
        successes=8,
        findings_generated=5,
    )
    assert eff.success_rate == 0.8


# ===== Store Tests =====

def test_store_add_and_get_session(store):
    """Test adding and retrieving session summary."""
    summary = SessionSummary(
        session_id="sess_1",
        target="10.0.0.1",
        timestamp=time.time(),
        duration=30.0,
        skills_run=["quick-triage"],
    )
    entry = store.add_session_summary(summary)
    
    assert entry.memory_type == MemoryType.SESSION_SUMMARY
    assert "session" in entry.tags
    assert "10.0.0.1" in entry.tags
    
    # Retrieve
    sessions = store.get_recent_sessions(10)
    assert len(sessions) == 1
    assert sessions[0].session_id == "sess_1"


def test_store_finding_pattern_deduplication(store):
    """Test that similar finding patterns are merged."""
    pattern1 = FindingPattern(
        pattern_id="pat_1",
        pattern_type="port",
        description="Web ports",
        indicators=["80", "443", "8080"],
        seen_count=1,
        last_seen=time.time(),
        confidence=ConfidenceLevel.MEDIUM,
        example_targets=["10.0.0.1"],
    )
    store.add_finding_pattern(pattern1)
    
    # Add similar pattern - should merge (high indicator overlap)
    pattern2 = FindingPattern(
        pattern_id="pat_2",
        pattern_type="port",
        description="Web ports",
        indicators=["80", "443", "8080"],  # Same indicators - 100% overlap
        seen_count=1,
        last_seen=time.time(),
        confidence=ConfidenceLevel.MEDIUM,
        example_targets=["10.0.0.2"],
    )
    entry = store.add_finding_pattern(pattern2)
    
    # Should have merged (same entry_id)
    patterns = store.get_by_type(MemoryType.FINDING_PATTERN)
    assert len(patterns) == 1
    assert patterns[0].content["seen_count"] == 2
    assert "10.0.0.2" in patterns[0].content["example_targets"]


def test_store_tool_effectiveness(store):
    """Test tool effectiveness tracking."""
    eff = ToolEffectiveness(
        tool_name="nmap",
        context_hash="web_nginx",
        runs=1,
        successes=1,
        findings_generated=3,
        avg_duration=2.5,
        last_used=time.time(),
    )
    store.add_tool_effectiveness(eff)
    
    # Add another run
    eff2 = ToolEffectiveness(
        tool_name="nmap",
        context_hash="web_nginx",
        runs=1,
        successes=0,
        findings_generated=0,
        avg_duration=3.0,
        last_used=time.time(),
    )
    store.add_tool_effectiveness(eff2)
    
    # Check merged
    recs = store.get_tool_recommendations("web_nginx")
    assert len(recs) == 1
    assert recs[0].runs == 2
    assert recs[0].successes == 1
    assert recs[0].success_rate == 0.5


def test_store_cve_knowledge(store):
    """Test CVE knowledge tracking."""
    cve = CVEKnowledge(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        affected_technologies=["log4j", "java"],
        exploit_available=True,
        cvss_score=10.0,
        confidence=ConfidenceLevel.VERIFIED,
    )
    store.add_cve_knowledge(cve)
    
    retrieved = store.get_cve_knowledge("CVE-2021-44228")
    assert retrieved is not None
    assert retrieved.cve_id == "CVE-2021-44228"
    assert retrieved.exploit_available is True
    assert retrieved.cvss_score == 10.0


def test_store_credential_patterns(store):
    """Test credential pattern tracking."""
    pattern = CredentialPattern(
        pattern_id="cred_1",
        service="ssh",
        username="admin",
        password="admin",
        context="default",
        success_count=1,
        attempted_count=5,
    )
    store.add_credential_pattern(pattern)
    
    patterns = store.get_credential_patterns("ssh")
    assert len(patterns) == 1
    assert patterns[0].username == "admin"
    assert patterns[0].success_rate == 0.2


def test_store_search(store):
    """Test memory search."""
    summary = SessionSummary(
        session_id="sess_search",
        target="192.168.50.10",
        timestamp=time.time(),
        duration=10.0,
        high_signal_facts=["Port 22 open: ssh", "CVE-2021-44228"],
    )
    store.add_session_summary(summary)
    
    # Search by target
    results = store.search("192.168.50")
    assert len(results) == 1
    
    # Search by CVE
    results = store.search("CVE-2021")
    assert len(results) == 1
    
    # Search non-existent
    results = store.search("nonexistent")
    assert len(results) == 0


def test_store_clear(store):
    """Test clearing memory."""
    summary = SessionSummary(
        session_id="sess_clear",
        target="10.0.0.1",
        timestamp=time.time(),
        duration=5.0,
    )
    store.add_session_summary(summary)
    
    assert len(store._entries) == 1
    store.clear(MemoryType.SESSION_SUMMARY)
    assert len(store._entries) == 0
    assert len(store._by_type[MemoryType.SESSION_SUMMARY]) == 0


def test_store_persistence(temp_memory_dir):
    """Test that memory persists across store instances."""
    # Create store and add data
    store1 = MemoryStore(memory_dir=temp_memory_dir)
    summary = SessionSummary(
        session_id="sess_persist",
        target="10.0.0.50",
        timestamp=time.time(),
        duration=5.0,
    )
    store1.add_session_summary(summary)
    
    # Create new store with same dir
    store2 = MemoryStore(memory_dir=temp_memory_dir)
    store2.load()
    
    sessions = store2.get_recent_sessions(10)
    assert len(sessions) == 1
    assert sessions[0].session_id == "sess_persist"


# ===== Retriever Tests =====

def test_retriever_get_context(retriever, state):
    """Test retrieving context for assessment."""
    # Add some past sessions
    for i in range(3):
        summary = SessionSummary(
            session_id=f"sess_{i}",
            target="192.168.1.50",
            timestamp=time.time() - i * 3600,
            duration=30.0,
            skills_run=["quick-triage"],
            high_signal_facts=["Port 80 open", "CVE-2021-44228"],
            critical_findings=["CVE-2021-44228"],
        )
        retriever.store.add_session_summary(summary)
    
    # Add finding pattern with example target that matches
    pattern = FindingPattern(
        pattern_id="pat_web",
        pattern_type="web",
        description="Common web vulns",
        indicators=["80", "443"],
        seen_count=5,
        last_seen=time.time(),
        confidence=ConfidenceLevel.HIGH,
        example_targets=["192.168.1.100"],  # Matches test target
    )
    retriever.store.add_finding_pattern(pattern)
    
    # Get context
    context = retriever.get_context_for_assessment(
        target="192.168.1.100",
        state=state,
    )
    
    assert len(context.relevant_sessions) > 0
    assert len(context.finding_patterns) > 0
    assert "past session" in context.summary.lower() or "pattern" in context.summary.lower()


def test_retriever_target_similarity(retriever):
    """Test target similarity calculation."""
    # Same target
    assert retriever._target_similarity("10.0.0.1", "10.0.0.1") == 1.0
    
    # Same network
    assert retriever._target_similarity("10.0.0.1", "10.0.0.2") == 0.7
    
    # Both private
    assert retriever._target_similarity("192.168.1.1", "10.0.0.1") == 0.3
    
    # Different
    assert retriever._target_similarity("8.8.8.8", "10.0.0.1") == 0.0


def test_retriever_cve_knowledge(retriever, state):
    """Test CVE knowledge retrieval."""
    state.context.high_signal_facts = ["Vulnerability: CVE-2021-44228 found"]
    
    # Add CVE knowledge
    cve = CVEKnowledge(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        exploit_available=True,
    )
    retriever.store.add_cve_knowledge(cve)
    
    context = retriever.get_context_for_assessment("10.0.0.1", state)
    assert len(context.cve_knowledge) == 1
    assert context.cve_knowledge[0].cve_id == "CVE-2021-44228"


def test_retriever_credential_patterns(retriever, state):
    """Test credential pattern retrieval."""
    state.context.high_signal_facts = ["Port 22 open: ssh", "Port 3389 open: rdp"]
    
    # Add patterns
    retriever.store.add_credential_pattern(CredentialPattern(
        pattern_id="ssh_admin",
        service="ssh",
        username="admin",
        password="admin",
        context="default",
    ))
    retriever.store.add_credential_pattern(CredentialPattern(
        pattern_id="rdp_admin",
        service="rdp",
        username="administrator",
        password="password",
        context="default",
    ))
    
    context = retriever.get_context_for_assessment("10.0.0.1", state)
    assert len(context.credential_patterns) >= 1


def test_memory_entry_wrapper(store):
    """Test MemoryEntry wrapper."""
    entry = MemoryEntry(
        entry_id="test_1",
        memory_type=MemoryType.SESSION_SUMMARY,
        content={"test": "data"},
        created_at=time.time(),
        updated_at=time.time(),
        tags=["test", "wrapper"],
    )
    
    assert entry.memory_type == MemoryType.SESSION_SUMMARY
    assert "test" in entry.tags
    
    data = entry.to_dict()
    assert data["memory_type"] == "session_summary"
    
    restored = MemoryEntry.from_dict(data)
    assert restored.entry_id == "test_1"
    assert restored.memory_type == MemoryType.SESSION_SUMMARY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])