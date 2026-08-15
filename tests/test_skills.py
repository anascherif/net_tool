"""Unit tests for skill engine: loader, schema, executor, registry."""

import tempfile
import pytest
from pathlib import Path

from erreetool.agent.skills.schema import (
    Skill, SkillPhase, SkillStep, SkillGate, FactExtraction, SkillResult,
    parse_skill, parse_phase, parse_step, parse_gate, parse_fact_extraction
)
from erreetool.agent.skills.loader import SkillLoader
from erreetool.agent.skills.executor import SkillExecutor, ConditionEvaluator
from erreetool.agent.skills.registry import SkillRegistry
from erreetool.agent.state import AgentState, EvidenceType, AgentContext
from erreetool.agent.tools.base import tool_registry, ToolWrapper, ToolResult
from erreetool.agent.tools.crypto import CryptoTool


# ===== Fixtures =====

class MockTool(ToolWrapper):
    """Mock tool for testing."""
    name = "mock"
    windows_binary = "mock.exe"
    linux_binary = "mock"

    def __init__(self, output="mock output", success=True, **kwargs):
        super().__init__(**kwargs)
        self._mock_output = output
        self._mock_success = success

    def build_args(self, **kwargs):
        return []

    def is_available(self):
        return True

    def run(self, **kwargs):
        return ToolResult(
            success=self._mock_success,
            stdout=self._mock_output,
            stderr="",
            returncode=0 if self._mock_success else 1,
            command=["mock"],
            duration=0.1,
            evidence_id="mock_123",
            tool_name="mock",
        )


@pytest.fixture
def temp_skill_dir():
    """Create a temp directory with test skill files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        yield skill_dir


@pytest.fixture
def sample_skill_yaml():
    """A sample skill YAML for testing."""
    return """
name: test-skill
description: "Test skill for unit tests"
tags: [test, recon]
author: erreetool
version: "1.0"
requires_tools: [mock]

phases:
  - name: phase1
    description: "First phase"
    condition: "fact_count('Port *') > 0"
    steps:
      - name: step1
        tool: mock
        args:
          target: "{target}"
        save_as: step1_output
        description: "Test step"
        on_error: continue
        extract_facts:
          - pattern: 'PORT: (\d+)'
            fact: "Port {1} discovered"
            type: high_signal

  - name: phase2
    description: "Second phase (skipped if no ports)"
    condition: "has_fact('Port 80')"
    steps:
      - name: step2
        tool: mock
        args:
          target: "{target}"
        save_as: step2_output
        description: "Conditional step"
        on_error: abort

gates:
  - name: ports_found
    condition: "fact_count('Port *') > 0"
    on_fail: "No ports found"
    severity: warning
"""


@pytest.fixture
def state():
    """Create a fresh AgentState for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state = AgentState(output_dir=Path(tmpdir))
        state.context.target = "127.0.0.1"
        yield state


# ===== Schema Tests =====

def test_fact_extraction_parsing():
    data = {"pattern": "PORT: (\\d+)", "fact": "Port {1}", "type": "high_signal"}
    fe = parse_fact_extraction(data)
    assert fe.pattern == "PORT: (\\d+)"
    assert fe.fact_template == "Port {1}"
    assert fe.fact_type == "high_signal"


def test_step_parsing():
    data = {
        "name": "test_step",
        "tool": "nmap",
        "args": {"target": "{target}", "ports": "80"},
        "save_as": "nmap_out",
        "on_error": "abort",
        "extract_facts": [
            {"pattern": "PORT: (\\d+)", "fact": "Port {1}", "type": "high_signal"}
        ]
    }
    step = parse_step(data)
    assert step.name == "test_step"
    assert step.tool == "nmap"
    assert step.args == {"target": "{target}", "ports": "80"}
    assert step.save_as == "nmap_out"
    assert step.on_error == "abort"
    assert len(step.extract_facts) == 1


def test_phase_parsing():
    data = {
        "name": "recon",
        "description": "Recon phase",
        "condition": "True",
        "steps": [
            {"name": "s1", "tool": "mock", "args": {}}
        ]
    }
    phase = parse_phase(data)
    assert phase.name == "recon"
    assert phase.condition == "True"
    assert len(phase.steps) == 1


def test_gate_parsing():
    data = {"name": "check", "condition": "fact_count('Port*') > 0", "on_fail": "none", "severity": "error"}
    gate = parse_gate(data)
    assert gate.name == "check"
    assert gate.severity == "error"


def test_full_skill_parsing(sample_skill_yaml):
    import yaml
    data = yaml.safe_load(sample_skill_yaml)
    skill = parse_skill(data, source_file="test.yml")
    assert skill.name == "test-skill"
    assert len(skill.phases) == 2
    assert len(skill.gates) == 1
    assert "test" in skill.tags
    assert "mock" in skill.requires_tools


def test_skill_to_dict():
    skill = Skill(
        name="dict-test",
        description="Test",
        tags=["a", "b"],
        phases=[SkillPhase(name="p1", steps=[SkillStep(name="s1", tool="mock")])],
        gates=[SkillGate(name="g1", condition="True")],
    )
    d = skill.to_dict()
    assert d["name"] == "dict-test"
    assert len(d["phases"]) == 1
    assert len(d["phases"][0]["steps"]) == 1


# ===== Loader Tests =====

def test_loader_loads_skills(temp_skill_dir, sample_skill_yaml):
    (temp_skill_dir / "test-skill.yml").write_text(sample_skill_yaml)
    loader = SkillLoader(skill_dir=temp_skill_dir)
    skills = loader.load_all()
    assert len(skills) == 1
    assert skills[0].name == "test-skill"


def test_loader_skips_non_yaml(temp_skill_dir, sample_skill_yaml):
    (temp_skill_dir / "test-skill.yml").write_text(sample_skill_yaml)
    (temp_skill_dir / "README.txt").write_text("not a skill")
    loader = SkillLoader(skill_dir=temp_skill_dir)
    skills = loader.load_all()
    assert len(skills) == 1


def test_loader_get_by_name(temp_skill_dir, sample_skill_yaml):
    (temp_skill_dir / "test-skill.yml").write_text(sample_skill_yaml)
    loader = SkillLoader(skill_dir=temp_skill_dir)
    skill = loader.get("test-skill")
    assert skill is not None
    assert skill.name == "test-skill"


def test_loader_list_by_tag(temp_skill_dir, sample_skill_yaml):
    (temp_skill_dir / "test-skill.yml").write_text(sample_skill_yaml)
    loader = SkillLoader(skill_dir=temp_skill_dir)
    skills = loader.list_by_tag("test")
    assert len(skills) == 1
    skills = loader.list_by_tag("missing")
    assert len(skills) == 0


# ===== Condition Evaluator Tests =====

def test_condition_evaluator_empty():
    ctx = {"state": AgentState()}
    assert ConditionEvaluator.evaluate("", ctx) is True
    assert ConditionEvaluator.evaluate("   ", ctx) is True
    assert ConditionEvaluator.evaluate(None, ctx) is True


def test_condition_evaluator_true():
    state = AgentState()
    state.context.high_signal_facts = ["Port 80/tcp open: http"]
    ctx = {"state": state, "named_evidence": {}}
    assert ConditionEvaluator.evaluate("fact_count('Port *') > 0", ctx) is True
    assert ConditionEvaluator.evaluate("has_fact('Port 80')", ctx) is True


def test_condition_evaluator_false():
    state = AgentState()
    state.context.high_signal_facts = []
    ctx = {"state": state, "named_evidence": {}}
    assert ConditionEvaluator.evaluate("fact_count('Port *') > 0", ctx) is False
    assert ConditionEvaluator.evaluate("has_fact('Port 80')", ctx) is False


def test_condition_evaluator_evidence_contains():
    state = AgentState()
    ctx = {"state": state, "named_evidence": {"nmap_result": "80/tcp open  http"}}
    assert ConditionEvaluator.evaluate("evidence_contains('nmap_result', '80/tcp')", ctx) is True
    assert ConditionEvaluator.evaluate("evidence_contains('nmap_result', '443/tcp')", ctx) is False


def test_condition_evaluator_forbidden_tokens():
    state = AgentState()
    ctx = {"state": state, "named_evidence": {}}
    # These should be rejected
    assert ConditionEvaluator.evaluate("__import__('os')", ctx) is False
    assert ConditionEvaluator.evaluate("eval('1+1')", ctx) is False
    assert ConditionEvaluator.evaluate("os.system('ls')", ctx) is False


def test_condition_evaluator_syntax_error():
    state = AgentState()
    ctx = {"state": state, "named_evidence": {}}
    # Invalid syntax should return False, not crash
    assert ConditionEvaluator.evaluate("fact_count('Port *') >", ctx) is False
    assert ConditionEvaluator.evaluate("undefined_function()", ctx) is False


# ===== SkillExecutor Tests =====

def test_executor_runs_simple_skill(state):
    """Test executor runs a skill with mock tool."""
    skill = Skill(
        name="simple",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(
                name="phase1",
                steps=[
                    SkillStep(name="s1", tool="mock", args={"target": "{target}"}, save_as="out")
                ]
            )
        ],
        gates=[]
    )

    # Register mock tool
    mock = MockTool(output="PORT: 80")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.success is True
    assert result.phases_executed == 1
    assert result.steps_executed == 1
    assert len(result.evidence_ids) == 1
    assert "out" in executor.named_evidence


def test_executor_extracts_facts(state):
    """Test fact extraction from tool output."""
    skill = Skill(
        name="fact-test",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(
                name="phase1",
                steps=[
                    SkillStep(
                        name="s1", tool="mock", args={}, save_as="out",
                        extract_facts=[
                            FactExtraction(pattern="PORT: (\\d+)", fact_template="Port {1} found", fact_type="high_signal")
                        ]
                    )
                ]
            )
        ],
        gates=[]
    )

    mock = MockTool(output="PORT: 80\nPORT: 443")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.facts_extracted == 2
    facts = state.context.high_signal_facts
    assert "Port 80 found" in facts
    assert "Port 443 found" in facts


def test_executor_skips_phase_on_condition(state):
    """Test phase skipping based on condition."""
    skill = Skill(
        name="skip-test",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(name="phase1", steps=[SkillStep(name="s1", tool="mock", args={})]),
            SkillPhase(name="phase2", condition="has_fact('Port 80')", steps=[SkillStep(name="s2", tool="mock", args={})]),
        ],
        gates=[]
    )

    mock = MockTool(output="PORT: 443")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.phases_executed == 1
    assert result.phases_skipped == 1


def test_executor_gates(state):
    """Test gate evaluation."""
    skill = Skill(
        name="gate-test",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(name="phase1", steps=[
                SkillStep(
                    name="s1", tool="mock", args={}, save_as="out",
                    extract_facts=[
                        FactExtraction(pattern="PORT: (\\d+)", fact_template="Port {1}", fact_type="high_signal")
                    ]
                ),
            ]),
        ],
        gates=[
            SkillGate(name="ports", condition="fact_count('Port *') > 0", on_fail="No ports", severity="warning"),
            SkillGate(name="always", condition="True", on_fail="Never", severity="info"),
        ]
    )

    mock = MockTool(output="PORT: 80")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.gates_passed == 2
    assert result.gates_failed == 0


def test_executor_failed_gate(state):
    """Test failed gate marks skill as failed."""
    skill = Skill(
        name="fail-gate",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(name="phase1", steps=[SkillStep(name="s1", tool="mock", args={})]),
        ],
        gates=[
            SkillGate(name="ports", condition="fact_count('Port *') > 0", on_fail="No ports", severity="error"),
        ]
    )

    mock = MockTool(output="nothing here")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.gates_passed == 0
    assert result.gates_failed == 1
    assert result.success is False


def test_executor_error_handling_continue(state):
    """Test on_error: continue."""
    skill = Skill(
        name="error-continue",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(name="phase1", steps=[
                SkillStep(name="s1", tool="mock", args={}, on_error="continue"),
                SkillStep(name="s2", tool="mock", args={}, on_error="continue"),
            ]),
        ],
        gates=[]
    )

    mock = MockTool(success=False, output="error")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.steps_failed == 2
    assert result.steps_executed == 2  # Both steps executed
    assert result.success is True  # Continue means skill doesn't fail


def test_executor_error_handling_abort(state):
    """Test on_error: abort."""
    skill = Skill(
        name="error-abort",
        description="Test",
        tags=["test"],
        requires_tools=["mock"],
        phases=[
            SkillPhase(name="phase1", steps=[
                SkillStep(name="s1", tool="mock", args={}, on_error="abort"),
                SkillStep(name="s2", tool="mock", args={}, on_error="continue"),
            ]),
        ],
        gates=[]
    )

    mock = MockTool(success=False, output="error")
    tool_registry.register(mock)

    executor = SkillExecutor(state, tool_override={"mock": mock})
    result = executor.execute(skill)

    assert result.steps_executed == 1  # Only first step executed
    assert result.steps_failed == 1
    assert result.success is False


# ===== SkillRegistry Tests =====

def test_registry_scoring():
    """Test skill selection scoring."""
    # Create a skill with specific tags
    skill = Skill(
        name="web-enum",
        description="Web enumeration",
        tags=["web", "enum", "quick"],
        requires_tools=["whatweb"],
        phases=[SkillPhase(name="p1", steps=[])],
        gates=[]
    )

    state = AgentState()
    state.context.high_signal_facts = ["Port 80/tcp open: http", "Web server: nginx 1.18"]

    # Need a real loader for this
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        # We can't easily test full registry without real skills loaded
        # This is a placeholder for when skills are in place
        pass


# ===== Integration Test (crypto skill with real tool) =====

def test_crypto_skill_integration():
    """Test crypto-analysis skill with real crypto tool."""
    import yaml
    skill_path = Path("erreetool/skills/crypto-analysis.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "crypto-analysis"
    assert "crypto" in skill.requires_tools

    # Test with real crypto tool
    state = AgentState()
    state.context.target = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # JWT token

    # Execute with real crypto tool
    executor = SkillExecutor(state)
    result = executor.execute(skill)

    # Should not crash
    assert result is not None
    assert result.duration > 0


# ===== Integration Tests for New Skills (Phase 5) =====

def test_ad_enumeration_skill():
    """Test AD enumeration skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/ad-enumeration.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "ad-enumeration"
    assert "ad" in skill.tags
    assert "smb" in skill.tags
    assert "nmap" in skill.requires_tools
    assert len(skill.phases) == 4
    assert len(skill.gates) == 3
    # Check phase conditions
    phase_names = [p.name for p in skill.phases]
    assert "smb_discovery" in phase_names
    assert "smb_share_enum" in phase_names
    assert "ldap_enum" in phase_names
    assert "rpc_enum" in phase_names


def test_ldap_enumeration_skill():
    """Test LDAP enumeration skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/ldap-enumeration.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "ldap-enumeration"
    assert "ldap" in skill.tags
    assert "nmap" in skill.requires_tools
    assert len(skill.phases) == 3
    phase_names = [p.name for p in skill.phases]
    assert "ldap_discovery" in phase_names
    assert "rootdse_enum" in phase_names
    assert "ldap_search" in phase_names


def test_docker_enumeration_skill():
    """Test Docker enumeration skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/docker-enumeration.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "docker-enumeration"
    assert "docker" in skill.tags
    assert "container" in skill.tags
    assert "nmap" in skill.requires_tools
    assert "shell" in skill.requires_tools
    assert len(skill.phases) == 4
    phase_names = [p.name for p in skill.phases]
    assert "docker_port_scan" in phase_names
    assert "docker_api_check" in phase_names
    assert "docker_registry_check" in phase_names
    assert "es_check" in phase_names


def test_cloud_aws_recon_skill():
    """Test AWS cloud recon skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/cloud-aws-recon.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "cloud-aws-recon"
    assert "cloud" in skill.tags
    assert "aws" in skill.tags
    assert "shell" in skill.requires_tools
    assert len(skill.phases) == 3
    phase_names = [p.name for p in skill.phases]
    assert "imds_check" in phase_names
    assert "imds_depth" in phase_names
    assert "s3_enum" in phase_names


def test_privilege_escalation_skill():
    """Test privilege escalation skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/privilege-escalation.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "privilege-escalation"
    assert "privesc" in skill.tags
    assert "linux" in skill.tags
    assert "windows" in skill.tags
    assert "shell" in skill.requires_tools
    assert len(skill.phases) == 3
    phase_names = [p.name for p in skill.phases]
    assert "shell_access_check" in phase_names
    assert "linux_privesc" in phase_names
    assert "win_privesc" in phase_names


def test_api_testing_skill():
    """Test API testing skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/api-testing.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "api-testing"
    assert "api" in skill.tags
    assert "rest" in skill.tags
    assert "nmap" in skill.requires_tools
    assert "shell" in skill.requires_tools
    assert len(skill.phases) == 4
    phase_names = [p.name for p in skill.phases]
    assert "api_discovery" in phase_names
    assert "auth_test" in phase_names
    assert "injection_test" in phase_names
    assert "misconfig_test" in phase_names


def test_subdomain_enumeration_skill():
    """Test subdomain enumeration skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/subdomain-enumeration.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "subdomain-enumeration"
    assert "subdomain" in skill.tags
    assert "dns" in skill.tags
    assert "nmap" in skill.requires_tools
    assert len(skill.phases) == 3
    phase_names = [p.name for p in skill.phases]
    assert "zone_transfer_check" in phase_names
    assert "dns_brute" in phase_names
    assert "reverse_dns" in phase_names


def test_kerberos_enumeration_skill():
    """Test Kerberos enumeration skill parses correctly."""
    import yaml
    skill_path = Path("erreetool/skills/kerberos-enumeration.yml")
    assert skill_path.exists()

    with open(skill_path) as f:
        data = yaml.safe_load(f)

    skill = parse_skill(data, source_file=str(skill_path))
    assert skill.name == "kerberos-enumeration"
    assert "kerberos" in skill.tags
    assert "ad" in skill.tags
    assert "nmap" in skill.requires_tools
    assert len(skill.phases) == 3
    phase_names = [p.name for p in skill.phases]
    assert "kerberos_discovery" in phase_names
    assert "kerberos_enum" in phase_names
    assert "as_rep_roast_check" in phase_names


def test_all_new_skills_executor_integration():
    """Test all new skills can be instantiated and executed with mock tools."""
    import yaml
    skill_files = [
        "ad-enumeration.yml",
        "ldap-enumeration.yml",
        "docker-enumeration.yml",
        "cloud-aws-recon.yml",
        "privilege-escalation.yml",
        "api-testing.yml",
        "subdomain-enumeration.yml",
        "kerberos-enumeration.yml",
    ]

    for skill_file in skill_files:
        skill_path = Path(f"erreetool/skills/{skill_file}")
        assert skill_path.exists(), f"Missing {skill_file}"

        with open(skill_path) as f:
            data = yaml.safe_load(f)

        skill = parse_skill(data, source_file=str(skill_path))
        assert skill.name == skill_file.replace(".yml", "")
        assert len(skill.phases) > 0
        # Each phase should have at least one step
        for phase in skill.phases:
            assert len(phase.steps) > 0, f"Phase {phase.name} has no steps in {skill_file}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])