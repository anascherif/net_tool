"""
Attack Path Planning - Graph-based attack path analysis.

Builds an attack graph from discovered vulnerabilities, credentials,
and lateral movement opportunities. Uses memory to suggest likely
paths based on historical data.

Core concepts:
    Node: A host, service, credential, or vulnerability
    Edge: A relationship (can_exploit, lateral_move, privilege_escalate)
    Path: A sequence from initial access to high-value target
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from erreetool.agent.memory.schema import (
    FindingPattern,
    CredentialPattern,
    CVEKnowledge,
    ToolEffectiveness,
    MemoryEntry,
    MemoryType,
)
from erreetool.agent.state import AgentState, Evidence


# ============================================================
# Graph nodes and edges
# ============================================================

class NodeType(str, Enum):
    """Types of nodes in the attack graph."""
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    USER = "user"
    GROUP = "group"
    DOMAIN = "domain"
    TRUST = "trust"
    FILE = "file"
    CONFIG = "config"


class EdgeType(str, Enum):
    """Types of edges (relationships) in the attack graph."""
    EXPLOITS = "exploits"           # vuln -> service/host
    LEADS_TO = "leads_to"           # service -> host, cred -> host
    LATERAL_MOVE = "lateral_move"   # host -> host via cred/trust
    PRIVESC = "privilege_escalate"  # user/service -> higher priv
    HAS_CRED = "has_credential"     # user/host -> credential
    MEMBER_OF = "member_of"         # user -> group
    TRUSTS = "trusts"               # domain -> domain
    READS = "reads"                 # user/process -> file
    EXECUTES = "executes"           # user/process -> binary


@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str
    type: NodeType
    label: str
    host: str = ""           # IP/hostname this node belongs to
    port: int = 0            # Port (for services)
    metadata: dict = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)  # Supporting evidence
    score: float = 0.0       # Risk/importance score (0-10)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return isinstance(other, AttackNode) and self.id == other.id


@dataclass
class AttackEdge:
    """An edge (relationship) in the attack graph."""
    source: str
    target: str
    type: EdgeType
    confidence: float = 0.5  # 0-1, how confident we are
    technique: str = ""      # MITRE ATT&CK technique ID
    description: str = ""
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """A complete attack path from initial access to objective."""
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    objective: str = ""      # What this path achieves
    risk_score: float = 0.0  # Aggregate risk
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n.id, "type": n.type.value, "label": n.label,
                       "host": n.host, "port": n.port, "score": n.score}
                      for n in self.nodes],
            "edges": [{"source": e.source, "target": e.target,
                       "type": e.type.value, "confidence": e.confidence,
                       "technique": e.technique, "description": e.description}
                      for e in self.edges],
            "objective": self.objective,
            "risk_score": self.risk_score,
            "mitre_techniques": self.mitre_techniques,
        }


# ============================================================
# Attack Graph Builder
# ============================================================

class AttackGraphBuilder:
    """Builds an attack graph from agent state and memory."""

    def __init__(self, state: AgentState):
        self.state = state
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self.host_cache: dict[str, AttackNode] = {}

    def build(self) -> "AttackGraph":
        """Build the full attack graph."""
        self._add_host_node()
        self._parse_evidence_for_nodes()
        self._parse_high_signal_facts()  # Also parse facts directly
        self._infer_edges_from_facts()
        self._infer_edges_from_memory()
        self._calculate_scores()
        return AttackGraph(self.nodes, self.edges)

    def _add_host_node(self):
        """Add the target host as root node."""
        host_node = AttackNode(
            id=f"host:{self.state.context.target}",
            type=NodeType.HOST,
            label=self.state.context.target,
            host=self.state.context.target,
            score=5.0,
        )
        self.nodes[host_node.id] = host_node
        self.host_cache[self.state.context.target] = host_node

    def _parse_evidence_for_nodes(self):
        """Extract nodes from evidence (tool outputs)."""
        for ev in self.state.evidence_log:
            if ev.type.value == "tool_output":
                self._parse_tool_output(ev)

    def _parse_high_signal_facts(self):
        """Parse high-signal facts directly for nodes (when no tool output)."""
        for fact in self.state.context.high_signal_facts:
            # Try to parse as nmap-style port finding
            match = re.search(r'Port (\d+)/tcp open: (\S+)', fact)
            if match:
                port, service = match.groups()
                node_id = f"service:{self.state.context.target}:{port}:{service}"
                node = self._get_or_create_node(
                    node_id,
                    NodeType.SERVICE,
                    f"{service} ({port}/tcp)",
                    self.state.context.target,
                    int(port),
                    "",
                    {"service": service, "protocol": "tcp", "source": "fact"}
                )
                self._add_edge(
                    f"host:{self.state.context.target}",
                    node_id,
                    EdgeType.LEADS_TO,
                )
                continue

            # CVE
            match = re.search(r'(CVE-\d{4}-\d{4,7})', fact)
            if match:
                cve_id = match.group(1)
                node_id = f"vuln:{self.state.context.target}:{cve_id}"
                node = self._get_or_create_node(
                    node_id,
                    NodeType.VULNERABILITY,
                    cve_id,
                    self.state.context.target,
                    0,
                    "",
                    {"cve_id": cve_id, "source": "fact"}
                )
                # Score by fact content
                if "critical" in fact.lower():
                    node.score = 9.0
                elif "high" in fact.lower():
                    node.score = 7.0
                elif "medium" in fact.lower():
                    node.score = 5.0
                else:
                    node.score = 4.0
                # Add edge from host to vulnerability with MITRE technique
                self._add_edge(
                    f"host:{self.state.context.target}",
                    node_id,
                    EdgeType.EXPLOITS,
                    technique="T1190",
                )
                continue

            # Credential facts
            if "as-rep roastable" in fact.lower() or "as-rep roastable" in fact.lower():
                user_match = re.search(r'user:\s*(\S+)', fact, re.IGNORECASE)
                if user_match:
                    user = user_match.group(1)
                    node_id = f"cred:kerberos:asrep:{user}"
                    node = self._get_or_create_node(
                        node_id,
                        NodeType.CREDENTIAL,
                        f"AS-REP roastable: {user}",
                        self.state.context.target,
                        88,
                        "",
                        {"service": "kerberos", "username": user, "type": "as_rep_roast"}
                    )
                    node.score = 8.0
                    self._add_edge(
                        f"host:{self.state.context.target}",
                        node_id,
                        EdgeType.HAS_CRED,
                    )
                continue

            # SQL injection
            if "sql injection" in fact.lower():
                node_id = f"vuln:{self.state.context.target}:sql_injection"
                node = self._get_or_create_node(
                    node_id,
                    NodeType.VULNERABILITY,
                    "SQL Injection",
                    self.state.context.target,
                    0,
                    "",
                    {"type": "sql_injection", "source": "fact"}
                )
                node.score = 8.0
                self._add_edge(
                    f"host:{self.state.context.target}",
                    node_id,
                    EdgeType.EXPLOITS,
                    technique="T1190",
                )
                continue

            # Docker API
            if "docker api exposed" in fact.lower():
                match = re.search(r'(\d+)/tcp', fact)
                port = int(match.group(1)) if match else 2375
                node_id = f"service:{self.state.context.target}:{port}:docker"
                node = self._get_or_create_node(
                    node_id,
                    NodeType.SERVICE,
                    f"Docker API ({port}/tcp)",
                    self.state.context.target,
                    port,
                    "",
                    {"service": "docker", "protocol": "tcp", "source": "fact"}
                )
                node.score = 7.0
                self._add_edge(
                    f"host:{self.state.context.target}",
                    node_id,
                    EdgeType.LEADS_TO,
                    technique="T1190",
                )

    def _parse_tool_output(self, ev: Evidence):
        """Parse a single tool output for nodes."""
        content = ev.content.lower()
        tool = ev.source

        # Nmap port/service findings
        if tool == "nmap":
            self._parse_nmap_output(content, ev.id)

        # Nuclei vulnerability findings
        elif tool == "nuclei":
            self._parse_nuclei_output(content, ev.id)

        # WhatWeb technology findings
        elif tool == "whatweb":
            self._parse_whatweb_output(content, ev.id)

        # Gobuster/feroxbuster findings
        elif tool in ("gobuster", "feroxbuster"):
            self._parse_gobuster_output(content, ev.id)

        # SQLMap findings
        elif tool == "sqlmap":
            self._parse_sqlmap_output(content, ev.id)

    def _parse_nmap_output(self, content: str, evidence_id: str):
        """Parse nmap output for services and OS."""
        # Port patterns
        for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', content):
            port, service = match.groups()
            node_id = f"service:{self.state.context.target}:{port}:{service}"
            node = self._get_or_create_node(
                node_id,
                NodeType.SERVICE,
                f"{service} ({port}/tcp)",
                self.state.context.target,
                int(port),
                evidence_id,
                {"service": service, "protocol": "tcp"}
            )
            # Link to host
            self._add_edge(
                f"host:{self.state.context.target}",
                node_id,
                EdgeType.LEADS_TO,
                evidence_ids=[evidence_id],
            )

        # OS detection
        for match in re.finditer(r'OS:\s*(.+)', content, re.IGNORECASE):
            os_info = match.group(1).strip()
            node_id = f"config:{self.state.context.target}:os"
            node = self._get_or_create_node(
                node_id,
                NodeType.CONFIG,
                f"OS: {os_info}",
                self.state.context.target,
                0,
                evidence_id,
                {"config_type": "os", "value": os_info}
            )
            self._add_edge(
                f"host:{self.state.context.target}",
                node_id,
                EdgeType.LEADS_TO,
                evidence_ids=[evidence_id],
            )

    def _parse_nuclei_output(self, content: str, evidence_id: str):
        """Parse nuclei output for vulnerabilities."""
        # CVE pattern
        for cve in re.finditer(r'(CVE-\d{4}-\d{4,7})', content):
            cve_id = cve.group(1)
            # Try to extract severity from context
            severity = "unknown"
            for sev in ("critical", "high", "medium", "low", "info"):
                if sev in content[max(0, cve.start()-100):cve.start()].lower():
                    severity = sev
                    break

            node_id = f"vuln:{self.state.context.target}:{cve_id}"
            node = self._get_or_create_node(
                node_id,
                NodeType.VULNERABILITY,
                cve_id,
                self.state.context.target,
                0,
                evidence_id,
                {"cve_id": cve_id, "severity": severity}
            )
            # Score by severity
            severity_scores = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}
            node.score = severity_scores.get(severity, 2.0)

    def _parse_whatweb_output(self, content: str, evidence_id: str):
        """Parse whatweb output for technologies."""
        for match in re.finditer(r'(?i)(Apache|nginx|IIS|Tomcat|Jetty|Node\.js|Express|Django|Flask|WordPress|Drupal|Joomla)[/\s]([\d.]+)', content):
            tech, version = match.groups()
            node_id = f"service:{self.state.context.target}:web:{tech.lower()}"
            node = self._get_or_create_node(
                node_id,
                NodeType.SERVICE,
                f"{tech} {version}",
                self.state.context.target,
                80,  # default web port
                evidence_id,
                {"tech": tech.lower(), "version": version}
            )
            self._add_edge(
                f"host:{self.state.context.target}",
                node_id,
                EdgeType.LEADS_TO,
                evidence_ids=[evidence_id],
            )

    def _parse_gobuster_output(self, content: str, evidence_id: str):
        """Parse gobuster/feroxbuster output for directories."""
        for match in re.finditer(r'Status:\s+(\d+)\s+\[Size:\s+\d+\]\s+(\S+)', content):
            status, path = match.groups()
            if status in ("200", "301", "302", "401", "403"):
                node_id = f"file:{self.state.context.target}:{path}"
                node = self._get_or_create_node(
                    node_id,
                    NodeType.FILE,
                    path,
                    self.state.context.target,
                    80,
                    evidence_id,
                    {"path": path, "http_status": int(status)}
                )
                self._add_edge(
                    f"host:{self.state.context.target}",
                    node_id,
                    EdgeType.READS,
                    evidence_ids=[evidence_id],
                )

    def _parse_sqlmap_output(self, content: str, evidence_id: str):
        """Parse sqlmap output for SQL injection and DB info."""
        if "injectable" in content.lower() or "sql injection" in content.lower():
            node_id = f"vuln:{self.state.context.target}:sql_injection"
            node = self._get_or_create_node(
                node_id,
                NodeType.VULNERABILITY,
                "SQL Injection",
                self.state.context.target,
                0,
                evidence_id,
                {"type": "sql_injection", "exploitable": True}
            )
            node.score = 8.0

    def _infer_edges_from_facts(self):
        """Infer edges from high-signal facts."""
        for fact in self.state.context.high_signal_facts:
            self._infer_edges_from_fact(fact)

    def _infer_edges_from_fact(self, fact: str):
        """Infer edges from a single high-signal fact."""
        fact_lower = fact.lower()

        # SMB -> lateral move potential
        if "445/tcp" in fact_lower or "smb" in fact_lower:
            self._add_lateral_move_potential("smb", fact)

        # RDP
        if "3389/tcp" in fact_lower or "rdp" in fact_lower:
            self._add_lateral_move_potential("rdp", fact)

        # SSH
        if "22/tcp" in fact_lower or "ssh" in fact_lower:
            self._add_lateral_move_potential("ssh", fact)

        # WinRM
        if "5985/tcp" in fact_lower or "5986/tcp" in fact_lower or "winrm" in fact_lower:
            self._add_lateral_move_potential("winrm", fact)

        # Database
        if any(db in fact_lower for db in ("mysql", "postgresql", "mssql", "oracle")):
            self._add_credential_target("database", fact)

    def _add_lateral_move_potential(self, service: str, fact: str):
        """Add potential lateral move edges for a service."""
        # This would be expanded with actual credential matching
        pass

    def _add_credential_target(self, target_type: str, fact: str):
        """Add potential credential access targets."""
        pass

    def _infer_edges_from_memory(self):
        """Use memory to infer likely edges based on historical patterns."""
        from erreetool.agent.memory import memory_store, memory_retriever
        memory_store.load()

        # Get finding patterns for this target
        patterns = memory_store.get_patterns_for_target(self.state.context.target)
        for entry in patterns:
            pattern = FindingPattern.from_dict(entry.content)
            for indicator in pattern.indicators:
                if indicator.lower() in " ".join(self.state.context.high_signal_facts).lower():
                    # This pattern matches - add edges it suggests
                    self._add_edges_from_pattern(pattern)

        # Get credential patterns
        creds = memory_store.get_by_type(MemoryType.CREDENTIAL_PATTERN)
        for entry in creds:
            cred = CredentialPattern.from_dict(entry.content)
            if cred.service in " ".join(self.state.context.high_signal_facts).lower():
                self._add_credential_edge(cred)

    def _add_edges_from_pattern(self, pattern: FindingPattern):
        """Add edges suggested by a finding pattern."""
        # Pattern could suggest lateral moves, privesc, etc.
        pass

    def _add_credential_edge(self, cred: CredentialPattern):
        """Add a credential-based edge."""
        node_id = f"cred:{cred.service}:{cred.username}:{cred.password}"
        node = self._get_or_create_node(
            node_id,
            NodeType.CREDENTIAL,
            f"{cred.username} ({cred.service})",
            self.state.context.target,
            0,
            "",
            {"service": cred.service, "username": cred.username}
        )
        self._add_edge(
            f"host:{self.state.context.target}",
            node_id,
            EdgeType.HAS_CRED,
            confidence=cred.confidence.value == "high" and 0.8 or 0.5,
        )

    def _calculate_scores(self):
        """Calculate risk scores for nodes."""
        for node in self.nodes.values():
            if node.type == NodeType.VULNERABILITY:
                # Vulns already scored by severity
                pass
            elif node.type == NodeType.SERVICE:
                # Services score based on what they are
                service_scores = {
                    "smb": 6.0, "rdp": 7.0, "ssh": 5.0, "winrm": 7.0,
                    "http": 4.0, "https": 4.0, "mysql": 5.0, "mssql": 6.0,
                }
                for svc, score in service_scores.items():
                    if svc in node.label.lower():
                        node.score = max(node.score, score)
                        break
            elif node.type == NodeType.CREDENTIAL:
                node.score = 8.0  # Credentials are high value

    def _get_or_create_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        host: str,
        port: int,
        evidence_id: str,
        metadata: dict,
    ) -> AttackNode:
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if evidence_id and evidence_id not in node.evidence_ids:
                node.evidence_ids.append(evidence_id)
            return node

        node = AttackNode(
            id=node_id,
            type=node_type,
            label=label,
            host=host,
            port=port,
            metadata=metadata,
            evidence_ids=[evidence_id] if evidence_id else [],
        )
        self.nodes[node_id] = node
        return node

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        confidence: float = 0.5,
        technique: str = "",
        description: str = "",
        evidence_ids: list[str] = None,
    ):
        if source not in self.nodes or target not in self.nodes:
            return

        edge = AttackEdge(
            source=source,
            target=target,
            type=edge_type,
            confidence=confidence,
            technique=technique,
            description=description,
            evidence_ids=evidence_ids or [],
        )
        self.edges.append(edge)


class AttackGraph:
    """Complete attack graph with pathfinding capabilities."""

    def __init__(self, nodes: dict[str, AttackNode], edges: list[AttackEdge]):
        self.nodes = nodes
        self.edges = edges
        self._adj = self._build_adjacency()

    def _build_adjacency(self) -> dict[str, list[AttackEdge]]:
        """Build adjacency list for pathfinding."""
        adj = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            adj[edge.source].append(edge)
        return adj

    def find_paths(
        self,
        start_types: list[NodeType] = None,
        end_types: list[NodeType] = None,
        max_depth: int = 6,
        min_score: float = 0.0,
    ) -> list[AttackPath]:
        """Find attack paths from start to end node types.

        Args:
            start_types: Node types to start from (default: HOST, SERVICE)
            end_types: Node types to end at (default: VULNERABILITY, CREDENTIAL)
            max_depth: Maximum path length
            min_score: Minimum aggregate score to include path

        Returns:
            List of AttackPath objects sorted by risk score (descending)
        """
        if start_types is None:
            start_types = [NodeType.HOST, NodeType.SERVICE]
        if end_types is None:
            end_types = [NodeType.VULNERABILITY, NodeType.CREDENTIAL, NodeType.CONFIG]

        start_nodes = [n for n in self.nodes.values() if n.type in start_types]
        end_nodes = {n.id for n in self.nodes.values() if n.type in end_types}

        paths = []
        for start in start_nodes:
            if start.score < min_score:
                continue
            self._dfs_paths(start, end_nodes, [], [], paths, max_depth)

        # Sort by risk score
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def _dfs_paths(
        self,
        current: AttackNode,
        end_nodes: set[str],
        visited_nodes: list[AttackNode],
        current_edges: list[AttackEdge],
        paths: list[AttackPath],
        max_depth: int,
    ):
        """DFS to find all paths."""
        if len(visited_nodes) >= max_depth:
            return

        visited_nodes.append(current)

        if current.id in end_nodes and len(visited_nodes) > 1:
            # Found a path to an objective
            path = self._create_path(visited_nodes, current_edges)
            paths.append(path)

        for edge in self._adj.get(current.id, []):
            if edge.target not in [n.id for n in visited_nodes]:
                target = self.nodes[edge.target]
                if target.score >= 0:  # Always traverse (could filter by score)
                    self._dfs_paths(target, end_nodes, visited_nodes, current_edges + [edge], paths, max_depth)

    def _create_path(
        self,
        visited_nodes: list[AttackNode],
        edges: list[AttackEdge],
    ) -> AttackPath:
        """Create an AttackPath from visited nodes/edges."""
        # Determine objective
        objectives = {
            NodeType.VULNERABILITY: "vulnerability exploitation",
            NodeType.CREDENTIAL: "credential access",
            NodeType.CONFIG: "configuration access",
            NodeType.USER: "user compromise",
        }
        last_node = visited_nodes[-1]
        objective = objectives.get(last_node.type, "target reached")

        # Calculate risk score (sum of node scores, weighted by edge confidence)
        risk = sum(n.score for n in visited_nodes)
        risk += sum(e.confidence * 2 for e in edges)

        # Collect MITRE techniques
        techniques = [e.technique for e in edges if e.technique]

        return AttackPath(
            nodes=visited_nodes,
            edges=edges,
            objective=objective,
            risk_score=risk,
            mitre_techniques=techniques,
        )

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n.id, "type": n.type.value, "label": n.label,
                       "host": n.host, "port": n.port, "score": n.score}
                      for n in self.nodes.values()],
            "edges": [{"source": e.source, "target": e.target,
                       "type": e.type.value, "confidence": e.confidence,
                       "technique": e.technique, "description": e.description}
                      for e in self.edges],
        }


# ============================================================
# High-level function
# ============================================================

def build_attack_graph(state: AgentState) -> AttackGraph:
    """Build attack graph from agent state."""
    builder = AttackGraphBuilder(state)
    return builder.build()


def find_attack_paths(
    state: AgentState,
    max_depth: int = 6,
    min_score: float = 0.0,
) -> list[AttackPath]:
    """Find all viable attack paths for the current assessment."""
    graph = build_attack_graph(state)
    return graph.find_paths(max_depth=max_depth, min_score=min_score)


if __name__ == "__main__":
    # Quick test
    state = AgentState()
    state.context.target = "192.168.1.100"
    state.add_high_signal_fact("Port 445/tcp open: smb")
    state.add_high_signal_fact("Port 3389/tcp open: rdp")
    state.add_high_signal_fact("Vulnerability found: CVE-2021-34527")

    graph = build_attack_graph(state)
    paths = graph.find_paths()

    print(f"Nodes: {len(graph.nodes)}")
    print(f"Edges: {len(graph.edges)}")
    print(f"Paths: {len(paths)}")
    for i, path in enumerate(paths[:3]):
        print(f"\nPath {i+1}: {path.objective} (risk: {path.risk_score:.1f})")
        for node in path.nodes:
            print(f"  {node.type.value}: {node.label}")