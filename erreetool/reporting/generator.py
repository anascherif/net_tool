"""
Report generator for agent sessions.

Creates professional Markdown/HTML/JSON reports from AgentState.
Includes MITRE ATT&CK mapping, attack path analysis (Phase 6),
and compliance mapping (Phase 7).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from erreetool.agent.state import AgentState, EvidenceType
from erreetool.agent.mitre import (
    map_findings_batch,
    generate_mitre_heatmap,
    generate_mitre_technique_table,
)
from erreetool.agent.attack_path import find_attack_paths, AttackPath
from erreetool.compliance import ComplianceMapper, Framework


class ReportGenerator:
    """Generates reports from agent state."""
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path.cwd() / "erreetool-output" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(
        self,
        state: AgentState,
        format: str = "markdown",
        template: str = None
    ) -> Path:
        """Generate report from agent state."""
        if format == "markdown":
            content = self._generate_markdown(state)
            ext = "md"
        elif format == "html":
            content = self._generate_html(state)
            ext = "html"
        elif format == "json":
            content = self._generate_json(state)
            ext = "json"
        else:
            raise ValueError(f"Unknown format: {format}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{state.session_id}_{timestamp}.{ext}"
        filepath = self.output_dir / filename
        
        filepath.write_text(content, encoding="utf-8")
        return filepath
    
    def _generate_markdown(self, state: AgentState) -> str:
        """Generate Markdown report with MITRE ATT&CK, attack paths (Phase 6), and compliance (Phase 7)."""
        summary = state.get_summary()
        ctx = state.context
        
        # Phase 6: Generate MITRE mappings and attack paths
        mitre_mappings = []
        if ctx.high_signal_facts:
            finding_types = ["finding"] * len(ctx.high_signal_facts)
            mitre_mappings = map_findings_batch(ctx.high_signal_facts, finding_types)
        
        attack_paths = []
        if mitre_mappings:
            attack_paths = find_attack_paths(state, max_depth=6, min_score=1.0)
        
        # Phase 7: Compliance mapping
        compliance_report = None
        if ctx.high_signal_facts:
            try:
                mapper = ComplianceMapper()
                compliance_report = mapper.generate_report(
                    assessment_id=state.session_id,
                    target=ctx.target or "unknown",
                    findings=ctx.high_signal_facts,
                    frameworks=[Framework.NIST_CSF, Framework.ISO_27001, Framework.PCI_DSS, Framework.CIS_CONTROLS],
                )
            except Exception as e:
                pass  # Silently skip compliance if it fails
        
        lines = [
            f"# Penetration Test Report",
            f"",
            f"**Target:** {ctx.target}",
            f"**Session:** {state.session_id}",
            f"**Date:** {datetime.fromtimestamp(state.created_at).strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {summary.get('duration', 0):.1f} seconds",
            f"",
            f"## Executive Summary",
            f"",
            f"This report details the findings of an automated penetration test "
            f"conducted against **{ctx.target}**. The assessment was performed "
            f"using an autonomous AI agent with access to standard security tools.",
            f"",
            f"## Assessment Scope",
            f"",
        ]
        
        if ctx.goals:
            lines.append("### Goals")
            for goal in ctx.goals:
                lines.append(f"- {goal}")
            lines.append("")
        
        lines.extend([
            f"## Summary Statistics",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Steps | {summary.get('steps_total', 0)} |",
            f"| Completed | {summary.get('steps_completed', 0)} |",
            f"| Failed | {summary.get('steps_failed', 0)} |",
            f"| Evidence Collected | {summary.get('evidence_total', 0)} |",
            f"| High-Signal Facts | {summary.get('high_signal_facts', 0)} |",
            f"| MITRE Techniques Mapped | {len(set(t.id for m in mitre_mappings for t in m.techniques))} |",
            f"| Attack Paths Found | {len(attack_paths)} |",
            f"| Compliance Frameworks | {len(compliance_report.frameworks) if compliance_report else 0} |",
            f"",
        ])
        
        # Phase 7: Compliance Summary
        if compliance_report:
            lines.extend([
                f"## Compliance Summary",
                f"",
                f"| Framework | Controls | Compliant | Non-Compliant | Partial |",
                f"|-----------|----------|-----------|---------------|---------|",
            ])
            for fw, summary_data in compliance_report.framework_summary.items():
                lines.append(
                    f"| {fw.upper()} | {summary_data['total']} | "
                    f"{summary_data['compliant']} | {summary_data['non_compliant']} | {summary_data['partial']} |"
                )
            lines.append("")
        
        # Phase 6: MITRE ATT&CK Heatmap
        if mitre_mappings:
            lines.extend([
                f"## MITRE ATT&CK Mapping",
                f"",
                generate_mitre_heatmap(mitre_mappings),
                f"",
                f"### Top Techniques",
                f"",
                generate_mitre_technique_table(mitre_mappings),
                f"",
            ])
        
        # Phase 6: Attack Paths
        if attack_paths:
            lines.extend([
                f"## Attack Paths",
                f"",
                f"Potential attack paths from initial access to high-value objectives:",
                f"",
            ])
            for i, path in enumerate(attack_paths[:5], 1):
                lines.extend([
                    f"### Path {i}: {path.objective} (Risk: {path.risk_score:.1f})",
                    f"",
                    f"**MITRE Techniques:** {', '.join(path.mitre_techniques) if path.mitre_techniques else 'N/A'}",
                    f"",
                    f"**Sequence:**",
                ])
                for j, node in enumerate(path.nodes, 1):
                    lines.append(f"  {j}. [{node.type.value}] {node.label} (score: {node.score:.1f})")
                lines.append("")
        
        # High-signal facts
        if ctx.high_signal_facts:
            lines.extend([
                f"## Verified Facts",
                f"",
            ])
            for fact in ctx.high_signal_facts:
                lines.append(f"- {fact}")
            lines.append("")
        
        # Tool execution summary
        tool_usage = {}
        for step in state.steps:
            if step.tool not in tool_usage:
                tool_usage[step.tool] = {"total": 0, "success": 0, "failed": 0}
            tool_usage[step.tool]["total"] += 1
            if step.status.value == "completed":
                tool_usage[step.tool]["success"] += 1
            else:
                tool_usage[step.tool]["failed"] += 1
        
        if tool_usage:
            lines.extend([
                f"## Tool Usage",
                f"",
                f"| Tool | Total | Success | Failed |",
                f"|------|-------|---------|--------|",
            ])
            for tool, stats in sorted(tool_usage.items()):
                lines.append(f"| {tool} | {stats['total']} | {stats['success']} | {stats['failed']} |")
            lines.append("")
        
        # Evidence details
        lines.extend([
            f"## Evidence Log",
            f"",
        ])
        
        for ev in state.evidence_log[-50:]:  # Last 50 evidence items
            lines.extend([
                f"### [{ev.id}] {ev.type.value} from {ev.source}",
                f"",
                f"```",
                ev.content[:2000],
                f"```",
                f"",
            ])
        
        # Findings
        if ctx.findings:
            lines.extend([
                f"## Findings",
                f"",
            ])
            for category, findings in ctx.findings.items():
                lines.append(f"### {category}")
                if isinstance(findings, list):
                    for finding in findings:
                        lines.append(f"- {finding}")
                else:
                    lines.append(f"- {findings}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_html(self, state: AgentState) -> str:
        """Generate HTML report."""
        md = self._generate_markdown(state)
        # Simple markdown to HTML conversion
        html = md.replace("\n", "<br>\n")
        html = html.replace("# ", "<h1>").replace("\n", "</h1>\n")
        html = html.replace("## ", "<h2>").replace("\n", "</h2>\n")
        html = html.replace("### ", "<h3>").replace("\n", "</h3>\n")
        html = html.replace("| ", "<tr><td>").replace(" |", "</td><td>").replace(" |\n", "</td></tr>\n")
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {state.context.target}</title>
    <style>
        body {{ font-family: monospace; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f0f0f0; }}
        .evidence {{ border-left: 3px solid #3498db; padding-left: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
{html}
</body>
</html>"""
    
    def _generate_json(self, state: AgentState) -> str:
        """Generate JSON report."""
        return json.dumps({
            "session_id": state.session_id,
            "target": state.context.target,
            "created_at": state.created_at,
            "summary": state.get_summary(),
            "context": state.context.to_dict(),
            "steps": [s.to_dict() for s in state.steps],
            "evidence": [e.to_dict() for e in state.evidence_log],
        }, indent=2)