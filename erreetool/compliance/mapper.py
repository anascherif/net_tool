"""
Compliance Mapper - Maps findings to compliance frameworks.
"""
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from erreetool.compliance.models import (
    Framework,
    ComplianceRequirement,
    ComplianceMapping,
    ComplianceReport,
    ControlStatus,
    FINDING_TO_CONTROLS,
    get_controls_for_finding,
    get_all_frameworks,
)


class ComplianceMapper:
    """
    Maps security findings to compliance framework controls.
    
    Supports NIST CSF, ISO 27001/27002, PCI-DSS v4.0, CIS Controls v8,
    and can be extended for other frameworks.
    """
    
    def __init__(self):
        self.frameworks = get_all_frameworks()
    
    def classify_finding(self, finding: str) -> str:
        """Classify a finding into a type for compliance mapping."""
        finding_lower = finding.lower()
        
        # Critical vulnerabilities
        if re.search(r'cve-\d{4}-\d{4,7}', finding_lower):
            if any(kw in finding_lower for kw in ['critical', 'rce', 'remote code execution']):
                return "cve_critical"
            return "cve_high"
        
        # Network exposure
        if "smb" in finding_lower and ("445" in finding_lower or "exposed" in finding_lower or "open" in finding_lower):
            return "smb_exposed"
        if "rdp" in finding_lower and ("3389" in finding_lower or "exposed" in finding_lower or "open" in finding_lower):
            return "rdp_exposed"
        if "ssh" in finding_lower and ("22" in finding_lower or "exposed" in finding_lower or "open" in finding_lower):
            return "ssh_exposed"
        if any(db in finding_lower for db in ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis']) and ("exposed" in finding_lower or "open" in finding_lower):
            return "database_exposed"
        if "80/tcp" in finding_lower or "443/tcp" in finding_lower or "8080" in finding_lower or "web server" in finding_lower:
            return "web_exposed"
        if re.search(r'port \d+/tcp open', finding_lower):
            return "open_port"
        
        # Vulnerabilities
        if "sql injection" in finding_lower or "sqli" in finding_lower:
            return "sql_injection"
        if "xss" in finding_lower or "cross-site scripting" in finding_lower:
            return "xss"
        if "rce" in finding_lower or "remote code execution" in finding_lower:
            return "rce"
        if "lfi" in finding_lower or "local file inclusion" in finding_lower:
            return "rce"
        if "rfi" in finding_lower or "remote file inclusion" in finding_lower:
            return "rce"
        
        # Auth findings
        if "default cred" in finding_lower or "default password" in finding_lower or "default login" in finding_lower:
            return "default_credentials"
        if "weak password" in finding_lower or "password policy" in finding_lower:
            return "weak_password_policy"
        if "mfa" in finding_lower and ("missing" in finding_lower or "not enabled" in finding_lower or "disabled" in finding_lower):
            return "mfa_missing"
        if "privilege escalation" in finding_lower or "privesc" in finding_lower:
            return "privilege_escalation"
        
        # Data protection
        if "sensitive data" in finding_lower or "pii" in finding_lower or "credit card" in finding_lower or "ssn" in finding_lower:
            return "sensitive_data_exposure"
        if "encryption" in finding_lower and ("missing" in finding_lower or "not enabled" in finding_lower or "disabled" in finding_lower):
            return "encryption_missing"
        if "cleartext" in finding_lower or "unencrypted" in finding_lower:
            return "encryption_missing"
        
        # Config
        if "misconfiguration" in finding_lower or "misconfigured" in finding_lower:
            return "misconfiguration"
        if "unnecessary service" in finding_lower or "unused service" in finding_lower:
            return "unnecessary_services"
        
        # Credentials
        if "credential reuse" in finding_lower or "password reuse" in finding_lower:
            return "credential_reuse"
        if "kerberos" in finding_lower or "as-rep" in finding_lower or "as_rep" in finding_lower:
            return "kerberos_issues"
        
        # Cloud
        if "s3" in finding_lower and ("public" in finding_lower or "open" in finding_lower):
            return "s3_public"
        if "iam" in finding_lower and ("overprivileged" in finding_lower or "excessive" in finding_lower or "wildcard" in finding_lower):
            return "iam_overprivileged"
        
        # Container
        if "container" in finding_lower and "root" in finding_lower:
            return "container_root"
        if "docker api" in finding_lower and ("exposed" in finding_lower or "open" in finding_lower):
            return "docker_api_exposed"
        
        return "unknown"
    
    def map_finding(
        self,
        finding: str,
        finding_type: Optional[str] = None,
        severity: str = "medium",
        evidence_ids: List[str] = None,
        frameworks: List[Framework] = None,
    ) -> ComplianceMapping:
        """Map a single finding to compliance controls."""
        if frameworks is None:
            frameworks = self.frameworks
        
        if finding_type is None:
            finding_type = self.classify_finding(finding)
        
        if evidence_ids is None:
            evidence_ids = []
        
        # Get relevant controls
        controls = get_controls_for_finding(finding_type, frameworks)
        
        # Build mapping structure
        mappings = []
        for framework, control_ids in controls.items():
            if control_ids:
                mappings.append({
                    "framework": framework.value,
                    "controls": control_ids,
                    "finding_type": finding_type,
                })
        
        return ComplianceMapping(
            finding=finding,
            finding_type=finding_type,
            severity=severity,
            evidence_ids=evidence_ids,
            mappings=mappings,
            frameworks_affected=[f for f, c in controls.items() if c],
            highest_severity=severity,
        )
    
    def map_findings(
        self,
        findings: List[str],
        frameworks: List[Framework] = None,
        severities: Dict[str, str] = None,
        evidence_map: Dict[str, List[str]] = None,
    ) -> List[ComplianceMapping]:
        """Map multiple findings to compliance controls."""
        if frameworks is None:
            frameworks = self.frameworks
        if severities is None:
            severities = {}
        if evidence_map is None:
            evidence_map = {}
        
        mappings = []
        for finding in findings:
            finding_type = self.classify_finding(finding)
            severity = severities.get(finding, "medium")
            evidence_ids = evidence_map.get(finding, [])
            
            mapping = self.map_finding(
                finding=finding,
                finding_type=finding_type,
                severity=severity,
                evidence_ids=evidence_ids,
                frameworks=frameworks,
            )
            mappings.append(mapping)
        
        return mappings
    
    def generate_report(
        self,
        assessment_id: str,
        target: str,
        findings: List[str],
        frameworks: List[Framework] = None,
        severities: Dict[str, str] = None,
        evidence_map: Dict[str, List[str]] = None,
    ) -> ComplianceReport:
        """Generate a full compliance report."""
        if frameworks is None:
            frameworks = [Framework.NIST_CSF, Framework.ISO_27001, Framework.PCI_DSS, Framework.CIS_CONTROLS]
        
        mappings = self.map_findings(findings, frameworks, severities, evidence_map)
        
        # Calculate summary
        total_controls = 0
        compliant = 0
        non_compliant = 0
        partial = 0
        not_applicable = 0
        not_assessed = 0
        
        framework_summary = {}
        
        for framework in frameworks:
            fw_controls = set()
            fw_compliant = 0
            fw_non_compliant = 0
            fw_partial = 0
            fw_na = 0
            
            for mapping in mappings:
                for m in mapping.mappings:
                    if m["framework"] == framework.value:
                        for ctrl in m["controls"]:
                            fw_controls.add(ctrl)
                            # Simplified: if finding exists, control is non-compliant
                            if mapping.severity in ("critical", "high"):
                                fw_non_compliant += 1
                            elif mapping.severity == "medium":
                                fw_partial += 1
                            else:
                                fw_compliant += 1
            
            framework_summary[framework.value] = {
                "total": len(fw_controls),
                "compliant": fw_compliant,
                "non_compliant": fw_non_compliant,
                "partial": fw_partial,
                "not_applicable": fw_na,
            }
            
            total_controls += len(fw_controls)
            compliant += fw_compliant
            non_compliant += fw_non_compliant
            partial += fw_partial
            not_applicable += fw_na
        
        not_assessed = total_controls - (compliant + non_compliant + partial + not_applicable)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(mappings)
        
        return ComplianceReport(
            assessment_id=assessment_id,
            target=target,
            generated_at=datetime.now(timezone.utc),
            frameworks=frameworks,
            total_controls=total_controls,
            compliant=compliant,
            non_compliant=non_compliant,
            partial=partial,
            not_applicable=not_applicable,
            not_assessed=not_assessed,
            mappings=mappings,
            framework_summary=framework_summary,
            recommendations=recommendations,
        )
    
    def _generate_recommendations(self, mappings: List[ComplianceMapping]) -> List[str]:
        """Generate remediation recommendations based on mappings."""
        recommendations = []
        
        # Group by framework
        framework_issues = {}
        for mapping in mappings:
            for m in mapping.mappings:
                fw = m["framework"]
                if fw not in framework_issues:
                    framework_issues[fw] = []
                framework_issues[fw].append({
                    "finding": mapping.finding,
                    "severity": mapping.severity,
                    "controls": m["controls"],
                })
        
        for framework, issues in framework_issues.items():
            critical_high = [i for i in issues if i["severity"] in ("critical", "high")]
            if critical_high:
                controls = set()
                for i in critical_high:
                    controls.update(i["controls"])
                recommendations.append(
                    f"[{framework.upper()}] Address {len(critical_high)} critical/high findings "
                    f"affecting controls: {', '.join(sorted(controls))}"
                )
            
            medium = [i for i in issues if i["severity"] == "medium"]
            if medium:
                controls = set()
                for i in medium:
                    controls.update(i["controls"])
                recommendations.append(
                    f"[{framework.upper()}] Review {len(medium)} medium findings "
                    f"affecting controls: {', '.join(sorted(controls))}"
                )
        
        # General recommendations
        if any(m.severity == "critical" for m in mappings):
            recommendations.append(
                "Immediate action required: Critical vulnerabilities detected. "
                "Prioritize patching and exploitation verification."
            )
        
        if any("smb_exposed" in m.finding_type for m in mappings):
            recommendations.append(
                "Disable SMBv1, restrict SMB (port 445) to trusted networks only, "
                "and enable SMB signing."
            )
        
        if any("rdp_exposed" in m.finding_type for m in mappings):
            recommendations.append(
                "Restrict RDP (port 3389) access via VPN or bastion host. "
                "Enable Network Level Authentication (NLA)."
            )
        
        if any("default_credentials" in m.finding_type for m in mappings):
            recommendations.append(
                "Change all default credentials immediately. Implement password rotation policy."
            )
        
        if any("mfa_missing" in m.finding_type for m in mappings):
            recommendations.append(
                "Enable Multi-Factor Authentication (MFA) for all remote access and privileged accounts."
            )
        
        if any("encryption_missing" in m.finding_type for m in mappings):
            recommendations.append(
                "Implement encryption in transit (TLS 1.2+) and at rest (AES-256) for sensitive data."
            )
        
        return recommendations
    
    def export_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Export compliance report to various formats."""
        if format == "json":
            return report.model_dump_json(indent=2)
        elif format == "markdown":
            return self._export_markdown(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_markdown(self, report: ComplianceReport) -> str:
        """Export report as Markdown."""
        lines = [
            f"# Compliance Assessment Report",
            f"",
            f"**Target:** {report.target}",
            f"**Assessment ID:** {report.assessment_id}",
            f"**Generated:** {report.generated_at.isoformat()}",
            f"**Frameworks:** {', '.join(f.value.upper() for f in report.frameworks)}",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total Controls Assessed | {report.total_controls} |",
            f"| ✅ Compliant | {report.compliant} |",
            f"| ❌ Non-Compliant | {report.non_compliant} |",
            f"| ⚠️ Partial | {report.partial} |",
            f"| ➖ Not Applicable | {report.not_applicable} |",
            f"| ❓ Not Assessed | {report.not_assessed} |",
            f"",
        ]
        
        # Per-framework breakdown
        for framework, summary in report.framework_summary.items():
            lines.extend([
                f"### {framework.upper()}",
                f"",
                f"| Metric | Count |",
                f"|--------|-------|",
                f"| Total Controls | {summary['total']} |",
                f"| Compliant | {summary['compliant']} |",
                f"| Non-Compliant | {summary['non_compliant']} |",
                f"| Partial | {summary['partial']} |",
                f"| Not Applicable | {summary['not_applicable']} |",
                f"",
            ])
        
        # Detailed mappings
        lines.extend([
            f"## Detailed Findings",
            f"",
        ])
        
        for mapping in report.mappings:
            lines.extend([
                f"### Finding: {mapping.finding}",
                f"",
                f"- **Type:** {mapping.finding_type}",
                f"- **Severity:** {mapping.severity.upper()}",
                f"- **Frameworks:** {', '.join(f.value.upper() for f in mapping.frameworks_affected)}",
                f"- **Evidence:** {', '.join(mapping.evidence_ids) if mapping.evidence_ids else 'N/A'}",
                f"",
            ])
            
            for m in mapping.mappings:
                lines.append(f"- **{m['framework'].upper()} Controls:** {', '.join(m['controls'])}")
            
            lines.append(f"")
        
        # Recommendations
        if report.recommendations:
            lines.extend([
                f"## Recommendations",
                f"",
            ])
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
        
        return "\n".join(lines)


# Convenience function
def map_findings_to_compliance(
    findings: List[str],
    target: str,
    assessment_id: str,
    frameworks: List[Framework] = None,
) -> ComplianceReport:
    """Quick function to map findings and generate report."""
    mapper = ComplianceMapper()
    return mapper.generate_report(
        assessment_id=assessment_id,
        target=target,
        findings=findings,
        frameworks=frameworks,
    )