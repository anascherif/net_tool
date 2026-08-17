"""
Compliance Models - Data structures for compliance mapping.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class Framework(str, Enum):
    """Supported compliance frameworks."""
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    ISO_27002 = "iso_27002"
    PCI_DSS = "pci_dss"
    CIS_CONTROLS = "cis_controls"
    MITRE_ATTACK = "mitre_attack"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"


class ControlStatus(str, Enum):
    """Compliance control status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class ComplianceRequirement(BaseModel):
    """A single compliance requirement/control."""
    framework: Framework
    control_id: str
    title: str
    description: str
    category: Optional[str] = None
    subcategory: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    related_techniques: List[str] = Field(default_factory=list)  # MITRE ATT&CK techniques


class ComplianceMapping(BaseModel):
    """Mapping between a finding and compliance requirements."""
    finding: str
    finding_type: str  # vulnerability, misconfiguration, exposure, etc.
    severity: str  # critical, high, medium, low, info
    evidence_ids: List[str] = Field(default_factory=list)
    mappings: List[Dict[str, Any]] = Field(default_factory=list)  # framework -> list of controls
    
    # Computed fields
    frameworks_affected: List[Framework] = Field(default_factory=list)
    highest_severity: str = "info"


class ComplianceReport(BaseModel):
    """Full compliance assessment report."""
    assessment_id: str
    target: str
    generated_at: datetime
    frameworks: List[Framework]
    
    # Summary
    total_controls: int = 0
    compliant: int = 0
    non_compliant: int = 0
    partial: int = 0
    not_applicable: int = 0
    not_assessed: int = 0
    
    # Detailed mappings
    mappings: List[ComplianceMapping] = Field(default_factory=list)
    
    # Per-framework breakdown
    framework_summary: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list)


class Evidence(BaseModel):
    """Evidence supporting a compliance determination."""
    evidence_id: str
    source: str
    content: str
    timestamp: datetime
    tool: str


# Pre-defined control mappings for common findings
FINDING_TO_CONTROLS = {
    # Network exposure findings
    "open_port": {
        Framework.NIST_CSF: ["PR.AC-3", "PR.AC-4", "PR.AC-5", "DE.CM-1"],
        Framework.ISO_27001: ["A.13.1.1", "A.13.1.3"],
        Framework.PCI_DSS: ["1.2.1", "1.3.1", "1.3.2"],
        Framework.CIS_CONTROLS: ["4.1", "4.2", "4.3"],
    },
    "smb_exposed": {
        Framework.NIST_CSF: ["PR.AC-3", "PR.AC-4", "PR.PT-3"],
        Framework.ISO_27001: ["A.13.1.1", "A.13.2.1"],
        Framework.PCI_DSS: ["1.2.1", "2.2.2"],
        Framework.CIS_CONTROLS: ["4.1", "4.8", "13.5"],
    },
    "rdp_exposed": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-3", "PR.AC-7"],
        Framework.ISO_27001: ["A.9.2.3", "A.13.1.1"],
        Framework.PCI_DSS: ["1.2.1", "8.3.1"],
        Framework.CIS_CONTROLS: ["4.1", "4.3", "16.4"],
    },
    "ssh_exposed": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-3", "PR.AC-7"],
        Framework.ISO_27001: ["A.9.2.3", "A.13.1.1"],
        Framework.PCI_DSS: ["1.2.1", "8.3.1"],
        Framework.CIS_CONTROLS: ["4.1", "4.3", "16.4"],
    },
    "database_exposed": {
        Framework.NIST_CSF: ["PR.AC-3", "PR.AC-4", "PR.DS-1", "PR.DS-5"],
        Framework.ISO_27001: ["A.13.1.1", "A.13.2.1", "A.8.2.3"],
        Framework.PCI_DSS: ["1.2.1", "1.3.4", "3.4.1"],
        Framework.CIS_CONTROLS: ["3.3", "4.1", "13.5"],
    },
    "web_exposed": {
        Framework.NIST_CSF: ["PR.AC-3", "PR.PT-4", "DE.CM-1"],
        Framework.ISO_27001: ["A.13.1.1", "A.14.2.5"],
        Framework.PCI_DSS: ["1.2.1", "6.5.6", "11.4"],
        Framework.CIS_CONTROLS: ["4.1", "9.1", "16.5"],
    },
    
    # Vulnerability findings
    "cve_critical": {
        Framework.NIST_CSF: ["ID.RA-1", "ID.RA-5", "PR.IP-12", "RS.MI-3"],
        Framework.ISO_27001: ["A.12.6.1", "A.16.1.2"],
        Framework.PCI_DSS: ["6.5.6", "6.5.10", "11.3"],
        Framework.CIS_CONTROLS: ["7.1", "7.2", "7.3"],
    },
    "cve_high": {
        Framework.NIST_CSF: ["ID.RA-1", "ID.RA-5", "PR.IP-12"],
        Framework.ISO_27001: ["A.12.6.1"],
        Framework.PCI_DSS: ["6.5.6", "11.3"],
        Framework.CIS_CONTROLS: ["7.1", "7.2"],
    },
    "sql_injection": {
        Framework.NIST_CSF: ["PR.IP-1", "PR.DS-1", "DE.CM-1"],
        Framework.ISO_27001: ["A.14.2.5", "A.8.2.3"],
        Framework.PCI_DSS: ["6.5.1", "6.5.6", "11.4"],
        Framework.CIS_CONTROLS: ["16.5", "16.6"],
    },
    "xss": {
        Framework.NIST_CSF: ["PR.IP-1", "DE.CM-1"],
        Framework.ISO_27001: ["A.14.2.5"],
        Framework.PCI_DSS: ["6.5.7", "11.4"],
        Framework.CIS_CONTROLS: ["16.5"],
    },
    "rce": {
        Framework.NIST_CSF: ["ID.RA-1", "PR.IP-12", "RS.MI-3"],
        Framework.ISO_27001: ["A.12.6.1", "A.16.1.2"],
        Framework.PCI_DSS: ["6.5.6", "11.3"],
        Framework.CIS_CONTROLS: ["7.1", "7.3"],
    },
    
    # Authentication/Authorization findings
    "default_credentials": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-7", "PR.PT-3"],
        Framework.ISO_27001: ["A.9.2.1", "A.9.2.3", "A.9.4.3"],
        Framework.PCI_DSS: ["2.1", "8.2.1", "8.2.3"],
        Framework.CIS_CONTROLS: ["4.1", "4.7", "16.2"],
    },
    "weak_password_policy": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-7"],
        Framework.ISO_27001: ["A.9.2.1", "A.9.4.2"],
        Framework.PCI_DSS: ["8.2.3", "8.3.6", "8.3.9"],
        Framework.CIS_CONTROLS: ["4.1", "4.7", "5.2"],
    },
    "mfa_missing": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-7"],
        Framework.ISO_27001: ["A.9.4.2"],
        Framework.PCI_DSS: ["8.3.1", "8.3.2"],
        Framework.CIS_CONTROLS: ["4.5", "6.3"],
    },
    "privilege_escalation": {
        Framework.NIST_CSF: ["PR.AC-4", "PR.AC-6", "PR.PT-3"],
        Framework.ISO_27001: ["A.9.2.3", "A.9.4.4"],
        Framework.PCI_DSS: ["7.1", "7.2"],
        Framework.CIS_CONTROLS: ["4.1", "4.8", "5.4"],
    },
    
    # Data protection findings
    "sensitive_data_exposure": {
        Framework.NIST_CSF: ["PR.DS-1", "PR.DS-2", "PR.DS-5"],
        Framework.ISO_27001: ["A.8.2.1", "A.8.2.3", "A.13.2.1"],
        Framework.PCI_DSS: ["3.1", "3.2", "3.4", "4.1"],
        Framework.CIS_CONTROLS: ["3.1", "3.3", "3.5"],
    },
    "encryption_missing": {
        Framework.NIST_CSF: ["PR.DS-1", "PR.DS-2"],
        Framework.ISO_27001: ["A.10.1.1", "A.13.2.1"],
        Framework.PCI_DSS: ["3.4", "4.1"],
        Framework.CIS_CONTROLS: ["3.4", "14.8"],
    },
    
    # Configuration findings
    "misconfiguration": {
        Framework.NIST_CSF: ["PR.IP-1", "PR.IP-3", "PR.IP-12"],
        Framework.ISO_27001: ["A.12.1.2", "A.12.5.1"],
        Framework.PCI_DSS: ["2.2", "6.5.6"],
        Framework.CIS_CONTROLS: ["4.1", "5.1", "5.2"],
    },
    "unnecessary_services": {
        Framework.NIST_CSF: ["PR.IP-1", "PR.IP-9"],
        Framework.ISO_27001: ["A.12.1.2"],
        Framework.PCI_DSS: ["2.2.2", "2.2.4"],
        Framework.CIS_CONTROLS: ["4.1", "4.8", "9.2"],
    },
    
    # Credential findings
    "credential_reuse": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-7"],
        Framework.ISO_27001: ["A.9.2.1", "A.9.4.3"],
        Framework.PCI_DSS: ["8.2.1", "8.2.3"],
        Framework.CIS_CONTROLS: ["4.1", "5.2"],
    },
    "kerberos_issues": {
        Framework.NIST_CSF: ["PR.AC-1", "PR.AC-3", "PR.AC-7"],
        Framework.ISO_27001: ["A.9.2.3", "A.9.4.2"],
        Framework.PCI_DSS: ["8.3.1"],
        Framework.CIS_CONTROLS: ["4.1", "4.5", "16.4"],
    },
    
    # Cloud findings
    "s3_public": {
        Framework.NIST_CSF: ["PR.AC-3", "PR.AC-4", "PR.DS-1"],
        Framework.ISO_27001: ["A.13.1.1", "A.13.2.1", "A.8.2.1"],
        Framework.PCI_DSS: ["1.3.4", "3.4.1"],
        Framework.CIS_CONTROLS: ["3.3", "4.1", "12.3"],
    },
    "iam_overprivileged": {
        Framework.NIST_CSF: ["PR.AC-4", "PR.AC-6"],
        Framework.ISO_27001: ["A.9.2.3", "A.9.4.4"],
        Framework.PCI_DSS: ["7.1", "7.2"],
        Framework.CIS_CONTROLS: ["4.1", "4.8", "5.4"],
    },
    
    # Container findings
    "container_root": {
        Framework.NIST_CSF: ["PR.AC-4", "PR.PT-3"],
        Framework.ISO_27001: ["A.9.2.3", "A.12.1.2"],
        Framework.PCI_DSS: ["2.2", "7.1"],
        Framework.CIS_CONTROLS: ["4.1", "5.4"],
    },
    "docker_api_exposed": {
        Framework.NIST_CSF: ["PR.AC-3", "PR.AC-4", "PR.PT-4"],
        Framework.ISO_27001: ["A.13.1.1", "A.13.2.1"],
        Framework.PCI_DSS: ["1.2.1", "2.2"],
        Framework.CIS_CONTROLS: ["4.1", "4.8", "13.5"],
    },
}


def get_controls_for_finding(finding_type: str, frameworks: List[Framework]) -> Dict[Framework, List[str]]:
    """Get compliance controls relevant to a finding type."""
    finding_controls = FINDING_TO_CONTROLS.get(finding_type, {})
    return {f: finding_controls.get(f, []) for f in frameworks if f in finding_controls}


def get_all_frameworks() -> List[Framework]:
    """Get all supported frameworks."""
    return list(Framework)