"""
Compliance Mapping Module

Maps findings to compliance frameworks:
- NIST Cybersecurity Framework (CSF)
- ISO 27001 / ISO 27002
- PCI-DSS v4.0
- CIS Controls v8
- MITRE ATT&CK (already implemented)

Usage:
    from erreetool.compliance import ComplianceMapper, Framework
    
    mapper = ComplianceMapper()
    mappings = mapper.map_findings(findings, [Framework.NIST_CSF, Framework.ISO_27001])
"""
from erreetool.compliance.mapper import ComplianceMapper, Framework
from erreetool.compliance.models import (
    ComplianceRequirement,
    ComplianceMapping,
    ComplianceReport,
    ControlStatus,
)

__all__ = [
    "ComplianceMapper",
    "Framework",
    "ComplianceRequirement",
    "ComplianceMapping",
    "ComplianceReport",
    "ControlStatus",
]