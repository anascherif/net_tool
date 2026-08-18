"""
MITRE ATT&CK mapping for reports and findings.

Provides structured mapping from findings/vulnerabilities to
MITRE ATT&CK techniques and tactics for compliance reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Minimal MITRE ATT&CK dataset (enterprise matrix)
# In production, this would be loaded from STIX or the official MITRE JSON

_MITRE_TECHNIQUES = {
    # Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": [
            "initial-access",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
        ],
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactics": ["initial-access"],
        "description": "Adversaries may leverage external remote services to access a network.",
    },
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["execution"],
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["execution"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactics": ["execution"],
        "description": "Adversaries may abuse Unix shell commands and scripts for execution.",
    },
    # Persistence
    "T1505.003": {
        "name": "Web Shell",
        "tactics": ["persistence", "execution"],
        "description": "Adversaries may backdoor web servers with web shells.",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactics": ["persistence"],
        "description": "Adversaries may manipulate accounts to maintain access.",
    },
    # Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactics": ["privilege-escalation"],
        "description": "Adversaries may exploit software vulnerabilities to escalate privileges.",
    },
    "T1078.003": {
        "name": "Local Accounts",
        "tactics": ["privilege-escalation"],
        "description": "Adversaries may obtain and abuse credentials of local accounts.",
    },
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactics": ["privilege-escalation", "defense-evasion"],
        "description": "Adversaries may bypass UAC mechanisms to elevate privileges.",
    },
    # Defense Evasion
    "T1070": {
        "name": "Indicator Removal",
        "tactics": ["defense-evasion"],
        "description": "Adversaries may delete or modify artifacts to remove evidence.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactics": ["defense-evasion"],
        "description": "Adversaries may use trusted system binaries to execute malicious code.",
    },
    # Credential Access
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ["credential-access"],
        "description": "Adversaries may attempt to dump credentials from OS storage.",
    },
    "T1558.004": {
        "name": "AS-REP Roasting",
        "tactics": ["credential-access"],
        "description": "Adversaries may exploit Kerberos pre-authentication configuration.",
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactics": ["credential-access"],
        "description": "Adversaries may exploit Kerberos service principal names.",
    },
    "T1555.003": {
        "name": "Credentials from Web Browsers",
        "tactics": ["credential-access"],
        "description": "Adversaries may extract credentials from web browsers.",
    },
    # Discovery
    "T1018": {
        "name": "Remote System Discovery",
        "tactics": ["discovery"],
        "description": "Adversaries may attempt to get a listing of other systems by IP address.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactics": ["discovery"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactics": ["discovery"],
        "description": "Adversaries may attempt to get detailed information about the OS and hardware.",
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactics": ["discovery"],
        "description": "Adversaries may attempt to find group and permission settings.",
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactics": ["discovery"],
        "description": "Adversaries may attempt to gather information on domain trust relationships.",
    },
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactics": ["lateral-movement"],
        "description": "Adversaries may use valid accounts to log into remote services.",
    },
    "T1021.004": {
        "name": "Pass the Hash",
        "tactics": ["lateral-movement", "credential-access"],
        "description": "Adversaries may use Pass the Hash to move laterally.",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactics": ["lateral-movement"],
        "description": "Adversaries may use RDP to log into remote systems.",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactics": ["lateral-movement"],
        "description": "Adversaries may use SMB to move laterally.",
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactics": ["lateral-movement"],
        "description": "Adversaries may use WinRM to move laterally.",
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactics": ["lateral-movement"],
        "description": "Adversaries may exploit remote services to gain access.",
    },
    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactics": ["collection"],
        "description": "Adversaries may search local systems to find files of interest.",
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactics": ["collection"],
        "description": "Adversaries may search network shared drives for files of interest.",
    },
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactics": ["command-and-control"],
        "description": "Adversaries may communicate using application layer protocols.",
    },
    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over Command and Control Channel",
        "tactics": ["exfiltration"],
        "description": "Adversaries may exfiltrate data over C2 channels.",
    },
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ["impact"],
        "description": "Adversaries may encrypt data for impact (ransomware).",
    },
}


# Mapping from our findings to MITRE techniques
_FINDING_TO_MITRE = {
    # Vulnerabilities
    "cve": ["T1190", "T1068"],  # Exploit public-facing app, priv esc
    "sql_injection": ["T1190", "T1059"],  # Web app exploit
    "rce": ["T1190", "T1210"],  # Remote code execution
    "lfi": ["T1190", "T1005"],  # Local file inclusion
    "rfi": ["T1190", "T1105"],  # Remote file inclusion
    # Services & open ports
    "smb": ["T1021.002", "T1021.004"],  # SMB, Pass the Hash
    "rdp": ["T1021.001"],  # RDP
    "winrm": ["T1021.006"],  # WinRM
    # Credential access
    "as-rep roastable": ["T1558.004"],  # AS-REP Roasting
    "ssh": ["T1021", "T1003"],  # SSH, credential dumping
    "ldap": ["T1069", "T1482"],  # AD discovery
    "kerberos": ["T1558.003", "T1558.004"],  # Kerberoasting, AS-REP
    "mssql": ["T1021.002", "T1003"],  # SQL Server
    "mysql": ["T1021", "T1003"],
    "postgresql": ["T1021", "T1003"],
    "vnc": ["T1021"],  # VNC
    "ftp": ["T1021", "T1005"],  # FTP
    # Web
    "web_shell": ["T1505.003"],  # Web shell
    "directory_traversal": ["T1005", "T1039"],
    "open_redirect": ["T1190"],
    "xss": ["T1190"],
    "csrf": ["T1190"],
    "cors_misconfig": ["T1190"],
    # Credentials
    "default_credentials": ["T1078"],
    "weak_password": ["T1078", "T1110"],
    "credential_dumping": ["T1003"],
    "as_rep_roastable": ["T1558.004"],
    "kerberoastable": ["T1558.003"],
    # Config
    "unquoted_service_path": ["T1574.009"],
    "always_install_elevated": ["T1548.002"],
    "writable_service": ["T1574.009"],
    # Cloud
    "imdsv1_exposed": ["T1082", "T1530"],  # AWS metadata
    "s3_bucket_open": ["T1005", "T1530"],  # Data from cloud storage
    "docker_api_exposed": ["T1190", "T1611"],  # Docker daemon
    "k8s_api_exposed": ["T1190", "T1611"],  # K8s API
}


@dataclass
class MITRETechnique:
    """A MITRE ATT&CK technique."""

    id: str
    name: str
    tactics: list[str]
    description: str


@dataclass
class MITREMapping:
    """A mapping from a finding to MITRE techniques."""

    finding: str
    finding_type: str
    techniques: list[MITRETechnique] = field(default_factory=list)
    primary_tactic: str = ""

    def to_dict(self) -> dict:
        return {
            "finding": self.finding,
            "finding_type": self.finding_type,
            "techniques": [
                {"id": t.id, "name": t.name, "tactics": t.tactics}
                for t in self.techniques
            ],
            "primary_tactic": self.primary_tactic,
        }


def get_technique(technique_id: str) -> MITRETechnique | None:
    """Get a MITRE technique by ID."""
    if technique_id not in _MITRE_TECHNIQUES:
        return None
    data = _MITRE_TECHNIQUES[technique_id]
    return MITRETechnique(
        id=technique_id,
        name=data["name"],
        tactics=data["tactics"],
        description=data["description"],
    )


def map_finding_to_mitre(finding: str, finding_type: str = "") -> MITREMapping:
    """Map a finding to MITRE ATT&CK techniques."""
    techniques: list[MITRETechnique] = []
    seen = set()

    # Check finding type mapping
    type_key = finding_type.lower()
    if type_key in _FINDING_TO_MITRE:
        for tid in _FINDING_TO_MITRE[type_key]:
            if tid not in seen:
                t = get_technique(tid)
                if t:
                    techniques.append(t)
                    seen.add(tid)

    # Check finding text for keywords
    finding_lower = finding.lower()
    for keyword, tids in _FINDING_TO_MITRE.items():
        if keyword in finding_lower:
            for tid in tids:
                if tid not in seen:
                    t = get_technique(tid)
                    if t:
                        techniques.append(t)
                        seen.add(tid)

    # Determine primary tactic
    tactic_counts = {}
    for t in techniques:
        for tactic in t.tactics:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    primary_tactic = (
        max(tactic_counts.items(), key=lambda x: x[1])[0] if tactic_counts else ""
    )

    return MITREMapping(
        finding=finding,
        finding_type=finding_type,
        techniques=techniques,
        primary_tactic=primary_tactic,
    )


def map_findings_batch(
    findings: list[str], types: list[str] = None
) -> list[MITREMapping]:
    """Map multiple findings to MITRE ATT&CK."""
    if types is None:
        types = [""] * len(findings)
    return [map_finding_to_mitre(f, t) for f, t in zip(findings, types)]


def get_tactic_summary(mappings: list[MITREMapping]) -> dict[str, int]:
    """Get count of findings per MITRE tactic."""
    tactic_counts = {}
    for m in mappings:
        for t in m.techniques:
            for tactic in t.tactics:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    return dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True))


def get_technique_summary(mappings: list[MITREMapping]) -> dict[str, int]:
    """Get count of findings per MITRE technique."""
    tech_counts = {}
    for m in mappings:
        for t in m.techniques:
            tech_counts[t.id] = tech_counts.get(t.id, 0) + 1
    return dict(sorted(tech_counts.items(), key=lambda x: x[1], reverse=True))


# ============================================================
# Report generation helpers
# ============================================================


def generate_mitre_heatmap(mappings: list[MITREMapping]) -> str:
    """Generate a markdown heatmap table for MITRE tactics."""
    tactic_counts = get_tactic_summary(mappings)
    if not tactic_counts:
        return "No MITRE mappings found."

    # Tactic order (standard MITRE order)
    tactic_order = [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]

    lines = [
        "| Tactic | Findings |",
        "|--------|----------|",
    ]
    for tactic in tactic_order:
        if tactic in tactic_counts:
            count = tactic_counts[tactic]
            # Use text-based bar for Windows compatibility
            bar = "#" * min(count, 10)
            lines.append(f"| {tactic.replace('-', ' ').title()} | {count} {bar} |")

    return "\n".join(lines)


def generate_mitre_technique_table(mappings: list[MITREMapping]) -> str:
    """Generate a markdown table of top MITRE techniques."""
    tech_counts = get_technique_summary(mappings)
    if not tech_counts:
        return "No MITRE techniques mapped."

    lines = [
        "| Technique ID | Name | Count | Tactic(s) |",
        "|--------------|------|-------|-----------|",
    ]
    for tid, count in list(tech_counts.items())[:20]:
        t = get_technique(tid)
        if t:
            tactics = ", ".join(t.tactics)
            lines.append(f"| {tid} | {t.name} | {count} | {tactics} |")

    return "\n".join(lines)


if __name__ == "__main__":
    # Quick test
    findings = [
        "Port 445/tcp open: smb",
        "Vulnerability found: CVE-2021-34527",
        "AS-REP roastable user: john",
        "SQL injection vulnerability detected",
    ]
    types = ["service", "vulnerability", "credential", "vulnerability"]

    mappings = map_findings_batch(findings, types)

    print("=== MITRE Heatmap ===")
    print(generate_mitre_heatmap(mappings))

    print("\n=== Top Techniques ===")
    print(generate_mitre_technique_table(mappings))
