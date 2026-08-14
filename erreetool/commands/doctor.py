import os
import platform
import shutil
import socket
import subprocess
import sys
from typing import List, Tuple
import typer

from rich.console import Console
from rich.table import Table

from erreetool.utils import is_admin
from erreetool.config import OPENROUTER_API_KEY, NVIDIA_NIM_API_KEY, GROQ_API_KEY, TOGETHER_API_KEY, get_memory_dir

console = Console()


def _check_internet() -> bool:
    try:
        sock = socket.create_connection(("1.1.1.1", 53), timeout=2)
        sock.close()
        return True
    except OSError:
        return False


def _check_package(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


def _check_binary(name: str) -> Tuple[bool, str]:
    """Check if binary exists in PATH and return (found, version_string)."""
    path = shutil.which(name)
    if not path:
        return False, "not in PATH"
    try:
        result = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=5)
        version = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
        return True, version
    except Exception:
        return True, "found (version check failed)"


def _status_label(ok: bool, warn: bool = False) -> Tuple[str, str]:
    if ok:
        return "PASS", "green"
    if warn:
        return "WARN", "yellow"
    return "FAIL", "red"


def _add_check(checks: List[Tuple[str, bool, str, bool]], label: str, ok: bool, details: str, warn: bool = False):
    checks.append((label, ok, details, warn))


def run(
    explain: bool = typer.Option(False, "--explain", is_flag=True, help="Show human-friendly explanation."),
    json_output: bool = typer.Option(False, "--json", is_flag=True, help="Output as JSON."),
) -> None:
    checks: List[Tuple[str, bool, str, bool]] = []

    # ---- Core system ----
    py_ok = sys.version_info >= (3, 10)
    _add_check(checks, "Python >= 3.10", py_ok, sys.version.split()[0], False)

    _add_check(checks, "Admin privileges", is_admin(), "Required for ARP scan / raw sockets", True)

    internet_ok = _check_internet()
    _add_check(checks, "Internet connectivity", internet_ok, "1.1.1.1:53", False)

    os_name = platform.system()
    os_ok = os_name.lower() == "windows"
    _add_check(checks, "OS compatibility", os_ok, os_name, True)

    # ---- Core Python packages ----
    _add_check(checks, "typer", _check_package("typer"), "package", False)
    _add_check(checks, "rich", _check_package("rich"), "package", False)
    _add_check(checks, "scapy", _check_package("scapy"), "package", False)
    _add_check(checks, "dnspython", _check_package("dns"), "package", False)
    _add_check(checks, "python-nmap", _check_package("nmap"), "package", True)
    _add_check(checks, "speedtest-cli", _check_package("speedtest"), "package", True)
    _add_check(checks, "httpx", _check_package("httpx"), "package", False)
    _add_check(checks, "pyyaml", _check_package("yaml"), "package", False)

    # ---- Agent binaries ----
    agent_bins = [
        ("nmap", "Nmap", True),
        ("nuclei", "Nuclei", True),
        ("whatweb", "WhatWeb", True),
        ("gobuster", "Gobuster", True),
        ("feroxbuster", "Feroxbuster", False),
        ("sqlmap", "SQLMap", True),
    ]
    for binary, label, required in agent_bins:
        found, version = _check_binary(binary)
        _add_check(checks, label, found, version, warn=not required)

    # ---- LLM Providers ----
    _add_check(checks, "OpenRouter API key", bool(OPENROUTER_API_KEY), "Set OPENROUTER_API_KEY in .env", True)
    _add_check(checks, "Groq API key", bool(GROQ_API_KEY), "Set GROQ_API_KEY in .env", True)
    _add_check(checks, "Together.ai API key", bool(TOGETHER_API_KEY), "Set TOGETHER_API_KEY in .env", True)
    _add_check(checks, "NVIDIA NIM API key", bool(NVIDIA_NIM_API_KEY), "Set NVIDIA_NIM_API_KEY in .env", True)

    # ---- Memory & Output dirs ----
    try:
        mem_dir = get_memory_dir()
        mem_ok = mem_dir.exists() and os.access(mem_dir, os.W_OK)
        _add_check(checks, "Memory directory", mem_ok, str(mem_dir), False)
    except Exception as e:
        _add_check(checks, "Memory directory", False, f"error: {e}", True)

    # ---- Wordlists ----
    wordlist_paths = [
        os.path.expanduser("~/.local/share/wordlists/SecLists"),
        "/usr/share/wordlists/SecLists",
        "/opt/wordlists/SecLists",
        "C:\\Tools\\wordlists",
    ]
    wordlist_found = any(os.path.isdir(p) for p in wordlist_paths)
    wordlist_detail = next((p for p in wordlist_paths if os.path.isdir(p)), "not found (run install-tools.sh/ps1)")
    _add_check(checks, "SecLists wordlists", wordlist_found, wordlist_detail, True)

    # ---- Nuclei templates ----
    nuclei_templates = os.path.expanduser("~/nuclei-templates")
    templates_ok = os.path.isdir(nuclei_templates) and len(os.listdir(nuclei_templates)) > 0
    _add_check(checks, "Nuclei templates", templates_ok, nuclei_templates if templates_ok else "run 'nuclei -update-templates'", True)

    # ---- Output ----
    if json_output:
        import json
        data = {
            "python_version": sys.version.split()[0],
            "platform": os_name,
            "checks": [
                {"name": label, "status": "PASS" if ok else ("WARN" if warn else "FAIL"), "details": details}
                for label, ok, details, warn in checks
            ],
        }
        console.print_json(json.dumps(data))
        return

    table = Table(title="ERREETOOL Doctor — System Health Check")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", justify="center")
    table.add_column("Details", style="green")

    for label, ok, details, warn in checks:
        status, color = _status_label(ok, warn=warn)
        table.add_row(label, f"[{color}]{status}[/{color}]", details)

    console.print(table)

    # Summary
    passed = sum(1 for _, ok, _, _ in checks if ok)
    warned = sum(1 for _, ok, _, w in checks if not ok and w)
    failed = sum(1 for _, ok, _, w in checks if not ok and not w)
    console.print(f"\n[bold]Summary:[/bold] {passed} passed, {warned} warnings, {failed} failed")

    if failed > 0:
        console.print("\n[yellow]Run install scripts:[/yellow]")
        if os_name == "Windows":
            console.print("  PowerShell: .\\scripts\\install-tools.ps1")
        else:
            console.print("  Bash: ./scripts/install-tools.sh")

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("doctor")