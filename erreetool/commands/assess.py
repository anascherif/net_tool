import ipaddress
import json
import socket
import shutil
import time
from typing import Iterable, List, Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Only scan systems you own or are explicitly authorized to test.


def _quick_ports() -> List[int]:
    return [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]


def _default_ports() -> List[int]:
    return [
        21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 139, 143, 161, 389, 443,
        445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
    ]


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _nmap_available() -> bool:
    try:
        import nmap  # noqa: F401
    except ImportError:
        return False
    return shutil.which("nmap") is not None


def _scan_with_nmap(target: str, full: bool) -> List[Tuple[int, str, str, str]]:
    import nmap

    scanner = nmap.PortScanner()
    arguments = "-sV -T4 -p-" if full else "-sV -T4 --top-ports 1000"
    scanner.scan(hosts=target, arguments=arguments)

    results: List[Tuple[int, str, str, str]] = []
    if target not in scanner.all_hosts():
        return results

    tcp_data = scanner[target].get("tcp", {})
    for port, data in tcp_data.items():
        if data.get("state") == "open":
            service = data.get("name", "unknown")
            product = data.get("product") or ""
            version = data.get("version") or ""
            results.append((int(port), service, product, version))
    return results


def _scan_with_socket(target: str, ports: Iterable[int]) -> List[Tuple[int, str, str, str]]:
    results: List[Tuple[int, str, str, str]] = []
    port_list = list(ports)
    
    console.print(f"[dim]Scanning {len(port_list)} ports...[/dim]")
    for port in port_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((target, port)) == 0:
                results.append((port, _service_name(port), "", ""))
        finally:
            sock.close()
    return results


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _query_nvd(product: str, version: str, timeout: float = 15.0) -> List[dict]:
    import httpx
    import os

    nvd_key = os.getenv("NVD_API_KEY")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword}
    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key

    max_retries = 3
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(base_url, params=params, headers=headers)

            if resp.status_code == 403 or resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "6"))
                console.print(
                    f"[dim yellow]NVD rate-limited, retrying in {retry_after:.0f}s...[/dim yellow]"
                )
                time.sleep(retry_after)
                continue

            resp.raise_for_status()
            data = resp.json()
            vulns = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc_text = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                    "",
                )
                cvss_metrics = cve.get("metrics", {})
                cvss3 = cvss_metrics.get("cvssMetricV31", cvss_metrics.get("cvssMetricV30", []))
                score = ""
                severity = ""
                if cvss3:
                    first = cvss3[0].get("cvssData", {})
                    score = first.get("baseScore", "")
                    severity = first.get("baseSeverity", "")

                refs = [r.get("url", "") for r in cve.get("references", [])[:3]]
                vulns.append({
                    "cveId": cve_id,
                    "description": desc_text,
                    "cvss3": score,
                    "severity": severity,
                    "published": cve.get("published", ""),
                    "references": refs,
                })
            return vulns
        except (httpx.HTTPError, httpx.RequestError) as exc:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            console.print(f"[bold red]NVD query failed for {keyword}: {exc}[/bold red]")
            return []
        except Exception as exc:
            console.print(f"[bold red]NVD error for {keyword}: {exc}[/bold red]")
            return []
    return []


def _enrich_with_cves(scan_results: List[Tuple[int, str, str, str]]) -> List[dict]:
    enriched = []
    for port, service, product, version in sorted(scan_results, key=lambda x: x[0]):
        entry = {
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "version_string": f"{product} {version}".strip(),
            "cves": [],
        }
        if product and version:
            console.print(f"[dim]Querying NVD: {product} {version}...[/dim]")
            entry["cves"] = _query_nvd(product, version)
            time.sleep(6)
        enriched.append(entry)
    return enriched


def _compile_report(target: str, enriched: List[dict], offline: bool) -> dict:
    total_cves = sum(len(e["cves"]) for e in enriched)
    return {
        "target": target,
        "scan_type": "offline" if offline else "online",
        "open_ports": [
            {
                "port": e["port"],
                "service": e["service"],
                "version": e["version_string"],
                "product": e["product"],
            }
            for e in enriched
        ],
        "cve_findings": [
            {
                "port": e["port"],
                "service": e["service"],
                "version": e["version_string"],
                "cves": e["cves"],
            }
            for e in enriched if e["cves"]
        ],
        "summary": {
            "total_open_ports": len(enriched),
            "total_cves_found": total_cves if not offline else 0,
            "services_with_versions": sum(1 for e in enriched if e["version_string"]),
        },
    }


def _llm_triage(report: dict) -> Optional[str]:
    from erreetool.config import OPENROUTER_API_KEY

    if not OPENROUTER_API_KEY or not OPENROUTER_API_KEY.strip():
        console.print(
            Panel(
                "[bold red]No OPENROUTER_API_KEY found in .env[/bold red]\n"
                "Add your free OpenRouter key to .env to enable AI triage.",
                title="Configuration Missing",
            )
        )
        return None

    import httpx

    system_prompt = (
        "You are a senior security analyst performing vulnerability triage on a lab machine "
        "(e.g. Metasploitable2, HackTheBox VMs). "
        "Rank findings by exploitability/severity: Critical, High, Medium, Low. "
        "For each finding: explain in plain English why it matters, reference the CVE IDs, "
        "and indicate whether it's a likely entry point for further manual exploitation "
        "(recon-level suggestion only, not an actual exploit). "
        "Keep the tone practical and terminal-friendly — short, scannable, no fluff. "
        "Format clearly with severity labels and bullet points."
    )

    user_prompt = (
        "Analyze the following reconnaissance data and produce a vulnerability triage report "
        "ranked by severity (Critical/High/Medium/Low). For each finding explain why it matters "
        "in plain English and identify the most likely entry point for further manual exploitation.\n\n"
        f"{json.dumps(report, indent=2)}"
    )

    models = ["openrouter/auto", "openrouter/free", "poolside/laguna-xs.2:free"]
    for attempt, model in enumerate(models):
        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "max_tokens": 1500,
                        "temperature": 0.3,
                    },
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            if attempt < len(models) - 1:
                console.print(f"[dim yellow]Model {model} failed ({exc}), trying next...[/dim yellow]")
                time.sleep(1)
                continue

    console.print(Panel("[bold red]AI triage failed. See raw report above.[/bold red]"))
    return None


def run(
    target: str = typer.Argument(..., help="Target host or IP address."),
    full: bool = typer.Option(False, "--full", is_flag=True, flag_value=True, help="Scan all ports (1-65535)."),
    quick: bool = typer.Option(False, "--quick", is_flag=True, flag_value=True, help="Scan only common ports (fast)."),
    offline: bool = typer.Option(False, "--offline", is_flag=True, flag_value=True, help="Skip NVD CVE lookups."),
    explain: bool = typer.Option(False, "--explain", is_flag=True, flag_value=True, help="Show AI explanation."),
) -> None:
    console.print(Panel(f"[bold cyan]Security Assessment for {target}[/bold cyan]"))

    if _nmap_available():
        try:
            results = _scan_with_nmap(target, full)
        except Exception as exc:
            console.print(Panel(f"[bold yellow]Nmap failed: {exc}\nFalling back to socket.[/bold yellow]"))
            if quick:
                ports = _quick_ports()
            elif full:
                ports = range(1, 65536)
            else:
                ports = _default_ports()
            results = _scan_with_socket(target, ports)
    else:
        console.print(Panel("[dim]Nmap not available, using socket scanner.[/dim]"))
        if quick:
            ports = _quick_ports()
        elif full:
            ports = range(1, 65536)
        else:
            ports = _default_ports()
        results = _scan_with_socket(target, ports)

    if not results:
        console.print(Panel("[bold yellow]No open ports found.[/bold yellow]"))
        return

    ports_table = Table(title="Open Ports")
    ports_table.add_column("Port", style="cyan", justify="right")
    ports_table.add_column("Service", style="green")
    ports_table.add_column("Product", style="magenta")
    ports_table.add_column("Version", style="yellow")

    for port, service, product, version in sorted(results, key=lambda x: x[0]):
        ports_table.add_row(str(port), service, product or "-", version or "-")

    console.print(ports_table)

    if not offline:
        console.print(Panel("[bold cyan]Querying NVD for CVEs...[/bold cyan]"))
        enriched = _enrich_with_cves(results)
    else:
        console.print(Panel("[dim cyan]Offline mode — skipping NVD queries.[/dim cyan]"))
        enriched = [
            {
                "port": p, "service": s, "product": prod, "version": ver,
                "version_string": f"{prod} {ver}".strip(), "cves": [],
            }
            for p, s, prod, ver in results
        ]

    report = _compile_report(target, enriched, offline)

    if not offline and report["summary"]["total_cves_found"] > 0:
        cve_table = Table(title="CVE Summary")
        cve_table.add_column("Port", style="cyan", justify="right")
        cve_table.add_column("Service", style="green")
        cve_table.add_column("Version", style="yellow")
        cve_table.add_column("CVEs", style="red", justify="right")
        cve_table.add_column("Max Severity", style="bold red")

        for finding in report["cve_findings"]:
            severities = [c["severity"] for c in finding["cves"] if c["severity"]]
            order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            max_sev = max(severities, key=lambda x: order.get(x.upper(), 0)) if severities else "-"
            cve_table.add_row(
                str(finding["port"]),
                finding["service"],
                finding["version"] or "-",
                str(len(finding["cves"])),
                max_sev,
            )
        console.print(cve_table)

    console.print(Panel("[bold cyan]Sending to OpenRouter for AI triage...[/bold cyan]"))
    triage_text = _llm_triage(report)
    if triage_text:
        console.print(Panel(triage_text, title="[bold cyan]AI Triage Report[/bold cyan]"))

    if explain:
        from erreetool.utils.explanations import show_explanation
        show_explanation("assess", f"Assessed {target}")
