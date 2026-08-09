"""
Nmap tool wrapper for port scanning and service detection.
"""

from typing import Optional
from erreetool.agent.tools.base import ToolWrapper, ToolResult


class NmapWrapper(ToolWrapper):
    """Wrapper for nmap port scanner."""
    
    name = "nmap"
    windows_binary = "nmap.exe"
    linux_binary = "nmap"
    DEFAULT_TIMEOUT = 600  # 10 minutes for full scans
    
    def build_args(
        self,
        target: str,
        ports: str = "top-1000",
        service_detection: bool = True,
        os_detection: bool = False,
        scripts: str = None,
        timing: str = "T4",
        output_format: str = "normal",
        extra_args: list[str] = None,
        **kwargs
    ) -> list[str]:
        """Build nmap command arguments."""
        args = []
        
        # Timing template
        args.extend(["-T", timing])
        
        # Port specification
        if ports == "all":
            args.append("-p-")
        elif ports == "top-1000":
            args.append("--top-ports 1000")
        elif ports == "top-100":
            args.append("--top-ports 100")
        else:
            args.extend(["-p", ports])
        
        # Service detection
        if service_detection:
            args.append("-sV")
        
        # OS detection
        if os_detection:
            args.append("-O")
        
        # NSE scripts
        if scripts:
            args.extend(["--script", scripts])
        
        # Output format
        if output_format == "xml":
            args.extend(["-oX", "-"])
        elif output_format == "json":
            args.extend(["-oJ", "-"])
        elif output_format == "grepable":
            args.extend(["-oG", "-"])
        
        # Extra args
        if extra_args:
            args.extend(extra_args)
        
        # Target (always last)
        args.append(target)
        
        return args
    
    def quick_scan(self, target: str) -> ToolResult:
        """Quick scan of top 100 ports."""
        return self.run(target=target, ports="top-100", timing="T4")
    
    def full_scan(self, target: str) -> ToolResult:
        """Full port scan with service detection."""
        return self.run(target=target, ports="all", service_detection=True, timing="T3")
    
    def service_scan(self, target: str, ports: str = "top-1000") -> ToolResult:
        """Service version detection on specific ports."""
        return self.run(target=target, ports=ports, service_detection=True)
    
    def vuln_scan(self, target: str, ports: str = "top-1000") -> ToolResult:
        """Run vulnerability scripts."""
        return self.run(
            target=target,
            ports=ports,
            service_detection=True,
            scripts="vuln",
            timing="T3"
        )
    
    def smb_scan(self, target: str) -> ToolResult:
        """SMB-specific enumeration."""
        return self.run(
            target=target,
            ports="445,139",
            scripts="smb-enum-shares,smb-enum-users,smb-vuln*",
            service_detection=True
        )


# Register the tool
from erreetool.agent.tools.base import tool_registry
tool_registry.register(NmapWrapper())