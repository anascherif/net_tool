"""
Nuclei tool wrapper for vulnerability scanning.

Uses 3000+ community templates for CVE detection, misconfigurations, etc.
"""

from typing import Optional
from erreetool.agent.tools.base import ToolWrapper, ToolResult


class NucleiWrapper(ToolWrapper):
    """Wrapper for nuclei vulnerability scanner."""
    
    name = "nuclei"
    windows_binary = "nuclei.exe"
    linux_binary = "nuclei"
    DEFAULT_TIMEOUT = 600
    
    def build_args(
        self,
        target: str,
        templates: str = None,
        tags: str = None,
        severity: str = None,
        exclude_tags: str = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        output_format: str = "json",
        extra_args: list[str] = None,
        **kwargs
    ) -> list[str]:
        """Build nuclei command arguments."""
        args = []
        
        # Target
        args.extend(["-u", target])
        
        # Templates
        if templates:
            args.extend(["-t", templates])
        
        # Tags
        if tags:
            args.extend(["-tags", tags])
        
        # Severity filter
        if severity:
            args.extend(["-severity", severity])
        
        # Exclude tags
        if exclude_tags:
            args.extend(["-exclude-tags", exclude_tags])
        
        # Rate limiting
        args.extend(["-rate-limit", str(rate_limit)])
        args.extend(["-c", str(concurrency)])
        
        # Output format
        if output_format == "json":
            args.extend(["-json"])
        elif output_format == "markdown":
            args.extend(["-markdown-export", "-"])
        
        # Always include template info
        args.append("-include-rr")
        args.append("-include-tags")
        
        # Extra args
        if extra_args:
            args.extend(extra_args)
        
        return args
    
    def quick_scan(self, target: str) -> ToolResult:
        """Quick scan with critical/high severity templates."""
        return self.run(
            target=target,
            severity="critical,high",
            rate_limit=100
        )
    
    def full_scan(self, target: str) -> ToolResult:
        """Full scan with all templates."""
        return self.run(target=target, rate_limit=50)
    
    def cve_scan(self, target: str) -> ToolResult:
        """Scan for known CVEs only."""
        return self.run(
            target=target,
            tags="cve",
            severity="critical,high,medium"
        )
    
    def misconfig_scan(self, target: str) -> ToolResult:
        """Scan for misconfigurations."""
        return self.run(
            target=target,
            tags="misconfig",
            severity="high,medium,low"
        )
    
    def tech_scan(self, target: str) -> ToolResult:
        """Technology detection scan."""
        return self.run(
            target=target,
            tags="tech,tech-detect",
            severity="info"
        )
    
    def custom_template(self, target: str, template_path: str) -> ToolResult:
        """Run a custom template file or directory."""
        return self.run(target=target, templates=template_path)


# Register the tool
from erreetool.agent.tools.base import tool_registry
tool_registry.register(NucleiWrapper())