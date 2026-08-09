"""
WhatWeb tool wrapper for web technology fingerprinting.

Identifies CMS, frameworks, servers, and other web technologies.
"""

from erreetool.agent.tools.base import ToolWrapper, ToolResult


class WhatWebWrapper(ToolWrapper):
    """Wrapper for whatweb technology fingerprinting."""
    
    name = "whatweb"
    windows_binary = "whatweb.exe"
    linux_binary = "whatweb"
    DEFAULT_TIMEOUT = 120
    
    def build_args(
        self,
        target: str,
        aggression: int = 1,
        plugins: str = None,
        output_format: str = "json",
        extra_args: list[str] = None,
        **kwargs
    ) -> list[str]:
        """Build whatweb command arguments."""
        args = []
        
        # Aggression level (1-4)
        args.extend(["-a", str(aggression)])
        
        # Plugins
        if plugins:
            args.extend(["-p", plugins])
        
        # Output format
        if output_format == "json":
            args.extend(["--log-json=-"])
        elif output_format == "xml":
            args.extend(["--log-xml=-"])
        elif output_format == "brief":
            args.extend(["--log-brief=-"])
        
        # No color, quiet
        args.extend(["--no-colors", "--quiet"])
        
        # Extra args
        if extra_args:
            args.extend(extra_args)
        
        # Target
        args.append(target)
        
        return args
    
    def scan(self, target: str, aggression: int = 2) -> ToolResult:
        """Standard technology scan."""
        return self.run(target=target, aggression=aggression)
    
    def aggressive_scan(self, target: str) -> ToolResult:
        """Aggressive scan (may trigger WAF)."""
        return self.run(target=target, aggression=3)
    
    def cms_scan(self, target: str) -> ToolResult:
        """Focus on CMS detection."""
        return self.run(target=target, plugins="cms,wordpress,joomla,drupal")


# Register the tool
from erreetool.agent.tools.base import tool_registry
tool_registry.register(WhatWebWrapper())