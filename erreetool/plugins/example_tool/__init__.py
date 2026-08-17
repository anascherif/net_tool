"""
Example Tool Plugin - Demonstrates how to create a custom tool plugin.

This plugin adds a simple 'whois' tool for domain registration lookup.
"""
import subprocess
import re
from typing import Dict, Any

from erreetool.plugins import ToolPlugin, PluginMetadata
from erreetool.agent.tools.base import ToolWrapper, ToolResult


class WhoisTool(ToolWrapper):
    """WHOIS lookup tool wrapper."""
    
    name = "whois"
    windows_binary = "whois.exe"
    linux_binary = "whois"
    
    def build_args(self, **kwargs) -> list:
        target = kwargs.get("target", "")
        return [target]
    
    def is_available(self) -> bool:
        # Check if whois is available
        try:
            subprocess.run(["whois", "--version"], capture_output=True, timeout=2)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def run(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        if not target:
            return ToolResult(
                success=False,
                stdout="",
                stderr="No target specified",
                returncode=1,
                command=["whois"],
                duration=0,
                evidence_id="whois_error",
                tool_name="whois",
            )
        
        import time
        start = time.time()
        
        try:
            proc = subprocess.run(
                ["whois", target],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            return ToolResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                command=["whois", target],
                duration=time.time() - start,
                evidence_id=f"whois_{int(start)}",
                tool_name="whois",
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                stdout="",
                stderr="Timeout after 30s",
                returncode=-1,
                command=["whois", target],
                duration=time.time() - start,
                evidence_id=f"whois_{int(start)}",
                tool_name="whois",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                stdout="",
                stderr=str(e),
                returncode=-1,
                command=["whois", target],
                duration=time.time() - start,
                evidence_id=f"whois_{int(start)}",
                tool_name="whois",
            )


class WhoisPlugin(ToolPlugin):
    """WHOIS tool plugin."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="whois-tool",
            version="1.0.0",
            description="WHOIS domain registration lookup tool",
            author="ERREETOOL Team",
            license="MIT",
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return True
    
    def shutdown(self) -> None:
        pass
    
    def get_tool_class(self) -> type:
        return WhoisTool
    
    def get_tool_name(self) -> str:
        return "whois"


# Plugin entry point
def get_plugin() -> WhoisPlugin:
    """Entry point for plugin loader."""
    return WhoisPlugin()