"""
Tool registry - exports all available tool wrappers.
"""

from erreetool.agent.tools.base import ToolWrapper, ToolResult, ToolRegistry, tool_registry
from erreetool.agent.tools.nmap import NmapWrapper
from erreetool.agent.tools.nuclei import NucleiWrapper
from erreetool.agent.tools.whatweb import WhatWebWrapper
from erreetool.agent.tools.gobuster import GobusterWrapper, FeroxbusterWrapper
from erreetool.agent.tools.sqlmap import SQLMapWrapper
from erreetool.agent.tools.crypto import CryptoWrapper, CryptoTool

__all__ = [
    "ToolWrapper",
    "ToolResult", 
    "ToolRegistry",
    "tool_registry",
    "NmapWrapper",
    "NucleiWrapper",
    "WhatWebWrapper",
    "GobusterWrapper",
    "FeroxbusterWrapper",
    "SQLMapWrapper",
    "CryptoWrapper",
    "CryptoTool",
]