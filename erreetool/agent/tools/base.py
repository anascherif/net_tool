"""
Cross-platform tool wrapper base class.

Provides unified interface for executing CLI tools on Windows and Linux.
"""

import platform
import shutil
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ToolResult:
    """Result of a tool execution."""
    success: bool
    stdout: str
    stderr: str
    returncode: int
    command: list[str]
    duration: float
    evidence_id: str = ""
    tool_name: str = ""
    metadata: dict = field(default_factory=dict)
    
    @property
    def output(self) -> str:
        """Combined stdout and stderr."""
        if self.stdout and self.stderr:
            return f"{self.stdout}\n--- STDERR ---\n{self.stderr}"
        return self.stdout or self.stderr or ""
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "command": self.command,
            "duration": self.duration,
            "evidence_id": self.evidence_id,
            "tool_name": self.tool_name,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ToolResult":
        return cls(**data)


class ToolWrapper(ABC):
    """
    Abstract base class for cross-platform tool wrappers.
    
    Subclasses must define:
    - name: Tool identifier
    - windows_binary: Binary name on Windows (e.g., "nmap.exe")
    - linux_binary: Binary name on Linux (e.g., "nmap")
    - build_args(): Convert parameters to command-line arguments
    """
    
    # Default timeout in seconds
    DEFAULT_TIMEOUT = 300
    
    def __init__(self, timeout: int = None, custom_binary: str = None):
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.custom_binary = custom_binary
        self._binary_path: Optional[str] = None
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Tool identifier (e.g., 'nmap', 'nuclei')."""
        pass
    
    @property
    @abstractmethod
    def windows_binary(self) -> str:
        """Binary name on Windows."""
        pass
    
    @property
    @abstractmethod
    def linux_binary(self) -> str:
        """Binary name on Linux/macOS."""
        pass
    
    @property
    def binary(self) -> str:
        """Get the appropriate binary for current platform."""
        if self.custom_binary:
            return self.custom_binary
        if platform.system() == "Windows":
            return self.windows_binary
        return self.linux_binary
    
    @abstractmethod
    def build_args(self, **kwargs) -> list[str]:
        """Build command-line arguments from parameters."""
        pass
    
    def resolve_binary(self) -> Optional[str]:
        """Resolve full path to binary."""
        if self._binary_path:
            return self._binary_path
        
        binary = self.binary
        path = shutil.which(binary)
        if path:
            self._binary_path = path
            return path
        
        # Try common install locations on Windows
        if platform.system() == "Windows":
            common_paths = [
                Path(r"C:\Program Files") / binary,
                Path(r"C:\Program Files (x86)") / binary,
                Path(r"C:\Tools") / binary,
                Path.home() / "scoop" / "shims" / binary,
                Path.home() / "AppData" / "Local" / "Microsoft" / "WinGet" / "Links" / binary,
            ]
            for p in common_paths:
                if p.exists():
                    self._binary_path = str(p)
                    return str(p)
        
        return None
    
    def is_available(self) -> bool:
        """Check if tool is installed and available."""
        return self.resolve_binary() is not None
    
    def run(self, **kwargs) -> ToolResult:
        """
        Execute the tool with given parameters.
        
        Returns ToolResult with stdout, stderr, returncode, etc.
        """
        binary_path = self.resolve_binary()
        if not binary_path:
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Tool '{self.name}' not found. Binary: {self.binary}",
                returncode=-1,
                command=[],
                duration=0,
                tool_name=self.name,
                metadata={"error": "binary_not_found"},
            )
        
        args = self.build_args(**kwargs)
        command = [binary_path] + args
        
        evidence_id = f"{self.name}_{uuid.uuid4().hex[:8]}"
        start_time = time.time()
        
        try:
            # Use shell=False for security, but handle Windows paths
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
            )
            duration = time.time() - start_time
            
            return ToolResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                command=command,
                duration=duration,
                evidence_id=evidence_id,
                tool_name=self.name,
            )
        
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Tool '{self.name}' timed out after {self.timeout}s",
                returncode=-1,
                command=command,
                duration=duration,
                evidence_id=evidence_id,
                tool_name=self.name,
                metadata={"error": "timeout"},
            )
        
        except Exception as e:
            duration = time.time() - start_time
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Tool '{self.name}' execution failed: {e}",
                returncode=-1,
                command=command,
                duration=duration,
                evidence_id=evidence_id,
                tool_name=self.name,
                metadata={"error": "exception", "exception": str(e)},
            )


class ToolRegistry:
    """Registry for managing available tools."""
    
    def __init__(self):
        self._tools: dict[str, ToolWrapper] = {}
    
    def register(self, tool: ToolWrapper):
        """Register a tool wrapper."""
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> Optional[ToolWrapper]:
        """Get tool by name."""
        return self._tools.get(name)
    
    def list_available(self) -> list[str]:
        """List names of available tools."""
        return [name for name, tool in self._tools.items() if tool.is_available()]
    
    def list_all(self) -> list[str]:
        """List all registered tools."""
        return list(self._tools.keys())
    
    def get_status(self) -> dict[str, bool]:
        """Get availability status for all tools."""
        return {name: tool.is_available() for name, tool in self._tools.items()}


# Global registry instance
tool_registry = ToolRegistry()