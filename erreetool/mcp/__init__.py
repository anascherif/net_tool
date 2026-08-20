"""
MCP (Model Context Protocol) Client and Server Framework.

Provides stdio-based MCP communication for tool integration.
Supports fetch, memory, chrome-devtools, and burp servers.
"""

import asyncio
import json
import os
import shlex
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from enum import Enum

from rich.console import Console

console = Console()


class TransportType(str, Enum):
    """MCP transport type."""
    STDIO = "stdio"
    SSE = "sse"


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""
    name: str
    enabled: bool = False
    transport: TransportType = TransportType.STDIO
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    working_dir: str = ""
    timeout: float = 30.0
    auto_restart: bool = True
    max_restarts: int = 3


@dataclass
class MCPTool:
    """MCP tool definition."""
    name: str
    description: str
    input_schema: dict
    server_name: str = ""
    server_name: str


@dataclass
class MCPServer:
    """MCP server instance."""
    config: MCPServerConfig
    process: Optional[subprocess.Popen] = None
    tools: dict[str, MCPTool] = field(default_factory=dict)
    initialized: bool = False
    restart_count: int = 0
    
    def __post_init__(self):
        if not self.config.working_dir:
            self.config.working_dir = str(Path.cwd())


class MCPClient:
    """
    MCP Client for stdio-based communication with MCP servers.
    
    Handles:
    - Process lifecycle (start, stop, restart)
    - JSON-RPC communication over stdin/stdout
    - Tool discovery and invocation
    - Request/response correlation
    """
    
    def __init__(self, server: MCPServer):
        self.server = server
        self._request_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._buffer = ""
    
    async def start(self) -> bool:
        """Start the MCP server process."""
        if self.server.process and self.server.process.poll() is None:
            return True  # Already running
        
        try:
            env = os.environ.copy()
            env.update(self.server.config.env)
            
            self.server.process = subprocess.Popen(
                [self.server.config.command] + self.server.config.args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.server.config.working_dir,
                env=env,
                text=True,
                bufsize=1,  # Line buffered
            )
            
            # Start reader task
            self._reader_task = asyncio.create_task(self._read_loop())
            
            # Initialize
            await self._initialize()
            
            console.print(f"[green]MCP server '{self.server.config.name}' started[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Failed to start MCP server '{self.server.config.name}': {e}[/red]")
            return False
    
    async def stop(self):
        """Stop the MCP server process."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        
        if self.server.process:
            try:
                self.server.process.terminate()
                await asyncio.wait_for(
                    asyncio.to_thread(self.server.process.wait),
                    timeout=5.0
                )
            except (subprocess.TimeoutExpired, asyncio.TimeoutError):
                self.server.process.kill()
                await asyncio.to_thread(self.server.process.wait)
            self.server.process = None
        
        self.server.initialized = False
        console.print(f"[dim]MCP server '{self.server.config.name}' stopped[/dim]")
    
    async def restart(self) -> bool:
        """Restart the MCP server."""
        await self.stop()
        self.server.restart_count += 1
        if self.server.restart_count > self.server.config.max_restarts:
            console.print(f"[red]Max restarts exceeded for '{self.server.config.name}'[/red]")
            return False
        return await self.start()
    
    async def _initialize(self):
        """Send initialize request and discover tools."""
        # Send initialize
        init_response = await self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "erreetool", "version": "1.0.0"}
        })
        
        # Send initialized notification
        await self._send_notification("notifications/initialized", {})
        
        # List tools
        tools_response = await self._send_request("tools/list", {})
        
        if "tools" in tools_response:
            for tool_data in tools_response["tools"]:
                tool = MCPTool(
                    name=tool_data["name"],
                    description=tool_data.get("description", ""),
                    input_schema=tool_data.get("inputSchema", {}),
                    server_name=self.server.config.name
                )
                self.server.tools[tool.name] = tool
            
            self.server.initialized = True
            console.print(f"[dim]MCP server '{self.server.config.name}' initialized with {len(self.server.tools)} tools[/dim]")
    
    async def _read_loop(self):
        """Background task to read stdout from server process."""
        if not self.server.process or not self.server.process.stdout:
            return
        
        try:
            loop = asyncio.get_event_loop()
            while True:
                line = await loop.run_in_executor(None, self.server.process.stdout.readline)
                if not line:
                    break  # EOF
                
                line = line.strip()
                if not line:
                    continue
                
                try:
                    message = json.loads(line)
                    await self._handle_message(message)
                except json.JSONDecodeError:
                    console.print(f"[yellow]MCP '{self.server.config.name}' invalid JSON: {line[:100]}[/yellow]")
                    
        except asyncio.CancelledError:
            raise
        except Exception as e:
            console.print(f"[red]MCP '{self.server.config.name}' read error: {e}[/red]")
    
    async def _handle_message(self, message: dict):
        """Handle incoming message (response or notification)."""
        # Response to our request
        if "id" in message and message["id"] in self._pending:
            future = self._pending.pop(message["id"])
            if "error" in message:
                future.set_exception(Exception(message["error"].get("message", "Unknown error")))
            else:
                future.set_result(message.get("result"))
            return
        
        # Notification (server -> client)
        if "method" in message and message["method"].startswith("notifications/"):
            # Handle notifications if needed
            pass
    
    async def _send_request(self, method: str, params: dict = None) -> dict:
        """Send a JSON-RPC request and wait for response."""
        if not self.server.process or self.server.process.poll() is not None:
            raise RuntimeError(f"MCP server '{self.server.config.name}' not running")
        
        self._request_id += 1
        request_id = self._request_id
        
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {}
        }
        
        future = asyncio.Future()
        self._pending[request_id] = future
        
        try:
            await self._write_line(request)
            result = await asyncio.wait_for(future, timeout=self.server.config.timeout)
            return result
        except asyncio.TimeoutError:
            self._pending.pop(request_id, None)
            raise TimeoutError(f"MCP request {method} timed out")
        except Exception:
            self._pending.pop(request_id, None)
            raise
    
    async def _send_notification(self, method: str, params: dict = None):
        """Send a JSON-RPC notification (no response expected)."""
        if not self.server.process or self.server.process.poll() is not None:
            return
        
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {}
        }
        
        await self._write_line(notification)
    
    async def _write_line(self, data: dict):
        """Write a JSON line to stdin."""
        if not self.server.process or not self.server.process.stdin:
            raise RuntimeError("Server stdin not available")
        
        line = json.dumps(data) + "\n"
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.server.process.stdin.write, line)
        await loop.run_in_executor(None, self.server.process.stdin.flush)
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool on this server."""
        if tool_name not in self.server.tools:
            raise ValueError(f"Tool '{tool_name}' not found on server '{self.server.config.name}'")
        
        result = await self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })
        return result
    
    def is_running(self) -> bool:
        """Check if server process is running."""
        return self.server.process is not None and self.server.process.poll() is None


class MCPRegistry:
    """
    Registry for managing multiple MCP servers.
    
    Handles:
    - Server configuration and lifecycle
    - Unified tool discovery across all servers
    - Tool routing to appropriate server
    """
    
    def __init__(self):
        self._servers: dict[str, MCPServer] = {}
        self._clients: dict[str, MCPClient] = {}
        self._tool_to_server: dict[str, str] = {}
    
    def register_server(self, config: MCPServerConfig) -> MCPServer:
        """Register an MCP server configuration."""
        server = MCPServer(config=config)
        self._servers[config.name] = server
        return server
    
    def get_server(self, name: str) -> Optional[MCPServer]:
        """Get server by name."""
        return self._servers.get(name)
    
    def get_client(self, name: str) -> Optional[MCPClient]:
        """Get client for server."""
        return self._clients.get(name)
    
    async def start_server(self, name: str) -> bool:
        """Start a specific server."""
        server = self._servers.get(name)
        if not server:
            return False
        
        if not server.config.enabled:
            console.print(f"[yellow]MCP server '{name}' is disabled[/yellow]")
            return False
        
        client = MCPClient(server)
        self._clients[name] = client
        
        success = await client.start()
        if success:
            # Update tool routing
            for tool_name in server.tools:
                self._tool_to_server[tool_name] = name
        return success
    
    async def start_all(self) -> dict[str, bool]:
        """Start all enabled servers."""
        results = {}
        for name, server in self._servers.items():
            if server.config.enabled:
                results[name] = await self.start_server(name)
        return results
    
    async def stop_server(self, name: str):
        """Stop a specific server."""
        client = self._clients.pop(name, None)
        if client:
            await client.stop()
        
        # Remove tool routing
        server = self._servers.get(name)
        if server:
            for tool_name in server.tools:
                self._tool_to_server.pop(tool_name, None)
    
    async def stop_all(self):
        """Stop all servers."""
        for name in list(self._clients.keys()):
            await self.stop_server(name)
    
    def list_tools(self) -> list[dict]:
        """List all available tools across all servers."""
        tools = []
        for server in self._servers.values():
            if server.initialized:
                for tool in server.tools.values():
                    tools.append({
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                        "server": server.config.name
                    })
        return tools
    
    def get_tool_server(self, tool_name: str) -> Optional[str]:
        """Get the server name that provides a tool."""
        return self._tool_to_server.get(tool_name)
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool, routing to the correct server."""
        server_name = self.get_tool_server(tool_name)
        if not server_name:
            raise ValueError(f"Tool '{tool_name}' not found on any server")
        
        client = self._clients.get(server_name)
        if not client:
            raise RuntimeError(f"Server '{server_name}' not running")
        
        return await client.call_tool(tool_name, arguments)
    
    def get_tool_definitions(self) -> list[dict]:
        """Get OpenAI-compatible tool definitions for all MCP tools."""
        definitions = []
        for server in self._servers.values():
            if server.initialized:
                for tool in server.tools.values():
                    definitions.append({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": f"[MCP:{server.config.name}] {tool.description}",
                            "parameters": tool.input_schema
                        }
                    })
        return definitions


# Global registry instance
mcp_registry = MCPRegistry()


def load_mcp_config(config_path: Path = None) -> list[MCPServerConfig]:
    """Load MCP server configurations from YAML file."""
    import yaml
    
    if config_path is None:
        config_path = Path.home() / ".erreetool" / "config.yaml"
    
    if not config_path.exists():
        return []
    
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    
    mcp_config = data.get("mcp", {})
    servers_config = mcp_config.get("servers", {})
    
    configs = []
    for name, server_config in servers_config.items():
        if not server_config.get("enabled", False):
            continue
        
        transport_str = server_config.get("transport", "stdio")
        transport = TransportType(transport_str) if isinstance(transport_str, str) else transport_str
        
        config = MCPServerConfig(
            name=name,
            enabled=server_config.get("enabled", True),
            transport=transport,
            command=server_config.get("command", ""),
            args=server_config.get("args", []),
            env=server_config.get("env", {}),
            working_dir=server_config.get("working_dir", ""),
            timeout=server_config.get("timeout", 30.0),
            auto_restart=server_config.get("auto_restart", True),
            max_restarts=server_config.get("max_restarts", 3),
        )
        configs.append(config)
    
    return configs


async def initialize_mcp_servers(config_path: Path = None, agent_state=None) -> dict[str, bool]:
    """Initialize all MCP servers from configuration."""
    configs = load_mcp_config(config_path)
    
    for config in configs:
        mcp_registry.register_server(config)
    
    # For local servers (fetch, memory), create them directly
    if agent_state:
        from .servers.memory import MemoryMCPServer
        memory_config = next((c for c in configs if c.name == "memory"), None)
        if memory_config:
            memory_server = MemoryMCPServer(memory_config, agent_state)
            await memory_server.start()
            # Register with registry
            mcp_registry._servers["memory"] = type('Server', (), {
                'config': memory_config,
                'tools': memory_server.tools,
                'initialized': True
            })()
            for tool_name in memory_server.tools:
                mcp_registry._tool_to_server[tool_name] = "memory"
        
        from .servers.fetch import FetchMCPServer
        fetch_config = next((c for c in configs if c.name == "fetch"), None)
        if fetch_config:
            fetch_server = FetchMCPServer(fetch_config)
            await fetch_server.start()
            mcp_registry._servers["fetch"] = type('Server', (), {
                'config': fetch_config,
                'tools': fetch_server.tools,
                'initialized': True
            })()
            for tool_name in fetch_server.tools:
                mcp_registry._tool_to_server[tool_name] = "fetch"
    
    return await mcp_registry.start_all()


async def shutdown_mcp_servers():
    """Shutdown all MCP servers."""
    await mcp_registry.stop_all()


def create_local_servers(agent_state) -> dict[str, Any]:
    """Create local MCP servers (fetch, memory) with agent_state reference."""
    from .servers.fetch import FetchMCPServer
    from .servers.memory import MemoryMCPServer
    
    fetch_config = MCPServerConfig(name="fetch", enabled=True, transport=TransportType.STDIO)
    memory_config = MCPServerConfig(name="memory", enabled=True, transport=TransportType.STDIO)
    
    fetch_server = FetchMCPServer(fetch_config)
    memory_server = MemoryMCPServer(memory_config, agent_state)
    
    return {
        "fetch": fetch_server,
        "memory": memory_server,
    }