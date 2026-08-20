"""
Memory MCP Server - Provides access to AgentState via MCP.

This server exposes AgentState functionality:
- evidence_search: Search evidence by keyword
- evidence_view: View full evidence content
- evidence_list: List recent evidence
- state_get: Get current agent state
- state_set_fact: Add high-signal fact
- memory_sessions: List past sessions
- memory_patterns: List finding patterns
"""

import asyncio
import json
import os
import sys
from dataclasses import asdict
from typing import Any, Optional

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mcp import MCPServerConfig, MCPTool, TransportType


class MemoryMCPServer:
    """Memory MCP Server implementation."""
    
    def __init__(self, config: MCPServerConfig, agent_state=None):
        self.config = config
        self.agent_state = agent_state
        self.tools = {
            "evidence_search": MCPTool(
                name="evidence_search",
                description="Search evidence by keyword. Returns matching evidence IDs and previews.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search term"},
                        "type": {"type": "string", "enum": ["tool_output", "tool_error", "llm_reasoning", "skill_result", "observation"]},
                        "source": {"type": "string", "description": "Tool/source name filter"},
                        "limit": {"type": "integer", "default": 10}
                    },
                    "required": ["query"]
                },
                server_name="memory"
            ),
            "evidence_view": MCPTool(
                name="evidence_view",
                description="View full content of specific evidence by ID.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "evidence_id": {"type": "string", "description": "Evidence ID (e.g., e0001)"},
                        "max_chars": {"type": "integer", "default": 5000}
                    },
                    "required": ["evidence_id"]
                },
                server_name="memory"
            ),
            "evidence_list": MCPTool(
                name="evidence_list",
                description="List recent evidence with previews.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 20},
                        "type": {"type": "string"}
                    }
                },
                server_name="memory"
            ),
            "state_get": MCPTool(
                name="state_get",
                description="Get current agent state summary.",
                input_schema={
                    "type": "object",
                    "properties": {}
                },
                server_name="memory"
            ),
            "state_set_fact": MCPTool(
                name="state_set_fact",
                description="Add a high-signal fact to agent context.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "fact": {"type": "string", "description": "High-signal fact to add"}
                    },
                    "required": ["fact"]
                },
                server_name="memory"
            ),
            "memory_sessions": MCPTool(
                name="memory_sessions",
                description="List past assessment sessions from memory.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Filter by target"},
                        "limit": {"type": "integer", "default": 20}
                    }
                },
                server_name="memory"
            ),
            "memory_patterns": MCPTool(
                name="memory_patterns",
                description="List finding patterns from memory.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "pattern_type": {"type": "string", "description": "Filter by pattern type"},
                        "limit": {"type": "integer", "default": 20}
                    }
                },
                server_name="memory"
            ),
        }
    
    def set_agent_state(self, state):
        """Set the agent state reference."""
        self.agent_state = state
    
    async def start(self):
        """Initialize server."""
        pass
    
    async def stop(self):
        """Cleanup."""
        pass
    
    async def handle_request(self, method: str, params: dict) -> dict:
        """Handle incoming MCP request."""
        if method == "initialize":
            return {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "memory", "version": "1.0.0"}
            }
        
        elif method == "tools/list":
            return {"tools": [self._tool_to_dict(t) for t in self.tools.values()]}
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            if not self.agent_state:
                return {"error": {"code": -32603, "message": "Agent state not available"}}
            
            try:
                if tool_name == "evidence_search":
                    return await self._handle_evidence_search(arguments)
                elif tool_name == "evidence_view":
                    return await self._handle_evidence_view(arguments)
                elif tool_name == "evidence_list":
                    return await self._handle_evidence_list(arguments)
                elif tool_name == "state_get":
                    return await self._handle_state_get(arguments)
                elif tool_name == "state_set_fact":
                    return await self._handle_state_set_fact(arguments)
                elif tool_name == "memory_sessions":
                    return await self._handle_memory_sessions(arguments)
                elif tool_name == "memory_patterns":
                    return await self._handle_memory_patterns(arguments)
                else:
                    return {"error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}
            except Exception as e:
                return {"error": {"code": -32603, "message": str(e)}}
        
        return {"error": {"code": -32601, "message": f"Unknown method: {method}"}}
    
    def _tool_to_dict(self, tool: MCPTool) -> dict:
        return {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema
        }
    
    async def _handle_evidence_search(self, args: dict) -> dict:
        """Search evidence by keyword."""
        from erreetool.agent.state import EvidenceType
        
        query = args["query"]
        ev_type = args.get("type")
        source = args.get("source")
        limit = args.get("limit", 10)
        
        ev_type_enum = EvidenceType(ev_type) if ev_type else None
        results = self.agent_state.search_evidence(query, ev_type_enum, source, limit)
        
        return {
            "results": [
                {"id": ev.id, "type": ev.type.value, "source": ev.source, "preview": ev.preview(200)}
                for ev in results
            ],
            "count": len(results)
        }
    
    async def _handle_evidence_view(self, args: dict) -> dict:
        """View full evidence content."""
        evidence_id = args["evidence_id"]
        max_chars = args.get("max_chars", 5000)
        
        ev = self.agent_state.get_evidence(evidence_id)
        if not ev:
            return {"error": f"Evidence {evidence_id} not found"}
        
        return {
            "id": ev.id,
            "type": ev.type.value,
            "source": ev.source,
            "content": ev.content[:max_chars],
            "metadata": ev.metadata,
            "hash": ev.hash,
            "size": ev.size,
            "truncated": len(ev.content) > max_chars
        }
    
    async def _handle_evidence_list(self, args: dict) -> dict:
        """List recent evidence."""
        from erreetool.agent.state import EvidenceType
        
        limit = args.get("limit", 20)
        ev_type = args.get("type")
        
        ev_type_enum = EvidenceType(ev_type) if ev_type else None
        results = []
        
        for ev in reversed(self.agent_state.evidence_log[-limit:]):
            if ev_type_enum and ev.type != ev_type_enum:
                continue
            results.append({
                "id": ev.id,
                "type": ev.type.value,
                "source": ev.source,
                "preview": ev.preview(150),
                "timestamp": ev.timestamp
            })
        
        return {"results": results, "count": len(results)}
    
    async def _handle_state_get(self, args: dict) -> dict:
        """Get current agent state summary."""
        return self.agent_state.get_summary()
    
    async def _handle_state_set_fact(self, args: dict) -> dict:
        """Add a high-signal fact."""
        fact = args["fact"]
        self.agent_state.add_high_signal_fact(fact)
        return {"success": True, "fact": fact}
    
    async def _handle_memory_sessions(self, args: dict) -> dict:
        """List past sessions from memory."""
        from erreetool.agent.memory import memory_store
        
        target = args.get("target")
        limit = args.get("limit", 20)
        
        memory_store.load()
        sessions = list(memory_store._sessions.values())
        
        if target:
            sessions = [s for s in sessions if s.target == target]
        
        sessions.sort(key=lambda x: x.timestamp, reverse=True)
        sessions = sessions[:limit]
        
        return {
            "sessions": [
                {
                    "session_id": s.session_id,
                    "target": s.target,
                    "timestamp": s.timestamp,
                    "duration": s.duration,
                    "skills_run": s.skills_run,
                    "tools_used": s.tools_used,
                    "high_signal_facts": len(s.high_signal_facts),
                    "critical_findings": len(s.critical_findings),
                    "success": s.success,
                }
                for s in sessions
            ],
            "total": len(sessions)
        }
    
    async def _handle_memory_patterns(self, args: dict) -> dict:
        """List finding patterns from memory."""
        from erreetool.agent.memory import memory_store
        
        pattern_type = args.get("pattern_type")
        limit = args.get("limit", 20)
        
        memory_store.load()
        patterns = list(memory_store._patterns.values())
        
        if pattern_type:
            patterns = [p for p in patterns if p.pattern_type == pattern_type]
        
        return {
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "pattern_type": p.pattern_type,
                    "description": p.description,
                    "indicators": p.indicators,
                    "seen_count": p.seen_count,
                    "confidence": p.confidence.value,
                    "tags": p.tags,
                }
                for p in patterns[:limit]
            ],
            "total": len(patterns)
        }


async def run_server(agent_state=None):
    """Run the memory MCP server (stdio transport)."""
    import sys
    
    config = MCPServerConfig(
        name="memory",
        enabled=True,
        transport=TransportType.STDIO,
        command=sys.executable,
        args=[__file__]
    )
    
    server = MemoryMCPServer(config, agent_state)
    
    # Read stdin line by line
    loop = asyncio.get_event_loop()
    
    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            
            line = line.strip()
            if not line:
                continue
            
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})
            
            try:
                result = await server.handle_request(method, params)
                
                if "id" in request:
                    response = {"jsonrpc": "2.0", "id": request_id, "result": result}
                else:
                    continue
                    
            except Exception as e:
                response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": str(e)}}
            
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            
        except asyncio.CancelledError:
            break
        except Exception:
            break
    
    await server.stop()


if __name__ == "__main__":
    asyncio.run(run_server())