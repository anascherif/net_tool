"""
Fetch MCP Server - Provides HTTP/HTTPS request capabilities.

This server implements the MCP protocol and exposes HTTP tools:
- fetch: Single HTTP request
- fetch_batch: Multiple HTTP requests in parallel
"""

import asyncio
import json
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin

import httpx

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import MCPServerConfig, MCPTool, TransportType


class FetchMCPServer:
    """Fetch MCP Server implementation."""
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.tools = {
            "fetch": MCPTool(
                name="fetch",
                description="Make an HTTP/HTTPS request. Supports GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS. Returns full response including body, headers, status.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], "default": "GET"},
                        "headers": {"type": "object", "description": "HTTP headers", "additionalProperties": {"type": "string"}},
                        "params": {"type": "object", "description": "Query parameters", "additionalProperties": {"type": "string"}},
                        "cookies": {"type": "object", "description": "Cookies", "additionalProperties": {"type": "string"}},
                        "body": {"type": "string", "description": "Raw request body"},
                        "json": {"type": "object", "description": "JSON request body"},
                        "form": {"type": "object", "description": "Form data", "additionalProperties": {"type": "string"}},
                        "timeout": {"type": "number", "default": 30, "description": "Timeout in seconds"},
                        "follow_redirects": {"type": "boolean", "default": True},
                        "verify_ssl": {"type": "boolean", "default": False, "description": "Verify SSL certificates (default false for CTF/lab)"},
                        "max_body_chars": {"type": "integer", "default": 10000, "description": "Max chars to return in response body (0 = unlimited)"}
                    },
                    "required": ["url"]
                },
                server_name="fetch"
            ),
            "fetch_batch": MCPTool(
                name="fetch_batch",
                description="Execute multiple HTTP requests in parallel. Useful for comparing variants (different params, headers, paths). Returns array of responses with request surface for analysis.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "requests": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "string", "description": "Optional identifier for this request"},
                                    "url": {"type": "string"},
                                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], "default": "GET"},
                                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                                    "params": {"type": "object", "additionalProperties": {"type": "string"}},
                                    "cookies": {"type": "object", "additionalProperties": {"type": "string"}},
                                    "body": {"type": "string"},
                                    "json": {"type": "object"},
                                    "form": {"type": "object", "additionalProperties": {"type": "string"}},
                                    "timeout": {"type": "number", "default": 30},
                                    "follow_redirects": {"type": "boolean", "default": True},
                                    "verify_ssl": {"type": "boolean", "default": False}
                                },
                                "required": ["url"]
                            },
                            "minItems": 1,
                            "maxItems": 50
                        },
                        "concurrency": {"type": "integer", "default": 10, "description": "Max concurrent requests"}
                    },
                    "required": ["requests"]
                },
                server_name="fetch"
            )
        }
        self._client: Optional[httpx.AsyncClient] = None
    
    async def start(self):
        """Initialize HTTP client."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
            verify=False,  # Default false for CTF/lab
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10)
        )
    
    async def stop(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def handle_request(self, method: str, params: dict) -> dict:
        """Handle incoming MCP request."""
        if method == "initialize":
            return {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fetch", "version": "1.0.0"}
            }
        
        elif method == "tools/list":
            return {"tools": [self._tool_to_dict(t) for t in self.tools.values()]}
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            if tool_name == "fetch":
                return await self._handle_fetch(arguments)
            elif tool_name == "fetch_batch":
                return await self._handle_fetch_batch(arguments)
            else:
                return {"error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}
        
        return {"error": {"code": -32601, "message": f"Unknown method: {method}"}}
    
    def _tool_to_dict(self, tool: MCPTool) -> dict:
        return {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema
        }
    
    async def _handle_fetch(self, args: dict) -> dict:
        """Handle single fetch request."""
        if not self._client:
            await self.start()
        
        url = args["url"]
        method = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        params = args.get("params", {})
        cookies = args.get("cookies", {})
        body = args.get("body")
        json_data = args.get("json")
        form_data = args.get("form")
        timeout = args.get("timeout", 30)
        follow_redirects = args.get("follow_redirects", True)
        verify_ssl = args.get("verify_ssl", False)
        max_body_chars = args.get("max_body_chars", 10000)
        
        # Build request
        request_kwargs = {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "cookies": cookies,
            "follow_redirects": follow_redirects,
            "timeout": httpx.Timeout(timeout)
        }
        
        if body is not None:
            request_kwargs["content"] = body
        elif json_data is not None:
            request_kwargs["json"] = json_data
        elif form_data is not None:
            request_kwargs["data"] = form_data
        
        # Override SSL verification per request
        if not verify_ssl:
            # Create a client with verify=False for this request
            async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, timeout=timeout) as client:
                response = await client.request(**request_kwargs)
                return self._format_response(response, max_body_chars)
        else:
            # Use shared client (verify=True by default)
            old_verify = self._client._verify
            self._client._verify = verify_ssl
            try:
                response = await self._client.request(**request_kwargs)
                return self._format_response(response, max_body_chars)
            finally:
                self._client._verify = old_verify
    
    async def _handle_fetch_batch(self, args: dict) -> dict:
        """Handle batch fetch requests."""
        requests = args["requests"]
        concurrency = args.get("concurrency", 10)
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def execute_one(req: dict) -> dict:
            async with semaphore:
                return await self._handle_fetch(req)
        
        # Execute all requests
        tasks = [execute_one(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Format results
        formatted = []
        for i, (req, result) in enumerate(zip(requests, results)):
            req_id = req.get("id", f"req_{i}")
            if isinstance(result, Exception):
                formatted.append({
                    "id": req_id,
                    "error": str(result),
                    "request_surface": self._get_request_surface(req)
                })
            else:
                result["id"] = req_id
                result["request_surface"] = self._get_request_surface(req)
                formatted.append(result)
        
        return {"results": formatted}
    
    def _get_request_surface(self, req: dict) -> dict:
        """Extract request surface for analysis."""
        return {
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "has_headers": bool(req.get("headers")),
            "has_params": bool(req.get("params")),
            "has_cookies": bool(req.get("cookies")),
            "has_body": bool(req.get("body")),
            "has_json": bool(req.get("json")),
            "has_form": bool(req.get("form")),
        }
    
    def _format_response(self, response: httpx.Response, max_body_chars: int) -> dict:
        """Format HTTP response for MCP."""
        body = response.text
        truncated = False
        if max_body_chars > 0 and len(body) > max_body_chars:
            body = body[:max_body_chars]
            truncated = True
        
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "truncated": truncated,
            "url": str(response.url),
            "history": [{"status_code": r.status_code, "url": str(r.url)} for r in response.history],
            "elapsed_ms": response.elapsed.total_seconds() * 1000
        }


async def run_server():
    """Run the fetch MCP server (stdio transport)."""
    import sys
    
    config = MCPServerConfig(
        name="fetch",
        enabled=True,
        transport=TransportType.STDIO,
        command=sys.executable,
        args=[__file__]
    )
    
    server = FetchMCPServer(config)
    
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
                    # Notification - no response needed
                    continue
                    
            except Exception as e:
                response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": str(e)}}
            
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            
        except asyncio.CancelledError:
            break
        except Exception:
            break
    
    if server._client:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(run_server())