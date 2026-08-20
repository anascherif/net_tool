"""
Enhanced HTTP Tools for Phase 8.

Provides:
- run_fetch: Full HTTP client with raw traffic storage
- run_http_probe_batch: Parallel request comparison
- run_source_extract: Extract clean source from responses
- run_runtime_diff_probe: Filter vs parser inconsistency testing
"""

import asyncio
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import httpx

from erreetool.agent.tools.base import ToolWrapper, ToolResult
from erreetool.agent.state import AgentState, EvidenceType


@dataclass
class TrafficRecord:
    """Single HTTP request/response record."""
    id: str
    timestamp: float
    request: dict
    response: dict
    session_id: str
    
    def to_jsonl(self) -> str:
        return json.dumps({
            "id": self.id,
            "timestamp": self.timestamp,
            "request": self.request,
            "response": self.response,
            "session_id": self.session_id
        })


class TrafficStore:
    """Manages traffic evidence storage (JSONL index + raw files)."""
    
    def __init__(self, session_id: str, base_dir: Path):
        self.session_id = session_id
        self.base_dir = base_dir / "evidence" / "traffic" / session_id
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.base_dir / "index.jsonl"
        self._lock = asyncio.Lock()
    
    async def record(self, request: dict, response: dict) -> str:
        """Record a request/response pair."""
        record_id = f"traffic_{uuid.uuid4().hex[:8]}"
        timestamp = time.time()
        
        record = TrafficRecord(
            id=record_id,
            timestamp=timestamp,
            request=request,
            response=response,
            session_id="",
        )
        
        # Write raw request/response files
        req_file = self.base_dir / f"{record_id}_request.json"
        resp_file = self.base_dir / f"{record_id}_response.json"
        
        req_file.write_text(json.dumps(request, indent=2))
        resp_file.write_text(json.dumps(response, indent=2))
        
        # Append to index
        async with self._lock:
            with open(self.index_file, "a", encoding="utf-8") as f:
                f.write(record.to_jsonl() + "\n")
        
        return record_id
    
    async def search(self, query: str, limit: int = 20) -> list[dict]:
        """Search traffic records by query."""
        results = []
        if not self.index_file.exists():
            return results
        
        query_lower = query.lower()
        with open(self.index_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    # Search in request URL, method, response body
                    searchable = f"{record['request'].get('url', '')} {record['request'].get('method', '')} {record['response'].get('body', '')[:1000]}"
                    if query_lower in searchable.lower():
                        results.append({
                            "id": record["id"],
                            "timestamp": record["timestamp"],
                            "method": record["request"].get("method"),
                            "url": record["request"].get("url"),
                            "status_code": record["response"].get("status_code"),
                            "preview": record["response"].get("body", "")[:200]
                        })
                        if len(results) >= limit:
                            break
                except:
                    continue
        return results
    
    async def view(self, record_id: str) -> Optional[dict]:
        """View full traffic record."""
        req_file = self.base_dir / f"{record_id}_request.json"
        resp_file = self.base_dir / f"{record_id}_response.json"
        
        if not req_file.exists() or not resp_file.exists():
            return None
        
        request = json.loads(req_file.read_text())
        response = json.loads(resp_file.read_text())
        
        return {"request": request, "response": response}


class FetchTool(ToolWrapper):
    """Enhanced HTTP fetch tool with traffic storage."""
    
    name = "fetch"
    windows_binary = "fetch.exe"
    linux_binary = "fetch"
    
    def __init__(self, state: AgentState = None, traffic_store: TrafficStore = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
        self.traffic_store = traffic_store
        self._client: Optional[httpx.AsyncClient] = None
    
    @property
    def binary(self) -> str:
        return "python"  # Uses Python httpx
    
    def build_args(self, **kwargs) -> list:
        return []
    
    def is_available(self) -> bool:
        return True
    
    async def _ensure_client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
                verify=False,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10)
            )
    
    def run(self, **kwargs) -> ToolResult:
        """Synchronous wrapper for async fetch."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self._arun(**kwargs))
    
    async def _arun(
        self,
        url: str,
        method: str = "GET",
        headers: dict = None,
        params: dict = None,
        cookies: dict = None,
        body: str = None,
        json: dict = None,
        form: dict = None,
        timeout: float = 30,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        max_body_chars: int = 10000,
        **kwargs
    ) -> ToolResult:
        await self._ensure_client()
        
        method = method.upper()
        headers = headers or {}
        params = params or {}
        cookies = cookies or {}
        
        # Build request dict for traffic storage
        request_data = {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "cookies": cookies,
        }
        
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
            request_data["body"] = body
        elif json is not None:
            request_kwargs["json"] = json
            request_data["json"] = json
        elif form is not None:
            request_kwargs["data"] = form
            request_data["form"] = form
        
        # Execute with SSL verification override
        if not verify_ssl:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=follow_redirects,
                timeout=timeout
            ) as client:
                start = time.time()
                response = await client.request(**request_kwargs)
                duration = time.time() - start
        else:
            start = time.time()
            response = await self._client.request(**request_kwargs)
            duration = time.time() - start
        
        # Format response
        response_body = response.text
        truncated = False
        if max_body_chars > 0 and len(response_body) > max_body_chars:
            response_body = response_body[:max_body_chars]
            truncated = True
        
        response_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body,
            "truncated": truncated,
            "url": str(response.url),
            "history": [{"status_code": r.status_code, "url": str(r.url)} for r in response.history],
            "elapsed_ms": duration * 1000
        }
        
        # Store traffic
        traffic_id = None
        if self.traffic_store:
            traffic_id = await self.traffic_store.record(request_data, response_data)
        
        # Add evidence if state provided
        if self.state:
            ev = self.state.add_evidence(
                EvidenceType.TOOL_OUTPUT,
                "fetch",
                f"HTTP {method} {url} -> {response.status_code}",
                {
                    "command": [method, url],
                    "duration": duration,
                    "traffic_id": traffic_id,
                    "request": request_data,
                    "response": response_data,
                }
            )
            
            # Extract high-signal facts
            self._extract_facts(response)
        
        return ToolResult(
            success=response.status_code < 400,
            stdout=response_body,
            stderr="" if response.status_code < 400 else f"HTTP {response.status_code}",
            returncode=response.status_code,
            command=[method, url],
            duration=duration,
            evidence_id=traffic_id or f"fetch_{uuid.uuid4().hex[:8]}",
            tool_name="fetch",
            metadata={"traffic_id": traffic_id, "status_code": response.status_code}
        )
    
    def _extract_facts(self, response: httpx.Response):
        """Extract high-signal facts from HTTP response."""
        if not self.state:
            return
        
        content = response.text
        url = str(response.url)
        
        # Forms
        for match in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', content, re.IGNORECASE):
            self.state.add_high_signal_fact(f"Form endpoint: {urljoin(url, match.group(1))}")
        
        for match in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\']', content, re.IGNORECASE):
            self.state.add_high_signal_fact(f"Form parameter: {match.group(1)}")
        
        # JS endpoints
        for match in re.finditer(r'(?:fetch|axios|\.get|\.post|ajax)\s*\(\s*["\']([^"\']+)["\']', content):
            self.state.add_high_signal_fact(f"JS endpoint: {urljoin(url, match.group(1))}")
        
        # PHP/Backend endpoints
        for match in re.finditer(r'(?:href|action|src)=["\']([^"\']*\.php[^"\']*)["\']', content, re.IGNORECASE):
            self.state.add_high_signal_fact(f"PHP endpoint: {urljoin(url, match.group(1))}")
        
        # Dangerous sinks
        sink_patterns = [
            (r'eval\s*\(', "eval() sink"),
            (r'exec\s*\(', "exec() sink"),
            (r'system\s*\(', "system() sink"),
            (r'shell_exec\s*\(', "shell_exec() sink"),
            (r'passthru\s*\(', "passthru() sink"),
            (r'unserialize\s*\(', "unserialize() sink"),
            (r'base64_decode\s*\(', "base64_decode() sink"),
        ]
        for pattern, label in sink_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.state.add_high_signal_fact(f"Dangerous sink: {label}")
        
        # Source code detection
        if "highlight_file" in content or "show_source" in content:
            self.state.add_high_signal_fact("PHP source code exposed (highlight_file/show_source)")
        
        if len(content) > 5000 and ("<html" in content.lower() or "<?php" in content):
            self.state.add_high_signal_fact(f"Large response with source code ({len(content)} chars)")


class HTTPProbeBatchTool(ToolWrapper):
    """Batch HTTP probe tool for comparing request variants."""
    
    name = "http_probe_batch"
    windows_binary = "http_probe_batch.exe"
    linux_binary = "http_probe_batch"
    
    def __init__(self, state: AgentState = None, traffic_store: TrafficStore = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
        self.traffic_store = traffic_store
    
    @property
    def binary(self) -> str:
        return "python"
    
    def build_args(self, **kwargs) -> list:
        return []
    
    def is_available(self) -> bool:
        return True
    
    def run(self, **kwargs) -> ToolResult:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self._arun(**kwargs))
    
    async def _arun(
        self,
        requests: list[dict],
        concurrency: int = 10,
        **kwargs
    ) -> ToolResult:
        semaphore = asyncio.Semaphore(concurrency)
        
        async def execute_one(req: dict) -> dict:
            async with semaphore:
                # Reuse fetch logic
                fetch_tool = FetchTool(state=self.state, traffic_store=self.traffic_store)
                return await fetch_tool._arun(**req)
        
        start = time.time()
        tasks = [execute_one(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start
        
        # Format results
        formatted = []
        evidence_ids = []
        
        for i, (req, result) in enumerate(zip(requests, results)):
            req_id = req.get("id", f"req_{i}")
            if isinstance(result, Exception):
                formatted.append({
                    "id": req_id,
                    "error": str(result),
                    "request_surface": self._get_request_surface(req)
                })
            else:
                result_dict = {
                    "id": req_id,
                    "status_code": result.metadata.get("status_code"),
                    "elapsed_ms": result.duration * 1000,
                    "traffic_id": result.metadata.get("traffic_id"),
                    "request_surface": self._get_request_surface(req)
                }
                formatted.append(result_dict)
                if result.metadata.get("traffic_id"):
                    evidence_ids.append(result.metadata["traffic_id"])
        
        # Add batch evidence
        if self.state:
            ev = self.state.add_evidence(
                EvidenceType.TOOL_OUTPUT,
                "http_probe_batch",
                f"Batch probe: {len(requests)} requests in {duration:.1f}s",
                {
                    "command": ["http_probe_batch", str(len(requests))],
                    "duration": duration,
                    "results": formatted,
                }
            )
            evidence_ids.append(ev.id)
        
        return ToolResult(
            success=True,
            stdout=json.dumps({"results": formatted}, indent=2),
            stderr="",
            returncode=0,
            command=["http_probe_batch", str(len(requests))],
            duration=duration,
            evidence_id=evidence_ids[0] if evidence_ids else f"batch_{uuid.uuid4().hex[:8]}",
            tool_name="http_probe_batch",
            metadata={"results": formatted, "evidence_ids": evidence_ids}
        )
    
    def _get_request_surface(self, req: dict) -> dict:
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


class SourceExtractTool(ToolWrapper):
    """Extract clean source code from HTTP responses."""
    
    name = "source_extract"
    windows_binary = "source_extract.exe"
    linux_binary = "source_extract"
    
    def __init__(self, state: AgentState = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
    
    @property
    def binary(self) -> str:
        return "python"
    
    def build_args(self, **kwargs) -> list:
        return []
    
    def is_available(self) -> bool:
        return True
    
    def run(self, **kwargs) -> ToolResult:
        evidence_id = kwargs.get("evidence_id")
        max_chars = kwargs.get("max_chars", 50000)
        
        if not self.state:
            return ToolResult(success=False, stdout="", stderr="No agent state", returncode=-1, command=[], duration=0, evidence_id="", tool_name="source_extract")
        
        # Find evidence
        ev = self.state.get_evidence(evidence_id)
        if not ev:
            return ToolResult(success=False, stdout="", stderr=f"Evidence {evidence_id} not found", returncode=-1, command=[], duration=0, evidence_id="", tool_name="source_extract")
        
        content = ev.content
        extracted = {}
        
        # Extract PHP source from highlight_file
        php_blocks = re.findall(r'<\?php(.*?)\?>', content, re.DOTALL)
        if php_blocks:
            extracted["php_sources"] = [block[:max_chars] for block in php_blocks[:5]]
        
        # Extract JavaScript
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
        if js_blocks:
            extracted["javascript"] = [block[:max_chars] for block in js_blocks[:5]]
        
        # Extract HTML comments with source
        comment_blocks = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        source_comments = [c for c in comment_blocks if any(kw in c.lower() for kw in ['source', 'code', 'debug', 'todo', 'fixme', 'password', 'secret', 'key'])]
        if source_comments:
            extracted["source_comments"] = source_comments[:10]
        
        # Extract highlighted source (common patterns)
        for pattern in [
            r'<pre[^>]*class=["\']brush: php["\']>(.*?)</pre>',
            r'<code[^>]*class=["\']language-php["\']>(.*?)</code>',
            r'<div[^>]*class=["\']highlight["\']>(.*?)</div>',
        ]:
            matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
            if matches:
                extracted.setdefault("highlighted_source", []).extend([m[:max_chars] for m in matches[:3]])
        
        # Add evidence
        new_ev = self.state.add_evidence(
            EvidenceType.TOOL_OUTPUT,
            "source_extract",
            f"Extracted source from {evidence_id}: {len(extracted)} categories",
            {"source_evidence_id": evidence_id, "extracted": extracted}
        )
        
        if extracted:
            self.state.add_high_signal_fact(f"Source code extracted from {evidence_id} ({len(extracted)} categories)")
        
        return ToolResult(
            success=bool(extracted),
            stdout=json.dumps(extracted, indent=2),
            stderr="",
            returncode=0 if extracted else 1,
            command=["source_extract", evidence_id],
            duration=0.1,
            evidence_id=new_ev.id,
            tool_name="source_extract",
            metadata={"extracted": extracted}
        )


class RuntimeDiffProbeTool(ToolWrapper):
    """Runtime diff probe for filter vs parser inconsistency testing."""
    
    name = "runtime_diff_probe"
    windows_binary = "runtime_diff_probe.exe"
    linux_binary = "runtime_diff_probe"
    
    def __init__(self, state: AgentState = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
    
    @property
    def binary(self) -> str:
        return "python"
    
    def build_args(self, **kwargs) -> list:
        return []
    
    def is_available(self) -> bool:
        return True
    
    def run(self, **kwargs) -> ToolResult:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self._arun(**kwargs))
    
    async def _arun(
        self,
        target_url: str,
        parameter: str,
        payloads: list[str],
        local_php_path: str = "php",
        max_concurrent: int = 5,
        **kwargs
    ) -> ToolResult:
        """Test payloads locally and remotely to find filter bypasses."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # Test locally first
        local_results = {}
        for payload in payloads:
            try:
                proc = await asyncio.create_subprocess_exec(
                    local_php_path, "-r", payload,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                local_results[payload] = {
                    "stdout": stdout.decode()[:1000],
                    "stderr": stderr.decode()[:500],
                    "returncode": proc.returncode
                }
            except Exception as e:
                local_results[payload] = {"error": str(e)}
        
        # Test remotely
        fetch_tool = FetchTool(state=self.state)
        remote_results = {}
        
        async def test_remote(payload: str):
            url = target_url
            # Inject payload into parameter
            # This is simplified - real implementation would be more sophisticated
            test_url = f"{url}?{parameter}={payload}"
            result = await fetch_tool._arun(
                url=test_url,
                method="GET",
                timeout=10,
                verify_ssl=False,
                max_body_chars=5000
            )
            return payload, result
        
        tasks = [test_remote(p) for p in payloads]
        remote_responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for payload, response in zip(payloads, remote_responses):
            if isinstance(response, Exception):
                remote_results[payload] = {"error": str(response)}
            else:
                remote_results[payload] = {
                    "status_code": response.metadata.get("status_code"),
                    "body_preview": response.stdout[:500] if response.stdout else "",
                    "traffic_id": response.metadata.get("traffic_id")
                }
        
        # Analyze differences
        bypass_candidates = []
        for payload in payloads:
            local = local_results.get(payload, {})
            remote = remote_results.get(payload, {})
            
            # PHP signed length / filter bypass indicators
            local_accepted = local.get("returncode") == 0 or "unserialize" in local.get("stdout", "")
            remote_accepted = remote.get("status_code") == 200 and "error" not in remote.get("body_preview", "").lower()
            
            if local_accepted and remote_accepted:
                bypass_candidates.append({
                    "payload": payload[:100],
                    "local_result": local.get("stdout", "")[:200],
                    "remote_status": remote.get("status_code"),
                    "requires_verification": True
                })
        
        # Add evidence
        evidence_ids = []
        if self.state:
            ev = self.state.add_evidence(
                EvidenceType.TOOL_OUTPUT,
                "runtime_diff_probe",
                f"Runtime diff probe: {len(payloads)} payloads, {len(bypass_candidates)} bypass candidates",
                {
                    "command": ["runtime_diff_probe", target_url, parameter, str(len(payloads))],
                    "duration": 0,
                    "local_results": local_results,
                    "remote_results": remote_results,
                    "bypass_candidates": bypass_candidates
                }
            )
            evidence_ids.append(ev.id)
            
            if bypass_candidates:
                self.state.add_high_signal_fact(f"Runtime diff: {len(bypass_candidates)} filter bypass candidates found")
        
        return ToolResult(
            success=True,
            stdout=json.dumps({
                "local_results": local_results,
                "remote_results": remote_results,
                "bypass_candidates": bypass_candidates
            }, indent=2),
            stderr="",
            returncode=0,
            command=["runtime_diff_probe", target_url, parameter, str(len(payloads))],
            duration=0,
            evidence_id=evidence_ids[0] if evidence_ids else f"diff_{uuid.uuid4().hex[:8]}",
            tool_name="runtime_diff_probe",
            metadata={"bypass_candidates": bypass_candidates}
        )


# Traffic tools for MCP
class TrafficListTool(ToolWrapper):
    name = "traffic_list"
    windows_binary = "traffic_list.exe"
    linux_binary = "traffic_list"
    
    def __init__(self, state: AgentState = None, traffic_store: TrafficStore = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
        self.traffic_store = traffic_store
    
    @property
    def binary(self) -> str:
        return "python"
    
    def build_args(self, **kwargs) -> list:
        return []
    
    def is_available(self) -> bool:
        return self.traffic_store is not None
    
    def run(self, **kwargs) -> ToolResult:
        import asyncio
        limit = kwargs.get("limit", 20)
        
        if not self.traffic_store:
            return ToolResult(success=False, stdout="", stderr="No traffic store", returncode=-1, command=[], duration=0, evidence_id="", tool_name="traffic_list")
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        results = loop.run_until_complete(self.traffic_store.search("", limit))
        
        return ToolResult(
            success=True,
            stdout=json.dumps({"results": results, "count": len(results)}, indent=2),
            stderr="",
            returncode=0,
            command=["traffic_list"],
            duration=0.1,
            evidence_id=f"traffic_list_{uuid.uuid4().hex[:8]}",
            tool_name="traffic_list",
            metadata={"results": results}
        )


class TrafficViewTool(ToolWrapper):
    name = "traffic_view"
    windows_binary = "traffic_view.exe"
    linux_binary = "traffic_view"
    
    def __init__(self, state: AgentState = None, traffic_store: TrafficStore = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
        self.traffic_store = traffic_store
    
    @property
    def binary(self) -> str:
        return "python"
    
    def build_args(self, **kwargs) -> list:
        return []
    
    def is_available(self) -> bool:
        return self.traffic_store is not None
    
    def run(self, **kwargs) -> ToolResult:
        import asyncio
        record_id = kwargs.get("record_id")
        
        if not self.traffic_store:
            return ToolResult(success=False, stdout="", stderr="No traffic store", returncode=-1, command=[], duration=0, evidence_id="", tool_name="traffic_view")
        
        if not record_id:
            return ToolResult(success=False, stdout="", stderr="record_id required", returncode=-1, command=[], duration=0, evidence_id="", tool_name="traffic_view")
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(self.traffic_store.view(record_id))
        
        if not result:
            return ToolResult(success=False, stdout="", stderr=f"Record {record_id} not found", returncode=-1, command=[], duration=0.1, evidence_id="", tool_name="traffic_view")
        
        return ToolResult(
            success=True,
            stdout=json.dumps(result, indent=2),
            stderr="",
            returncode=0,
            command=["traffic_view", record_id],
            duration=0.1,
            evidence_id=f"traffic_view_{uuid.uuid4().hex[:8]}",
            tool_name="traffic_view",
            metadata={"record": result}
        )


# Tool registration helper
def register_enhanced_tools(state: AgentState, traffic_store: TrafficStore):
    """Register enhanced tools with the tool registry."""
    from erreetool.agent.tools.base import tool_registry
    
    tool_registry.register(FetchTool(state=state, traffic_store=traffic_store))
    tool_registry.register(HTTPProbeBatchTool(state=state, traffic_store=traffic_store))
    tool_registry.register(SourceExtractTool(state=state))
    tool_registry.register(RuntimeDiffProbeTool(state=state))
    tool_registry.register(TrafficListTool(state=state, traffic_store=traffic_store))
    tool_registry.register(TrafficViewTool(state=state, traffic_store=traffic_store))