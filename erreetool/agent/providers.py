"""
LLM Provider abstraction for OpenRouter and NVIDIA NIM.

Supports free models from both providers with automatic fallback.
"""

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import httpx

# Load .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class LLMMessage:
    """A message in the conversation."""
    role: str  # system, user, assistant, tool
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    tool_call_id: str = ""
    name: str = ""
    
    def to_dict(self) -> dict:
        d = {"role": self.role, "content": self.content}
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.name:
            d["name"] = self.name
        return d


@dataclass
class LLMResponse:
    """Response from LLM provider."""
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    model: str = ""
    usage: dict = field(default_factory=dict)
    finish_reason: str = ""
    raw: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "tool_calls": self.tool_calls,
            "model": self.model,
            "usage": self.usage,
            "finish_reason": self.finish_reason,
        }


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float = 60.0,
        max_retries: int = 3
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        # Reuse a single HTTP client across chat() calls for connection pooling.
        # The client is lazily created on first use.
        self._client: Optional[httpx.Client] = None

    @abstractmethod
    def _build_headers(self) -> dict:
        """Build request headers."""
        pass

    @abstractmethod
    def _build_payload(
        self,
        messages: list[LLMMessage],
        temperature: float,
        max_tokens: int,
        tools: list[dict] = None,
        tool_choice: str = "auto"
    ) -> dict:
        """Build request payload."""
        pass

    @abstractmethod
    def _parse_response(self, response: httpx.Response) -> LLMResponse:
        """Parse provider-specific response."""
        pass

    def _get_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def close(self):
        """Close the underlying HTTP client."""
        if self._client is not None and not self._client.is_closed:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.3,
        max_tokens: int = 4000,
        tools: list[dict] = None,
        tool_choice: str = "auto"
    ) -> LLMResponse:
        """Send chat completion request with retries."""
        headers = self._build_headers()
        payload = self._build_payload(messages, temperature, max_tokens, tools, tool_choice)

        client = self._get_client()
        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )

                if response.status_code == 429:
                    # Rate limited - wait and retry
                    try:
                        retry_after = int(response.headers.get("Retry-After", "5"))
                    except (TypeError, ValueError):
                        retry_after = 5
                    time.sleep(min(retry_after, 30))
                    continue

                response.raise_for_status()
                return self._parse_response(response)

            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code >= 500:
                    time.sleep(2 ** attempt)
                    continue
                # Client error - don't retry
                raise
            except httpx.RequestError as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue

        raise RuntimeError(
            f"LLM request failed after {self.max_retries} attempts: {last_error}"
        )


class OpenRouterProvider(LLMProvider):
    """OpenRouter provider - routes to multiple free models."""
    
    # Free models on OpenRouter (as of 2024)
    FREE_MODELS = [
        "openrouter/auto",                    # Auto-routes to best free
        "google/gemini-flash-1.5",            # Free tier
        "meta-llama/llama-3.1-70b-instruct:free",
        "qwen/qwen-2.5-72b-instruct:free",
        "deepseek/deepseek-chat:free",
        "mistralai/mistral-7b-instruct:free",
    ]
    
    def __init__(
        self,
        api_key: str = None,
        model: str = "openrouter/auto",
        **kwargs
    ):
        api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY not set")
        
        super().__init__(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            model=model,
            **kwargs
        )
    
    def _build_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/anascherif/erreetool",
            "X-Title": "erreetool",
        }
    
    def _build_payload(
        self,
        messages: list[LLMMessage],
        temperature: float,
        max_tokens: int,
        tools: list[dict] = None,
        tool_choice: str = "auto"
    ) -> dict:
        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        return payload
    
    def _parse_response(self, response: httpx.Response) -> LLMResponse:
        data = response.json()
        choice = data["choices"][0]
        message = choice["message"]
        
        return LLMResponse(
            content=message.get("content", "") or "",
            tool_calls=message.get("tool_calls", []),
            model=data.get("model", self.model),
            usage=data.get("usage", {}),
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
        )
    
    def try_free_models(self, messages: list[LLMMessage], **kwargs) -> LLMResponse:
        """Try multiple free models in sequence."""
        last_error = None
        
        for model in self.FREE_MODELS:
            original_model = self.model
            self.model = model
            try:
                return self.chat(messages, **kwargs)
            except Exception as e:
                last_error = e
                # Continue to next model
                continue
            finally:
                self.model = original_model
        
        raise RuntimeError(f"All free models failed. Last error: {last_error}")


class NVIDIANIMProvider(LLMProvider):
    """NVIDIA NIM provider - free tier available."""
    
    # Free models on NVIDIA NIM
    FREE_MODELS = [
        "nvidia/nemotron-3-ultra",
        "nvidia/nemotron-4-340b-instruct",
        "meta/llama-3.1-70b-instruct",
        "mistralai/mixtral-8x22b-instruct",
    ]
    
    def __init__(
        self,
        api_key: str = None,
        model: str = "nvidia/nemotron-3-ultra",
        **kwargs
    ):
        api_key = api_key or os.getenv("NVIDIA_NIM_API_KEY")
        if not api_key:
            raise ValueError("NVIDIA_NIM_API_KEY not set")
        
        super().__init__(
            api_key=api_key,
            base_url="https://integrate.api.nvidia.com/v1",
            model=model,
            **kwargs
        )
    
    def _build_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
    
    def _build_payload(
        self,
        messages: list[LLMMessage],
        temperature: float,
        max_tokens: int,
        tools: list[dict] = None,
        tool_choice: str = "auto"
    ) -> dict:
        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        return payload
    
    def _parse_response(self, response: httpx.Response) -> LLMResponse:
        data = response.json()
        choice = data["choices"][0]
        message = choice["message"]
        
        return LLMResponse(
            content=message.get("content", "") or "",
            tool_calls=message.get("tool_calls", []),
            model=data.get("model", self.model),
            usage=data.get("usage", {}),
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
        )


class GroqProvider(LLMProvider):
    """Groq provider - fast inference with free tier."""

    FREE_MODELS = [
        "llama-3.1-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ]

    def __init__(
        self,
        api_key: str = None,
        model: str = "llama-3.1-70b-versatile",
        **kwargs
    ):
        api_key = api_key or os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY not set")

        super().__init__(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            model=model,
            **kwargs
        )

    def _build_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _build_payload(
        self,
        messages: list[LLMMessage],
        temperature: float,
        max_tokens: int,
        tools: list[dict] = None,
        tool_choice: str = "auto"
    ) -> dict:
        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        return payload

    def _parse_response(self, response: httpx.Response) -> LLMResponse:
        data = response.json()
        choice = data["choices"][0]
        message = choice["message"]

        return LLMResponse(
            content=message.get("content", "") or "",
            tool_calls=message.get("tool_calls", []),
            model=data.get("model", self.model),
            usage=data.get("usage", {}),
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
        )


class TogetherAIProvider(LLMProvider):
    """Together.ai provider - free tier available."""

    FREE_MODELS = [
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        "mistralai/Mixtral-8x7B-Instruct-v0.1",
        "Qwen/Qwen2.5-72B-Instruct-Turbo",
    ]

    def __init__(
        self,
        api_key: str = None,
        model: str = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        **kwargs
    ):
        api_key = api_key or os.getenv("TOGETHER_API_KEY")
        if not api_key:
            raise ValueError("TOGETHER_API_KEY not set")

        super().__init__(
            api_key=api_key,
            base_url="https://api.together.xyz/v1",
            model=model,
            **kwargs
        )

    def _build_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _build_payload(
        self,
        messages: list[LLMMessage],
        temperature: float,
        max_tokens: int,
        tools: list[dict] = None,
        tool_choice: str = "auto"
    ) -> dict:
        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        return payload

    def _parse_response(self, response: httpx.Response) -> LLMResponse:
        data = response.json()
        choice = data["choices"][0]
        message = choice["message"]

        return LLMResponse(
            content=message.get("content", "") or "",
            tool_calls=message.get("tool_calls", []),
            model=data.get("model", self.model),
            usage=data.get("usage", {}),
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
        )


class MultiProvider:
    """
    Multi-provider with automatic fallback.

    Tries providers in order until one succeeds.
    """

    def __init__(self, providers: list[LLMProvider] = None):
        self.providers = providers or []

    def add_provider(self, provider: LLMProvider):
        self.providers.append(provider)

    def chat(self, messages: list[LLMMessage], **kwargs) -> LLMResponse:
        last_error = None

        for provider in self.providers:
            try:
                # Use try_free_models for OpenRouter if available
                if hasattr(provider, "try_free_models"):
                    return provider.try_free_models(messages, **kwargs)
                return provider.chat(messages, **kwargs)
            except Exception as e:
                last_error = e
                # Log via stdout so callers don't have to handle Rich output
                print(
                    f"[multi-provider] {provider.__class__.__name__} failed: {e}"
                )
                continue

        raise RuntimeError(
            f"All providers failed. Last error: {last_error}"
        )

    def close(self):
        """Close all providers."""
        for provider in self.providers:
            if hasattr(provider, "close"):
                try:
                    provider.close()
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @classmethod
    def from_env(cls) -> "MultiProvider":
        """Create multi-provider from environment variables.

        Priority order (first available is tried first):
        1. OpenRouter - many free models, auto-routing
        2. Groq - fast inference, generous free tier
        3. Together.ai - many open models, free tier
        4. NVIDIA NIM - hosted open models, free tier
        """
        providers = []

        # OpenRouter (primary - most free models)
        if os.getenv("OPENROUTER_API_KEY"):
            providers.append(OpenRouterProvider())

        # Groq (fast, good free tier)
        if os.getenv("GROQ_API_KEY"):
            providers.append(GroqProvider())

        # Together.ai (many open models)
        if os.getenv("TOGETHER_API_KEY"):
            providers.append(TogetherAIProvider())

        # NVIDIA NIM (fallback)
        if os.getenv("NVIDIA_NIM_API_KEY"):
            providers.append(NVIDIANIMProvider())

        if not providers:
            raise ValueError(
                "No LLM API keys found. Set at least one of:\n"
                "  OPENROUTER_API_KEY (https://openrouter.ai/keys)\n"
                "  GROQ_API_KEY (https://console.groq.com/keys)\n"
                "  TOGETHER_API_KEY (https://api.together.xyz/settings/api-keys)\n"
                "  NVIDIA_NIM_API_KEY (https://build.nvidia.com/)"
            )

        return cls(providers)


# Tool definitions for function calling
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "run_nmap",
            "description": "Run nmap port scan on target",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "ports": {"type": "string", "description": "Ports to scan (e.g., 'top-1000', 'all', '80,443')"},
                    "service_detection": {"type": "boolean", "default": True},
                    "scripts": {"type": "string", "description": "NSE scripts to run (e.g., 'vuln', 'smb-enum-shares')"},
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_nuclei",
            "description": "Run nuclei vulnerability scanner",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or IP"},
                    "tags": {"type": "string", "description": "Template tags (e.g., 'cve', 'misconfig')"},
                    "severity": {"type": "string", "description": "Severity filter (critical,high,medium,low)"},
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_whatweb",
            "description": "Run whatweb for technology fingerprinting",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                    "aggression": {"type": "integer", "default": 2, "minimum": 1, "maximum": 4},
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_gobuster",
            "description": "Run gobuster for directory enumeration",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                    "wordlist": {"type": "string", "description": "Path to wordlist"},
                    "extensions": {"type": "string", "default": "php,html,txt,js,json"},
                    "threads": {"type": "integer", "default": 50},
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap",
            "description": "Run sqlmap for SQL injection testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "risk": {"type": "integer", "default": 1, "minimum": 1, "maximum": 3},
                    "level": {"type": "integer", "default": 1, "minimum": 1, "maximum": 5},
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_crypto",
            "description": "Run crypto/encoding operations",
            "parameters": {
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "description": "Operation (base64_encode, base64_decode, auto_decode, jwt_decode, etc.)"},
                    "data": {"type": "string", "description": "Input data"},
                    "key": {"type": "string", "description": "Key for AES/JWT operations"},
                },
                "required": ["operation", "data"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Execute local shell command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute"},
                    "timeout": {"type": "integer", "default": 60},
                },
                "required": ["command"]
            }
        }
    },
]