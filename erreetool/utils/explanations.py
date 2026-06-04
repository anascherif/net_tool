import json
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()
_LOG_FILE = Path(__file__).parent.parent / "ai_debug.log"


def _log(msg: str):
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass


def load_static_explanation(module_name: str) -> str:
    path = Path(__file__).parent.parent / "explanations" / f"{module_name}.json"
    if not path.exists():
        return "No static explanation available for this command."
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            tips_text = "\n".join(f"- {tip}" for tip in data.get("tips", []))
            return f"[bold cyan]{data.get('title', 'Explanation')}[/bold cyan]\n\n{data.get('description', '')}\n\n[bold green]What to do next:[/bold green]\n{tips_text}"
    except Exception as e:
        return f"Error loading explanation: {e}"


def _get_ai_explanation(command: str, context: str) -> str:
    from erreetool.config import OPENROUTER_API_KEY

    if not OPENROUTER_API_KEY or not OPENROUTER_API_KEY.strip():
        _log("[AI] No API key configured")
        return ""

    _log(f"[AI] Key loaded (prefix: {OPENROUTER_API_KEY[:15]}...)")
    _log(f"[AI] Request: command={command!r}, context={context!r}")

    try:
        import httpx
        import time
        prompt = (
            f"You are a helpful IT Assistant explaining network outputs to a non-technical user.\n"
            f"Command: {command}\nSummary/Output: {context}\n\n"
            "Provide a short, non-technical explanation (2-3 sentences max) of what this means, "
            "and 2 short actionable tips. Avoid jargon."
        )
        models = ["openrouter/free", "poolside/laguna-xs.2:free"]
        for attempt, model in enumerate(models):
            try:
                _log(f"[AI] Attempt {attempt + 1}: model={model}")
                with httpx.Client() as client:
                    resp = client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": 300,
                        },
                        timeout=12.0
                    )
                    _log(f"[AI] HTTP {resp.status_code}")
                    resp.raise_for_status()
                    text = resp.json()["choices"][0]["message"]["content"]
                    _log(f"[AI] Response received ({len(text)} chars)")
                    if text and text.strip():
                        return text
            except Exception as e:
                _log(f"[AI] Attempt {attempt + 1} failed: {e}")
                if attempt < len(models) - 1:
                    time.sleep(1)
        _log("[AI] All models exhausted, returning empty")
        return ""
    except Exception as e:
        _log(f"[AI] Fatal error: {e}")
        return ""


def _safe_print(text: str) -> bool:
    try:
        encoding = sys.stdout.encoding or "utf-8"
        safe = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        sys.stdout.write(safe + "\n")
        sys.stdout.flush()
        return True
    except Exception as e:
        _log(f"[SAFE_PRINT] Failed: {e}")
        return False


def _has_api_key() -> bool:
    from erreetool.config import OPENROUTER_API_KEY
    return bool(OPENROUTER_API_KEY and OPENROUTER_API_KEY.strip())


def show_explanation(command: str, context: str = ""):
    _log(f"[SHOW] command={command!r}, context={context!r}")

    if not _has_api_key():
        _log("[SHOW] No API key, showing static")
        static_text = load_static_explanation(command)
        console.print(Panel(static_text, title="[bold cyan]Explanation[/bold cyan]"))
        return

    _safe_print("Fetching AI explanation...")

    ai_text = _get_ai_explanation(command, context)
    if ai_text and ai_text.strip():
        _log("[SHOW] AI text received, printing")
        _safe_print("")
        _safe_print("=== AI Explanation ===")
        _safe_print(ai_text)
        _safe_print("======================")
        _log("[SHOW] AI explanation displayed successfully")
        return

    _log("[SHOW] AI text empty or missing, showing static fallback")
    static_text = load_static_explanation(command)
    console.print(Panel(static_text, title="[bold cyan]Explanation[/bold cyan]"))
