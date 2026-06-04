import json
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from erreetool.config import OPENROUTER_API_KEY

console = Console()

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

async def _get_ai_explanation(command: str, context: str) -> str:
    if not OPENROUTER_API_KEY:
        return ""
    try:
        import httpx
        prompt = (
            f"You are a helpful IT Assistant explaining network outputs to a non-technical user.\n"
            f"Command: {command}\nSummary/Output: {context}\n\n"
            "Provide a short, non-technical explanation (2-3 sentences max) of what this means, "
            "and 2 short actionable tips. Avoid jargon."
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
                json={
                    "model": "meta-llama/llama-3-8b-instruct:free",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 300,
                },
                timeout=12.0
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI Generation Failed: {e}"

def show_explanation(command: str, context: str = ""):
    with console.status("[bold green]Generating explanation...[/bold green]"):
        if OPENROUTER_API_KEY:
            try:
                ai_text = asyncio.run(_get_ai_explanation(command, context))
                if ai_text and not "Failed" in ai_text:
                    console.print(Panel(ai_text, title="[bold yellow]🤖 AI Explanation[/bold yellow]"))
                    return
            except Exception:
                pass
        
        # Fallback to static
        static_text = load_static_explanation(command)
        console.print(Panel(static_text, title="[bold cyan]💡 Explanation[/bold cyan]"))