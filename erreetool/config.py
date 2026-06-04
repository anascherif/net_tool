import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    # Explicitly load .env from project root
    project_root = Path(__file__).parent.parent
    env_file = project_root / ".env"
    if env_file.exists():
        load_dotenv(str(env_file))
except ImportError:
    pass

# OpenRouter API Key for AI explanation fallback
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")