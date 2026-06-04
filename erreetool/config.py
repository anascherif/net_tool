import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# OpenRouter API Key for AI explanation fallback
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")