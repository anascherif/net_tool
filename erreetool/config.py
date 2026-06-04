import os
from pathlib import Path

project_root = Path(__file__).parent.parent
env_file = project_root / ".env"

def _load_dotenv(path: Path):
    if not path.exists():
        return
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip("\"'")
            if key:
                os.environ.setdefault(key, val)

try:
    from dotenv import load_dotenv
    if env_file.exists():
        load_dotenv(str(env_file))
except ImportError:
    _load_dotenv(env_file)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
