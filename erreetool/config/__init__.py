"""
Configuration for erreetool agent.

Loads .env, exposes API keys, and resolves stable on-disk paths for
memory and per-session output that persist across different working
directories.
"""

import os
import sys
from pathlib import Path

# Project root is three levels up from this package:
#   erreetool/config/__init__.py  ->  erreetool/  ->  project_root/
project_root = Path(__file__).resolve().parent.parent.parent
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

# Also expose under a clearer name for callers
NVIDIA_NIM_API_KEY = os.getenv("NVIDIA_NIM_API_KEY") or os.getenv("NIM_API_KEY")


def get_memory_dir() -> Path:
    """
    Resolve a stable memory directory that persists across runs.

    Priority:
      1. ERREETOOL_MEMORY_DIR env var (if set)
      2. Portable folder next to the project root (if it already exists)
      3. Per-user data dir (platform-appropriate)

    This avoids the cwd-dependent 'erreetool-memory' folder so the agent
    accumulates long-term memory no matter where it's invoked from.
    """
    env_dir = os.getenv("ERREETOOL_MEMORY_DIR")
    if env_dir:
        p = Path(env_dir).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Portable mode: keep memory next to the project (USB sticks etc.)
    portable = project_root / "erreetool-memory"
    if portable.exists():
        return portable

    # Otherwise use a per-user data directory
    if sys.platform == "win32":
        base = Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    else:
        # Linux/macOS: follow XDG_DATA_HOME convention
        base = Path(os.getenv("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    p = base / "erreetool" / "memory"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_output_dir(session_id: str) -> Path:
    """
    Resolve the output directory for a given session.

    Mirrors get_memory_dir() logic so report artifacts don't pollute cwd.
    """
    env_dir = os.getenv("ERREETOOL_OUTPUT_DIR")
    if env_dir:
        p = Path(env_dir).expanduser() / session_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    portable = project_root / "erreetool-output"
    if portable.exists():
        p = portable / session_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    if sys.platform == "win32":
        base = Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    else:
        base = Path(os.getenv("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    p = base / "erreetool" / "output" / session_id
    p.mkdir(parents=True, exist_ok=True)
    return p
