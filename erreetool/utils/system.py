import os
import platform
import subprocess
from typing import List, Tuple


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError, ImportError):
            return False
    return os.geteuid() == 0


def run_command(command: List[str]) -> Tuple[int, str, str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr
