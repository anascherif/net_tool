"""
TUI (Terminal User Interface) for ERREETOOL.

Built with Textual - provides a terminal-based workspace for:
- Target scope configuration
- Live evidence panel
- Tool output streaming
- Attack graph visualization
- Mode selection (quick/deep/continuous)
- Dry-run preview
"""

from erreetool.tui.app import ERREETOOLApp, run_tui

__all__ = ["ERREETOOLApp", "run_tui"]