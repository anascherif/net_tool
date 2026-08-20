"""
Web UI Module - FastAPI + React served from same process.

Provides a web-based interface for:
- Assessment dashboard
- Live evidence streaming
- Attack graph visualization
- Report viewing
- Configuration management
"""

from erreetool.web.app import create_web_app, run_web

__all__ = ["create_web_app", "run_web"]