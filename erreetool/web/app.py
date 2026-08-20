"""
Web UI Application - FastAPI + Static React frontend.
"""

import os
import json
import asyncio
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from erreetool.api.server import app as api_app


class ConnectionManager:
    """Manage WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass


manager = ConnectionManager()


def create_web_app(static_dir: Optional[Path] = None) -> FastAPI:
    """Create the web UI FastAPI application."""
    
    if static_dir is None:
        static_dir = Path(__file__).parent / "static"
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        yield
        # Shutdown
        pass
    
    app = FastAPI(
        title="ERREETOOL Web UI",
        description="Web-based penetration testing dashboard",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Mount API routes
    app.mount("/api/v1", api_app)
    
    # WebSocket for real-time updates
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                # Echo for now
                await websocket.send_json({"type": "echo", "data": data})
        except WebSocketDisconnect:
            manager.disconnect(websocket)
    
    # Serve React static files
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir / "static"), name="static")
        
        @app.get("/", response_class=HTMLResponse)
        async def serve_spa():
            index_file = static_dir / "index.html"
            if index_file.exists():
                return FileResponse(index_file)
            return HTMLResponse("<h1>ERREETOOL Web UI</h1><p>Build frontend first</p>")
        
        # Catch-all for SPA routing
        @app.get("/{path:path}", response_class=HTMLResponse)
        async def spa_catch_all(path: str):
            index_file = static_dir / "index.html"
            if index_file.exists():
                return FileResponse(index_file)
            return HTMLResponse("<h1>ERREETOOL Web UI</h1><p>Build frontend first</p>")
    else:
        @app.get("/", response_class=HTMLResponse)
        async def root():
            return HTMLResponse("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>ERREETOOL Web UI</title>
                <style>
                    body { font-family: monospace; padding: 2rem; background: #1a1a2e; color: #eee; }
                    .container { max-width: 800px; margin: 0 auto; }
                    h1 { color: #00d9ff; }
                    .card { background: #16213e; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; }
                    .status { color: #00d9ff; }
                    button { background: #0f3460; color: #00d9ff; border: 1px solid #00d9ff; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; margin: 0.5rem; }
                    button:hover { background: #00d9ff; color: #1a1a2e; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🦞 ERREETOOL Web UI</h1>
                    <p class="status">Backend API running at <a href="/api/v1/docs" style="color: #00d9ff;">/api/v1/docs</a></p>
                    <div class="card">
                        <h2>Frontend Not Built</h2>
                        <p>To build the React frontend:</p>
                        <pre style="background: #0f3460; padding: 1rem; border-radius: 4px;">
cd erreetool/web
npm install
npm run build
                        </pre>
                        <p>Then restart the server.</p>
                    </div>
                    <div class="card">
                        <h2>Quick Links</h2>
                        <a href="/api/v1/docs"><button>API Documentation</button></a>
                        <a href="/api/v1/health"><button>Health Check</button></a>
                    </div>
                </div>
            </body>
            </html>
            """)
    
    return app


def run_web(host: str = "127.0.0.1", port: int = 7788, reload: bool = False):
    """Run the web UI server."""
    import uvicorn
    
    static_dir = Path(__file__).parent / "static"
    app = create_web_app(static_dir)
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    run_web()