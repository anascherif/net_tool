"""
ERREETOOL API Server - FastAPI application entry point.
"""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from erreetool.api.routes import router
from erreetool.api.auth import init_default_users


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    init_default_users()
    print("ERREETOOL API Server started")
    yield
    # Shutdown
    print("ERREETOOL API Server stopped")


app = FastAPI(
    title="ERREETOOL API",
    description="REST API for ERREETOOL penetration testing toolkit",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ERREETOOL_API_CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api/v1")


# Root endpoint
@app.get("/")
async def root():
    return {
        "name": "ERREETOOL API",
        "version": "1.0.0",
        "description": "REST API for ERREETOOL penetration testing toolkit",
        "docs": "/docs",
        "health": "/api/v1/health",
    }


# CLI entry point
def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    workers: int = 1,
):
    """Run the API server."""
    import uvicorn
    
    uvicorn.run(
        "erreetool.api.server:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
    )


if __name__ == "__main__":
    run_server()