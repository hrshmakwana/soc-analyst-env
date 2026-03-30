"""
SOC Analyst Environment — FastAPI Server.

Creates the FastAPI application with all OpenEnv endpoints:
  POST /reset   — Start a new episode
  POST /step    — Take an action
  GET  /state   — Get current environment state
  GET  /health  — Health check
"""

import sys
import os

# Ensure parent package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.environment import SOCEnvironment
from models import SOCAction, SOCObservation

# ---------------------------------------------------------------------------
# Create app via openenv-core (handles /reset, /step, /state)
# ---------------------------------------------------------------------------
try:
    from openenv.core.env_server import create_fastapi_app
    app = create_fastapi_app(SOCEnvironment, SOCAction, SOCObservation)
except Exception as exc:
    print(f"Warning: openenv create_fastapi_app failed ({exc}), using fallback server")
    # Fallback: create a manual FastAPI app
    from server._fallback import create_fallback_app
    app = create_fallback_app()

# ---------------------------------------------------------------------------
# CORS — allow all origins for HF Spaces
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Health endpoint (always added, even if openenv provides /reset etc.)
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "environment": "soc_analyst_env"}
