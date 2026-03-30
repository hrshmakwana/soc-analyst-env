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

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from server.environment import SOCEnvironment
from models import SOCAction, SOCObservation, SOCState

# ---------------------------------------------------------------------------
# Try to use openenv's create_fastapi_app if available and compatible
# ---------------------------------------------------------------------------
_openenv_app = None
try:
    from openenv.core.env_server import create_fastapi_app
    _openenv_app = create_fastapi_app(SOCEnvironment, SOCAction, SOCObservation)
except Exception:
    pass

if _openenv_app is not None:
    app = _openenv_app
else:
    # Fallback: create our own FastAPI app with the correct endpoints
    app = FastAPI(
        title="SOC Analyst Environment",
        description="Cybersecurity SOC Analyst Environment for OpenEnv",
        version="1.0.0",
    )

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
# Shared environment instance
# ---------------------------------------------------------------------------
_env = SOCEnvironment()


# ---------------------------------------------------------------------------
# Endpoints (register even if openenv's create_fastapi_app was used,
# to guarantee they exist and work for the validator)
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "environment": "soc_analyst_env"}


@app.post("/reset")
async def reset(request: Request):
    """Reset the environment for a new episode."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    task_id = body.get("task_id", "alert_triage")
    seed = body.get("seed")
    episode_id = body.get("episode_id")

    obs = _env.reset(seed=seed, episode_id=episode_id, task_id=task_id)
    return _obs_to_dict(obs)


@app.post("/step")
async def step(request: Request):
    """Take an action in the environment."""
    body = await request.json()

    action_type = body.get("action_type", "")
    parameters = body.get("parameters", {})

    action = SOCAction(action_type=action_type, parameters=parameters)
    obs = _env.step(action)
    return _obs_to_dict(obs)


@app.get("/state")
async def state():
    """Get the current environment state."""
    st = _env.state
    return st.model_dump() if hasattr(st, "model_dump") else st.dict()


def _obs_to_dict(obs: SOCObservation) -> dict:
    """Convert an observation to a JSON-serializable dict."""
    data = obs.model_dump() if hasattr(obs, "model_dump") else obs.dict()
    return data
