"""
SOC Analyst Environment — FastAPI Server.

Provides HTTP endpoints for the OpenEnv SOC Analyst Environment:
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
# Create the FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SOC Analyst Environment",
    description="Cybersecurity SOC Analyst Environment for OpenEnv",
    version="1.0.0",
)

# CORS — allow all origins for HF Spaces
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared environment instance (single session for HTTP)
_env = SOCEnvironment()


def _obs_to_response(obs: SOCObservation) -> dict:
    """Convert SOCObservation to the openenv-core wire format."""
    obs_dict = obs.model_dump() if hasattr(obs, "model_dump") else obs.dict()
    # Return in openenv wire format: {observation: {...}, reward: ..., done: ...}
    return {
        "observation": obs_dict,
        "reward": obs_dict.get("reward"),
        "done": obs_dict.get("done", False),
    }


@app.get("/")
async def root():
    """Root endpoint for Hugging Face Space liveness probe."""
    return {"status": "ready", "app": "soc_analyst_env"}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "environment": "soc_analyst_env"}


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
    return _obs_to_response(obs)


@app.post("/step")
async def step(request: Request):
    """Take an action in the environment."""
    body = await request.json()

    # Support both wrapped {"action": {...}} and flat {"action_type": ...} formats
    action_data = body.get("action", body)
    action_type = action_data.get("action_type", "")
    parameters = action_data.get("parameters", {})

    action = SOCAction(action_type=action_type, parameters=parameters)
    obs = _env.step(action)
    return _obs_to_response(obs)


@app.get("/state")
async def state():
    """Get the current environment state."""
    st = _env.state
    return st.model_dump() if hasattr(st, "model_dump") else st.dict()


@app.get("/metadata")
async def metadata():
    """Return environment metadata."""
    return {
        "name": "soc_analyst_env",
        "description": "Cybersecurity SOC Analyst Environment for OpenEnv",
        "version": "1.0.0",
        "tasks": [
            {"id": "alert_triage", "name": "Alert Triage", "difficulty": "easy", "max_steps": 15},
            {"id": "incident_investigation", "name": "Incident Investigation", "difficulty": "medium", "max_steps": 30},
            {"id": "full_incident_response", "name": "Full Incident Response", "difficulty": "hard", "max_steps": 50},
        ],
    }


def main():
    """Entry point for running the server directly."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()

