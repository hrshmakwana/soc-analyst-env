"""
Fallback FastAPI server for when openenv-core is not available.

Provides manual /reset, /step, /state endpoints.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Request
from server.environment import SOCEnvironment
from models import SOCAction, SOCObservation


def create_fallback_app() -> FastAPI:
    """Create a manual FastAPI app with all environment endpoints."""
    app = FastAPI(
        title="SOC Analyst Environment",
        description="Cybersecurity SOC Analyst Environment for OpenEnv",
        version="1.0.0",
    )

    env = SOCEnvironment()

    @app.get("/health")
    async def health():
        return {"status": "healthy", "environment": "soc_analyst_env"}

    @app.post("/reset")
    async def reset(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        task_id = body.get("task_id", "alert_triage")
        obs = env.reset(task_id=task_id)
        obs_dict = obs.model_dump() if hasattr(obs, "model_dump") else obs.dict()
        return {
            "observation": obs_dict,
            "reward": obs_dict.get("reward"),
            "done": obs_dict.get("done", False),
        }

    @app.post("/step")
    async def step(request: Request):
        body = await request.json()
        action_data = body.get("action", body)
        action = SOCAction(
            action_type=action_data.get("action_type", ""),
            parameters=action_data.get("parameters", {}),
        )
        obs = env.step(action)
        obs_dict = obs.model_dump() if hasattr(obs, "model_dump") else obs.dict()
        return {
            "observation": obs_dict,
            "reward": obs_dict.get("reward"),
            "done": obs_dict.get("done", False),
        }

    @app.get("/state")
    async def state():
        st = env.state
        return st.model_dump() if hasattr(st, "model_dump") else st.dict()

    return app
