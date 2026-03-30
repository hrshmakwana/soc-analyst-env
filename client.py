"""
SOC Analyst Environment — Client Implementation.

Provides the EnvClient subclass for connecting to the SOC Analyst
environment server via WebSocket.
"""

from typing import Dict, Any
from openenv.core.env_client import EnvClient
from openenv.core.client_types import StepResult
from .models import SOCAction, SOCObservation, SOCState


class SOCAnalystEnv(EnvClient[SOCAction, SOCObservation, SOCState]):
    """
    Client for the SOC Analyst OpenEnv environment.

    Usage:
        with SOCAnalystEnv(base_url="https://your-space.hf.space").sync() as env:
            obs = env.reset(task_id="alert_triage")
            result = env.step(SOCAction(
                action_type="classify_alert",
                parameters={"alert_id": "ALT-001", "classification": "true_positive"}
            ))
    """

    def _step_payload(self, action: SOCAction) -> dict:
        """Convert action to wire format."""
        return {
            "action_type": action.action_type,
            "parameters": action.parameters,
        }

    def _parse_result(self, payload: dict) -> StepResult:
        """Parse step result from wire format."""
        obs_data = payload.get("observation", {})
        return StepResult(
            observation=SOCObservation(
                done=payload.get("done", False),
                reward=payload.get("reward"),
                alerts=obs_data.get("alerts", []),
                investigation_notes=obs_data.get("investigation_notes", []),
                query_results=obs_data.get("query_results"),
                available_actions=obs_data.get("available_actions", []),
                containment_status=obs_data.get("containment_status", {}),
                message=obs_data.get("message", ""),
                task_id=obs_data.get("task_id", ""),
                task_description=obs_data.get("task_description", ""),
            ),
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict) -> SOCState:
        """Parse state from wire format."""
        return SOCState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            task_id=payload.get("task_id", ""),
            current_scenario=payload.get("current_scenario", ""),
            alert_classifications=payload.get("alert_classifications", {}),
            investigated_alerts=payload.get("investigated_alerts", []),
            queries_made=payload.get("queries_made", []),
            iocs_identified=payload.get("iocs_identified", []),
            attack_vector_identified=payload.get("attack_vector_identified", ""),
            severity_assessment=payload.get("severity_assessment", ""),
            affected_systems_identified=payload.get("affected_systems_identified", []),
            isolated_hosts=payload.get("isolated_hosts", []),
            blocked_ips=payload.get("blocked_ips", []),
            disabled_accounts=payload.get("disabled_accounts", []),
            incident_report=payload.get("incident_report", ""),
            escalated=payload.get("escalated", False),
            cumulative_reward=payload.get("cumulative_reward", 0.0),
            actions_taken=payload.get("actions_taken", 0),
        )


__all__ = ["SOCAnalystEnv"]
