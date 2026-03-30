"""
Data models for the SOC Analyst Environment.

Defines typed Action, Observation, and State models using Pydantic
for the Cybersecurity SOC Analyst training environment.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import Field

try:
    from openenv.core.env_server import Action, Observation, State
except ImportError:
    from openenv.core.env_server.types import Action, Observation, State


class SOCAction(Action):
    """
    Action taken by the SOC analyst agent.

    action_type determines which action to perform:
    - classify_alert: Classify an alert as true_positive, false_positive, or needs_investigation
    - query_logs: Search SIEM logs for indicators
    - lookup_threat_intel: Check IP/domain/hash against threat intelligence database
    - check_network: View network connections for a host
    - isolate_host: Containment: isolate a compromised host from the network
    - block_ip: Containment: block a malicious IP at the firewall
    - disable_account: Containment: disable a compromised user account
    - submit_report: Submit an incident report with findings
    - escalate: Escalate the incident to senior analyst / management
    """

    action_type: Literal[
        "classify_alert",
        "query_logs",
        "lookup_threat_intel",
        "check_network",
        "isolate_host",
        "block_ip",
        "disable_account",
        "submit_report",
        "escalate",
    ] = Field(..., description="Type of SOC analyst action to perform")

    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters (e.g., alert_id, query, ip_address, report_text)",
    )


class SOCObservation(Observation):
    """
    Observation returned by the SOC environment after each action.

    Provides a rich view of the current SOC analyst workspace.
    """

    # Alert queue
    alerts: List[Dict[str, Any]] = Field(
        default_factory=list, description="Current alert queue with alert details"
    )

    # Investigation context
    investigation_notes: List[str] = Field(
        default_factory=list, description="Running investigation log entries"
    )

    # Last action results
    query_results: Optional[Dict[str, Any]] = Field(
        None, description="Results from the last query/lookup action"
    )

    # Available actions in current context
    available_actions: List[str] = Field(
        default_factory=list, description="Actions available in current state"
    )

    # Containment status
    containment_status: Dict[str, Any] = Field(
        default_factory=dict,
        description="Status of containment actions (isolated hosts, blocked IPs, disabled accounts)",
    )

    # Feedback
    message: str = Field("", description="System feedback message")

    # Task info
    task_id: str = Field("", description="Current task identifier")
    task_description: str = Field("", description="Description of the current task objective")

    # Episode control
    done: bool = Field(False, description="Whether the episode is complete")
    reward: Optional[float] = Field(None, description="Reward for the action taken")


class SOCState(State):
    """
    Internal state of the SOC environment.

    Tracks all episode data including alert queue, investigation history,
    containment actions, and grading information.
    """

    # Task tracking
    task_id: str = Field("", description="Current task identifier")
    current_scenario: str = Field("", description="Loaded scenario name")

    # Alert management
    alert_classifications: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of alert_id -> classification made by agent",
    )

    # Investigation tracking
    investigated_alerts: List[str] = Field(
        default_factory=list, description="Alert IDs that have been investigated"
    )
    queries_made: List[Dict[str, Any]] = Field(
        default_factory=list, description="Log of all queries made"
    )
    iocs_identified: List[str] = Field(
        default_factory=list, description="IOCs (Indicators of Compromise) identified by agent"
    )
    attack_vector_identified: str = Field(
        "", description="Attack vector identified by agent"
    )
    severity_assessment: str = Field(
        "", description="Severity level assessed by agent"
    )
    affected_systems_identified: List[str] = Field(
        default_factory=list, description="Systems identified as affected"
    )

    # Containment actions
    isolated_hosts: List[str] = Field(
        default_factory=list, description="Hosts isolated from network"
    )
    blocked_ips: List[str] = Field(
        default_factory=list, description="IPs blocked at firewall"
    )
    disabled_accounts: List[str] = Field(
        default_factory=list, description="User accounts disabled"
    )

    # Report
    incident_report: str = Field("", description="Incident report submitted by agent")
    escalated: bool = Field(False, description="Whether incident was escalated")

    # Scoring
    cumulative_reward: float = Field(0.0, description="Cumulative reward this episode")
    actions_taken: int = Field(0, description="Number of actions taken")


__all__ = ["SOCAction", "SOCObservation", "SOCState"]
