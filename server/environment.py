"""
SOC Analyst Environment — Core Environment Logic.

Implements the OpenEnv Environment interface for a Cybersecurity SOC Analyst
training environment with 3 tasks: Alert Triage, Incident Investigation,
and Full Incident Response.
"""

import uuid
import sys
import os
from typing import Any, Dict, Optional

from openenv.core.env_server import Environment

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import SOCAction, SOCObservation, SOCState
from data.scenarios import (
    get_task,
    get_alerts_for_task,
    query_siem_logs,
    get_network_connections,
    TASKS,
)
from data.threat_intel import lookup_threat_intel
from server.graders import (
    grade_alert_triage,
    grade_investigation,
    grade_incident_response,
)


class SOCEnvironment(Environment):
    """
    Cybersecurity SOC Analyst Environment.

    An AI agent acts as a Security Operations Center analyst, performing
    alert triage, incident investigation, and incident response across
    3 difficulty levels.
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        super().__init__()
        self._state = SOCState()
        self._task: Dict[str, Any] = {}
        self._alerts = []
        self._investigation_notes = []
        self._step_rewards = []

    def reset(self, seed=None, episode_id=None, **kwargs) -> SOCObservation:
        """
        Reset the environment for a new episode.

        Args:
            seed: Optional random seed
            episode_id: Optional episode identifier
            **kwargs: Must include 'task_id' — one of 'alert_triage',
                      'incident_investigation', 'full_incident_response'
        """
        task_id = kwargs.get("task_id", "alert_triage")

        # Load task
        self._task = get_task(task_id)
        self._alerts = get_alerts_for_task(task_id)

        # Reset state
        self._state = SOCState(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
            task_id=task_id,
            current_scenario=self._task["name"],
        )
        self._investigation_notes = []
        self._step_rewards = []

        return SOCObservation(
            done=False,
            reward=None,
            alerts=self._alerts,
            investigation_notes=[],
            query_results=None,
            available_actions=self._task.get("available_actions", []),
            containment_status=self._get_containment_status(),
            message=f"🔔 SOC Shift Started — Task: {self._task['name']} ({self._task['difficulty'].upper()})\n\n{self._task['description']}",
            task_id=task_id,
            task_description=self._task["description"],
        )

    def step(self, action: SOCAction, timeout_s=None, **kwargs) -> SOCObservation:
        """Process a SOC analyst action and return observation with reward."""
        self._state.step_count += 1
        self._state.actions_taken += 1

        action_type = action.action_type
        params = action.parameters or {}

        # Validate action is available for current task
        available = self._task.get("available_actions", [])
        if action_type not in available:
            return self._make_obs(
                message=f"❌ Action '{action_type}' is not available for this task. Available: {available}",
                reward=-0.02,
            )

        # Dispatch action
        handlers = {
            "classify_alert": self._handle_classify_alert,
            "query_logs": self._handle_query_logs,
            "lookup_threat_intel": self._handle_lookup_threat_intel,
            "check_network": self._handle_check_network,
            "isolate_host": self._handle_isolate_host,
            "block_ip": self._handle_block_ip,
            "disable_account": self._handle_disable_account,
            "submit_report": self._handle_submit_report,
            "escalate": self._handle_escalate,
        }

        handler = handlers.get(action_type)
        if not handler:
            return self._make_obs(
                message=f"❌ Unknown action type: {action_type}",
                reward=-0.02,
            )

        result = handler(params)

        # Check if episode should end
        done = self._check_done()
        if done:
            final_grade = self._compute_final_grade()
            result["done"] = True
            result["reward"] = final_grade["score"]
            result["message"] += f"\n\n📊 FINAL SCORE: {final_grade['score']:.4f}/1.00\n"
            result["message"] += "\n".join(final_grade.get("breakdown", []))
            result["message"] += f"\n\n{final_grade.get('feedback', '')}"

        return self._make_obs(**result)

    @property
    def state(self) -> SOCState:
        """Return current internal state."""
        return self._state

    # ========================================================================
    # ACTION HANDLERS
    # ========================================================================

    def _handle_classify_alert(self, params: Dict) -> Dict[str, Any]:
        """Classify a security alert."""
        alert_id = params.get("alert_id", "")
        classification = params.get("classification", "").lower().strip()

        valid_classes = ["true_positive", "false_positive", "needs_investigation"]
        if classification not in valid_classes:
            return {
                "message": f"⚠️ Invalid classification '{classification}'. Must be one of: {valid_classes}",
                "reward": -0.01,
            }

        # Check if alert exists in current task
        alert_ids = [a["alert_id"] for a in self._alerts]
        if alert_id not in alert_ids:
            return {
                "message": f"⚠️ Alert '{alert_id}' not found in current queue. Available: {alert_ids}",
                "reward": -0.01,
            }

        self._state.alert_classifications[alert_id] = classification
        note = f"Classified {alert_id} as {classification}"
        self._investigation_notes.append(note)

        # Partial reward for triage task
        reward = 0.0
        task_id = self._state.task_id
        if task_id == "alert_triage":
            expected = self._task.get("expected_classifications", {})
            if alert_id in expected:
                if classification == expected[alert_id]:
                    reward = 0.15
                else:
                    reward = -0.05

        return {
            "message": f"✅ Alert {alert_id} classified as '{classification}'.",
            "reward": reward,
            "query_results": {"action": "classify_alert", "alert_id": alert_id, "classification": classification},
        }

    def _handle_query_logs(self, params: Dict) -> Dict[str, Any]:
        """Query SIEM logs."""
        log_type = params.get("log_type", "")
        filters = {k: v for k, v in params.items() if k != "log_type"}

        if not log_type:
            return {
                "message": "⚠️ Must specify 'log_type'. Available: auth, endpoint, network, database, email, waf",
                "reward": 0.0,
                "query_results": {"available_log_types": ["auth", "endpoint", "network", "database", "email", "waf"]},
            }

        results = query_siem_logs(log_type, **filters)
        note = f"Queried {log_type} logs with filters: {filters} — {len(results)} results"
        self._investigation_notes.append(note)
        self._state.queries_made.append({"type": log_type, "filters": filters, "result_count": len(results)})

        # Small reward for active investigation
        reward = 0.02 if len(results) > 0 and not results[0].get("error") else 0.0

        return {
            "message": f"🔍 SIEM query: {log_type} logs — {len(results)} entries found.",
            "reward": reward,
            "query_results": {"log_type": log_type, "filters": filters, "entries": results},
        }

    def _handle_lookup_threat_intel(self, params: Dict) -> Dict[str, Any]:
        """Look up threat intelligence."""
        query = params.get("query", "")
        query_type = params.get("query_type")

        if not query:
            return {
                "message": "⚠️ Must specify 'query' — an IP address, domain, or file hash to look up.",
                "reward": 0.0,
            }

        result = lookup_threat_intel(query, query_type)
        note = f"Threat intel lookup: {query} — reputation: {result.get('result', {}).get('reputation', 'N/A')}"
        self._investigation_notes.append(note)

        # Track IOCs if found to be malicious
        result_data = result.get("result", {})
        reputation = result_data.get("reputation", "unknown")
        if reputation == "malicious" and query not in self._state.iocs_identified:
            self._state.iocs_identified.append(query)

        # Mark alert as investigated
        for alert in self._alerts:
            source_ip = alert.get("source_ip", "")
            if source_ip == query:
                if alert["alert_id"] not in self._state.investigated_alerts:
                    self._state.investigated_alerts.append(alert["alert_id"])

        reward = 0.02 if reputation in ("malicious", "clean") else 0.0

        return {
            "message": f"🔎 Threat Intel: {query} — Reputation: {reputation}",
            "reward": reward,
            "query_results": result,
        }

    def _handle_check_network(self, params: Dict) -> Dict[str, Any]:
        """Check network connections for a host."""
        host = params.get("host", "")

        if not host:
            return {
                "message": "⚠️ Must specify 'host' — the hostname to check connections for.",
                "reward": 0.0,
            }

        connections = get_network_connections(host)
        note = f"Checked network connections for {host} — {len(connections)} connections"
        self._investigation_notes.append(note)

        return {
            "message": f"🌐 Network connections for {host}: {len(connections)} active connections.",
            "reward": 0.02,
            "query_results": {"host": host, "connections": connections},
        }

    def _handle_isolate_host(self, params: Dict) -> Dict[str, Any]:
        """Isolate a host from the network."""
        host = params.get("host", "")

        if not host:
            return {"message": "⚠️ Must specify 'host' to isolate.", "reward": 0.0}

        if host in self._state.isolated_hosts:
            return {"message": f"ℹ️ Host {host} is already isolated.", "reward": 0.0}

        self._state.isolated_hosts.append(host)
        note = f"🔒 CONTAINMENT: Isolated host {host} from network"
        self._investigation_notes.append(note)

        # Reward for correct containment
        reward = 0.0
        expected_containment = self._task.get("expected", {}).get("containment", {})
        expected_hosts = expected_containment.get("isolate_hosts", [])
        if host in expected_hosts:
            reward = 0.08
        else:
            reward = -0.05  # Penalty for isolating wrong host

        return {
            "message": f"🔒 Host {host} has been isolated from the network.",
            "reward": reward,
            "query_results": {"action": "isolate_host", "host": host, "status": "isolated"},
        }

    def _handle_block_ip(self, params: Dict) -> Dict[str, Any]:
        """Block an IP at the firewall."""
        ip = params.get("ip_address", params.get("ip", ""))

        if not ip:
            return {"message": "⚠️ Must specify 'ip_address' to block.", "reward": 0.0}

        if ip in self._state.blocked_ips:
            return {"message": f"ℹ️ IP {ip} is already blocked.", "reward": 0.0}

        self._state.blocked_ips.append(ip)
        note = f"🚫 CONTAINMENT: Blocked IP {ip} at firewall"
        self._investigation_notes.append(note)

        reward = 0.0
        expected_containment = self._task.get("expected", {}).get("containment", {})
        expected_ips = expected_containment.get("block_ips", [])
        if ip in expected_ips:
            reward = 0.05
        else:
            reward = -0.03

        return {
            "message": f"🚫 IP {ip} has been blocked at the firewall.",
            "reward": reward,
            "query_results": {"action": "block_ip", "ip": ip, "status": "blocked"},
        }

    def _handle_disable_account(self, params: Dict) -> Dict[str, Any]:
        """Disable a user account."""
        account = params.get("account", params.get("username", ""))

        if not account:
            return {"message": "⚠️ Must specify 'account' (username) to disable.", "reward": 0.0}

        if account in self._state.disabled_accounts:
            return {"message": f"ℹ️ Account {account} is already disabled.", "reward": 0.0}

        self._state.disabled_accounts.append(account)
        note = f"👤 CONTAINMENT: Disabled user account '{account}'"
        self._investigation_notes.append(note)

        reward = 0.0
        expected_containment = self._task.get("expected", {}).get("containment", {})
        expected_accounts = expected_containment.get("disable_accounts", [])
        if account in expected_accounts:
            reward = 0.06
        else:
            reward = -0.05

        return {
            "message": f"👤 Account '{account}' has been disabled.",
            "reward": reward,
            "query_results": {"action": "disable_account", "account": account, "status": "disabled"},
        }

    def _handle_submit_report(self, params: Dict) -> Dict[str, Any]:
        """Submit incident report."""
        report = params.get("report", params.get("text", ""))
        attack_vector = params.get("attack_vector", "")
        severity = params.get("severity", "")
        affected_systems = params.get("affected_systems", [])

        if not report:
            return {
                "message": "⚠️ Must specify 'report' with your incident report text.",
                "reward": 0.0,
            }

        self._state.incident_report = report
        if attack_vector:
            self._state.attack_vector_identified = attack_vector
        if severity:
            self._state.severity_assessment = severity
        if affected_systems:
            if isinstance(affected_systems, str):
                affected_systems = [s.strip() for s in affected_systems.split(",")]
            self._state.affected_systems_identified = affected_systems

        note = f"📝 Incident report submitted ({len(report)} chars)"
        self._investigation_notes.append(note)

        return {
            "message": f"📝 Incident report submitted successfully ({len(report)} characters).",
            "reward": 0.05,
            "query_results": {
                "action": "submit_report",
                "report_length": len(report),
                "attack_vector": attack_vector,
                "severity": severity,
                "affected_systems": affected_systems,
            },
        }

    def _handle_escalate(self, params: Dict) -> Dict[str, Any]:
        """Escalate the incident."""
        reason = params.get("reason", "No reason provided")
        self._state.escalated = True
        note = f"⬆️ Incident escalated: {reason}"
        self._investigation_notes.append(note)

        return {
            "message": f"⬆️ Incident escalated to senior analyst / management. Reason: {reason}",
            "reward": 0.03,
            "query_results": {"action": "escalate", "reason": reason, "status": "escalated"},
        }

    # ========================================================================
    # INTERNAL HELPERS
    # ========================================================================

    def _make_obs(self, message: str = "", reward: float = 0.0, done: bool = False,
                  query_results: Optional[Dict] = None, **kwargs) -> SOCObservation:
        """Create an observation from current state."""
        self._state.cumulative_reward += reward
        self._step_rewards.append(reward)

        return SOCObservation(
            done=done,
            reward=reward,
            alerts=self._alerts,
            investigation_notes=list(self._investigation_notes),
            query_results=query_results,
            available_actions=self._task.get("available_actions", []),
            containment_status=self._get_containment_status(),
            message=message,
            task_id=self._state.task_id,
            task_description=self._task.get("description", ""),
        )

    def _get_containment_status(self) -> Dict[str, Any]:
        """Get current containment status."""
        return {
            "isolated_hosts": list(self._state.isolated_hosts),
            "blocked_ips": list(self._state.blocked_ips),
            "disabled_accounts": list(self._state.disabled_accounts),
        }

    def _check_done(self) -> bool:
        """Check if the episode should end."""
        max_steps = self._task.get("max_steps", 50)

        # Max steps reached
        if self._state.step_count >= max_steps:
            return True

        task_id = self._state.task_id

        # Alert triage: done when all alerts classified
        if task_id == "alert_triage":
            expected = self._task.get("expected_classifications", {})
            if len(self._state.alert_classifications) >= len(expected):
                return True

        # Investigation: done when report submitted
        if task_id == "incident_investigation":
            if self._state.incident_report:
                return True

        # Full IR: done when report submitted AND containment actions taken
        if task_id == "full_incident_response":
            has_report = bool(self._state.incident_report)
            has_containment = (
                len(self._state.isolated_hosts) > 0 or
                len(self._state.blocked_ips) > 0 or
                len(self._state.disabled_accounts) > 0
            )
            if has_report and has_containment:
                return True

        return False

    def _compute_final_grade(self) -> Dict[str, Any]:
        """Compute the final grade using the appropriate task grader."""
        task_id = self._state.task_id

        if task_id == "alert_triage":
            return grade_alert_triage(
                classifications=self._state.alert_classifications,
                expected=self._task.get("expected_classifications", {}),
                investigated_alerts=self._state.investigated_alerts,
            )

        elif task_id == "incident_investigation":
            return grade_investigation(
                iocs_identified=self._state.iocs_identified,
                attack_vector=self._state.attack_vector_identified,
                severity=self._state.severity_assessment,
                affected_systems=self._state.affected_systems_identified,
                expected=self._task.get("expected", {}),
                queries_made=self._state.queries_made,
                steps_taken=self._state.step_count,
                max_steps=self._task.get("max_steps", 30),
            )

        elif task_id == "full_incident_response":
            return grade_incident_response(
                iocs_identified=self._state.iocs_identified,
                attack_vector=self._state.attack_vector_identified,
                severity=self._state.severity_assessment,
                affected_systems=self._state.affected_systems_identified,
                isolated_hosts=self._state.isolated_hosts,
                blocked_ips=self._state.blocked_ips,
                disabled_accounts=self._state.disabled_accounts,
                incident_report=self._state.incident_report,
                escalated=self._state.escalated,
                expected=self._task.get("expected", {}),
                steps_taken=self._state.step_count,
                max_steps=self._task.get("max_steps", 50),
            )

        return {"score": 0.0, "feedback": "Unknown task", "breakdown": []}
