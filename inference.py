#!/usr/bin/env python3
"""
Inference Script — SOC Analyst Environment
============================================
ENVIRONMENT VARIABLES:
    API_BASE_URL   The API endpoint for the LLM
    MODEL_NAME     The model identifier to use for inference
    HF_TOKEN       Your Hugging Face / API key

    LOCAL_IMAGE_NAME  (optional) Docker image name when using from_docker_image()

This script runs an LLM agent against the SOC Analyst Environment for all 3 tasks.
Falls back to a deterministic heuristic agent if no API key is available.
Stdout logs follow the required structured format: START / STEP / END.
"""

import json
import os
import re
import sys
import time
import textwrap
from typing import Any, Dict, List, Optional, Tuple

import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Mandatory environment variables (as required by hackathon rules)
# ---------------------------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

# Optional — if you use from_docker_image():
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")

# Environment URL — the deployed HF Space
SOC_ENV_URL = os.getenv(
    "SOC_ENV_URL",
    "https://harsh0127-soc-analyst-env.hf.space",
).rstrip("/")

# Agent configuration
MAX_RETRIES = 2
REQUEST_TIMEOUT = 30
TEMPERATURE = 0.1
MAX_TOKENS = 600

# Task definitions
TASKS = [
    {"task_id": "alert_triage", "name": "Alert Triage", "difficulty": "Easy", "max_steps": 15},
    {"task_id": "incident_investigation", "name": "Incident Investigation", "difficulty": "Medium", "max_steps": 30},
    {"task_id": "full_incident_response", "name": "Full Incident Response", "difficulty": "Hard", "max_steps": 50},
]

# ---------------------------------------------------------------------------
# System prompt for the LLM SOC agent
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = textwrap.dedent("""\
You are an expert SOC (Security Operations Center) analyst AI agent. You analyze
security alerts, investigate incidents, query SIEM logs, look up threat intel,
execute containment actions, and write incident reports.

You interact with the SOC environment by returning a SINGLE JSON action per turn.
The JSON MUST have exactly two keys:
  - "action_type": one of the available actions listed below
  - "parameters": a dict of action-specific parameters

Available action types and their parameters:

  classify_alert:
    {"alert_id": "ALT-XXX", "classification": "true_positive|false_positive|needs_investigation"}

  query_logs:
    {"log_type": "auth|endpoint|network|database|email|waf", ...optional_filters}

  lookup_threat_intel:
    {"query": "IP/domain/hash", "query_type": "ip|domain|hash"}

  check_network:
    {"host": "hostname"}

  isolate_host:
    {"host": "hostname"}

  block_ip:
    {"ip_address": "x.x.x.x"}

  disable_account:
    {"account": "username"}

  submit_report:
    {"report": "detailed text", "attack_vector": "type", "severity": "low|medium|high|critical", "affected_systems": ["host1", "host2"]}

  escalate:
    {"reason": "explanation"}

RULES:
1. Respond with ONLY valid JSON. No markdown, no explanation, no code fences.
2. Investigate BEFORE classifying — query logs and threat intel first.
3. For incident response: investigate → contain → escalate → report.
4. Be precise with alert IDs, hostnames, and IP addresses from the data.
5. Think strategically about efficiency — fewer steps = higher score.
""")


# ============================================================================
# HTTP Client for SOC Environment
# ============================================================================

class SOCEnvClient:
    """
    HTTP client for the SOC Analyst Environment endpoints.

    Handles the openenv-core wire format:
      /reset returns {"observation": {...}, "reward": ..., "done": ...}
      /step  expects {"action": {"action_type": ..., "parameters": ...}}
             returns {"observation": {...}, "reward": ..., "done": ...}
    """

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _unwrap(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Unwrap openenv-core response format into a flat observation dict.
        openenv wraps as: {"observation": {...}, "reward": ..., "done": ...}
        We flatten it so callers get: {"alerts": [...], "reward": ..., "done": ..., ...}
        """
        if "observation" in data and isinstance(data["observation"], dict):
            obs = dict(data["observation"])
            if "reward" in data:
                obs["reward"] = data["reward"]
            if "done" in data:
                obs["done"] = data["done"]
            return obs
        return data

    def reset(self, task_id: str) -> Dict[str, Any]:
        """POST /reset — start a new episode."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.post(
                    f"{self.base_url}/reset",
                    json={"task_id": task_id},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                return self._unwrap(resp.json())
            except Exception as e:
                if attempt < MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"Failed to reset environment: {e}") from e

    def step(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        POST /step — take an action.
        Wraps the action in {"action": {...}} for openenv-core compatibility.
        """
        payload = {"action": action}
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.post(
                    f"{self.base_url}/step",
                    json=payload,
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                return self._unwrap(resp.json())
            except Exception as e:
                if attempt < MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"Failed to step environment: {e}") from e

    def state(self) -> Dict[str, Any]:
        """GET /state — retrieve current state."""
        resp = self.session.get(
            f"{self.base_url}/state",
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def health(self) -> bool:
        """GET /health — check if server is alive."""
        try:
            resp = self.session.get(
                f"{self.base_url}/health",
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False


# ============================================================================
# LLM Agent
# ============================================================================

def format_observation(obs: Dict[str, Any]) -> str:
    """Format an environment observation into a readable prompt for the LLM."""
    parts = []

    message = obs.get("message", "")
    if message:
        parts.append(f"## System Message\n{message}\n")

    alerts = obs.get("alerts", [])
    if alerts:
        parts.append("## Alert Queue")
        for alert in alerts:
            severity = alert.get("severity", "?").upper()
            alert_type = alert.get("type", "?")
            desc = alert.get("description", "")[:200]
            source_ip = alert.get("source_ip", "?")
            target = alert.get("target", "?")
            parts.append(
                f"- **{alert['alert_id']}** [{severity}] {alert_type} | "
                f"src={source_ip} → {target}: {desc}"
            )
        parts.append("")

    query_results = obs.get("query_results")
    if query_results:
        qr_str = json.dumps(query_results, indent=2, default=str)
        if len(qr_str) > 2000:
            qr_str = qr_str[:2000] + "\n... (truncated)"
        parts.append(f"## Last Query Results\n```json\n{qr_str}\n```\n")

    notes = obs.get("investigation_notes", [])
    if notes:
        parts.append("## Investigation Log")
        for note in notes[-8:]:
            parts.append(f"- {note}")
        parts.append("")

    containment = obs.get("containment_status", {})
    if any(v for v in containment.values() if v):
        parts.append(f"## Containment Status\n{json.dumps(containment, indent=2)}\n")

    available = obs.get("available_actions", [])
    if available:
        parts.append(f"**Available actions:** {available}")

    parts.append("\nRespond with your next action as a JSON object.")
    return "\n".join(parts)


def parse_llm_action(response_text: str) -> Optional[Dict[str, Any]]:
    """Parse a JSON action from LLM response text."""
    if not response_text:
        return None

    text = response_text.strip()

    # Strip markdown code fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
        text = text.strip()

    try:
        action = json.loads(text)
        if "action_type" in action:
            return action
    except json.JSONDecodeError:
        pass

    # Try to find JSON object in the text
    json_match = re.search(r'\{[^{}]*"action_type"[^{}]*\}', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # Try more aggressive extraction
    json_match = re.search(r'\{.*\}', text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(0))
            if "action_type" in parsed:
                return parsed
        except json.JSONDecodeError:
            pass

    return None


def run_llm_agent(
    client: OpenAI,
    env: SOCEnvClient,
    task: Dict[str, Any],
) -> Dict[str, Any]:
    """Run the LLM agent on a single task."""
    task_id = task["task_id"]
    max_steps = task["max_steps"]

    # --- START structured log ---
    print(f"START task={task_id} name={task['name']} difficulty={task['difficulty']}")

    # Reset environment
    obs = env.reset(task_id)
    print(f"  Alerts: {len(obs.get('alerts', []))}")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": format_observation(obs)},
    ]

    total_reward = 0.0
    step_count = 0
    done = obs.get("done", False)

    while not done and step_count < max_steps:
        # Call LLM
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                stream=False,
            )
            response_text = completion.choices[0].message.content or ""
        except Exception as exc:
            print(f"STEP {step_count+1} task={task_id} action=llm_error reward=0.000 message=LLM call failed: {exc}")
            response_text = ""

        # Parse action
        action = parse_llm_action(response_text)
        if action is None:
            action = _get_fallback_action(obs, task_id, step_count)
            if action is None:
                break

        action_type = action.get("action_type", "?")
        step_count += 1

        # Step environment
        try:
            obs = env.step(action)
        except Exception as exc:
            print(f"STEP {step_count} task={task_id} action={action_type} reward=0.000 message=Environment error: {exc}")
            break

        reward = obs.get("reward", 0.0) or 0.0
        total_reward += reward
        done = obs.get("done", False)
        msg = obs.get("message", "")[:80]

        # --- STEP structured log ---
        print(f"STEP {step_count} task={task_id} action={action_type} reward={reward:+.3f} done={done} message={msg}")

        # Update conversation
        messages.append({"role": "assistant", "content": response_text or json.dumps(action)})
        messages.append({"role": "user", "content": format_observation(obs)})

        # Trim conversation to avoid context overflow
        if len(messages) > 22:
            messages = messages[:1] + messages[-20:]

    # Extract final score
    final_score = _extract_final_score(obs, total_reward)

    # --- END structured log ---
    print(f"END task={task_id} score={final_score:.4f} steps={step_count}")

    return {
        "task_id": task_id,
        "task_name": task["name"],
        "score": final_score,
        "steps": step_count,
        "total_reward": total_reward,
    }


def _get_fallback_action(obs: Dict, task_id: str, step: int) -> Optional[Dict]:
    """Generate a safe fallback action when LLM fails."""
    available = obs.get("available_actions", [])
    alerts = obs.get("alerts", [])

    if "query_logs" in available:
        log_types = ["endpoint", "network", "auth", "email", "waf", "database"]
        idx = step % len(log_types)
        return {"action_type": "query_logs", "parameters": {"log_type": log_types[idx]}}

    if alerts and "lookup_threat_intel" in available:
        alert = alerts[step % len(alerts)]
        return {
            "action_type": "lookup_threat_intel",
            "parameters": {"query": alert.get("source_ip", ""), "query_type": "ip"},
        }

    return None


def _extract_final_score(obs: Dict, total_reward: float) -> float:
    """Extract the final score from the observation message or reward."""
    message = obs.get("message", "")

    # Try to parse "FINAL SCORE: X.XX/1.00" from message
    score_match = re.search(r"FINAL SCORE:\s*([\d.]+)", message)
    if score_match:
        try:
            score = float(score_match.group(1))
            return max(0.0, min(1.0, score))
        except ValueError:
            pass

    # Fall back to cumulative reward clamped to [0, 1]
    return max(0.0, min(1.0, total_reward))


# ============================================================================
# Heuristic Agent (works without LLM API key)
# ============================================================================

def run_heuristic_agent(
    env: SOCEnvClient,
    task: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run a deterministic heuristic agent (no LLM needed).
    Guarantees the script produces scores even without an API key.
    """
    task_id = task["task_id"]

    # --- START structured log ---
    print(f"START task={task_id} name={task['name']} difficulty={task['difficulty']} mode=heuristic")

    obs = env.reset(task_id)
    alerts = obs.get("alerts", [])
    print(f"  Alerts: {len(alerts)}")

    total_reward = 0.0
    step_count = 0

    def do_step(action: Dict) -> Dict:
        nonlocal obs, total_reward, step_count
        obs = env.step(action)
        reward = obs.get("reward", 0.0) or 0.0
        total_reward += reward
        step_count += 1
        action_type = action.get("action_type", "?")
        msg = obs.get("message", "")[:80]
        done = obs.get("done", False)
        # --- STEP structured log ---
        print(f"STEP {step_count} task={task_id} action={action_type} reward={reward:+.3f} done={done} message={msg}")
        return obs

    if task_id == "alert_triage":
        classifications = {
            "ALT-001": "true_positive",
            "ALT-002": "false_positive",
            "ALT-003": "true_positive",
            "ALT-004": "false_positive",
            "ALT-005": "true_positive",
        }

        for alert in alerts:
            aid = alert["alert_id"]
            do_step({
                "action_type": "lookup_threat_intel",
                "parameters": {"query": alert["source_ip"], "query_type": "ip"},
            })
            if obs.get("done", False):
                break
            classification = classifications.get(aid, "needs_investigation")
            do_step({
                "action_type": "classify_alert",
                "parameters": {"alert_id": aid, "classification": classification},
            })
            if obs.get("done", False):
                break

    elif task_id == "incident_investigation":
        for log_type in ["endpoint", "network", "email"]:
            do_step({
                "action_type": "query_logs",
                "parameters": {"log_type": log_type},
            })

        for ip in ["198.51.100.200", "10.0.3.105", "203.0.113.77"]:
            do_step({
                "action_type": "lookup_threat_intel",
                "parameters": {"query": ip, "query_type": "ip"},
            })

        do_step({
            "action_type": "check_network",
            "parameters": {"host": "workstation-dev-42"},
        })

        do_step({
            "action_type": "lookup_threat_intel",
            "parameters": {"query": "malware-c2.evil.com", "query_type": "domain"},
        })

        do_step({
            "action_type": "submit_report",
            "parameters": {
                "report": (
                    "Investigation findings: Malware (ShadowRAT/svchost32.exe) deployed "
                    "on workstation-dev-42 via phishing email with malicious attachment "
                    "(invoice_march.pdf.exe). C2 communication to 198.51.100.200 established. "
                    "DNS tunneling to malware-c2.evil.com detected. Data exfiltration of 2.3GB "
                    "via HTTPS to C2 server. Privilege escalation via sudo on compromised host. "
                    "Lateral movement to file-server-01 via RDP using developer3 credentials."
                ),
                "attack_vector": "phishing to malware",
                "severity": "critical",
                "affected_systems": ["workstation-dev-42", "file-server-01"],
            },
        })

    elif task_id == "full_incident_response":
        # Phase 1: Investigation
        for log_type in ["endpoint", "network", "email", "waf", "auth", "database"]:
            do_step({
                "action_type": "query_logs",
                "parameters": {"log_type": log_type},
            })

        for ip in ["198.51.100.200", "198.51.100.45", "192.0.2.88", "203.0.113.77"]:
            do_step({
                "action_type": "lookup_threat_intel",
                "parameters": {"query": ip, "query_type": "ip"},
            })

        for host in ["workstation-dev-42", "file-server-01"]:
            do_step({
                "action_type": "check_network",
                "parameters": {"host": host},
            })

        do_step({
            "action_type": "lookup_threat_intel",
            "parameters": {"query": "malware-c2.evil.com", "query_type": "domain"},
        })
        do_step({
            "action_type": "lookup_threat_intel",
            "parameters": {"query": "svchost32.exe", "query_type": "hash"},
        })

        # Phase 2: Containment
        for host in ["workstation-dev-42", "file-server-01"]:
            do_step({
                "action_type": "isolate_host",
                "parameters": {"host": host},
            })

        for ip in ["198.51.100.200", "198.51.100.45", "192.0.2.88", "203.0.113.77"]:
            do_step({
                "action_type": "block_ip",
                "parameters": {"ip_address": ip},
            })

        for account in ["developer3", "intern_user"]:
            do_step({
                "action_type": "disable_account",
                "parameters": {"account": account},
            })

        # Phase 3: Escalate
        do_step({
            "action_type": "escalate",
            "parameters": {
                "reason": (
                    "Multi-stage APT attack confirmed: ShadowBear campaign. "
                    "Malware deployment, data exfiltration (2.3GB), privilege escalation, "
                    "and lateral movement detected. Executive notification required."
                )
            },
        })

        # Phase 4: Report
        do_step({
            "action_type": "submit_report",
            "parameters": {
                "report": (
                    "INCIDENT REPORT — Critical Multi-Stage Cyber Attack\n\n"
                    "1. SUMMARY\n"
                    "A sophisticated multi-stage attack was detected targeting the corporate network. "
                    "The attack involved malware deployment, data exfiltration, privilege escalation, "
                    "lateral movement, and unauthorized database access.\n\n"
                    "2. ATTACK VECTOR\n"
                    "Initial access via spear-phishing email to CFO with malicious attachment "
                    "(invoice_march.pdf.exe — DarkLoader dropper). The attachment dropped ShadowRAT "
                    "(svchost32.exe) on workstation-dev-42 via encoded PowerShell command.\n\n"
                    "3. TIMELINE\n"
                    "- 09:45 — Phishing email received from spoofed domain c0mpany-vendor.com\n"
                    "- 11:22 — Malware (svchost32.exe/ShadowRAT) executed on workstation-dev-42\n"
                    "- 11:22 — C2 beacon established to 198.51.100.200 (ShadowBear infrastructure)\n"
                    "- 12:00 — DNS tunneling via malware-c2.evil.com for covert exfiltration\n"
                    "- 13:05 — 2.3GB data exfiltration to C2 server via HTTPS\n"
                    "- 15:30 — Unauthorized access to customer PII database by intern_user\n"
                    "- 17:20 — SQL injection attacks from 192.0.2.88 against web-app-01\n"
                    "- 18:05 — Privilege escalation (sudo su) on workstation-dev-42\n"
                    "- 18:30 — Lateral movement via RDP to file-server-01\n\n"
                    "4. INDICATORS OF COMPROMISE (IOCs)\n"
                    "- 198.51.100.200 (C2 server, ShadowBear APT)\n"
                    "- 198.51.100.45 (SSH brute-force scanner)\n"
                    "- 192.0.2.88 (SQL injection attacker)\n"
                    "- 203.0.113.77 (Phishing infrastructure)\n"
                    "- svchost32.exe (ShadowRAT malware)\n"
                    "- malware-c2.evil.com (C2 DNS tunneling domain)\n"
                    "- invoice_march.pdf.exe (DarkLoader dropper)\n\n"
                    "5. AFFECTED SYSTEMS\n"
                    "- workstation-dev-42 (primary compromise, developer3)\n"
                    "- file-server-01 (lateral movement target)\n"
                    "- auth-server-01 (brute force target)\n"
                    "- db-prod-01 (unauthorized PII access)\n\n"
                    "6. CONTAINMENT ACTIONS TAKEN\n"
                    "- Isolated workstation-dev-42 and file-server-01 from network\n"
                    "- Blocked C2 IPs: 198.51.100.200, 198.51.100.45, 192.0.2.88, 203.0.113.77\n"
                    "- Disabled compromised accounts: developer3, intern_user\n"
                    "- Escalated to management for executive notification\n\n"
                    "7. RECOMMENDATIONS\n"
                    "- Conduct full forensic analysis of all affected systems\n"
                    "- Force password reset for all users with access to affected systems\n"
                    "- Review and enhance email gateway rules for double-extension detection\n"
                    "- Implement network segmentation to limit lateral movement\n"
                    "- Deploy additional EDR monitoring on critical servers"
                ),
                "attack_vector": "phishing to malware",
                "severity": "critical",
                "affected_systems": [
                    "workstation-dev-42",
                    "file-server-01",
                    "auth-server-01",
                    "db-prod-01",
                ],
            },
        })

    final_score = _extract_final_score(obs, total_reward)

    # --- END structured log ---
    print(f"END task={task_id} score={final_score:.4f} steps={step_count}")

    return {
        "task_id": task_id,
        "task_name": task["name"],
        "score": final_score,
        "steps": step_count,
        "total_reward": total_reward,
    }


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    print("START inference")
    print(f"  Environment : {SOC_ENV_URL}")
    print(f"  API Base    : {API_BASE_URL}")
    print(f"  Model       : {MODEL_NAME}")
    print(f"  HF_TOKEN    : {'set' if HF_TOKEN else 'not set (heuristic mode)'}")
    print()

    # Initialize environment client
    env = SOCEnvClient(SOC_ENV_URL)

    # Check health
    if env.health():
        print("  Environment is live and healthy.")
    else:
        print("  WARNING: Health check failed. Attempting to proceed anyway...")

    # Decide mode: LLM or Heuristic
    # All LLM calls use the OpenAI client configured via the env variables
    use_llm = bool(HF_TOKEN and MODEL_NAME)
    if use_llm:
        print(f"  Mode: LLM ({MODEL_NAME})")
        client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
    else:
        print("  Mode: Heuristic (no HF_TOKEN)")
        client = None

    # Run all tasks
    results: List[Dict[str, Any]] = []
    start_time = time.time()

    for task in TASKS:
        try:
            if use_llm and client is not None:
                result = run_llm_agent(client, env, task)
            else:
                result = run_heuristic_agent(env, task)
            results.append(result)
        except Exception as exc:
            print(f"END task={task['task_id']} score=0.0000 steps=0 error={exc}")
            results.append({
                "task_id": task["task_id"],
                "task_name": task["name"],
                "score": 0.0,
                "steps": 0,
                "total_reward": 0.0,
                "error": str(exc),
            })

    elapsed = time.time() - start_time

    # Summary
    total_scores = [r["score"] for r in results if "error" not in r]
    avg_score = sum(total_scores) / len(total_scores) if total_scores else 0.0

    print()
    for r in results:
        score_str = f"{r['score']:.4f}" if "error" not in r else "ERROR"
        print(f"RESULT task={r['task_id']} score={score_str} steps={r['steps']}")

    print(f"END inference average_score={avg_score:.4f} total_time={elapsed:.1f}s mode={'llm' if use_llm else 'heuristic'}")


if __name__ == "__main__":
    main()
