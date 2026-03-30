#!/usr/bin/env python3
"""
Baseline Inference Script for SOC Analyst Environment.

Runs a baseline LLM agent (via OpenAI API) against all 3 tasks
and reports reproducible scores.

Usage:
    OPENAI_API_KEY=sk-... python baseline_inference.py [--base-url URL]

Environment Variables:
    OPENAI_API_KEY: Your OpenAI API key
    SOC_ENV_URL: Base URL of the SOC environment (default: http://localhost:7860)
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except ImportError:
    print("Please install openai: pip install openai")
    sys.exit(1)

# Add parent dir for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import SOCAction, SOCObservation
from data.scenarios import get_task, get_alerts_for_task
from data.threat_intel import lookup_threat_intel
from server.environment import SOCEnvironment


SYSTEM_PROMPT = """You are an AI SOC (Security Operations Center) analyst. You analyze security alerts, investigate incidents, and execute incident response actions.

You interact with the environment by returning JSON actions. Each action has:
- "action_type": one of the available actions
- "parameters": a dict of action-specific parameters

Available action types and their parameters:
- classify_alert: {"alert_id": "ALT-XXX", "classification": "true_positive|false_positive|needs_investigation"}
- query_logs: {"log_type": "auth|endpoint|network|database|email|waf", ...optional_filters}
- lookup_threat_intel: {"query": "IP/domain/hash", "query_type": "ip|domain|hash"}
- check_network: {"host": "hostname"}
- isolate_host: {"host": "hostname"}
- block_ip: {"ip_address": "x.x.x.x"}
- disable_account: {"account": "username"}
- submit_report: {"report": "text", "attack_vector": "type", "severity": "level", "affected_systems": ["host1"]}
- escalate: {"reason": "explanation"}

Respond ONLY with a valid JSON object with "action_type" and "parameters" keys. No other text."""


def run_baseline_task(task_id: str, model: str = "gpt-4o-mini") -> Dict[str, Any]:
    """
    Run a baseline agent on a single task.

    Uses a local environment instance (no server needed).
    """
    print(f"\n{'='*60}")
    print(f"  Task: {task_id}")
    print(f"{'='*60}")

    # Create environment
    env = SOCEnvironment()

    # Reset with task
    obs = env.reset(task_id=task_id)
    print(f"  Description: {obs.message[:100]}...")
    print(f"  Alerts: {len(obs.alerts)}")
    print(f"  Available actions: {obs.available_actions}")

    # Build conversation history
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("  ⚠️  No OPENAI_API_KEY found. Running with heuristic baseline.")
        return run_heuristic_baseline(env, obs, task_id)

    client = OpenAI(api_key=api_key)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": format_observation(obs)},
    ]

    total_reward = 0.0
    step_count = 0
    max_steps = get_task(task_id).get("max_steps", 50)

    while not obs.done and step_count < max_steps:
        try:
            # Get LLM action
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.0,
                max_tokens=500,
            )

            action_text = response.choices[0].message.content.strip()
            # Clean markdown code blocks if present
            if action_text.startswith("```"):
                action_text = action_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

            action_dict = json.loads(action_text)
            action = SOCAction(
                action_type=action_dict["action_type"],
                parameters=action_dict.get("parameters", {}),
            )

            # Step environment
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

            print(f"  Step {step_count}: {action.action_type} → reward={obs.reward:.3f} | {obs.message[:80]}")

            # Update conversation
            messages.append({"role": "assistant", "content": action_text})
            messages.append({"role": "user", "content": format_observation(obs)})

        except (json.JSONDecodeError, KeyError, Exception) as e:
            print(f"  Step {step_count}: ERROR — {e}")
            step_count += 1
            if step_count >= max_steps:
                break
            continue

    # Get final score
    final_grade = env._compute_final_grade()
    print(f"\n  ✅ Final Score: {final_grade['score']:.4f}")
    print(f"  Steps taken: {step_count}")
    if "breakdown" in final_grade:
        for line in final_grade["breakdown"]:
            print(f"    {line}")

    return {
        "task_id": task_id,
        "score": final_grade["score"],
        "steps": step_count,
        "total_reward": total_reward,
        "feedback": final_grade.get("feedback", ""),
    }


def run_heuristic_baseline(env: SOCEnvironment, obs: SOCObservation, task_id: str) -> Dict[str, Any]:
    """
    Run a simple heuristic baseline (no LLM needed).
    Demonstrates that the environment works without an API key.
    """
    step_count = 0
    total_reward = 0.0

    if task_id == "alert_triage":
        # Heuristic: classify high/critical as true_positive, low as false_positive
        for alert in obs.alerts:
            if obs.done:
                break

            # First query threat intel on the source IP
            action = SOCAction(
                action_type="lookup_threat_intel",
                parameters={"query": alert["source_ip"], "query_type": "ip"},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

            # Classify based on threat intel result
            reputation = "unknown"
            if obs.query_results and "result" in obs.query_results:
                reputation = obs.query_results["result"].get("reputation", "unknown")

            if reputation == "malicious":
                classification = "true_positive"
            elif reputation in ("clean", "internal"):
                classification = "false_positive"
            elif alert["severity"] in ("critical", "high"):
                classification = "true_positive"
            else:
                classification = "false_positive"

            action = SOCAction(
                action_type="classify_alert",
                parameters={"alert_id": alert["alert_id"], "classification": classification},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0
            print(f"  Step {step_count}: classify {alert['alert_id']} as {classification} → reward={obs.reward:.3f}")

    elif task_id == "incident_investigation":
        # Query logs for key hosts
        for log_type in ["endpoint", "network"]:
            action = SOCAction(
                action_type="query_logs",
                parameters={"log_type": log_type},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        # Look up key IPs
        for ip in ["198.51.100.200", "10.0.3.105"]:
            action = SOCAction(
                action_type="lookup_threat_intel",
                parameters={"query": ip, "query_type": "ip"},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        # Check network for compromised host
        action = SOCAction(
            action_type="check_network",
            parameters={"host": "workstation-dev-42"},
        )
        obs = env.step(action)
        step_count += 1
        total_reward += obs.reward or 0.0

        # Submit findings
        action = SOCAction(
            action_type="submit_report",
            parameters={
                "report": "Investigation findings: Malware detected on workstation-dev-42. C2 communication to 198.51.100.200. DNS tunneling to malware-c2.evil.com. Data exfiltration of 2.3GB detected. Privilege escalation and lateral movement to file-server-01.",
                "attack_vector": "phishing to malware",
                "severity": "critical",
                "affected_systems": ["workstation-dev-42", "file-server-01"],
            },
        )
        obs = env.step(action)
        step_count += 1
        total_reward += obs.reward or 0.0

    elif task_id == "full_incident_response":
        # Investigate
        for log_type in ["endpoint", "network", "email", "waf"]:
            action = SOCAction(
                action_type="query_logs",
                parameters={"log_type": log_type},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        # Threat intel lookups
        for ip in ["198.51.100.200", "198.51.100.45", "192.0.2.88", "203.0.113.77"]:
            action = SOCAction(
                action_type="lookup_threat_intel",
                parameters={"query": ip, "query_type": "ip"},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        # Containment
        for host in ["workstation-dev-42", "file-server-01"]:
            action = SOCAction(
                action_type="isolate_host",
                parameters={"host": host},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        for ip in ["198.51.100.200", "198.51.100.45", "192.0.2.88", "203.0.113.77"]:
            action = SOCAction(
                action_type="block_ip",
                parameters={"ip_address": ip},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        for account in ["developer3", "intern_user"]:
            action = SOCAction(
                action_type="disable_account",
                parameters={"account": account},
            )
            obs = env.step(action)
            step_count += 1
            total_reward += obs.reward or 0.0

        # Escalate
        action = SOCAction(
            action_type="escalate",
            parameters={"reason": "Multi-stage APT attack with data exfiltration. Executive notification required."},
        )
        obs = env.step(action)
        step_count += 1
        total_reward += obs.reward or 0.0

        # Submit report
        action = SOCAction(
            action_type="submit_report",
            parameters={
                "report": (
                    "INCIDENT REPORT - Critical Security Breach\n\n"
                    "Summary: Multi-stage attack involving malware deployment, data exfiltration, "
                    "privilege escalation, and lateral movement.\n\n"
                    "Attack Vector: Initial access via phishing email with malicious attachment (invoice_march.pdf.exe). "
                    "Malware (ShadowRAT / svchost32.exe) dropped on workstation-dev-42.\n\n"
                    "Timeline: C2 beacon established to 198.51.100.200, DNS tunneling via malware-c2.evil.com, "
                    "2.3GB data exfiltration, privilege escalation via sudo, lateral movement to file-server-01 via RDP.\n\n"
                    "Containment Actions: Isolated workstation-dev-42 and file-server-01. "
                    "Blocked C2 IPs. Disabled compromised accounts (developer3, intern_user).\n\n"
                    "IOCs: 198.51.100.200, svchost32.exe, malware-c2.evil.com, 192.0.2.88\n\n"
                    "Recommendation: Full forensic analysis, password reset for all affected systems, "
                    "review of email gateway rules."
                ),
                "attack_vector": "phishing to malware",
                "severity": "critical",
                "affected_systems": ["workstation-dev-42", "file-server-01", "auth-server-01", "db-prod-01"],
            },
        )
        obs = env.step(action)
        step_count += 1
        total_reward += obs.reward or 0.0

    # Get final grade
    final_grade = env._compute_final_grade()
    print(f"\n  ✅ Final Score: {final_grade['score']:.4f}")
    print(f"  Steps taken: {step_count}")
    if "breakdown" in final_grade:
        for line in final_grade["breakdown"]:
            print(f"    {line}")

    return {
        "task_id": task_id,
        "score": final_grade["score"],
        "steps": step_count,
        "total_reward": total_reward,
        "feedback": final_grade.get("feedback", ""),
    }


def format_observation(obs: SOCObservation) -> str:
    """Format an observation as a readable prompt for the LLM."""
    parts = [f"## Current State\n{obs.message}\n"]

    if obs.alerts:
        parts.append("## Alert Queue")
        for alert in obs.alerts:
            parts.append(
                f"- **{alert['alert_id']}** [{alert['severity'].upper()}] {alert['type']}: "
                f"{alert['description'][:120]}..."
            )
        parts.append("")

    if obs.query_results:
        parts.append(f"## Last Query Results\n```json\n{json.dumps(obs.query_results, indent=2, default=str)[:1500]}\n```\n")

    if obs.investigation_notes:
        parts.append("## Investigation Log")
        for note in obs.investigation_notes[-5:]:  # Last 5 notes
            parts.append(f"- {note}")
        parts.append("")

    if any(obs.containment_status.values()):
        parts.append(f"## Containment Status\n{json.dumps(obs.containment_status, indent=2)}\n")

    parts.append(f"Available actions: {obs.available_actions}")
    parts.append("\nRespond with a JSON action object. What is your next action?")

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Run baseline inference on SOC Analyst Environment")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    parser.add_argument("--tasks", nargs="+", default=["alert_triage", "incident_investigation", "full_incident_response"])
    args = parser.parse_args()

    print("🔒 SOC Analyst Environment — Baseline Inference")
    print("=" * 60)

    results = []
    for task_id in args.tasks:
        result = run_baseline_task(task_id, model=args.model)
        results.append(result)

    # Summary
    print("\n\n" + "=" * 60)
    print("  BASELINE RESULTS SUMMARY")
    print("=" * 60)
    print(f"{'Task':<30} {'Score':>8} {'Steps':>8}")
    print("-" * 50)
    for r in results:
        print(f"{r['task_id']:<30} {r['score']:>8.4f} {r['steps']:>8}")
    avg_score = sum(r["score"] for r in results) / len(results)
    print("-" * 50)
    print(f"{'AVERAGE':<30} {avg_score:>8.4f}")
    print("=" * 60)

    return results


if __name__ == "__main__":
    main()
