"""
Deterministic graders for the SOC Analyst Environment.

Each grader scores agent performance on a specific task from 0.0 to 1.0.
Graders are deterministic — same input always produces same score.
"""

from typing import Any, Dict, List, Set


def grade_alert_triage(
    classifications: Dict[str, str],
    expected: Dict[str, str],
    investigated_alerts: List[str],
) -> Dict[str, Any]:
    """
    Grade the Alert Triage task.

    Scoring breakdown:
    - +0.20 per correct classification (max 1.0 for 5 alerts)
    - -0.10 per incorrect classification
    - +0.05 bonus per alert investigated before classifying (max 0.25 bonus, capped at 1.0)

    Args:
        classifications: Map of alert_id -> agent's classification
        expected: Map of alert_id -> correct classification
        investigated_alerts: List of alert_ids agent investigated before classifying

    Returns:
        Dict with score (0.0-1.0), breakdown, and feedback
    """
    score = 0.0
    correct = 0
    incorrect = 0
    unclassified = 0
    breakdown = []

    for alert_id, expected_class in expected.items():
        agent_class = classifications.get(alert_id)
        if agent_class is None:
            unclassified += 1
            breakdown.append(f"{alert_id}: NOT CLASSIFIED (0 pts)")
        elif agent_class == expected_class:
            correct += 1
            score += 0.20
            breakdown.append(f"{alert_id}: CORRECT ({agent_class}) (+0.20)")
        else:
            incorrect += 1
            score -= 0.10
            breakdown.append(f"{alert_id}: WRONG (got={agent_class}, expected={expected_class}) (-0.10)")

    # Thoroughness bonus: investigated before classifying
    investigation_bonus = 0.0
    for alert_id in expected:
        if alert_id in investigated_alerts:
            investigation_bonus += 0.05
    investigation_bonus = min(investigation_bonus, 0.25)
    score += investigation_bonus

    # Clamp to [0.0, 1.0]
    score = max(0.001, min(0.999, score))

    return {
        "score": round(score, 4),
        "correct": correct,
        "incorrect": incorrect,
        "unclassified": unclassified,
        "investigation_bonus": round(investigation_bonus, 4),
        "breakdown": breakdown,
        "feedback": _triage_feedback(correct, incorrect, unclassified, len(expected)),
    }


def grade_investigation(
    iocs_identified: List[str],
    attack_vector: str,
    severity: str,
    affected_systems: List[str],
    expected: Dict[str, Any],
    queries_made: List[Dict],
    steps_taken: int,
    max_steps: int,
) -> Dict[str, Any]:
    """
    Grade the Incident Investigation task.

    Scoring breakdown:
    - IOC identification: +0.15 per correct IOC (max ~0.60)
    - Attack vector: +0.20 for correct identification
    - Severity assessment: +0.15 for correct level
    - Affected systems: +0.10 per correctly identified system
    - False leads: -0.05 per incorrect IOC
    - Time efficiency: +0.10 bonus if completed in <60% of max steps

    Returns:
        Dict with score (0.0-1.0), breakdown, and feedback
    """
    score = 0.0
    breakdown = []

    # IOC scoring
    expected_iocs = set(expected.get("iocs", []))
    agent_iocs = set(iocs_identified)
    correct_iocs = agent_iocs & expected_iocs
    false_iocs = agent_iocs - expected_iocs

    ioc_score = len(correct_iocs) * 0.15
    ioc_penalty = len(false_iocs) * 0.05
    score += ioc_score - ioc_penalty
    breakdown.append(f"IOCs: {len(correct_iocs)}/{len(expected_iocs)} correct (+{ioc_score:.2f}), {len(false_iocs)} false (-{ioc_penalty:.2f})")

    # Attack vector
    expected_vector = expected.get("attack_vector", "").lower().replace("_", " ").replace("-", " ")
    agent_vector = attack_vector.lower().replace("_", " ").replace("-", " ")
    vector_match = _fuzzy_match(agent_vector, expected_vector)
    if vector_match:
        score += 0.20
        breakdown.append(f"Attack vector: CORRECT (+0.20)")
    else:
        breakdown.append(f"Attack vector: WRONG (got='{attack_vector}', expected='{expected.get('attack_vector')}')")

    # Severity
    expected_severity = expected.get("severity", "").lower()
    agent_severity = severity.lower()
    if agent_severity == expected_severity:
        score += 0.15
        breakdown.append(f"Severity: CORRECT ({severity}) (+0.15)")
    else:
        breakdown.append(f"Severity: WRONG (got='{severity}', expected='{expected.get('severity')}')")

    # Affected systems
    expected_systems = set(expected.get("affected_systems", []))
    agent_systems = set(affected_systems)
    correct_systems = agent_systems & expected_systems
    system_score = len(correct_systems) * 0.10
    score += system_score
    breakdown.append(f"Affected systems: {len(correct_systems)}/{len(expected_systems)} correct (+{system_score:.2f})")

    # Time efficiency bonus
    if steps_taken > 0 and steps_taken < max_steps * 0.6:
        score += 0.10
        breakdown.append(f"Time efficiency bonus: +0.10 (completed in {steps_taken}/{max_steps} steps)")

    score = max(0.001, min(0.999, score))

    return {
        "score": round(score, 4),
        "iocs_correct": len(correct_iocs),
        "iocs_total": len(expected_iocs),
        "attack_vector_correct": vector_match,
        "severity_correct": agent_severity == expected_severity,
        "systems_correct": len(correct_systems),
        "breakdown": breakdown,
        "feedback": _investigation_feedback(score),
    }


def grade_incident_response(
    iocs_identified: List[str],
    attack_vector: str,
    severity: str,
    affected_systems: List[str],
    isolated_hosts: List[str],
    blocked_ips: List[str],
    disabled_accounts: List[str],
    incident_report: str,
    escalated: bool,
    expected: Dict[str, Any],
    steps_taken: int,
    max_steps: int,
) -> Dict[str, Any]:
    """
    Grade the Full Incident Response task.

    Scoring breakdown:
    - Investigation accuracy: 0.25 (IOCs + attack vector + severity)
    - Containment actions: 0.35 (isolate, block, disable - with penalty for wrong targets)
    - Escalation: 0.10
    - Incident report: 0.20 (completeness based on keywords)
    - Time efficiency: 0.10

    Returns:
        Dict with score (0.0-1.0), breakdown, and feedback
    """
    score = 0.0
    breakdown = []

    # --- Investigation accuracy (0.25) ---
    expected_iocs = set(expected.get("iocs", []))
    agent_iocs = set(iocs_identified)
    correct_iocs = agent_iocs & expected_iocs
    ioc_ratio = len(correct_iocs) / max(len(expected_iocs), 1)

    expected_vector = expected.get("attack_vector", "").lower().replace("_", " ").replace("-", " ")
    agent_vector = attack_vector.lower().replace("_", " ").replace("-", " ")
    vector_correct = _fuzzy_match(agent_vector, expected_vector)

    severity_correct = severity.lower() == expected.get("severity", "").lower()

    investigation_score = (ioc_ratio * 0.10) + (0.10 if vector_correct else 0) + (0.05 if severity_correct else 0)
    score += investigation_score
    breakdown.append(f"Investigation: +{investigation_score:.2f} (IOCs: {len(correct_iocs)}/{len(expected_iocs)}, vector: {'✓' if vector_correct else '✗'}, severity: {'✓' if severity_correct else '✗'})")

    # --- Containment actions (0.35) ---
    containment = expected.get("containment", {})

    # Host isolation
    expected_hosts = set(containment.get("isolate_hosts", []))
    agent_hosts = set(isolated_hosts)
    correct_hosts = agent_hosts & expected_hosts
    wrong_hosts = agent_hosts - expected_hosts
    host_score = (len(correct_hosts) / max(len(expected_hosts), 1)) * 0.12
    host_penalty = len(wrong_hosts) * 0.05
    score += host_score - host_penalty
    breakdown.append(f"Host isolation: {len(correct_hosts)}/{len(expected_hosts)} correct (+{host_score:.2f}), {len(wrong_hosts)} wrong (-{host_penalty:.2f})")

    # IP blocking
    expected_block_ips = set(containment.get("block_ips", []))
    agent_block_ips = set(blocked_ips)
    correct_blocks = agent_block_ips & expected_block_ips
    wrong_blocks = agent_block_ips - expected_block_ips
    block_score = (len(correct_blocks) / max(len(expected_block_ips), 1)) * 0.12
    block_penalty = len(wrong_blocks) * 0.03
    score += block_score - block_penalty
    breakdown.append(f"IP blocking: {len(correct_blocks)}/{len(expected_block_ips)} correct (+{block_score:.2f}), {len(wrong_blocks)} wrong (-{block_penalty:.2f})")

    # Account disabling
    expected_accounts = set(containment.get("disable_accounts", []))
    agent_accounts = set(disabled_accounts)
    correct_accounts = agent_accounts & expected_accounts
    wrong_accounts = agent_accounts - expected_accounts
    account_score = (len(correct_accounts) / max(len(expected_accounts), 1)) * 0.11
    account_penalty = len(wrong_accounts) * 0.05
    score += account_score - account_penalty
    breakdown.append(f"Account disable: {len(correct_accounts)}/{len(expected_accounts)} correct (+{account_score:.2f}), {len(wrong_accounts)} wrong (-{account_penalty:.2f})")

    # --- Escalation (0.10) ---
    should_escalate = expected.get("should_escalate", False)
    if escalated == should_escalate:
        score += 0.10
        breakdown.append(f"Escalation: CORRECT ({'escalated' if escalated else 'not escalated'}) (+0.10)")
    else:
        breakdown.append(f"Escalation: WRONG (expected={'escalate' if should_escalate else 'do not escalate'})")

    # --- Incident report (0.20) ---
    report_keywords = expected.get("report_keywords", [])
    if incident_report:
        report_lower = incident_report.lower()
        matched_keywords = [kw for kw in report_keywords if kw.lower() in report_lower]
        keyword_ratio = len(matched_keywords) / max(len(report_keywords), 1)
        report_score = keyword_ratio * 0.15

        # Length bonus (at least 100 chars for a real report)
        if len(incident_report) >= 100:
            report_score += 0.05

        score += report_score
        breakdown.append(f"Report: {len(matched_keywords)}/{len(report_keywords)} keywords (+{report_score:.2f})")
    else:
        breakdown.append("Report: NOT SUBMITTED (0 pts)")

    # --- Time efficiency (0.10) ---
    if steps_taken > 0 and steps_taken < max_steps * 0.6:
        score += 0.10
        breakdown.append(f"Time efficiency: +0.10 (completed in {steps_taken}/{max_steps} steps)")
    elif steps_taken > 0 and steps_taken < max_steps * 0.8:
        score += 0.05
        breakdown.append(f"Time efficiency: +0.05 (completed in {steps_taken}/{max_steps} steps)")

    score = max(0.001, min(0.999, score))

    return {
        "score": round(score, 4),
        "breakdown": breakdown,
        "feedback": _ir_feedback(score),
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _fuzzy_match(agent: str, expected: str) -> bool:
    """Fuzzy match for attack vector identification."""
    if not agent or not expected:
        return False
    # Exact match
    if agent == expected:
        return True
    # Check if key terms overlap
    agent_terms = set(agent.split())
    expected_terms = set(expected.split())
    overlap = agent_terms & expected_terms
    # If at least half of expected terms are present
    if len(overlap) >= max(1, len(expected_terms) // 2):
        return True
    # Check containment
    if expected in agent or agent in expected:
        return True
    return False


def _triage_feedback(correct: int, incorrect: int, unclassified: int, total: int) -> str:
    """Generate feedback for triage performance."""
    if correct == total:
        return "Excellent! Perfect alert triage. All alerts correctly classified."
    elif correct >= total * 0.8:
        return f"Good triage performance. {correct}/{total} correct. Review misclassified alerts."
    elif correct >= total * 0.5:
        return f"Moderate performance. {correct}/{total} correct. Additional investigation before classification recommended."
    else:
        return f"Poor triage. {correct}/{total} correct. Significant improvement needed in alert analysis."


def _investigation_feedback(score: float) -> str:
    """Generate feedback for investigation performance."""
    if score >= 0.9:
        return "Outstanding investigation. Thorough analysis with accurate findings."
    elif score >= 0.7:
        return "Good investigation. Most key indicators identified. Some findings missing."
    elif score >= 0.4:
        return "Partial investigation. Several key indicators missed. Deeper analysis needed."
    else:
        return "Insufficient investigation. Most indicators were missed."


def _ir_feedback(score: float) -> str:
    """Generate feedback for incident response performance."""
    if score >= 0.9:
        return "Exceptional incident response. Thorough investigation, effective containment, comprehensive reporting."
    elif score >= 0.7:
        return "Good incident response. Effective containment with minor gaps."
    elif score >= 0.4:
        return "Partial incident response. Some containment actions taken but gaps remain."
    else:
        return "Insufficient incident response. Critical gaps in containment and investigation."
