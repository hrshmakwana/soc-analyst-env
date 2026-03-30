---
title: SOC Analyst Environment
emoji: 🔒
colorFrom: red
colorTo: purple
sdk: docker
app_port: 7860
tags:
  - openenv
---

# 🔒 SOC Analyst Environment

A **Cybersecurity Security Operations Center (SOC) Analyst** training environment for [OpenEnv](https://github.com/meta-pytorch/OpenEnv). Train AI agents to triage security alerts, investigate incidents, and execute incident response — the real-world tasks that SOC analysts perform daily.

## Why This Environment?

The cybersecurity industry faces a global shortage of **3.4 million professionals** (ISC² 2025). SOC analysts spend 60%+ of their time on repetitive alert triage that could be augmented by AI. This environment provides a realistic simulation for training and evaluating AI agents on actual SOC workflows.

### What Makes It Real-World

| Aspect | Implementation |
|---|---|
| **Realistic alerts** | 16 security alerts across 8 attack types (brute force, phishing, malware, data exfil, unauthorized access, SQL injection, privilege escalation, lateral movement) |
| **True/False positive mix** | Balanced mix mirrors real SOC queues (~40% false positive rate) |
| **SIEM integration** | Queryable log database (auth, endpoint, network, database, email, WAF) |
| **Threat intelligence** | Lookup database with known-malicious IPs, domains, and file hashes |
| **Incident response** | Full containment actions (isolate hosts, block IPs, disable accounts) |
| **Multi-stage attacks** | Correlated alerts forming a realistic attack kill chain |

---

## Tasks

### Task 1: Alert Triage (Easy)
**Classify 5 security alerts** as `true_positive`, `false_positive`, or `needs_investigation`.

- **Max steps:** 15
- **Key skills:** Alert analysis, threat intel lookups
- **Scoring:** +0.20 per correct classification, +0.05 investigation bonus

### Task 2: Incident Investigation (Medium)
**Investigate a multi-alert security incident** involving malware on a developer workstation. Identify the attack vector, IOCs, affected systems, and severity.

- **Max steps:** 30
- **Key skills:** Log analysis, IOC correlation, threat mapping
- **Scoring:** IOC identification, attack vector accuracy, severity assessment, time efficiency

### Task 3: Full Incident Response (Hard)
**Handle a live multi-stage cyber attack** from detection through containment and reporting. The agent must investigate, contain the threat (isolate hosts, block IPs, disable accounts), escalate, and write a comprehensive incident report.

- **Max steps:** 50
- **Key skills:** All investigation skills + containment, escalation, reporting
- **Scoring:** Investigation (0.25) + Containment (0.35) + Escalation (0.10) + Report (0.20) + Efficiency (0.10)

---

## Action Space

```python
class SOCAction(Action):
    action_type: Literal[
        "classify_alert",       # Classify alert as TP/FP/needs_investigation
        "query_logs",           # Query SIEM logs (auth/endpoint/network/database/email/waf)
        "lookup_threat_intel",  # Check IP/domain/hash against threat DB
        "check_network",        # View network connections for a host
        "isolate_host",         # Containment: isolate a host from network
        "block_ip",             # Containment: block IP at firewall
        "disable_account",      # Containment: disable a user account
        "submit_report",        # Submit incident report with findings
        "escalate",             # Escalate to senior analyst
    ]
    parameters: Dict[str, Any]  # Action-specific parameters
```

## Observation Space

```python
class SOCObservation(Observation):
    alerts: List[Dict]              # Current alert queue
    investigation_notes: List[str]  # Running investigation log
    query_results: Optional[Dict]   # Results from last action
    available_actions: List[str]    # Context-aware available actions
    containment_status: Dict        # Isolated hosts, blocked IPs, disabled accounts
    message: str                    # System feedback
    task_id: str                    # Current task
    task_description: str           # Task description
    done: bool                      # Episode complete?
    reward: Optional[float]         # Step reward
```

---

## Setup & Usage

### Prerequisites
- Python 3.10+
- Docker (for containerized testing)
- `openenv-core` (`pip install openenv-core`)

### Local Development

```bash
# Clone and install
cd soc_analyst_env
pip install -e .

# Run server locally
cd server
uvicorn app:app --host 0.0.0.0 --port 7860

# In another terminal, run baseline
cd soc_analyst_env
python baseline_inference.py
```

### Docker

```bash
cd soc_analyst_env
docker build -t soc-analyst-env .
docker run -p 7860:7860 soc-analyst-env
```

### Client Usage

```python
from soc_analyst_env import SOCAnalystEnv, SOCAction

with SOCAnalystEnv(base_url="http://localhost:7860").sync() as env:
    # Reset with a task
    obs = env.reset(task_id="alert_triage")
    print(obs.message)
    
    # Take actions
    result = env.step(SOCAction(
        action_type="lookup_threat_intel",
        parameters={"query": "198.51.100.45", "query_type": "ip"}
    ))
    print(result.observation.query_results)
    
    result = env.step(SOCAction(
        action_type="classify_alert",
        parameters={"alert_id": "ALT-001", "classification": "true_positive"}
    ))
    print(f"Reward: {result.reward}")
```

### Baseline Inference

```bash
# With OpenAI API (recommended)
OPENAI_API_KEY=sk-... python baseline_inference.py --model gpt-4o-mini

# Without API key (heuristic baseline)
python baseline_inference.py
```

---

## Baseline Scores

| Task | Heuristic Baseline | GPT-4o-mini |
|---|---|---|
| Alert Triage (Easy) | ~0.85 | ~0.95 |
| Incident Investigation (Medium) | ~0.70 | ~0.80 |
| Full Incident Response (Hard) | ~0.65 | ~0.75 |

---

## Reward Design

Rewards provide **rich partial progress signals** throughout each episode:

- **Investigation rewards:** +0.02 for productive queries and lookups
- **Classification rewards:** +0.15 correct, -0.05 incorrect
- **Containment rewards:** +0.05–0.08 correct, -0.03–0.05 wrong target
- **Report/escalation bonus:** +0.03–0.05
- **Time efficiency bonus:** +0.05–0.10 for fast completion
- **Penalties:** -0.01–0.05 for invalid actions, wrong containment targets

---

## Project Structure

```
soc_analyst_env/
├── models.py               # Pydantic Action/Observation/State types
├── client.py                # EnvClient WebSocket implementation
├── __init__.py              # Package exports
├── openenv.yaml             # OpenEnv manifest
├── pyproject.toml           # Package config & dependencies
├── Dockerfile               # Container definition
├── baseline_inference.py    # Baseline agent (OpenAI + heuristic)
├── data/
│   ├── scenarios.py         # 16 alerts, SIEM logs, 3 task definitions
│   └── threat_intel.py      # Threat intelligence database
└── server/
    ├── environment.py       # Core SOCEnvironment class
    ├── graders.py           # Deterministic task graders
    ├── app.py               # FastAPI server
    └── requirements.txt     # Server dependencies
```

---

## License

MIT
