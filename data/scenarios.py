"""
Realistic cybersecurity scenarios for the SOC Analyst Environment.

Contains security alerts, SIEM logs, network data, and expected solutions
for 3 difficulty levels of tasks.
"""

import copy
import random
from typing import Any, Dict, List


# ============================================================================
# SECURITY ALERTS DATABASE
# ============================================================================

ALERTS_DB: List[Dict[str, Any]] = [
    # --- BRUTE FORCE ---
    {
        "alert_id": "ALT-001",
        "timestamp": "2026-03-15T02:14:33Z",
        "type": "brute_force",
        "severity": "high",
        "source_ip": "198.51.100.45",
        "target": "auth-server-01",
        "target_account": "admin",
        "description": "Multiple failed SSH login attempts detected (47 attempts in 5 minutes) from external IP targeting root/admin accounts.",
        "raw_log": "sshd[2847]: Failed password for admin from 198.51.100.45 port 54213 ssh2",
        "ground_truth": "true_positive",
    },
    {
        "alert_id": "ALT-002",
        "timestamp": "2026-03-15T08:30:12Z",
        "type": "brute_force",
        "severity": "low",
        "source_ip": "10.0.5.22",
        "target": "auth-server-01",
        "target_account": "jsmith",
        "description": "5 failed login attempts from internal IP for user jsmith. User successfully logged in on 6th attempt.",
        "raw_log": "sshd[3102]: Failed password for jsmith from 10.0.5.22 port 41822 ssh2",
        "ground_truth": "false_positive",
    },
    # --- PHISHING ---
    {
        "alert_id": "ALT-003",
        "timestamp": "2026-03-15T09:45:00Z",
        "type": "phishing",
        "severity": "critical",
        "source_ip": "203.0.113.77",
        "target": "mail-gw-01",
        "target_account": "cfo@company.com",
        "description": "Email with malicious attachment detected. Subject: 'Urgent Invoice #INV-29841'. Attachment: invoice_march.pdf.exe. Sender domain spoofing vendor.",
        "raw_log": "mail-gw: BLOCKED attachment=invoice_march.pdf.exe from=billing@c0mpany-vendor.com to=cfo@company.com",
        "ground_truth": "true_positive",
    },
    {
        "alert_id": "ALT-004",
        "timestamp": "2026-03-15T10:12:30Z",
        "type": "phishing",
        "severity": "medium",
        "source_ip": "172.217.14.100",
        "target": "mail-gw-01",
        "target_account": "hr@company.com",
        "description": "Email flagged as potential phishing. Subject: 'Job Application - Sr. Engineer'. Attachment: resume.docx. Sender: legitimate gmail address.",
        "raw_log": "mail-gw: FLAGGED attachment=resume.docx from=john.applicant@gmail.com to=hr@company.com score=62",
        "ground_truth": "false_positive",
    },
    # --- MALWARE ---
    {
        "alert_id": "ALT-005",
        "timestamp": "2026-03-15T11:22:15Z",
        "type": "malware",
        "severity": "critical",
        "source_ip": "10.0.3.105",
        "target": "workstation-dev-42",
        "target_account": "developer3",
        "description": "Endpoint detection: Suspicious process 'svchost32.exe' spawned from PowerShell with encoded command. C2 beacon pattern detected to 198.51.100.200.",
        "raw_log": "edr: ALERT host=workstation-dev-42 proc=svchost32.exe parent=powershell.exe cmdline='-enc aQBmACgA...' conn=198.51.100.200:443",
        "ground_truth": "true_positive",
    },
    {
        "alert_id": "ALT-006",
        "timestamp": "2026-03-15T11:45:00Z",
        "type": "malware",
        "severity": "medium",
        "source_ip": "10.0.3.108",
        "target": "workstation-qa-07",
        "target_account": "qa_engineer",
        "description": "Endpoint detection: Process 'python3' making outbound connections to pypi.org. Downloading packages: requests, beautifulsoup4.",
        "raw_log": "edr: INFO host=workstation-qa-07 proc=python3 conn=pypi.org:443 pkg_download=requests,beautifulsoup4",
        "ground_truth": "false_positive",
    },
    # --- DATA EXFILTRATION ---
    {
        "alert_id": "ALT-007",
        "timestamp": "2026-03-15T13:05:44Z",
        "type": "data_exfiltration",
        "severity": "critical",
        "source_ip": "10.0.3.105",
        "target": "workstation-dev-42",
        "target_account": "developer3",
        "description": "Large data transfer detected: 2.3GB uploaded to external IP 198.51.100.200 via HTTPS. Source is the same host with prior malware alert.",
        "raw_log": "dlp: ALERT host=workstation-dev-42 dest=198.51.100.200 bytes_out=2469396480 proto=HTTPS duration=847s",
        "ground_truth": "true_positive",
    },
    {
        "alert_id": "ALT-008",
        "timestamp": "2026-03-15T14:00:00Z",
        "type": "data_exfiltration",
        "severity": "low",
        "source_ip": "10.0.2.50",
        "target": "backup-server-01",
        "target_account": "backup_svc",
        "description": "Large data transfer: 15GB uploaded to cloud storage (AWS S3). This matches scheduled nightly backup pattern.",
        "raw_log": "dlp: INFO host=backup-server-01 dest=s3.amazonaws.com bytes_out=16106127360 proto=HTTPS tag=scheduled_backup",
        "ground_truth": "false_positive",
    },
    # --- UNAUTHORIZED ACCESS ---
    {
        "alert_id": "ALT-009",
        "timestamp": "2026-03-15T15:30:22Z",
        "type": "unauthorized_access",
        "severity": "high",
        "source_ip": "10.0.1.15",
        "target": "db-prod-01",
        "target_account": "intern_user",
        "description": "Database access from intern account to production customer PII database. Access outside business hours. 450 SELECT queries in 10 minutes.",
        "raw_log": "db-audit: WARN user=intern_user src=10.0.1.15 db=customer_pii queries=450 time=22:30UTC",
        "ground_truth": "true_positive",
    },
    {
        "alert_id": "ALT-010",
        "timestamp": "2026-03-15T16:15:00Z",
        "type": "unauthorized_access",
        "severity": "medium",
        "source_ip": "10.0.4.200",
        "target": "db-staging-02",
        "target_account": "dev_lead",
        "description": "Database access from dev_lead account to staging database. Running performance benchmark queries. Account has appropriate permissions.",
        "raw_log": "db-audit: INFO user=dev_lead src=10.0.4.200 db=app_staging queries=200 type=benchmark",
        "ground_truth": "false_positive",
    },
    # --- SUSPICIOUS DNS ---
    {
        "alert_id": "ALT-011",
        "timestamp": "2026-03-15T12:00:15Z",
        "type": "suspicious_dns",
        "severity": "high",
        "source_ip": "10.0.3.105",
        "target": "dns-resolver-01",
        "target_account": "N/A",
        "description": "DNS tunneling pattern detected: High-frequency TXT queries to subdomain of malware-c2.evil.com with encoded data in query names.",
        "raw_log": "dns: ALERT src=10.0.3.105 query=aGVsbG8=.data.malware-c2.evil.com type=TXT freq=120/min",
        "ground_truth": "true_positive",
    },
    # --- SQL INJECTION ---
    {
        "alert_id": "ALT-012",
        "timestamp": "2026-03-15T17:20:00Z",
        "type": "sql_injection",
        "severity": "high",
        "source_ip": "192.0.2.88",
        "target": "web-app-01",
        "target_account": "N/A",
        "description": "WAF detected SQL injection attempt: UNION SELECT in login form. Multiple payloads attempted from same source IP.",
        "raw_log": "waf: BLOCK src=192.0.2.88 uri=/api/login payload=\"' UNION SELECT username,password FROM users--\" attempts=15",
        "ground_truth": "true_positive",
    },
    # --- PRIVILEGE ESCALATION ---
    {
        "alert_id": "ALT-013",
        "timestamp": "2026-03-15T18:05:33Z",
        "type": "privilege_escalation",
        "severity": "critical",
        "source_ip": "10.0.3.105",
        "target": "workstation-dev-42",
        "target_account": "developer3",
        "description": "Privilege escalation detected: User developer3 executed 'sudo su -' followed by modification of /etc/shadow. Preceded by malware activity.",
        "raw_log": "audit: ALERT uid=developer3 cmd='sudo su -' followed_by='vi /etc/shadow' host=workstation-dev-42",
        "ground_truth": "true_positive",
    },
    # --- LATERAL MOVEMENT ---
    {
        "alert_id": "ALT-014",
        "timestamp": "2026-03-15T18:30:00Z",
        "type": "lateral_movement",
        "severity": "critical",
        "source_ip": "10.0.3.105",
        "target": "file-server-01",
        "target_account": "developer3",
        "description": "Lateral movement detected: RDP session from compromised workstation-dev-42 to file-server-01 using developer3 credentials. Mass file access follows.",
        "raw_log": "rdp: ALERT src=10.0.3.105(workstation-dev-42) dst=10.0.2.30(file-server-01) user=developer3 files_accessed=1247",
        "ground_truth": "true_positive",
    },
    # More false positives for balance
    {
        "alert_id": "ALT-015",
        "timestamp": "2026-03-15T19:00:00Z",
        "type": "brute_force",
        "severity": "medium",
        "source_ip": "10.0.5.30",
        "target": "vpn-gateway-01",
        "target_account": "remote_worker",
        "description": "3 failed VPN login attempts followed by successful login. User reports forgot password, just reset it.",
        "raw_log": "vpn: INFO user=remote_worker failures=3 src=home_ip success_on=4th_attempt",
        "ground_truth": "false_positive",
    },
    {
        "alert_id": "ALT-016",
        "timestamp": "2026-03-15T19:30:00Z",
        "type": "suspicious_dns",
        "severity": "low",
        "source_ip": "10.0.4.55",
        "target": "dns-resolver-01",
        "target_account": "N/A",
        "description": "Unusual DNS queries to dynamic DNS provider (dyndns.org). Source is IoT device (smart thermostat) performing regular check-ins.",
        "raw_log": "dns: INFO src=10.0.4.55(thermostat-lobby) query=update.dyndns.org type=A freq=1/min",
        "ground_truth": "false_positive",
    },
]

# ============================================================================
# SIEM LOG DATABASE (for querying)
# ============================================================================

SIEM_LOGS: Dict[str, List[Dict[str, Any]]] = {
    "auth": [
        {"timestamp": "2026-03-15T02:10:00Z", "host": "auth-server-01", "event": "Failed login", "user": "root", "source": "198.51.100.45", "count": 12},
        {"timestamp": "2026-03-15T02:12:00Z", "host": "auth-server-01", "event": "Failed login", "user": "admin", "source": "198.51.100.45", "count": 35},
        {"timestamp": "2026-03-15T02:14:33Z", "host": "auth-server-01", "event": "Account lockout", "user": "admin", "source": "198.51.100.45"},
        {"timestamp": "2026-03-15T08:28:00Z", "host": "auth-server-01", "event": "Failed login", "user": "jsmith", "source": "10.0.5.22", "count": 5},
        {"timestamp": "2026-03-15T08:30:12Z", "host": "auth-server-01", "event": "Successful login", "user": "jsmith", "source": "10.0.5.22"},
    ],
    "endpoint": [
        {"timestamp": "2026-03-15T11:20:00Z", "host": "workstation-dev-42", "event": "PowerShell execution", "user": "developer3", "cmdline": "powershell.exe -enc aQBmACgAKABnAHcAbQBpACAAVwBpA..."},
        {"timestamp": "2026-03-15T11:22:15Z", "host": "workstation-dev-42", "event": "Suspicious process", "process": "svchost32.exe", "parent": "powershell.exe", "user": "developer3"},
        {"timestamp": "2026-03-15T11:25:00Z", "host": "workstation-dev-42", "event": "C2 beacon", "dest": "198.51.100.200", "interval": "30s", "user": "developer3"},
        {"timestamp": "2026-03-15T12:00:15Z", "host": "workstation-dev-42", "event": "DNS tunneling", "dest": "malware-c2.evil.com", "user": "developer3"},
        {"timestamp": "2026-03-15T13:05:44Z", "host": "workstation-dev-42", "event": "Large upload", "dest": "198.51.100.200", "bytes": 2469396480, "user": "developer3"},
        {"timestamp": "2026-03-15T18:05:33Z", "host": "workstation-dev-42", "event": "Privilege escalation", "user": "developer3", "cmd": "sudo su -"},
        {"timestamp": "2026-03-15T18:06:00Z", "host": "workstation-dev-42", "event": "File modification", "user": "root", "file": "/etc/shadow"},
    ],
    "network": [
        {"timestamp": "2026-03-15T11:22:30Z", "src": "10.0.3.105", "dst": "198.51.100.200", "port": 443, "proto": "HTTPS", "bytes_out": 256, "type": "C2"},
        {"timestamp": "2026-03-15T13:05:44Z", "src": "10.0.3.105", "dst": "198.51.100.200", "port": 443, "proto": "HTTPS", "bytes_out": 2469396480, "type": "exfiltration"},
        {"timestamp": "2026-03-15T18:30:00Z", "src": "10.0.3.105", "dst": "10.0.2.30", "port": 3389, "proto": "RDP", "type": "lateral_movement"},
        {"timestamp": "2026-03-15T17:20:00Z", "src": "192.0.2.88", "dst": "10.0.1.100", "port": 443, "proto": "HTTPS", "type": "sql_injection"},
    ],
    "database": [
        {"timestamp": "2026-03-15T15:30:22Z", "host": "db-prod-01", "user": "intern_user", "source": "10.0.1.15", "database": "customer_pii", "queries": 450, "type": "mass_read"},
        {"timestamp": "2026-03-15T16:15:00Z", "host": "db-staging-02", "user": "dev_lead", "source": "10.0.4.200", "database": "app_staging", "queries": 200, "type": "benchmark"},
    ],
    "email": [
        {"timestamp": "2026-03-15T09:44:00Z", "event": "Inbound email", "from": "billing@c0mpany-vendor.com", "to": "cfo@company.com", "subject": "Urgent Invoice #INV-29841", "attachment": "invoice_march.pdf.exe", "verdict": "malicious"},
        {"timestamp": "2026-03-15T09:45:00Z", "event": "Attachment blocked", "attachment": "invoice_march.pdf.exe", "reason": "double_extension"},
        {"timestamp": "2026-03-15T10:12:30Z", "event": "Inbound email", "from": "john.applicant@gmail.com", "to": "hr@company.com", "subject": "Job Application - Sr. Engineer", "attachment": "resume.docx", "verdict": "clean"},
    ],
    "waf": [
        {"timestamp": "2026-03-15T17:18:00Z", "src": "192.0.2.88", "uri": "/api/login", "payload": "' OR 1=1--", "action": "block"},
        {"timestamp": "2026-03-15T17:19:00Z", "src": "192.0.2.88", "uri": "/api/login", "payload": "' UNION SELECT username,password FROM users--", "action": "block"},
        {"timestamp": "2026-03-15T17:20:00Z", "src": "192.0.2.88", "uri": "/api/search", "payload": "1; DROP TABLE users--", "action": "block"},
    ],
}

# ============================================================================
# NETWORK CONNECTIONS DATABASE (for check_network action)
# ============================================================================

NETWORK_CONNECTIONS: Dict[str, List[Dict[str, Any]]] = {
    "workstation-dev-42": [
        {"remote_ip": "198.51.100.200", "remote_port": 443, "proto": "TCP", "state": "ESTABLISHED", "process": "svchost32.exe", "pid": 4521},
        {"remote_ip": "10.0.2.30", "remote_port": 3389, "proto": "TCP", "state": "ESTABLISHED", "process": "mstsc.exe", "pid": 5102},
        {"remote_ip": "10.0.1.1", "remote_port": 53, "proto": "UDP", "state": "CONNECTED", "process": "svchost32.exe", "pid": 4521},
        {"remote_ip": "10.0.4.100", "remote_port": 443, "proto": "TCP", "state": "ESTABLISHED", "process": "chrome.exe", "pid": 3200},
    ],
    "file-server-01": [
        {"remote_ip": "10.0.3.105", "remote_port": 3389, "proto": "TCP", "state": "ESTABLISHED", "process": "rdp-svc", "pid": 1102},
        {"remote_ip": "10.0.2.50", "remote_port": 445, "proto": "TCP", "state": "ESTABLISHED", "process": "smbd", "pid": 800},
    ],
    "auth-server-01": [
        {"remote_ip": "198.51.100.45", "remote_port": 22, "proto": "TCP", "state": "SYN_RECV", "process": "sshd", "pid": 2847},
        {"remote_ip": "10.0.5.22", "remote_port": 22, "proto": "TCP", "state": "ESTABLISHED", "process": "sshd", "pid": 3102},
    ],
    "web-app-01": [
        {"remote_ip": "192.0.2.88", "remote_port": 443, "proto": "TCP", "state": "BLOCKED", "process": "nginx", "pid": 1001},
    ],
    "db-prod-01": [
        {"remote_ip": "10.0.1.15", "remote_port": 5432, "proto": "TCP", "state": "ESTABLISHED", "process": "postgres", "pid": 600},
    ],
}


# ============================================================================
# TASK DEFINITIONS
# ============================================================================

TASK_ALERT_TRIAGE = {
    "task_id": "alert_triage",
    "name": "Alert Triage",
    "difficulty": "easy",
    "description": (
        "You are a SOC analyst starting your shift. Your alert queue has 5 security alerts. "
        "For each alert, investigate and classify it as 'true_positive', 'false_positive', or 'needs_investigation'. "
        "Use query_logs and lookup_threat_intel to verify before classifying. "
        "Accurate and efficient triage is critical — false negatives let threats through, false positives waste resources."
    ),
    "max_steps": 15,
    "alert_ids": ["ALT-001", "ALT-002", "ALT-003", "ALT-004", "ALT-005"],
    "expected_classifications": {
        "ALT-001": "true_positive",
        "ALT-002": "false_positive",
        "ALT-003": "true_positive",
        "ALT-004": "false_positive",
        "ALT-005": "true_positive",
    },
    "available_actions": ["classify_alert", "query_logs", "lookup_threat_intel"],
}

TASK_INVESTIGATION = {
    "task_id": "incident_investigation",
    "name": "Incident Investigation",
    "difficulty": "medium",
    "description": (
        "Multiple alerts have been correlated to a potential security incident involving workstation-dev-42 (developer3). "
        "Investigate the incident by querying SIEM logs, checking network connections, and looking up threat intel. "
        "Determine: (1) the attack vector, (2) affected systems, (3) indicators of compromise (IOCs), "
        "and (4) severity level. Submit your findings in a report."
    ),
    "max_steps": 30,
    "alert_ids": ["ALT-005", "ALT-007", "ALT-011", "ALT-013", "ALT-014"],
    "expected": {
        "attack_vector": "phishing_to_malware",
        "iocs": ["198.51.100.200", "svchost32.exe", "malware-c2.evil.com", "10.0.3.105"],
        "affected_systems": ["workstation-dev-42", "file-server-01"],
        "severity": "critical",
    },
    "available_actions": [
        "classify_alert", "query_logs", "lookup_threat_intel",
        "check_network", "submit_report", "escalate",
    ],
}

TASK_INCIDENT_RESPONSE = {
    "task_id": "full_incident_response",
    "name": "Full Incident Response",
    "difficulty": "hard",
    "description": (
        "CRITICAL: A multi-stage cyber attack is in progress. Your alert queue shows malware, "
        "data exfiltration, privilege escalation, and lateral movement — all linked to workstation-dev-42. "
        "You must: (1) Investigate all alerts, (2) Identify all affected systems and IOCs, "
        "(3) Execute containment actions (isolate compromised hosts, block C2 IPs, disable compromised accounts), "
        "(4) Escalate appropriately, and (5) Submit a comprehensive incident report. "
        "Every minute counts — data is actively being exfiltrated. Balance speed with thoroughness."
    ),
    "max_steps": 50,
    "alert_ids": ["ALT-001", "ALT-003", "ALT-005", "ALT-007", "ALT-009", "ALT-011", "ALT-012", "ALT-013", "ALT-014"],
    "expected": {
        "attack_vector": "phishing_to_malware",
        "iocs": ["198.51.100.200", "svchost32.exe", "malware-c2.evil.com", "10.0.3.105", "192.0.2.88", "203.0.113.77"],
        "affected_systems": ["workstation-dev-42", "file-server-01", "auth-server-01", "db-prod-01"],
        "severity": "critical",
        "containment": {
            "isolate_hosts": ["workstation-dev-42", "file-server-01"],
            "block_ips": ["198.51.100.200", "198.51.100.45", "192.0.2.88", "203.0.113.77"],
            "disable_accounts": ["developer3", "intern_user"],
        },
        "should_escalate": True,
        "report_keywords": ["malware", "exfiltration", "lateral movement", "containment", "developer3"],
    },
    "available_actions": [
        "classify_alert", "query_logs", "lookup_threat_intel",
        "check_network", "isolate_host", "block_ip",
        "disable_account", "submit_report", "escalate",
    ],
}

TASKS = {
    "alert_triage": TASK_ALERT_TRIAGE,
    "incident_investigation": TASK_INVESTIGATION,
    "full_incident_response": TASK_INCIDENT_RESPONSE,
}


def get_task(task_id: str) -> Dict[str, Any]:
    """Get a deep copy of a task definition."""
    if task_id not in TASKS:
        raise ValueError(f"Unknown task_id: {task_id}. Available: {list(TASKS.keys())}")
    return copy.deepcopy(TASKS[task_id])


def get_alerts_for_task(task_id: str) -> List[Dict[str, Any]]:
    """Get the alerts associated with a task."""
    task = get_task(task_id)
    alert_ids = task["alert_ids"]
    alerts = []
    for alert in ALERTS_DB:
        if alert["alert_id"] in alert_ids:
            # Return alert without ground_truth (agent shouldn't see it)
            alert_copy = {k: v for k, v in alert.items() if k != "ground_truth"}
            alerts.append(alert_copy)
    return alerts


def query_siem_logs(log_type: str, **filters) -> List[Dict[str, Any]]:
    """Query SIEM logs with optional filters."""
    if log_type not in SIEM_LOGS:
        return [{"error": f"Unknown log type: {log_type}. Available: {list(SIEM_LOGS.keys())}"}]

    results = []
    for entry in SIEM_LOGS[log_type]:
        match = True
        for key, value in filters.items():
            if key in entry:
                entry_val = str(entry[key]).lower()
                search_val = str(value).lower()
                if search_val not in entry_val:
                    match = False
                    break
            # If filter key not in entry, skip (don't filter out)
        if match:
            results.append(copy.deepcopy(entry))

    return results if results else [{"message": f"No {log_type} logs found matching filters: {filters}"}]


def get_network_connections(host: str) -> List[Dict[str, Any]]:
    """Get network connections for a specific host."""
    if host in NETWORK_CONNECTIONS:
        return copy.deepcopy(NETWORK_CONNECTIONS[host])
    return [{"message": f"No network data available for host: {host}"}]
