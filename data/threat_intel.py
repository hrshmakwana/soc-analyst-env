"""
Threat Intelligence Database for the SOC Analyst Environment.

Simulated threat intelligence data including known-malicious IPs, domains,
file hashes, and CVE information.
"""

from typing import Any, Dict, List, Optional
import copy


# ============================================================================
# THREAT INTELLIGENCE DATABASE
# ============================================================================

THREAT_INTEL_IPS: Dict[str, Dict[str, Any]] = {
    "198.51.100.45": {
        "reputation": "malicious",
        "category": "brute_force_scanner",
        "country": "RU",
        "first_seen": "2025-11-20",
        "last_seen": "2026-03-15",
        "reports": 847,
        "tags": ["scanner", "brute-force", "ssh-attack"],
        "description": "Known SSH brute-force scanner. Part of botnet infrastructure.",
        "associated_campaigns": ["BruteFarm-2025"],
    },
    "198.51.100.200": {
        "reputation": "malicious",
        "category": "c2_server",
        "country": "CN",
        "first_seen": "2026-01-15",
        "last_seen": "2026-03-15",
        "reports": 234,
        "tags": ["c2", "apt", "data-theft", "malware-hosting"],
        "description": "Command and control server for APT group ShadowBear. Used for data exfiltration.",
        "associated_campaigns": ["ShadowBear-Q1-2026"],
        "malware_families": ["DarkLoader", "ShadowRAT"],
    },
    "203.0.113.77": {
        "reputation": "malicious",
        "category": "phishing_infrastructure",
        "country": "NG",
        "first_seen": "2026-02-01",
        "last_seen": "2026-03-15",
        "reports": 156,
        "tags": ["phishing", "bec", "email-spoof"],
        "description": "Phishing infrastructure used for Business Email Compromise (BEC) campaigns.",
        "associated_campaigns": ["InvoiceFraud-2026"],
    },
    "192.0.2.88": {
        "reputation": "malicious",
        "category": "web_attacker",
        "country": "KR",
        "first_seen": "2026-03-10",
        "last_seen": "2026-03-15",
        "reports": 89,
        "tags": ["sql-injection", "web-scanner", "vulnerability-scanner"],
        "description": "Automated web application scanner targeting login forms and APIs.",
        "associated_campaigns": ["WebProbe-March2026"],
    },
    "172.217.14.100": {
        "reputation": "clean",
        "category": "legitimate_service",
        "country": "US",
        "first_seen": "2020-01-01",
        "reports": 0,
        "tags": ["google", "email-service"],
        "description": "Google mail infrastructure. Legitimate service.",
    },
    "10.0.5.22": {
        "reputation": "internal",
        "category": "internal_workstation",
        "description": "Internal workstation IP. Employee jsmith.",
    },
    "10.0.3.105": {
        "reputation": "internal",
        "category": "internal_workstation",
        "description": "Internal workstation IP (workstation-dev-42). Assigned to developer3.",
    },
    "10.0.2.50": {
        "reputation": "internal",
        "category": "internal_server",
        "description": "Internal backup server IP.",
    },
}

THREAT_INTEL_DOMAINS: Dict[str, Dict[str, Any]] = {
    "malware-c2.evil.com": {
        "reputation": "malicious",
        "category": "c2_domain",
        "registered": "2026-01-10",
        "registrar": "ShadyRegistrar Inc.",
        "tags": ["c2", "dns-tunneling", "malware"],
        "description": "DNS tunneling C2 domain used by ShadowBear APT group.",
        "associated_ips": ["198.51.100.200"],
    },
    "c0mpany-vendor.com": {
        "reputation": "malicious",
        "category": "phishing_domain",
        "registered": "2026-03-14",
        "registrar": "QuickDomains LLC",
        "tags": ["phishing", "typosquatting", "bec"],
        "description": "Typosquatting domain mimicking company-vendor.com. Registered 1 day before attack.",
        "associated_ips": ["203.0.113.77"],
    },
    "dyndns.org": {
        "reputation": "neutral",
        "category": "dynamic_dns",
        "description": "Legitimate dynamic DNS service. Used by IoT devices.",
    },
    "pypi.org": {
        "reputation": "clean",
        "category": "package_registry",
        "description": "Official Python Package Index. Legitimate software repository.",
    },
}

THREAT_INTEL_HASHES: Dict[str, Dict[str, Any]] = {
    "a1b2c3d4e5f6...": {
        "filename": "svchost32.exe",
        "reputation": "malicious",
        "malware_family": "ShadowRAT",
        "first_seen": "2026-01-20",
        "detection_rate": "48/72",
        "tags": ["rat", "backdoor", "c2-beacon"],
        "description": "Remote Access Trojan with keylogging, screen capture, and data exfiltration capabilities.",
        "c2_servers": ["198.51.100.200"],
    },
    "f7e8d9c0b1a2...": {
        "filename": "invoice_march.pdf.exe",
        "reputation": "malicious",
        "malware_family": "DarkLoader",
        "first_seen": "2026-03-14",
        "detection_rate": "12/72",
        "tags": ["dropper", "downloader", "disguised"],
        "description": "First-stage dropper disguised as PDF. Downloads and executes ShadowRAT payload.",
        "c2_servers": ["198.51.100.200", "203.0.113.77"],
    },
}


def lookup_ip(ip_address: str) -> Dict[str, Any]:
    """Look up threat intelligence for an IP address."""
    if ip_address in THREAT_INTEL_IPS:
        return copy.deepcopy(THREAT_INTEL_IPS[ip_address])
    return {
        "ip": ip_address,
        "reputation": "unknown",
        "description": f"No threat intelligence data available for {ip_address}.",
    }


def lookup_domain(domain: str) -> Dict[str, Any]:
    """Look up threat intelligence for a domain."""
    # Check exact match first
    if domain in THREAT_INTEL_DOMAINS:
        return copy.deepcopy(THREAT_INTEL_DOMAINS[domain])
    # Check if it's a subdomain
    for known_domain, intel in THREAT_INTEL_DOMAINS.items():
        if domain.endswith(f".{known_domain}") or known_domain in domain:
            result = copy.deepcopy(intel)
            result["note"] = f"Match on parent domain: {known_domain}"
            return result
    return {
        "domain": domain,
        "reputation": "unknown",
        "description": f"No threat intelligence data available for {domain}.",
    }


def lookup_hash(file_hash: str) -> Dict[str, Any]:
    """Look up threat intelligence for a file hash."""
    if file_hash in THREAT_INTEL_HASHES:
        return copy.deepcopy(THREAT_INTEL_HASHES[file_hash])
    # Also match by filename
    for h, intel in THREAT_INTEL_HASHES.items():
        if intel.get("filename", "").lower() == file_hash.lower():
            result = copy.deepcopy(intel)
            result["matched_by"] = "filename"
            return result
    return {
        "hash": file_hash,
        "reputation": "unknown",
        "description": f"No threat intelligence data available for hash {file_hash}.",
    }


def lookup_threat_intel(query: str, query_type: Optional[str] = None) -> Dict[str, Any]:
    """
    General threat intel lookup. Auto-detects query type if not specified.

    Args:
        query: The IP, domain, or hash to look up
        query_type: Optional hint - 'ip', 'domain', or 'hash'

    Returns:
        Threat intelligence data for the query
    """
    if query_type == "ip" or _is_ip(query):
        return {"type": "ip", "query": query, "result": lookup_ip(query)}
    elif query_type == "domain" or ("." in query and not _is_ip(query) and not len(query) > 32):
        return {"type": "domain", "query": query, "result": lookup_domain(query)}
    elif query_type == "hash" or len(query) > 20:
        return {"type": "hash", "query": query, "result": lookup_hash(query)}
    else:
        # Try all
        results = {}
        ip_result = lookup_ip(query)
        if ip_result.get("reputation") != "unknown":
            results["ip"] = ip_result
        domain_result = lookup_domain(query)
        if domain_result.get("reputation") != "unknown":
            results["domain"] = domain_result
        hash_result = lookup_hash(query)
        if hash_result.get("reputation") != "unknown":
            results["hash"] = hash_result
        if results:
            return {"type": "multi", "query": query, "results": results}
        return {"type": "unknown", "query": query, "message": f"No threat intel found for: {query}"}


def _is_ip(s: str) -> bool:
    """Check if string looks like an IP address."""
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False
