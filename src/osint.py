"""
osint.py — Threat Intelligence Enrichment
Uses free-tier public APIs (no custom tool build required):
  • ip-api.com    — geolocation + VPN/proxy/hosting detection (free, no key)
  • AbuseIPDB     — abuse score, report count, community reporting (free tier)
"""

import os
import requests
from typing import Optional


ABUSEIPDB_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
REQUEST_TIMEOUT = 6


def _get_ipapi(ip: str) -> dict:
    """
    ip-api.com — free, no key, 45 req/min
    Returns geolocation + proxy/VPN/hosting flags.
    """
    fields = "status,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile"
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _check_abuseipdb(ip: str) -> dict:
    """
    AbuseIPDB — free tier: 1,000 checks/day
    Returns abuse confidence score, total reports, last seen.
    """
    if not ABUSEIPDB_KEY:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception:
        pass
    return {}


def report_to_abuseipdb(ip: str, comment: str) -> bool:
    """
    Report confirmed attacker IP to AbuseIPDB community database.
    Categories: 18 = Brute-Force, 22 = SSH
    This is legal and community-beneficial — we're the defender reporting evidence.
    """
    if not ABUSEIPDB_KEY:
        return False
    try:
        r = requests.post(
            "https://api.abuseipdb.com/api/v2/report",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            data={
                "ip": ip,
                "categories": "18,22",
                "comment": comment[:1024],
            },
            timeout=REQUEST_TIMEOUT,
        )
        return r.status_code == 200
    except Exception:
        return False


def enrich(ip: str) -> dict:
    """
    Full OSINT enrichment for a given attacker IP.
    Returns a normalized dict with all available intel.
    """
    result: dict = {"ip": ip}

    geo = _get_ipapi(ip)
    result["country"] = geo.get("country", "Unknown")
    result["country_code"] = geo.get("countryCode", "??")
    result["region"] = geo.get("regionName", "Unknown")
    result["city"] = geo.get("city", "Unknown")
    result["isp"] = geo.get("isp", "Unknown")
    result["org"] = geo.get("org", "")
    result["asn"] = geo.get("as", "")
    result["is_proxy"] = geo.get("proxy", False)
    result["is_hosting"] = geo.get("hosting", False)
    result["is_mobile"] = geo.get("mobile", False)

    abuse = _check_abuseipdb(ip)
    result["abuse_score"] = abuse.get("abuseConfidenceScore", "N/A")
    result["total_reports"] = abuse.get("totalReports", "N/A")
    result["last_reported"] = abuse.get("lastReportedAt") or "Never"
    result["abuse_categories"] = abuse.get("usageType", "Unknown")

    return result


def format_osint_block(data: dict) -> str:
    """Format enrichment data for Telegram message."""
    proxy_tag = " [VPN/Proxy]" if data.get("is_proxy") else ""
    hosting_tag = " [Hosting/DC]" if data.get("is_hosting") else ""

    lines = [
        f"🌍 {data.get('country', '?')} ({data.get('country_code', '??')}) — {data.get('city', '?')}",
        f"🏢 ISP: {data.get('isp', '?')}{proxy_tag}{hosting_tag}",
        f"🔢 ASN: {data.get('asn', '?')}",
    ]

    if data.get("abuse_score") != "N/A":
        score = data["abuse_score"]
        emoji = "🔴" if score >= 50 else "🟡" if score >= 10 else "🟢"
        lines.append(
            f"{emoji} AbuseIPDB Score: {score}/100 "
            f"({data.get('total_reports', 0)} reports, last: {data.get('last_reported', 'Never')})"
        )

    return "\n".join(lines)
