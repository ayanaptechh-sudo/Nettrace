"""
NetTrace — IP Reputation Lookup (Optional)
==========================================
Offline-safe stub. Enable real API calls via config.REPUTATION_ENABLED.
"""
from __future__ import annotations
import json
import time
import urllib.error
import urllib.request
import config
_CACHE: dict[str, tuple[float, dict]] = {}
def _cache_get(ip: str) -> dict | None:
    """Return a cached reputation result if still fresh."""
    hit = _CACHE.get(ip)
    if not hit:
        return None
    ts, data = hit
    if time.time() - ts > config.REPUTATION_CACHE_TTL:
        _CACHE.pop(ip, None)
        return None
    return data
def _cache_set(ip: str, data: dict) -> None:
    """Store a reputation result in the in-memory cache."""
    _CACHE[ip] = (time.time(), data)
def check(ip: str) -> dict:
    """Look up an IP's reputation.
    Always returns a dict with at least:
      {"ip": str, "score": int, "malicious": bool, "source": str}
    When reputation is disabled (default) it returns a neutral result
    without any network access.
    """
    if not config.REPUTATION_ENABLED or config.REPUTATION_PROVIDER == "none":
        return {
            "ip": ip,
            "score": 0,
            "malicious": False,
            "source": "disabled",
        }
    cached = _cache_get(ip)
    if cached is not None:
        return cached
    provider = config.REPUTATION_PROVIDER
    try:
        if provider == "virustotal":
            result = _query_virustotal(ip)
        elif provider == "abuseipdb":
            result = _query_abuseipdb(ip)
        else:
            result = {"ip": ip, "score": 0, "malicious": False,
                      "source": "unknown-provider"}
    except Exception as exc:
        result = {
            "ip": ip, "score": 0, "malicious": False,
            "source": f"error:{type(exc).__name__}",
        }
    _cache_set(ip, result)
    return result
def _query_virustotal(ip: str) -> dict:
    """Query the VirusTotal v3 API for an IP address."""
    if not config.VIRUSTOTAL_API_KEY:
        return {"ip": ip, "score": 0, "malicious": False,
                "source": "virustotal:no-key"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(
        url, headers={"x-apikey": config.VIRUSTOTAL_API_KEY}
    )
    with urllib.request.urlopen(req, timeout=config.REPUTATION_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    stats = (
        data.get("data", {}).get("attributes", {})
        .get("last_analysis_stats", {})
    )
    score = int(stats.get("malicious", 0)) * 10
    return {
        "ip": ip, "score": score,
        "malicious": score >= config.REPUTATION_MALICIOUS_THRESHOLD,
        "source": "virustotal",
    }
def _query_abuseipdb(ip: str) -> dict:
    """Query the AbuseIPDB v2 API for an IP address."""
    if not config.ABUSEIPDB_API_KEY:
        return {"ip": ip, "score": 0, "malicious": False,
                "source": "abuseipdb:no-key"}
    url = (
        "https://api.abuseipdb.com/api/v2/check"
        f"?ipAddress={ip}&maxAgeInDays=90"
    )
    req = urllib.request.Request(
        url,
        headers={
            "Key": config.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=config.REPUTATION_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    score = int(data.get("data", {}).get("abuseConfidenceScore", 0))
    return {
        "ip": ip, "score": score,
        "malicious": score >= config.REPUTATION_MALICIOUS_THRESHOLD,
        "source": "abuseipdb",
    }
