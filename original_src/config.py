"""
NetTrace — Configuration Module
================================
Central configuration for the NetTrace Network Security Monitoring System.
All tunables live here: paths, thresholds, risky/common ports, severities.
"""
from __future__ import annotations
import os
from pathlib import Path
# ─── App metadata ────────────────────────────────────────────────
APP_NAME: str = "NetTrace"
APP_TITLE: str = "🛡️ NetTrace — Network Security Monitoring System"
APP_SUBTITLE: str = "Unknown Network Traffic Detector"
APP_VERSION: str = "1.0.0"
APP_AUTHOR: str = "NetTrace Project"
APP_LICENSE: str = "Educational use only"
# ─── Directory structure ─────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
REPORT_DIR: Path = BASE_DIR / "reports"
REPORT_DIR_HTML: Path = REPORT_DIR / "html"
REPORT_DIR_PDF: Path = REPORT_DIR / "pdf"
TESTS_DIR: Path = BASE_DIR / "tests"
for _d in (DATA_DIR, REPORT_DIR_HTML, REPORT_DIR_PDF, TESTS_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
# ─── Database ────────────────────────────────────────────────────
DB_PATH: Path = DATA_DIR / "nettrace.db"
# ─── Baseline / anomaly ──────────────────────────────────────────
LEARNING_THRESHOLD: int = 5
ANOMALY_SIGMA: float = 3.0
MIN_STDDEV_SAMPLES: int = 3
RATE_WINDOW_SECONDS: int = 60
RATE_SPIKE_MULTIPLIER: float = 3.0
RATE_SPIKE_MIN_PACKETS: int = 20
MAX_BYTE_HISTORY: int = 500
MAX_RATE_SAMPLES: int = 200
# ─── Port classification ─────────────────────────────────────────
RISKY_PORTS: set[int] = {
    23, 21, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5900, 6667, 4444,
}
COMMON_PORTS: set[int] = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 143, 161, 162,
    179, 389, 443, 465, 514, 587, 636, 993, 995, 1080, 1194, 1433,
    1521, 1723, 2049, 3306, 3389, 5060, 5222, 5353, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017,
}
ICMP_PORT_SENTINEL: int = 0
# ─── Labels ──────────────────────────────────────────────────────
CLASS_KNOWN: str = "KNOWN"
CLASS_UNKNOWN: str = "UNKNOWN"
CLASS_SUSPICIOUS: str = "SUSPICIOUS"
ALL_CLASSES: tuple[str, ...] = (CLASS_KNOWN, CLASS_UNKNOWN, CLASS_SUSPICIOUS)
SEVERITY_LOW: str = "LOW"
SEVERITY_MEDIUM: str = "MEDIUM"
SEVERITY_HIGH: str = "HIGH"
SEVERITY_CRITICAL: str = "CRITICAL"
ALL_SEVERITIES: tuple[str, ...] = (
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)
# ─── Scanner / UI ────────────────────────────────────────────────
CAPTURE_FILTER: str = "ip"
CAPTURE_TIMEOUT: float = 1.0
UI_MAX_ROWS: int = 100
UI_REFRESH_INTERVAL: float = 1.0
# ─── Reputation (offline by default) ────────────────────────────
REPUTATION_ENABLED: bool = False
REPUTATION_PROVIDER: str = "none"   # "virustotal" | "abuseipdb" | "none"
VIRUSTOTAL_API_KEY: str = ""
ABUSEIPDB_API_KEY: str = ""
REPUTATION_TIMEOUT: int = 5
REPUTATION_CACHE_TTL: int = 3600
REPUTATION_MALICIOUS_THRESHOLD: int = 50
# ─── Reporting ───────────────────────────────────────────────────
REPORT_MAX_ALERT_ROWS: int = 60
REPORT_MAX_PACKET_ROWS: int = 100
REPORT_AUTHOR: str = "NetTrace Security Engine"
RISK_WEIGHT_SUSPICIOUS: int = 10
RISK_WEIGHT_UNKNOWN: int = 3
RISK_WEIGHT_ALERT_HIGH: int = 8
RISK_WEIGHT_ALERT_MEDIUM: int = 3
RISK_LOW_MAX: int = 20
RISK_MEDIUM_MAX: int = 60
# ─── Time ────────────────────────────────────────────────────────
TIMESTAMP_FORMAT: str = "%Y-%m-%d %H:%M:%S"
FILENAME_TIMESTAMP_FORMAT: str = "%Y%m%d_%H%M%S"
