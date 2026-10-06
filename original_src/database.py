"""
NetTrace — SQLite Storage Layer
===============================
Schema init, packet/alert insertion, baseline upsert, and queries.
"""
from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from typing import Iterator
from config import DB_PATH, MAX_BYTE_HISTORY, MAX_RATE_SAMPLES
from models import AlertRecord, BaselineEntry, PacketRecord
from utils import now_timestamp
@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row factory and safe close."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
def init_db() -> None:
    """Create tables and indexes if they do not exist."""
    with _connect() as conn:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                length INTEGER NOT NULL,
                classification TEXT NOT NULL,
                reason TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_packets_class ON packets(classification);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
            CREATE TABLE IF NOT EXISTS baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                hit_count INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                byte_history_json TEXT NOT NULL DEFAULT '[]',
                rate_window_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT '',
                UNIQUE(dst_port, protocol)
            );
            """
        )
# ─── Packets ─────────────────────────────────────────────────────
def insert_packet(p: PacketRecord) -> int:
    """Insert a packet record and return its row id."""
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO packets
              (timestamp, src_ip, dst_ip, src_port, dst_port,
               protocol, length, classification, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                p.timestamp, p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                p.protocol, p.length, p.classification, p.reason,
            ),
        )
        return int(cur.lastrowid or 0)
def get_recent_packets(limit: int = 100) -> list[PacketRecord]:
    """Return the most recent packets ordered by time desc."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
    return [
        PacketRecord(
            id=r["id"], timestamp=r["timestamp"], src_ip=r["src_ip"],
            dst_ip=r["dst_ip"], src_port=r["src_port"], dst_port=r["dst_port"],
            protocol=r["protocol"], length=r["length"],
            classification=r["classification"], reason=r["reason"] or "",
        )
        for r in rows
    ]
def get_packet_stats() -> tuple[int, int, int]:
    """Return (total, unknown, suspicious) packet counts."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        unknown = conn.execute(
            "SELECT COUNT(*) FROM packets WHERE classification='UNKNOWN'"
        ).fetchone()[0]
        suspicious = conn.execute(
            "SELECT COUNT(*) FROM packets WHERE classification='SUSPICIOUS'"
        ).fetchone()[0]
    return int(total), int(unknown), int(suspicious)
def get_protocol_stats() -> list[tuple[str, int]]:
    """Return protocol counts as (protocol, count) tuples."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT protocol, COUNT(*) AS c FROM packets GROUP BY protocol ORDER BY c DESC"
        ).fetchall()
    return [(r["protocol"], int(r["c"])) for r in rows]
def get_top_unknown_sources(limit: int = 20) -> list[tuple[str, int]]:
    """Return top source IPs with UNKNOWN/SUSPICIOUS traffic."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT src_ip, COUNT(*) AS c FROM packets
            WHERE classification IN ('UNKNOWN','SUSPICIOUS')
            GROUP BY src_ip ORDER BY c DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [(r["src_ip"], int(r["c"])) for r in rows]
# ─── Alerts ──────────────────────────────────────────────────────
def insert_alert(a: AlertRecord) -> int:
    """Insert an alert record and return its row id."""
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts
              (timestamp, severity, src_ip, dst_ip, dst_port, protocol, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                a.timestamp, a.severity, a.src_ip, a.dst_ip,
                a.dst_port, a.protocol, a.message,
            ),
        )
        return int(cur.lastrowid or 0)
def get_recent_alerts(limit: int = 100) -> list[AlertRecord]:
    """Return the most recent alerts ordered by time desc."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
    return [
        AlertRecord(
            id=r["id"], timestamp=r["timestamp"], severity=r["severity"],
            src_ip=r["src_ip"], dst_ip=r["dst_ip"], dst_port=r["dst_port"],
            protocol=r["protocol"], message=r["message"],
        )
        for r in rows
    ]
def get_alert_counts_by_severity() -> dict[str, int]:
    """Return a dict mapping severity -> count."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ).fetchall()
    return {r["severity"]: int(r["c"]) for r in rows}
# ─── Baseline ────────────────────────────────────────────────────
def _row_to_baseline(r: sqlite3.Row) -> BaselineEntry:
    """Convert a DB row into a BaselineEntry."""
    try:
        byte_history = json.loads(r["byte_history_json"] or "[]")
    except json.JSONDecodeError:
        byte_history = []
    try:
        rate_window = json.loads(r["rate_window_json"] or "[]")
    except json.JSONDecodeError:
        rate_window = []
    return BaselineEntry(
        id=r["id"], dst_port=r["dst_port"], protocol=r["protocol"],
        hit_count=r["hit_count"], total_bytes=r["total_bytes"],
        byte_history=byte_history, rate_window=rate_window,
        first_seen=r["first_seen"], last_seen=r["last_seen"],
    )
def get_baseline_entry(dst_port: int, protocol: str) -> BaselineEntry | None:
    """Fetch a baseline entry for (dst_port, protocol), or None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM baseline WHERE dst_port=? AND protocol=?",
            (int(dst_port), protocol),
        ).fetchone()
    return _row_to_baseline(row) if row else None
def get_all_baseline() -> list[BaselineEntry]:
    """Return all baseline entries ordered by hit_count desc."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM baseline ORDER BY hit_count DESC"
        ).fetchall()
    return [_row_to_baseline(r) for r in rows]
def upsert_baseline(entry: BaselineEntry) -> None:
    """Insert or update a baseline entry."""
    byte_history = entry.byte_history[-MAX_BYTE_HISTORY:]
    rate_window = entry.rate_window[-MAX_RATE_SAMPLES:]
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO baseline
              (dst_port, protocol, hit_count, total_bytes,
               byte_history_json, rate_window_json, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dst_port, protocol) DO UPDATE SET
              hit_count=excluded.hit_count,
              total_bytes=excluded.total_bytes,
              byte_history_json=excluded.byte_history_json,
              rate_window_json=excluded.rate_window_json,
              last_seen=excluded.last_seen
            """,
            (
                int(entry.dst_port), entry.protocol, int(entry.hit_count),
                int(entry.total_bytes), json.dumps(byte_history),
                json.dumps(rate_window),
                entry.first_seen or now_timestamp(),
                entry.last_seen or now_timestamp(),
            ),
        )
# ─── Maintenance ─────────────────────────────────────────────────
def clear_all() -> None:
    """Delete all rows from packets, alerts, and baseline."""
    with _connect() as conn:
        conn.execute("DELETE FROM packets")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM baseline")
analyzer
"""
NetTrace — Traffic Analyzer
===========================
Classifies packets, stores them, and emits alerts for unknown/suspicious.
"""
from __future__ import annotations
import config
import database as db
import reputation
from baseline import classify_packet
from models import AlertRecord, PacketRecord
from utils import now_timestamp
class TrafficAnalyzer:
    """Analyze, classify, persist, and alert on incoming packets."""
    def analyze(self, packet_info: dict) -> PacketRecord:
        """Process a single packet dict from the scanner.
        Args:
            packet_info: {"src_ip","dst_ip","src_port","dst_port",
                          "protocol","length"}
        Returns:
            The persisted PacketRecord.
        """
        src_ip = str(packet_info.get("src_ip", "0.0.0.0"))
        dst_ip = str(packet_info.get("dst_ip", "0.0.0.0"))
        src_port = int(packet_info.get("src_port", 0))
        dst_port = int(packet_info.get("dst_port", 0))
        protocol = str(packet_info.get("protocol", "OTHER")).upper()
        length = int(packet_info.get("length", 0))
        classification, reason = classify_packet(
            dst_port=dst_port, protocol=protocol,
            length=length, src_ip=src_ip,
        )
        rep = reputation.check(src_ip)
        if rep.get("malicious"):
            classification = config.CLASS_SUSPICIOUS
            reason = f"{reason} | Reputation: {rep['source']} score={rep['score']}"
        record = PacketRecord(
            timestamp=now_timestamp(),
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=protocol, length=length,
            classification=classification, reason=reason,
        )
        record.id = db.insert_packet(record)
        if classification == config.CLASS_SUSPICIOUS:
            self._alert(record, config.SEVERITY_HIGH)
        elif classification == config.CLASS_UNKNOWN:
            self._alert(record, config.SEVERITY_MEDIUM)
        return record
    @staticmethod
    def _alert(record: PacketRecord, severity: str) -> None:
        """Insert an alert row for a packet record."""
        alert = AlertRecord(
            timestamp=record.timestamp,
            severity=severity,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
            protocol=record.protocol,
            message=(
                f"{severity}: {record.classification} — {record.reason} "
                f"({record.src_ip} → {record.dst_ip}:{record.dst_port}/{record.protocol}, "
                f"{record.length} B)"
            ),
        )
        db.insert_alert(alert)
