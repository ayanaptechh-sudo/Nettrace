"""
NetTrace — Baseline Learning & Anomaly Detection
================================================
Statistical classification of packets vs learned (port, protocol) baselines.
"""
from __future__ import annotations
import time
import config
import database as db
from models import BaselineEntry
def _prune_rate_window(window: list[float], now: float) -> list[float]:
    """Drop rate samples older than RATE_WINDOW_SECONDS."""
    cutoff = now - config.RATE_WINDOW_SECONDS
    return [t for t in window if t >= cutoff]
def classify_packet(
    dst_port: int, protocol: str, length: int, src_ip: str
) -> tuple[str, str]:
    """Classify a packet.
    Args:
        dst_port: Destination port (ICMP uses 0).
        protocol: "TCP" | "UDP" | "ICMP".
        length: Packet payload length in bytes.
        src_ip: Source IP (used for rate tracking).
    Returns:
        (classification, reason) where classification is one of
        config.CLASS_KNOWN / CLASS_UNKNOWN / CLASS_SUSPICIOUS.
    """
    # Rule 1: Risky port
    if dst_port in config.RISKY_PORTS:
        return (
            config.CLASS_SUSPICIOUS,
            f"Risky port {dst_port} ({protocol})",
        )
    entry = db.get_baseline_entry(dst_port, protocol)
    now = time.time()
    # Rule 3: First-seen port
    if entry is None:
        entry = BaselineEntry(
            dst_port=dst_port,
            protocol=protocol,
            hit_count=1,
            total_bytes=length,
            byte_history=[length],
            rate_window=[now],
            first_seen=_now_str(),
            last_seen=_now_str(),
        )
        db.upsert_baseline(entry)
        if dst_port in config.COMMON_PORTS:
            return config.CLASS_KNOWN, "Common service port"
        return config.CLASS_UNKNOWN, "First-seen port — learning"
    # Update sliding rate window
    entry.rate_window = _prune_rate_window(entry.rate_window, now)
    entry.rate_window.append(now)
    # Rule 6: Rate spike check
    rate_per_min = len(entry.rate_window)
    if (
        entry.hit_count >= config.LEARNING_THRESHOLD
        and rate_per_min >= config.RATE_SPIKE_MIN_PACKETS
        and rate_per_min > config.RATE_SPIKE_MULTIPLIER * max(
            1, entry.hit_count / 10
        )
    ):
        entry.hit_count += 1
        entry.total_bytes += length
        entry.byte_history.append(length)
        entry.last_seen = _now_str()
        db.upsert_baseline(entry)
        return (
            config.CLASS_SUSPICIOUS,
            f"Traffic spike ({rate_per_min} pkt/min from {src_ip})",
        )
    # Rule 4: Learning phase
    if entry.hit_count < config.LEARNING_THRESHOLD:
        entry.hit_count += 1
        entry.total_bytes += length
        entry.byte_history.append(length)
        entry.last_seen = _now_str()
        db.upsert_baseline(entry)
        if dst_port in config.COMMON_PORTS:
            return config.CLASS_KNOWN, "Common service port (learning)"
        return (
            config.CLASS_UNKNOWN,
            f"Learning phase ({entry.hit_count}/{config.LEARNING_THRESHOLD})",
        )
    # Rule 5: Statistical outlier
    mean = entry.mean_bytes()
    stddev = entry.stddev_bytes()
    if len(entry.byte_history) >= config.MIN_STDDEV_SAMPLES and stddev > 0:
        z = (length - mean) / stddev
        if z > config.ANOMALY_SIGMA:
            entry.hit_count += 1
            entry.total_bytes += length
            entry.byte_history.append(length)
            entry.last_seen = _now_str()
            db.upsert_baseline(entry)
            return (
                config.CLASS_UNKNOWN,
                f"Byte-size anomaly (z={z:.2f} > {config.ANOMALY_SIGMA})",
            )
    # Baseline established — update history
    entry.hit_count += 1
    entry.total_bytes += length
    entry.byte_history.append(length)
    entry.last_seen = _now_str()
    db.upsert_baseline(entry)
    return config.CLASS_KNOWN, "Baseline established"
def _now_str() -> str:
    """Local import to avoid circulars."""
    from utils import now_timestamp
    return now_timestamp()
