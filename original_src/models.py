"""
NetTrace — Data Models
======================
Typed dataclasses for packets, alerts, and baseline entries.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
@dataclass(slots=True)
class PacketRecord:
    """A single captured packet metadata record."""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    classification: str
    reason: str = ""
    id: int | None = None
    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "classification": self.classification,
            "reason": self.reason,
        }
@dataclass(slots=True)
class AlertRecord:
    """A security alert derived from a packet classification."""
    timestamp: str
    severity: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    message: str
    id: int | None = None
    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "message": self.message,
        }
@dataclass(slots=True)
class BaselineEntry:
    """Statistical baseline for a (dst_port, protocol) pair."""
    dst_port: int
    protocol: str
    hit_count: int = 0
    total_bytes: int = 0
    byte_history: list[int] = field(default_factory=list)
    rate_window: list[float] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    id: int | None = None
    def mean_bytes(self) -> float:
        """Mean of byte_history, or 0.0 if empty."""
        if not self.byte_history:
            return 0.0
        return sum(self.byte_history) / len(self.byte_history)
    def stddev_bytes(self) -> float:
        """Population stddev of byte_history, or 0.0 if <2 samples."""
        n = len(self.byte_history)
        if n < 2:
            return 0.0
        mean = self.mean_bytes()
        variance = sum((x - mean) ** 2 for x in self.byte_history) / n
        return variance ** 0.5
