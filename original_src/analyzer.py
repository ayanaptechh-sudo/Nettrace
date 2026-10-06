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
