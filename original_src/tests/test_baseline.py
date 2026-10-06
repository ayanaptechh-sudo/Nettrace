"""
NetTrace — Baseline Unit Tests
==============================
Verifies the classification cascade and statistical helpers.
"""
from __future__ import annotations
import os
import tempfile
import unittest
from pathlib import Path
# Redirect DB to a temp file BEFORE importing config-dependent modules.
import config  # noqa: E402
_tmp_dir = tempfile.mkdtemp(prefix="nettrace_tests_")
config.DB_PATH = Path(_tmp_dir) / "test_nettrace.db"
import database as db  # noqa: E402
from baseline import classify_packet  # noqa: E402
from models import BaselineEntry  # noqa: E402
class TestBaseline(unittest.TestCase):
    """Unit tests for baseline learning & anomaly detection."""
    def setUp(self) -> None:
        """Wipe the test DB before each test."""
        db.init_db()
        db.clear_all()
    def test_risky_port_is_suspicious(self) -> None:
        """Packets to risky ports must be SUSPICIOUS immediately."""
        cls, reason = classify_packet(23, "TCP", 60, "10.0.0.1")
        self.assertEqual(cls, config.CLASS_SUSPICIOUS)
        self.assertIn("Risky port", reason)
    def test_common_port_is_known_first_time(self) -> None:
        """First packet to a common port should be KNOWN."""
        cls, _ = classify_packet(80, "TCP", 500, "10.0.0.1")
        self.assertEqual(cls, config.CLASS_KNOWN)
    def test_unknown_port_learning_then_known(self) -> None:
        """New port stays UNKNOWN during learning, then becomes KNOWN."""
        port = 50505
        results = []
        for _ in range(config.LEARNING_THRESHOLD + 1):
            cls, _ = classify_packet(port, "TCP", 400, "10.0.0.2")
            results.append(cls)
        self.assertEqual(results[0], config.CLASS_UNKNOWN)
        self.assertEqual(results[-1], config.CLASS_KNOWN)
    def test_byte_size_anomaly(self) -> None:
        """A huge packet after learning should trigger byte-size anomaly."""
        port = 50506
        for _ in range(config.LEARNING_THRESHOLD + 2):
            classify_packet(port, "UDP", 300, "10.0.0.3")
        cls, reason = classify_packet(port, "UDP", 50000, "10.0.0.3")
        self.assertEqual(cls, config.CLASS_UNKNOWN)
        self.assertIn("anomaly", reason.lower())
    def test_baseline_entry_persisted(self) -> None:
        """Baseline rows must be retrievable after classification."""
        classify_packet(50507, "TCP", 100, "10.0.0.4")
        entry = db.get_baseline_entry(50507, "TCP")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.hit_count, 1)
        self.assertEqual(entry.byte_history, [100])
    def test_entry_mean_and_stddev(self) -> None:
        """BaselineEntry mean/stddev helpers must be numerically correct."""
        entry = BaselineEntry(
            dst_port=1, protocol="TCP",
            byte_history=[10, 20, 30],
        )
        self.assertAlmostEqual(entry.mean_bytes(), 20.0, places=4)
        self.assertGreater(entry.stddev_bytes(), 0.0)
if __name__ == "__main__":
    unittest.main(verbosity=2)
