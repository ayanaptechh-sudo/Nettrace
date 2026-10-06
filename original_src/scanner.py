"""
NetTrace — Packet Capture Engine (Scapy)
========================================
Sniffs TCP/UDP/ICMP metadata in a daemon thread. No payload capture.
"""
from __future__ import annotations
import threading
from typing import Callable
try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False
    sniff = None  # type: ignore
class PacketScanner:
    """Background Scapy sniffer that emits packet metadata dicts."""
    def __init__(self, callback: Callable[[dict], None]) -> None:
        """Initialise the scanner with a callback for each packet."""
        self.callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
    def start(self) -> None:
        """Start the sniffer in a daemon thread."""
        if self._running:
            return
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install scapy"
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="NetTrace-Sniffer", daemon=True
        )
        self._thread.start()
        self._running = True
    def stop(self) -> None:
        """Signal the sniffer thread to stop and wait briefly."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._running = False
        self._thread = None
    @property
    def is_running(self) -> bool:
        """Return True if the sniffer thread is active."""
        return self._running
    def _run(self) -> None:
        """Main sniff loop with periodic timeout to honour stop()."""
        try:
            from config import CAPTURE_FILTER, CAPTURE_TIMEOUT
            while not self._stop_event.is_set():
                sniff(
                    filter=CAPTURE_FILTER,
                    prn=self._handle_packet,
                    store=False,
                    timeout=CAPTURE_TIMEOUT,
                )
        except Exception as exc:  # pragma: no cover
            print(f"[NetTrace] Scanner error: {exc}")
        finally:
            self._running = False
    def _handle_packet(self, pkt) -> None:  # noqa: ANN001
        """Extract metadata from a Scapy packet and invoke callback."""
        try:
            if IP not in pkt:
                return
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            length = int(len(pkt))
            protocol = "OTHER"
            src_port = 0
            dst_port = 0
            if TCP in pkt:
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
            elif UDP in pkt:
                protocol = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
            elif ICMP in pkt:
                protocol = "ICMP"
            else:
                return
            self.callback({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": protocol, "length": length,
            })
        except Exception:
            return
