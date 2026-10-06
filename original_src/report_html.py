"""
NetTrace — HTML Report Generator
================================
Self-contained HTML report with embedded CSS and zebra tables.
"""
from __future__ import annotations
import html
from pathlib import Path
from typing import Any
import config
import database as db
from utils import filename_timestamp, now_timestamp, open_path
def _risk_level(score: int) -> tuple[str, str]:
    """Return (label, css_class) for a risk score."""
    if score <= config.RISK_LOW_MAX:
        return "LOW", "risk-low"
    if score <= config.RISK_MEDIUM_MAX:
        return "MEDIUM", "risk-medium"
    return "HIGH", "risk-high"
def _compute_risk_score() -> int:
    """Compute the aggregate risk score from stored data."""
    total, unknown, suspicious = db.get_packet_stats()
    sev = db.get_alert_counts_by_severity()
    return (
        suspicious * config.RISK_WEIGHT_SUSPICIOUS
        + unknown * config.RISK_WEIGHT_UNKNOWN
        + sev.get(config.SEVERITY_HIGH, 0) * config.RISK_WEIGHT_ALERT_HIGH
        + sev.get(config.SEVERITY_MEDIUM, 0) * config.RISK_WEIGHT_ALERT_MEDIUM
    )
_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
       margin: 0; padding: 0; background: #f4f6f8; color: #2c3e50; }
.header { background: #2c3e50; color: #fff; padding: 24px 32px; }
.header h1 { margin: 0; font-size: 26px; }
.header .meta { opacity: .8; font-size: 13px; margin-top: 6px; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
.risk { padding: 14px 20px; border-radius: 8px; margin-bottom: 20px;
        font-weight: 600; font-size: 16px; color: #fff; }
.risk-low { background: #27ae60; }
.risk-medium { background: #e67e22; }
.risk-high { background: #c0392b; }
.cards { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 24px; }
.card { flex: 1; min-width: 160px; background: #fff; border-radius: 8px;
        padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.card .label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
.card .value { font-size: 26px; font-weight: 700; margin-top: 6px; }
h2 { color: #2c3e50; border-bottom: 2px solid #ecf0f1;
     padding-bottom: 6px; margin-top: 32px; }
table { width: 100%; border-collapse: collapse; background: #fff;
        box-shadow: 0 1px 3px rgba(0,0,0,.05); border-radius: 6px;
        overflow: hidden; font-size: 13px; }
th { background: #34495e; color: #fff; text-align: left;
     padding: 10px; font-weight: 600; }
td { padding: 8px 10px; border-top: 1px solid #ecf0f1; }
tr:nth-child(even) td { background: #f9fbfd; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 10px;
       font-size: 11px; font-weight: 600; }
.tag-known { background: #d4efdf; color: #1e8449; }
.tag-unknown { background: #fdebd0; color: #b9770e; }
.tag-suspicious { background: #fadbd8; color: #922b21; }
.sev-HIGH, .sev-CRITICAL { color: #c0392b; font-weight: 700; }
.sev-MEDIUM { color: #e67e22; font-weight: 700; }
.sev-LOW { color: #27ae60; font-weight: 700; }
ul { line-height: 1.7; }
.footer { text-align: center; color: #95a5a6; padding: 24px;
          font-size: 12px; }
"""
def _esc(v: Any) -> str:
    """HTML-escape a value."""
    return html.escape(str(v if v is not None else ""))
def _tag(cls: str) -> str:
    """Render a classification tag span."""
    key = cls.lower()
    return f'<span class="tag tag-{key}">{_esc(cls)}</span>'
def generate_html_report() -> str:
    """Build an HTML report, save it, open it, and return its path."""
    total, unknown, suspicious = db.get_packet_stats()
    known = total - unknown - suspicious
    alerts = db.get_recent_alerts(config.REPORT_MAX_ALERT_ROWS)
    packets = db.get_recent_packets(config.REPORT_MAX_PACKET_ROWS)
    baseline = db.get_all_baseline()
    protocols = db.get_protocol_stats()
    sources = db.get_top_unknown_sources(20)
    score = _compute_risk_score()
    label, css = _risk_level(score)
    parts: list[str] = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>{_esc(config.APP_TITLE)}</title>")
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append(
        f"<div class='header'><h1>🛡️ {_esc(config.APP_NAME)} Security Report</h1>"
        f"<div class='meta'>Generated: {_esc(now_timestamp())} · "
        f"v{_esc(config.APP_VERSION)}</div></div>"
    )
    parts.append("<div class='container'>")
    parts.append(
        f"<div class='risk {css}'>Overall Risk: {label} "
        f"(score {score})</div>"
    )
    # Summary cards
    parts.append("<div class='cards'>")
    for lbl, val in (("Total Packets", total), ("Known", known),
                     ("Unknown", unknown), ("Suspicious", suspicious)):
        parts.append(
            f"<div class='card'><div class='label'>{_esc(lbl)}</div>"
            f"<div class='value'>{val}</div></div>"
        )
    parts.append("</div>")
    # Protocol stats
    parts.append("<h2>Protocol Statistics</h2><table>")
    parts.append("<tr><th>Protocol</th><th>Count</th></tr>")
    for proto, count in protocols:
        parts.append(f"<tr><td>{_esc(proto)}</td><td>{count}</td></tr>")
    parts.append("</table>")
    # Top unknown sources
    parts.append("<h2>Top Unknown / Suspicious Sources</h2><table>")
    parts.append("<tr><th>Source IP</th><th>Packets</th></tr>")
    for ip, count in sources:
        parts.append(f"<tr><td>{_esc(ip)}</td><td>{count}</td></tr>")
    parts.append("</table>")
    # Alerts
    parts.append("<h2>Recent Security Alerts</h2><table>")
    parts.append(
        "<tr><th>Time</th><th>Severity</th><th>Source</th>"
        "<th>Destination</th><th>Message</th></tr>"
    )
    for a in alerts:
        parts.append(
            f"<tr><td>{_esc(a.timestamp)}</td>"
            f"<td class='sev-{_esc(a.severity)}'>{_esc(a.severity)}</td>"
            f"<td>{_esc(a.src_ip)}</td>"
            f"<td>{_esc(a.dst_ip)}:{a.dst_port}/{_esc(a.protocol)}</td>"
            f"<td>{_esc(a.message)}</td></tr>"
        )
    parts.append("</table>")
    # Recent packets
    parts.append("<h2>Recent Traffic</h2><table>")
    parts.append(
        "<tr><th>Time</th><th>Source</th><th>Destination</th>"
        "<th>Proto</th><th>Len</th><th>Class</th><th>Reason</th></tr>"
    )
    for p in packets:
        parts.append(
            f"<tr><td>{_esc(p.timestamp)}</td>"
            f"<td>{_esc(p.src_ip)}:{p.src_port}</td>"
            f"<td>{_esc(p.dst_ip)}:{p.dst_port}</td>"
            f"<td>{_esc(p.protocol)}</td><td>{p.length}</td>"
            f"<td>{_tag(p.classification)}</td>"
            f"<td>{_esc(p.reason)}</td></tr>"
        )
    parts.append("</table>")
    # Baseline
    parts.append("<h2>Learned Baseline</h2><table>")
    parts.append(
        "<tr><th>Port</th><th>Proto</th><th>Hits</th>"
        "<th>First Seen</th><th>Last Seen</th></tr>"
    )
    for b in baseline:
        parts.append(
            f"<tr><td>{b.dst_port}</td><td>{_esc(b.protocol)}</td>"
            f"<td>{b.hit_count}</td><td>{_esc(b.first_seen)}</td>"
            f"<td>{_esc(b.last_seen)}</td></tr>"
        )
    parts.append("</table>")
    # Recommendations
    parts.append("<h2>Recommendations</h2><ul>")
    recs = []
    if suspicious:
        recs.append(
            f"Investigate {suspicious} SUSPICIOUS packets — check risky ports "
            "and reputation of the source IPs listed above."
        )
    if unknown:
        recs.append(
            f"Review {unknown} UNKNOWN packets. If they come from trusted "
            "hosts, they will be promoted to KNOWN after learning."
        )
    if not recs:
        recs.append("No anomalies detected in this capture window.")
    recs.append("Restrict inbound access to risky ports (23, 445, 3389, …).")
    recs.append("Enable IP reputation lookups in config.py for enrichment.")
    recs.append("Re-run capture during peak hours to widen the baseline.")
    for r in recs:
        parts.append(f"<li>{_esc(r)}</li>")
    parts.append("</ul>")
    parts.append(
        "<div class='footer'>NetTrace — Network Security Monitoring System "
        "· Educational use only</div>"
    )
    parts.append("</div></body></html>")
    out_path = Path(config.REPORT_DIR_HTML) / (
        f"nettrace_report_{filename_timestamp()}.html"
    )
    out_path.write_text("".join(parts), encoding="utf-8")
    try:
        open_path(out_path)
    except Exception:
        pass
    print(f"[NetTrace] HTML report: {out_path}")
    return str(out_path)
