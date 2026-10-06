"""
NetTrace — PDF Report Generator (reportlab)
===========================================
Professional A4 report with risk banner, summary cards, zebra tables.
"""
from __future__ import annotations
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak,
)
import config
import database as db
from utils import filename_timestamp, now_timestamp, open_path
_HEADER_BG = colors.HexColor("#34495e")
_ZEBRA = colors.HexColor("#f9fbfd")
_GRID = colors.HexColor("#ecf0f1")
def _risk_level(score: int) -> tuple[str, colors.Color]:
    """Return (label, color) for a risk score."""
    if score <= config.RISK_LOW_MAX:
        return "LOW", colors.HexColor("#27ae60")
    if score <= config.RISK_MEDIUM_MAX:
        return "MEDIUM", colors.HexColor("#e67e22")
    return "HIGH", colors.HexColor("#c0392b")
def _compute_risk_score() -> int:
    """Compute the aggregate risk score from stored data."""
    _, unknown, suspicious = db.get_packet_stats()
    sev = db.get_alert_counts_by_severity()
    return (
        suspicious * config.RISK_WEIGHT_SUSPICIOUS
        + unknown * config.RISK_WEIGHT_UNKNOWN
        + sev.get(config.SEVERITY_HIGH, 0) * config.RISK_WEIGHT_ALERT_HIGH
        + sev.get(config.SEVERITY_MEDIUM, 0) * config.RISK_WEIGHT_ALERT_MEDIUM
    )
def _table(rows: list[list[str]], col_widths: list[float]) -> Table:
    """Build a zebra-striped, dark-header table."""
    data = [[Paragraph(str(c), _cell_style(header=True)) for c in rows[0]]]
    for r in rows[1:]:
        data.append([Paragraph(str(c), _cell_style(header=False)) for c in r])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, _GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), _ZEBRA))
    t.setStyle(TableStyle(style))
    return t
def _cell_style(header: bool) -> ParagraphStyle:
    """Return a Paragraph style for table cells."""
    return ParagraphStyle(
        name="cell-h" if header else "cell",
        fontName="Helvetica-Bold" if header else "Helvetica",
        fontSize=8,
        textColor=colors.white if header else colors.black,
        leading=10,
    )
def generate_pdf_report() -> str:
    """Build a PDF report, save it, open it, and return its path."""
    total, unknown, suspicious = db.get_packet_stats()
    known = total - unknown - suspicious
    alerts = db.get_recent_alerts(config.REPORT_MAX_ALERT_ROWS)
    packets = db.get_recent_packets(config.REPORT_MAX_PACKET_ROWS)
    baseline = db.get_all_baseline()
    protocols = db.get_protocol_stats()
    sources = db.get_top_unknown_sources(20)
    score = _compute_risk_score()
    label, color = _risk_level(score)
    out_path = Path(config.REPORT_DIR_PDF) / (
        f"nettrace_report_{filename_timestamp()}.pdf"
    )
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm,
        topMargin=1.8 * cm, bottomMargin=1.8 * cm,
        title="NetTrace Security Report",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=_HEADER_BG, fontSize=18, spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=_HEADER_BG, fontSize=13, spaceBefore=14,
                        spaceAfter=6)
    body = styles["BodyText"]
    story: list = []
    story.append(Paragraph("🛡️ NetTrace Security Report", h1))
    story.append(Paragraph(
        f"Generated: {now_timestamp()} · v{config.APP_VERSION}", body))
    story.append(Spacer(1, 10))
    # Risk banner
    banner = Table(
        [[Paragraph(
            f"<b>Overall Risk: {label}</b> &nbsp; (score {score})",
            ParagraphStyle("banner", fontName="Helvetica-Bold",
                           fontSize=11, textColor=colors.white),
        )]],
        colWidths=[doc.width],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(banner)
    story.append(Spacer(1, 12))
    # Summary cards
    story.append(Paragraph("Summary", h2))
    summary_rows = [[
        "Total Packets", "Known", "Unknown", "Suspicious",
    ], [str(total), str(known), str(unknown), str(suspicious)]]
    story.append(_table(summary_rows, [doc.width / 4] * 4))
    story.append(Spacer(1, 8))
    # Protocol stats
    story.append(Paragraph("Protocol Statistics", h2))
    if protocols:
        rows = [["Protocol", "Count"]] + [[p, str(c)] for p, c in protocols]
        story.append(_table(rows, [doc.width * 0.6, doc.width * 0.4]))
    # Unknown sources
    story.append(Paragraph("Top Unknown / Suspicious Sources", h2))
    if sources:
        rows = [["Source IP", "Packets"]] + [[ip, str(c)] for ip, c in sources]
        story.append(_table(rows, [doc.width * 0.6, doc.width * 0.4]))
    story.append(PageBreak())
    # Alerts
    story.append(Paragraph("Security Alerts", h2))
    if alerts:
        rows = [["Time", "Severity", "Source", "Destination", "Message"]]
        for a in alerts:
            rows.append([
                a.timestamp, a.severity, a.src_ip,
                f"{a.dst_ip}:{a.dst_port}/{a.protocol}",
                a.message,
            ])
        widths = [
            doc.width * 0.16, doc.width * 0.09, doc.width * 0.14,
            doc.width * 0.16, doc.width * 0.45,
        ]
        story.append(_table(rows, widths))
    else:
        story.append(Paragraph("No alerts recorded.", body))
    # Recent packets
    story.append(Paragraph("Recent Traffic", h2))
    if packets:
        rows = [["Time", "Source", "Destination", "Proto", "Len",
                 "Class", "Reason"]]
        for p in packets:
            rows.append([
                p.timestamp, f"{p.src_ip}:{p.src_port}",
                f"{p.dst_ip}:{p.dst_port}", p.protocol, str(p.length),
                p.classification, p.reason,
            ])
        widths = [
            doc.width * 0.15, doc.width * 0.15, doc.width * 0.15,
            doc.width * 0.08, doc.width * 0.07, doc.width * 0.12,
            doc.width * 0.28,
        ]
        story.append(_table(rows, widths))
    else:
        story.append(Paragraph("No packets recorded.", body))
    # Baseline
    story.append(Paragraph("Learned Baseline", h2))
    if baseline:
        rows = [["Port", "Proto", "Hits", "First Seen", "Last Seen"]]
        for b in baseline:
            rows.append([
                str(b.dst_port), b.protocol, str(b.hit_count),
                b.first_seen, b.last_seen,
            ])
        widths = [
            doc.width * 0.12, doc.width * 0.12, doc.width * 0.12,
            doc.width * 0.32, doc.width * 0.32,
        ]
        story.append(_table(rows, widths))
    else:
        story.append(Paragraph("No baseline entries yet.", body))
    # Recommendations
    story.append(Paragraph("Recommendations", h2))
    recs: list[str] = []
    if suspicious:
        recs.append(
            f"Investigate {suspicious} SUSPICIOUS packets — focus on risky "
            "ports and the source IPs listed above."
        )
    if unknown:
        recs.append(
            f"Review {unknown} UNKNOWN packets; trusted ports will be "
            "promoted to KNOWN after the learning threshold."
        )
    if not recs:
        recs.append("No anomalies detected in this capture window.")
    recs.extend([
        "Block inbound traffic to risky ports (23, 445, 3389, 5900, …).",
        "Enable reputation lookups in config.py for source enrichment.",
        "Re-run capture during peak hours to widen the baseline.",
    ])
    for r in recs:
        story.append(Paragraph(f"• {r}", body))
    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "<i>NetTrace — Network Security Monitoring System · "
        "Educational use only</i>",
        ParagraphStyle("footer", parent=body, fontSize=8,
                       textColor=colors.grey, alignment=1),
    ))
    doc.build(story)
    try:
        open_path(out_path)
    except Exception:
        pass
    print(f"[NetTrace] PDF report: {out_path}")
    return str(out_path)
