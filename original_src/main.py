"""
NetTrace — Premium Flet Dashboard
=================================
Real-desktop-app style dashboard with sidebar navigation, live charts,
animated stat cards, toast notifications, and theme toggle.
Professional dark theme — muted icon tiles, single accent color,
subtle borders. No rainbow colors.
Run:  python main.py   (needs admin/root for packet capture)
"""
from __future__ import annotations
import math
import threading
import time
import flet as ft
import config
import database as db
from analyzer import TrafficAnalyzer
from report_html import generate_html_report
from report_pdf import generate_pdf_report
from scanner import PacketScanner
from utils import open_path
# ═══════════════════════════════════════════════════════════════
#  THEME  —  Professional slate palette
# ═══════════════════════════════════════════════════════════════
class Theme:
    """Centralised professional palette — dark slate + muted accents."""
    # Backgrounds
    BG          = "#0B1120"
    BG_ALT      = "#0F172A"
    SIDEBAR     = "#080D1A"
    CARD        = "#131C2E"
    CARD_HOVER  = "#1A2438"
    TILE        = "#1E293B"          # icon tile background
    TILE_HOVER  = "#26344A"
    # Borders
    BORDER      = "#1F2A3D"
    BORDER_SOFT = "#182236"
    # Text
    TEXT        = "#E2E8F0"
    TEXT_MUTED  = "#94A3B8"
    TEXT_DIM    = "#64748B"
    # Single primary accent (cyan) + semantic muted tones
    ACCENT      = "#22D3EE"
    ACCENT_SOFT = "#0E7490"
    SUCCESS     = "#34D399"
    WARNING     = "#FBBF24"
    DANGER      = "#F87171"
    INFO        = "#60A5FA"
    PURPLE      = "#A78BFA"
    # Tint backgrounds for icon tiles (subtle, low-opacity feel)
    TINT_ACCENT     = "#0E3A47"
    TINT_SUCCESS    = "#0D3B32"
    TINT_WARNING    = "#3D2E0D"
    TINT_DANGER     = "#3D1A1A"
    TINT_INFO       = "#0F2742"
    TINT_PURPLE     = "#2A1F45"
# ═══════════════════════════════════════════════════════════════
#  MAIN APP
# ═══════════════════════════════════════════════════════════════
def main(page: ft.Page) -> None:
    """Entry point for the NetTrace Flet dashboard."""
    # ─── Page config ────────────────────────────────────────
    page.title = config.APP_TITLE
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = Theme.BG
    page.padding = 0
    page.spacing = 0
    page.window_width = 1400
    page.window_height = 900
    page.window_min_width = 1100
    page.window_min_height = 700
    db.init_db()
    analyzer = TrafficAnalyzer()
    scanner = PacketScanner(callback=lambda info: _on_packet(info))
    state: dict = {
        "packets": [],
        "alerts": [],
        "capturing": False,
        "pulse": 0.0,
        "view": "dashboard",
    }
    lock = threading.Lock()
    # ─── Content / sidebar / status bar ─────────────────────
    content_area = ft.Container(expand=True, padding=24)
    sidebar = _build_sidebar(state)
    status_bar = _build_status_bar()
    # ─── Stat cards ─────────────────────────────────────────
    stat_total = _stat_card(
        "Total Packets", "0", ft.icons.LAYERS_ROUNDED,
        Theme.ACCENT, Theme.TINT_ACCENT,
    )
    stat_known = _stat_card(
        "Known", "0", ft.icons.VERIFIED_ROUNDED,
        Theme.SUCCESS, Theme.TINT_SUCCESS,
    )
    stat_unknown = _stat_card(
        "Unknown", "0", ft.icons.HELP_OUTLINE_ROUNDED,
        Theme.WARNING, Theme.TINT_WARNING,
    )
    stat_suspicious = _stat_card(
        "Suspicious", "0", ft.icons.WARNING_AMBER_ROUNDED,
        Theme.DANGER, Theme.TINT_DANGER,
    )
    stats_row = ft.Row(
        [stat_total, stat_known, stat_unknown, stat_suspicious],
        spacing=14,
    )
    # ─── LIVE indicator ─────────────────────────────────────
    live_dot = ft.Container(
        width=8, height=8,
        border_radius=4,
        bgcolor=Theme.TEXT_DIM,
        opacity=1.0,
        animate_opacity=ft.animation.Animation(400,
                                               ft.AnimationCurve.EASE_IN_OUT),
    )
    live_text = ft.Text("IDLE", color=Theme.TEXT_MUTED,
                        size=10, weight=ft.FontWeight.BOLD)
    # ─── Charts ─────────────────────────────────────────────
    traffic_chart = _build_traffic_chart()
    protocol_chart = _build_protocol_bars()
    # ─── Lists ──────────────────────────────────────────────
    packets_list = ft.ListView(expand=True, spacing=6, auto_scroll=False)
    alerts_list = ft.ListView(expand=True, spacing=6, auto_scroll=False)
    # ─── Handlers ───────────────────────────────────────────
    def start_capture(e: ft.ControlEvent | None = None) -> None:
        """Start the packet scanner thread."""
        try:
            if state["capturing"]:
                return
            scanner.start()
            state["capturing"] = True
            live_text.value = "LIVE"
            live_text.color = Theme.SUCCESS
            live_dot.bgcolor = Theme.SUCCESS
            _toast(page, "Capture started — monitoring traffic",
                   Theme.SUCCESS, ft.icons.PLAY_ARROW_ROUNDED)
        except Exception as exc:
            _toast(page, f"Failed to start: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
        page.update()
    def stop_capture(e: ft.ControlEvent | None = None) -> None:
        """Stop the packet scanner thread."""
        try:
            scanner.stop()
            state["capturing"] = False
            live_text.value = "IDLE"
            live_text.color = Theme.TEXT_MUTED
            live_dot.bgcolor = Theme.TEXT_DIM
            live_dot.opacity = 1.0
            _toast(page, "Capture stopped", Theme.WARNING,
                   ft.icons.STOP_ROUNDED)
        except Exception as exc:
            _toast(page, f"Stop failed: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
        page.update()
    def refresh_data(e: ft.ControlEvent | None = None) -> None:
        """Reload data from the DB and refresh the UI."""
        try:
            _load_recent(state, lock)
            _render_lists(packets_list, alerts_list, state, lock)
            _update_stats(stat_total, stat_known, stat_unknown, stat_suspicious)
            _update_charts(traffic_chart, protocol_chart)
            _toast(page, "Data refreshed", Theme.INFO,
                   ft.icons.REFRESH_ROUNDED)
        except Exception as exc:
            _toast(page, f"Refresh failed: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
        page.update()
    def make_pdf(e: ft.ControlEvent | None = None) -> None:
        """Generate a PDF report."""
        try:
            path = generate_pdf_report()
            _toast(page, f"PDF saved: {_basename(path)}",
                   Theme.SUCCESS, ft.icons.PICTURE_AS_PDF_ROUNDED)
        except Exception as exc:
            _toast(page, f"PDF failed: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
    def make_html(e: ft.ControlEvent | None = None) -> None:
        """Generate an HTML report."""
        try:
            path = generate_html_report()
            _toast(page, f"HTML saved: {_basename(path)}",
                   Theme.SUCCESS, ft.icons.LANGUAGE_ROUNDED)
        except Exception as exc:
            _toast(page, f"HTML failed: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
    def open_reports(e: ft.ControlEvent | None = None) -> None:
        """Open the reports folder in the OS file manager."""
        try:
            open_path(config.REPORT_DIR)
            _toast(page, "Reports folder opened", Theme.INFO,
                   ft.icons.FOLDER_OPEN_ROUNDED)
        except Exception as exc:
            _toast(page, f"Open failed: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
    def reset_db(e: ft.ControlEvent | None = None) -> None:
        """Wipe all DB tables and reset the UI state."""
        try:
            db.clear_all()
            with lock:
                state["packets"].clear()
                state["alerts"].clear()
            packets_list.controls.clear()
            alerts_list.controls.clear()
            _update_stats(stat_total, stat_known, stat_unknown, stat_suspicious)
            _update_charts(traffic_chart, protocol_chart)
            _toast(page, "Database reset", Theme.WARNING,
                   ft.icons.DELETE_SWEEP_ROUNDED)
        except Exception as exc:
            _toast(page, f"Reset failed: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
        page.update()
    # ─── View switcher ──────────────────────────────────────
    def render_view(view: str) -> None:
        """Swap the content area to the requested view."""
        try:
            state["view"] = view
            content_area.content = _build_view(
                view, stats_row, packets_list, alerts_list,
                traffic_chart, protocol_chart,
                make_pdf, make_html, open_reports,
            )
            _highlight_sidebar(sidebar, view)
            page.update()
        except Exception as exc:
            _toast(page, f"View error: {exc}", Theme.DANGER,
                   ft.icons.ERROR_ROUNDED)
    state["handlers"] = {"render_view": render_view}
    # ─── Top action buttons ─────────────────────────────────
    top_actions = ft.Row(
        [
            _action_button("Start", ft.icons.PLAY_ARROW_ROUNDED,
                           Theme.SUCCESS, start_capture),
            _action_button("Stop", ft.icons.STOP_ROUNDED,
                           Theme.DANGER, stop_capture),
            _action_button("Refresh", ft.icons.REFRESH_ROUNDED,
                           Theme.ACCENT, refresh_data),
            _action_button("PDF", ft.icons.PICTURE_AS_PDF_ROUNDED,
                           Theme.PURPLE, make_pdf),
            _action_button("HTML", ft.icons.LANGUAGE_ROUNDED,
                           Theme.INFO, make_html),
            _action_button("Reports", ft.icons.FOLDER_OPEN_ROUNDED,
                           Theme.WARNING, open_reports),
            _action_button("Reset", ft.icons.DELETE_SWEEP_ROUNDED,
                           Theme.TEXT_MUTED, reset_db),
        ],
        spacing=8,
    )
    header = _build_header(top_actions, live_dot, live_text)
    # ─── Packet callback ────────────────────────────────────
    def _on_packet(packet_info: dict) -> None:
        """Handle a packet emitted by the scanner thread."""
        try:
            record = analyzer.analyze(packet_info)
            with lock:
                state["packets"].insert(0, record)
                state["packets"] = state["packets"][:config.UI_MAX_ROWS]
                if record.classification != config.CLASS_KNOWN:
                    state["alerts"].insert(0, {
                        "time": record.timestamp,
                        "severity": ("HIGH"
                                     if record.classification
                                     == config.CLASS_SUSPICIOUS
                                     else "MEDIUM"),
                        "msg": (f"{record.src_ip} → {record.dst_ip}:"
                                f"{record.dst_port}/{record.protocol}  "
                                f"{record.reason}"),
                    })
                    state["alerts"] = state["alerts"][:config.UI_MAX_ROWS]
        except Exception:
            pass
    # ─── Layout skeleton ────────────────────────────────────
    page.add(
        ft.Column(
            [
                header,
                ft.Row(
                    [
                        sidebar,
                        ft.Column(
                            [content_area, status_bar],
                            expand=True, spacing=0,
                        ),
                    ],
                    expand=True, spacing=0,
                ),
            ],
            expand=True, spacing=0,
        )
    )
    # ─── Boot ───────────────────────────────────────────────
    _load_recent(state, lock)
    _render_lists(packets_list, alerts_list, state, lock)
    _update_stats(stat_total, stat_known, stat_unknown, stat_suspicious)
    _update_charts(traffic_chart, protocol_chart)
    render_view("dashboard")
    # ─── Live refresh loop ──────────────────────────────────
    def _ticker() -> None:
        """Background loop for animations + periodic UI updates."""
        counter = 0
        while True:
            time.sleep(config.UI_REFRESH_INTERVAL)
            counter += 1
            try:
                if state["capturing"]:
                    state["pulse"] = (state["pulse"] + 0.5) % 2.0
                    alpha = 0.4 + 0.6 * abs(math.sin(state["pulse"] * math.pi))
                    try:
                        live_dot.opacity = alpha
                    except Exception:
                        pass
                _render_lists(packets_list, alerts_list, state, lock)
                if counter % 2 == 0:
                    _update_stats(stat_total, stat_known,
                                  stat_unknown, stat_suspicious)
                    _update_charts(traffic_chart, protocol_chart)
                page.update()
            except Exception:
                pass
    threading.Thread(target=_ticker, daemon=True).start()
# ═══════════════════════════════════════════════════════════════
#  HEADER / SIDEBAR / STATUS BAR
# ═══════════════════════════════════════════════════════════════
def _build_header(top_actions: ft.Row,
                  live_dot: ft.Container,
                  live_text: ft.Text) -> ft.Container:
    """Top header bar with logo tile, actions, and live badge."""
    # Logo icon tile — professional dark tile with cyan tint
    logo_tile = ft.Container(
        content=ft.Icon(ft.icons.SHIELD_ROUNDED, size=20,
                        color=Theme.ACCENT),
        width=40, height=40,
        bgcolor=Theme.TINT_ACCENT,
        border_radius=10,
        border=ft.border.all(1, Theme.BORDER),
        alignment=ft.alignment.center,
    )
    logo = ft.Row(
        [
            logo_tile,
            ft.Column(
                [
                    ft.Text("NetTrace", size=16, weight=ft.FontWeight.BOLD,
                            color=Theme.TEXT),
                    ft.Text(config.APP_SUBTITLE, size=10,
                            color=Theme.TEXT_MUTED),
                ],
                spacing=0,
            ),
        ],
        spacing=12,
    )
    badge = _live_badge(live_dot, live_text)
    row = ft.Row(
        [
            logo,
            ft.Container(expand=True),
            top_actions,
            ft.Container(width=12),
            badge,
        ],
        spacing=0,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )
    return ft.Container(
        content=row,
        padding=ft.padding.symmetric(horizontal=20, vertical=12),
        bgcolor=Theme.SIDEBAR,
        border=ft.border.only(bottom=ft.BorderSide(1, Theme.BORDER)),
    )
def _live_badge(dot: ft.Container, label: ft.Text) -> ft.Container:
    """Professional LIVE badge — dark pill with small status dot."""
    return ft.Container(
        content=ft.Row([dot, label], spacing=8),
        padding=ft.padding.symmetric(horizontal=12, vertical=6),
        bgcolor=Theme.TILE,
        border_radius=20,
        border=ft.border.all(1, Theme.BORDER),
    )
def _build_sidebar(state: dict) -> ft.Container:
    """Left navigation sidebar with icon tiles + labels."""
    items = [
        ("dashboard", ft.icons.DASHBOARD_ROUNDED, "Dashboard"),
        ("traffic",   ft.icons.SWAP_VERT_ROUNDED, "Live Traffic"),
        ("alerts",    ft.icons.NOTIFICATIONS_ACTIVE_ROUNDED, "Alerts"),
        ("baseline",  ft.icons.INSIGHTS_ROUNDED, "Baseline"),
        ("reports",   ft.icons.DESCRIPTION_ROUNDED, "Reports"),
    ]
    # Small brand label at top
    brand = ft.Container(
        content=ft.Text("NAVIGATION", size=9, weight=ft.FontWeight.BOLD,
                        color=Theme.TEXT_DIM),
        padding=ft.padding.only(left=12, top=6, bottom=10),
    )
    controls = [brand]
    for key, icon, label in items:
        controls.append(_sidebar_item(key, icon, label, state))
        controls.append(ft.Container(height=4))
    return ft.Container(
        content=ft.Column(controls, spacing=0),
        width=230,
        bgcolor=Theme.SIDEBAR,
        padding=ft.padding.symmetric(horizontal=12, vertical=20),
        border=ft.border.only(right=ft.BorderSide(1, Theme.BORDER)),
    )
def _sidebar_item(key: str, icon: str, label: str, state: dict) -> ft.Container:
    """A single sidebar navigation item with professional icon tile."""
    is_active = state.get("view") == key
    # Icon tile — muted background, subtle border, accent when active
    icon_tile = ft.Container(
        content=ft.Icon(
            icon, size=16,
            color=Theme.ACCENT if is_active else Theme.TEXT_MUTED,
        ),
        width=32, height=32,
        bgcolor=Theme.TINT_ACCENT if is_active else Theme.TILE,
        border_radius=8,
        border=ft.border.all(1, Theme.BORDER),
        alignment=ft.alignment.center,
    )
    label_text = ft.Text(
        label, size=12,
        color=Theme.TEXT if is_active else Theme.TEXT_MUTED,
        weight=ft.FontWeight.W_600 if is_active else ft.FontWeight.W_500,
    )
    container = ft.Container(
        content=ft.Row([icon_tile, label_text], spacing=12),
        padding=ft.padding.symmetric(horizontal=8, vertical=6),
        border_radius=10,
        bgcolor=Theme.CARD if is_active else None,
        border=ft.border.all(
            1, Theme.BORDER if is_active else "#00000000"
        ),
        ink=True,
    )
    container.data = {"key": key, "tile": icon_tile, "label": label_text}
    def on_click(e: ft.ControlEvent) -> None:
        try:
            state["handlers"]["render_view"](key)
        except Exception:
            pass
    def on_hover(e: ft.ControlEvent) -> None:
        if state.get("view") != key:
            try:
                e.control.bgcolor = (Theme.CARD_HOVER
                                     if e.data == "true" else None)
                e.control.update()
            except Exception:
                pass
    container.on_click = on_click
    container.on_hover = on_hover
    return container
def _highlight_sidebar(sidebar: ft.Container, active_key: str) -> None:
    """Update highlight colours on all sidebar items."""
    try:
        for ctrl in sidebar.content.controls:
            if not isinstance(ctrl, ft.Container) or not ctrl.data:
                continue
            key = ctrl.data.get("key")
            if key is None:
                continue
            is_active = (key == active_key)
            ctrl.bgcolor = Theme.CARD if is_active else None
            ctrl.border = ft.border.all(
                1, Theme.BORDER if is_active else "#00000000"
            )
            tile = ctrl.data.get("tile")
            label = ctrl.data.get("label")
            if tile is not None:
                tile.bgcolor = (Theme.TINT_ACCENT if is_active
                                else Theme.TILE)
                tile.content.color = (Theme.ACCENT if is_active
                                      else Theme.TEXT_MUTED)
            if label is not None:
                label.color = Theme.TEXT if is_active else Theme.TEXT_MUTED
                label.weight = (ft.FontWeight.W_600 if is_active
                                else ft.FontWeight.W_500)
    except Exception:
        pass
def _build_status_bar() -> ft.Container:
    """Footer status bar."""
    return ft.Container(
        content=ft.Row(
            [
                ft.Text(f"v{config.APP_VERSION}", size=11,
                        color=Theme.TEXT_DIM),
                ft.Container(expand=True),
                ft.Text("Educational use only", size=11,
                        color=Theme.TEXT_DIM),
            ],
        ),
        padding=ft.padding.symmetric(horizontal=24, vertical=8),
        bgcolor=Theme.SIDEBAR,
        border=ft.border.only(top=ft.BorderSide(1, Theme.BORDER)),
    )
# ═══════════════════════════════════════════════════════════════
#  VIEWS
# ═══════════════════════════════════════════════════════════════
def _build_view(view: str, stats_row, packets_list, alerts_list,
                traffic_chart, protocol_chart,
                make_pdf=None, make_html=None, open_reports=None):
    """Return the content widget for a given view key."""
    if view == "dashboard":
        return ft.Column(
            [
                _page_title("Dashboard",
                            "Real-time overview of network traffic"),
                ft.Container(height=16),
                stats_row,
                ft.Container(height=16),
                ft.Row(
                    [
                        _panel("Traffic Rate (last 60s)",
                               _wrap_chart(traffic_chart), flex=3),
                        ft.Container(width=16),
                        _panel("Protocol Distribution",
                               _wrap_chart(protocol_chart), flex=2),
                    ],
                    vertical_alignment=ft.CrossAxisAlignment.START,
                ),
                ft.Container(height=16),
                ft.Row(
                    [
                        _panel("Recent Traffic",
                               _wrap_list(packets_list), flex=1),
                        ft.Container(width=16),
                        _panel("Security Alerts",
                               _wrap_list(alerts_list), flex=1),
                    ],
                    vertical_alignment=ft.CrossAxisAlignment.START,
                ),
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=0,
        )
    if view == "traffic":
        return ft.Column(
            [
                _page_title("Live Traffic",
                            "Full stream of captured packets"),
                ft.Container(height=16),
                _panel("All Packets", _wrap_list(packets_list, height=620)),
            ],
            scroll=ft.ScrollMode.AUTO,
        )
    if view == "alerts":
        return ft.Column(
            [
                _page_title("Security Alerts",
                            "Unknown & suspicious packet notifications"),
                ft.Container(height=16),
                _panel("Alert Feed", _wrap_list(alerts_list, height=620)),
            ],
            scroll=ft.ScrollMode.AUTO,
        )
    if view == "baseline":
        baseline_table = _build_baseline_table()
        return ft.Column(
            [
                _page_title("Learned Baseline",
                            "Per-port statistical profiles"),
                ft.Container(height=16),
                _panel("Baseline Entries", baseline_table, height=620),
            ],
            scroll=ft.ScrollMode.AUTO,
        )
    if view == "reports":
        # Reports view — intentionally simple and compatibility-friendly.
        # The three cards are real clickable controls.
        report_cards = ft.Row(
            controls=[
                _report_card(
                    "PDF Report",
                    "Professional A4 layout",
                    ft.icons.PICTURE_AS_PDF_ROUNDED,
                    Theme.DANGER,
                    Theme.TINT_DANGER,
                    make_pdf,
                ),
                _report_card(
                    "HTML Report",
                    "Shareable web version",
                    ft.icons.LANGUAGE_ROUNDED,
                    Theme.INFO,
                    Theme.TINT_INFO,
                    make_html,
                ),
                _report_card(
                    "Open Folder",
                    "Browse saved reports",
                    ft.icons.FOLDER_OPEN_ROUNDED,
                    Theme.WARNING,
                    Theme.TINT_WARNING,
                    open_reports,
                ),
            ],
            spacing=16,
        )
        return ft.Column(
            controls=[
                _page_title("Reports", "Generate and export security reports"),
                ft.Container(height=16),
                report_cards,
            ],
            spacing=0,
            scroll=ft.ScrollMode.AUTO,
        )
    return ft.Text("Unknown view", color=Theme.TEXT)
def _page_title(title: str, subtitle: str) -> ft.Column:
    """Page title block."""
    return ft.Column(
        [
            ft.Text(title, size=22, weight=ft.FontWeight.BOLD,
                    color=Theme.TEXT),
            ft.Text(subtitle, size=12, color=Theme.TEXT_MUTED),
        ],
        spacing=2,
    )
def _panel(title: str, body: ft.Control, height: int | None = None,
           flex: int = 0) -> ft.Container:
    """Card-styled panel with title."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text(title, size=12, weight=ft.FontWeight.W_600,
                        color=Theme.TEXT_MUTED),
                ft.Container(height=10),
                body,
            ],
            spacing=0,
        ),
        bgcolor=Theme.CARD,
        border_radius=14,
        padding=18,
        border=ft.border.all(1, Theme.BORDER),
        height=height,
        expand=(flex > 0),
    )
# ═══════════════════════════════════════════════════════════════
#  STAT CARDS  —  Dark glass tiles with colored accent icon
# ═══════════════════════════════════════════════════════════════
def _stat_card(label: str, value: str, icon: str,
               accent: str, tint: str) -> ft.Container:
    """Professional stat card — dark surface, colored icon tile, thin
    accent line on the left edge."""
    value_text = ft.Text(value, size=28, weight=ft.FontWeight.BOLD,
                         color=Theme.TEXT)
    icon_tile = ft.Container(
        content=ft.Icon(icon, size=16, color=accent),
        width=36, height=36,
        bgcolor=tint,
        border_radius=10,
        border=ft.border.all(1, Theme.BORDER),
        alignment=ft.alignment.center,
    )
    card = ft.Container(
        content=ft.Row(
            [
                # Left accent bar
                ft.Container(width=3, bgcolor=accent, border_radius=2,
                             height=52),
                ft.Container(width=12),
                ft.Column(
                    [
                        ft.Text(label, size=11, color=Theme.TEXT_MUTED,
                                weight=ft.FontWeight.W_500),
                        ft.Container(height=4),
                        value_text,
                    ],
                    spacing=0, expand=True,
                ),
                icon_tile,
            ],
            spacing=0,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        padding=16,
        border_radius=14,
        bgcolor=Theme.CARD,
        border=ft.border.all(1, Theme.BORDER),
        expand=True,
        data=value_text,
        animate_scale=ft.animation.Animation(180, ft.AnimationCurve.EASE_OUT),
        animate=ft.animation.Animation(200, ft.AnimationCurve.EASE_OUT),
    )
    def on_hover(e: ft.ControlEvent) -> None:
        try:
            if e.data == "true":
                card.scale = 1.02
                card.bgcolor = Theme.CARD_HOVER
                card.shadow = ft.BoxShadow(
                    blur_radius=20, spread_radius=0,
                    color="#00000055",
                    offset=ft.Offset(0, 4),
                )
            else:
                card.scale = 1.0
                card.bgcolor = Theme.CARD
                card.shadow = None
            card.update()
        except Exception:
            pass
    card.on_hover = on_hover
    return card
def _set_card(card: ft.Container, value: str) -> None:
    """Update a stat card's numeric value."""
    try:
        card.data.value = value
    except Exception:
        pass
def _update_stats(c1, c2, c3, c4) -> None:
    """Refresh all stat cards from DB."""
    try:
        total, unknown, suspicious = db.get_packet_stats()
        known = total - unknown - suspicious
        _set_card(c1, str(total))
        _set_card(c2, str(known))
        _set_card(c3, str(unknown))
        _set_card(c4, str(suspicious))
    except Exception:
        pass
# ═══════════════════════════════════════════════════════════════
#  CHARTS
# ═══════════════════════════════════════════════════════════════
def _build_traffic_chart() -> ft.Column:
    """Build a bar-chart widget for traffic rate."""
    return ft.Column(spacing=8)
def _update_charts(traffic_chart: ft.Column,
                   protocol_chart: ft.Column) -> None:
    """Refresh both charts from DB."""
    try:
        _update_traffic_chart(traffic_chart)
        _update_protocol_chart(protocol_chart)
    except Exception:
        pass
def _update_traffic_chart(chart: ft.Column) -> None:
    """Simple traffic bar chart from recent packets."""
    packets = db.get_recent_packets(60)
    if not packets:
        chart.controls = [ft.Text("Waiting for data…", size=12,
                                  color=Theme.TEXT_MUTED)]
        return
    groups = {"KNOWN": 0, "UNKNOWN": 0, "SUSPICIOUS": 0}
    for p in packets:
        groups[p.classification] = groups.get(p.classification, 0) + 1
    total = max(1, sum(groups.values()))
    new_controls = []
    for label, count in groups.items():
        pct = count / total
        color = (Theme.SUCCESS if label == "KNOWN"
                 else Theme.WARNING if label == "UNKNOWN"
                 else Theme.DANGER)
        bar = ft.Container(
            bgcolor=color, border_radius=4,
            width=max(4, int(pct * 260)), height=6,
            animate=ft.animation.Animation(400, ft.AnimationCurve.EASE_OUT),
        )
        new_controls.append(
            ft.Column(
                [
                    ft.Row(
                        [
                            ft.Text(label, size=11, color=Theme.TEXT_MUTED),
                            ft.Container(expand=True),
                            ft.Text(f"{count}", size=12,
                                    weight=ft.FontWeight.BOLD,
                                    color=Theme.TEXT),
                        ],
                    ),
                    ft.Container(
                        content=bar,
                        bgcolor=Theme.BG_ALT,
                        border_radius=4,
                        height=6,
                    ),
                ],
                spacing=4,
            )
        )
    new_controls.append(ft.Container(height=4))
    new_controls.append(
        ft.Text(f"{total} packets in view", size=10,
                color=Theme.TEXT_DIM)
    )
    chart.controls = new_controls
def _build_protocol_bars() -> ft.Column:
    """Build protocol distribution widget."""
    return ft.Column(spacing=10)
def _update_protocol_chart(chart: ft.Column) -> None:
    """Refresh protocol distribution bars."""
    stats = db.get_protocol_stats()
    if not stats:
        chart.controls = [ft.Text("No protocol data", size=12,
                                  color=Theme.TEXT_MUTED)]
        return
    # Muted but distinct palette
    palette = [Theme.ACCENT, Theme.PURPLE, Theme.WARNING,
               Theme.SUCCESS, Theme.INFO, Theme.DANGER]
    total = max(1, sum(c for _, c in stats))
    controls = []
    for i, (proto, count) in enumerate(stats[:6]):
        pct = count / total
        color = palette[i % len(palette)]
        controls.append(
            ft.Column(
                [
                    ft.Row(
                        [
                            ft.Container(width=8, height=8,
                                         bgcolor=color, border_radius=2),
                            ft.Text(proto, size=11, color=Theme.TEXT),
                            ft.Container(expand=True),
                            ft.Text(f"{int(pct * 100)}%", size=11,
                                    color=Theme.TEXT_MUTED),
                        ],
                    ),
                    ft.Container(
                        content=ft.Container(
                            bgcolor=color, border_radius=4,
                            width=max(4, int(pct * 200)), height=6,
                            animate=ft.animation.Animation(
                                400, ft.AnimationCurve.EASE_OUT),
                        ),
                        bgcolor=Theme.BG_ALT, border_radius=4, height=6,
                    ),
                ],
                spacing=4,
            )
        )
    chart.controls = controls
# ═══════════════════════════════════════════════════════════════
#  LISTS
# ═══════════════════════════════════════════════════════════════
def _wrap_list(lv: ft.ListView, height: int = 340) -> ft.Container:
    """Wrap a ListView in a fixed-height container."""
    return ft.Container(content=lv, height=height)
def _wrap_chart(chart: ft.Column) -> ft.Container:
    """Wrap a chart in a fixed-height container."""
    return ft.Container(content=chart, height=160)
def _load_recent(state: dict, lock: threading.Lock) -> None:
    """Seed UI state from DB on startup."""
    try:
        with lock:
            if not state["packets"]:
                state["packets"] = db.get_recent_packets(config.UI_MAX_ROWS)
            if not state["alerts"]:
                for a in db.get_recent_alerts(config.UI_MAX_ROWS):
                    state["alerts"].append({
                        "time": a.timestamp, "severity": a.severity,
                        "msg": a.message,
                    })
    except Exception:
        pass
def _render_lists(packets_list: ft.ListView, alerts_list: ft.ListView,
                  state: dict, lock: threading.Lock) -> None:
    """Re-render the packet & alert lists from state."""
    with lock:
        packets = list(state["packets"])
        alerts = list(state["alerts"])
    new_packets = [_packet_row(p) for p in packets]
    if len(packets_list.controls) != len(new_packets):
        packets_list.controls = new_packets
    new_alerts = [_alert_row(a) for a in alerts]
    if len(alerts_list.controls) != len(new_alerts):
        alerts_list.controls = new_alerts
def _packet_row(p) -> ft.Container:
    """Build a single packet row container with professional icon tile."""
    if p.classification == config.CLASS_SUSPICIOUS:
        accent, tint = Theme.DANGER, Theme.TINT_DANGER
    elif p.classification == config.CLASS_UNKNOWN:
        accent, tint = Theme.WARNING, Theme.TINT_WARNING
    else:
        accent, tint = Theme.SUCCESS, Theme.TINT_SUCCESS
    ts = p.timestamp.split(" ")[-1] if " " in p.timestamp else p.timestamp
    icon_tile = ft.Container(
        content=ft.Icon(ft.icons.SWAP_VERT_ROUNDED, size=14, color=accent),
        width=30, height=30,
        bgcolor=tint,
        border_radius=8,
        border=ft.border.all(1, Theme.BORDER),
        alignment=ft.alignment.center,
    )
    return ft.Container(
        content=ft.Row(
            [
                icon_tile,
                ft.Column(
                    [
                        ft.Text(f"{p.src_ip}:{p.src_port} → "
                                f"{p.dst_ip}:{p.dst_port}",
                                size=12, color=Theme.TEXT,
                                weight=ft.FontWeight.W_500),
                        ft.Text(f"{ts} · {p.protocol} · "
                                f"{p.length}B · {p.reason}",
                                size=10, color=Theme.TEXT_MUTED),
                    ],
                    spacing=1, expand=True,
                ),
                ft.Container(
                    content=ft.Text(p.classification, size=9,
                                    weight=ft.FontWeight.BOLD,
                                    color=accent),
                    bgcolor=tint,
                    padding=ft.padding.symmetric(horizontal=8, vertical=3),
                    border_radius=8,
                    border=ft.border.all(1, Theme.BORDER),
                ),
            ],
            spacing=10,
        ),
        padding=ft.padding.symmetric(horizontal=10, vertical=8),
        bgcolor=Theme.BG_ALT,
        border_radius=10,
        border=ft.border.all(1, Theme.BORDER_SOFT),
    )
def _alert_row(a: dict) -> ft.Container:
    """Build a single alert row container with professional icon tile."""
    if a["severity"] in ("HIGH", "CRITICAL"):
        accent, tint = Theme.DANGER, Theme.TINT_DANGER
    else:
        accent, tint = Theme.WARNING, Theme.TINT_WARNING
    ts = a["time"].split(" ")[-1] if " " in a["time"] else a["time"]
    icon_tile = ft.Container(
        content=ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, size=14,
                        color=accent),
        width=30, height=30,
        bgcolor=tint,
        border_radius=8,
        border=ft.border.all(1, Theme.BORDER),
        alignment=ft.alignment.center,
    )
    return ft.Container(
        content=ft.Row(
            [
                icon_tile,
                ft.Column(
                    [
                        ft.Text(f"[{a['severity']}]", size=10,
                                color=accent, weight=ft.FontWeight.BOLD),
                        ft.Text(a["msg"], size=11, color=Theme.TEXT),
                        ft.Text(ts, size=9, color=Theme.TEXT_DIM),
                    ],
                    spacing=1, expand=True,
                ),
            ],
            spacing=10,
        ),
        padding=ft.padding.symmetric(horizontal=10, vertical=8),
        bgcolor=Theme.BG_ALT,
        border_radius=10,
        border=ft.border.all(1, Theme.BORDER_SOFT),
    )
# ═══════════════════════════════════════════════════════════════
#  BASELINE TABLE
# ═══════════════════════════════════════════════════════════════
def _build_baseline_table() -> ft.Column:
    """Build baseline table view."""
    entries = db.get_all_baseline()
    if not entries:
        return ft.Column([ft.Text("No baseline entries yet.",
                                  size=12, color=Theme.TEXT_MUTED)])
    header = ft.Row(
        [
            _cell("Port", bold=True, width=80),
            _cell("Proto", bold=True, width=80),
            _cell("Hits", bold=True, width=80),
            _cell("First Seen", bold=True, width=180),
            _cell("Last Seen", bold=True, width=180),
            _cell("Mean Bytes", bold=True, width=120),
        ],
        spacing=0,
    )
    rows = [header,
            ft.Container(height=1, bgcolor=Theme.BORDER)]
    for e in entries[:80]:
        rows.append(
            ft.Row(
                [
                    _cell(str(e.dst_port), width=80),
                    _cell(e.protocol, width=80),
                    _cell(str(e.hit_count), width=80),
                    _cell(e.first_seen, width=180),
                    _cell(e.last_seen, width=180),
                    _cell(f"{e.mean_bytes():.0f}", width=120),
                ],
                spacing=0,
            )
        )
        rows.append(ft.Container(height=1, bgcolor=Theme.BORDER_SOFT))
    return ft.Column(rows, spacing=0, scroll=ft.ScrollMode.AUTO)
def _cell(text: str, bold: bool = False, width: int = 100) -> ft.Container:
    """A table cell."""
    return ft.Container(
        content=ft.Text(text, size=11,
                        color=Theme.TEXT if bold else Theme.TEXT_MUTED,
                        weight=(ft.FontWeight.BOLD if bold
                                else ft.FontWeight.NORMAL)),
        width=width,
        padding=ft.padding.symmetric(horizontal=6, vertical=8),
    )
# ═══════════════════════════════════════════════════════════════
#  BUTTONS & NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════
def _action_button(label: str, icon: str, color: str,
                   handler) -> ft.Container:
    """Professional dark pill button with colored icon and left accent."""
    icon_widget = ft.Icon(icon, size=14, color=color)
    container = ft.Container(
        content=ft.Row(
            [
                icon_widget,
                ft.Text(label, size=11, color=Theme.TEXT,
                        weight=ft.FontWeight.W_500),
            ],
            spacing=6, tight=True,
        ),
        padding=ft.padding.symmetric(horizontal=12, vertical=8),
        bgcolor=Theme.TILE,
        border_radius=9,
        border=ft.border.all(1, Theme.BORDER),
        ink=True,
        animate_scale=ft.animation.Animation(140, ft.AnimationCurve.EASE_OUT),
        on_click=lambda e: handler(),
    )
    def on_hover(e: ft.ControlEvent) -> None:
        try:
            if e.data == "true":
                container.scale = 1.04
                container.bgcolor = Theme.TILE_HOVER
                container.border = ft.border.all(1, color)
                container.shadow = ft.BoxShadow(
                    blur_radius=10, color=f"{color}33",
                )
            else:
                container.scale = 1.0
                container.bgcolor = Theme.TILE
                container.border = ft.border.all(1, Theme.BORDER)
                container.shadow = None
            container.update()
        except Exception:
            pass
    container.on_hover = on_hover
    return container
def _toast(page: ft.Page, message: str, color: str, icon: str) -> None:
    """Show a floating toast notification."""
    try:
        snack = ft.SnackBar(
            content=ft.Row(
                [ft.Icon(icon, color=Theme.TEXT, size=16),
                 ft.Text(message, color=Theme.TEXT, size=12)],
                spacing=10,
            ),
            bgcolor=Theme.CARD,
            duration=2500,
            behavior=ft.SnackBarBehavior.FLOATING,
            margin=ft.margin.only(bottom=20, right=20, left=20),
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.overlay.append(snack)
        snack.open = True
        page.update()
    except Exception:
        pass
def _report_card(title: str, subtitle: str, icon: str,
                 accent: str, tint: str, handler=None) -> ft.Container:
    """Clickable report card with broad Flet-version compatibility."""
    icon_tile = ft.Container(
        content=ft.Icon(icon, size=24, color=accent),
        width=52,
        height=52,
        bgcolor=tint,
        border_radius=14,
        border=ft.border.all(1, Theme.BORDER),
        alignment=ft.alignment.center,
    )
    card = ft.Container(
        content=ft.Column(
            controls=[
                icon_tile,
                ft.Container(height=14),
                ft.Text(title, size=14, weight=ft.FontWeight.W_600,
                        color=Theme.TEXT),
                ft.Container(height=2),
                ft.Text(subtitle, size=11, color=Theme.TEXT_MUTED),
            ],
            spacing=0,
        ),
        padding=20,
        width=220,
        height=170,
        bgcolor=Theme.CARD,
        border_radius=14,
        border=ft.border.all(1, Theme.BORDER),
        ink=True,
    )
    # Assign the callback after creation to avoid constructor/event-version issues.
    if handler is not None:
        card.on_click = handler
    def on_hover(e: ft.ControlEvent) -> None:
        try:
            if e.data == "true":
                card.scale = 1.03
                card.bgcolor = Theme.CARD_HOVER
                card.border = ft.border.all(1, accent)
                card.shadow = ft.BoxShadow(
                    blur_radius=18, color=f"{accent}33",
                    offset=ft.Offset(0, 4),
                )
            else:
                card.scale = 1.0
                card.bgcolor = Theme.CARD
                card.border = ft.border.all(1, Theme.BORDER)
                card.shadow = None
            card.update()
        except Exception:
            pass
    card.on_hover = on_hover
    return card
def _basename(path: str) -> str:
    """Return the file name portion of a path."""
    try:
        return path.replace("\\", "/").rstrip("/").split("/")[-1]
    except Exception:
        return path
# ═══════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    ft.app(target=main)
