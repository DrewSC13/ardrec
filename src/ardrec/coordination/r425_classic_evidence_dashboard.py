"""R42.5: reutiliza el monitor R38; incorpora R42.2/R42.3 sin autoridad operacional.

Solo representación. Los recibos se autentican por R42.4 antes de entregar el
bundle. Nunca se consulta el huésped ni se ejecutan procesos de prueba aquí.
"""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

from ardrec.coordination import dashboard_tui as r38
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination import demo_session, development_cycle


class ClassicDashboardError(ValueError):
    """Fuente física o escenario de desarrollo incompatible con R38."""


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ClassicDashboardError(message)


def development_from_bundle(bundle: dict[str, Any], fixture: Path) -> dict[str, Any]:
    """Reconstruye el reporte original verificado para NO perder los detalles R38."""
    r424.verify_bundle(bundle)
    scenario = demo_session.read_fixed_scenario(fixture)
    report = development_cycle.build_development_cycle(scenario)
    development_cycle.verify_development_cycle(report)
    validate_binding(report, bundle)
    return report


def validate_binding(report: dict[str, Any], bundle: dict[str, Any]) -> None:
    """Una observación física jamás reemplaza el hash de la sesión sintética."""
    r424.verify_bundle(bundle)
    r38.validate_dashboard_report(report)
    d = bundle['development']
    need(report['session_id'] == d['session_id'] == 'DEV_TUTOR_001' and
         report['sha256'] == d['report_sha256'] and
         report['a10']['stages'] == d['stages'] and
         report['p8_operational'] == 'NO-GO' and
         report['operational_dispatch'] is False and
         report['final_risk'] is None,
         'development_bundle_binding_mismatch')


def physical_rows(bundle: dict[str, Any]) -> list[str]:
    """Etiquetas de procedencia: instantáneas NO son pruebas A5/A6."""
    r424.verify_bundle(bundle)
    p = bundle['physical']
    return [
        'SSH FISICO / NO EN VIVO',
        'RECIBOS: R42.2 + R42.3',
        'RUTA: ' + p['route'],
        'ARP: ' + p['arp'],
        f"ENS3 TX: {p['tx_snapshot']}",
        f"ENS3 RX: {p['rx_snapshot']}",
        f"PCAP TAP: {p['tap_frames_r422']}",
        f"PCAP BRIDGE: {p['bridge_frames_r422']}",
        'PING REPORTADO: 1 TX / 0 RX',
        'AISLAMIENTO: NO PROBADO',
        'PENTEST: NO EJECUTADO',
        'ORIGEN FISICO != A5/A6',
        'SHA R423: ' + p['r423_report_sha256'][:16],
    ]


def render_frame(report: dict[str, Any], bundle: dict[str, Any],
                 state: r38.DashboardState | None = None,
                 width: int = 120, height: int = 32) -> list[str]:
    """Paneles R38 originales; solo sustituye auditoría/detalle por datos sellados."""
    validate_binding(report, bundle)
    if state is None:
        state = r38.DashboardState()
    need(isinstance(state, r38.DashboardState) and
         type(state.selected) is int and 0 <= state.selected < 10,
         'dashboard_state_invalid')
    w = max(24, min(int(width), 240))
    h = max(6, min(int(height), 100))
    frame = r38.render_dashboard_frame(report, state, w, h)
    # No se cambia ni el motor de navegación ni los paneles ALGORITMOS de R38.
    frame[0] = r38._fit(' ARDREC / MONITOR R38  ' + report['session_id'] +
                          '  [DESARROLLO + SSH REAL HISTORICO]', w)
    original_flags = (' P8:NO-GO  DESPACHO:NO  RF:ND  VM:NO  SSH:R42.2/42.3'
                      + f"  VISTA:{report['a10']['stages'][state.selected]['algorithm']}")
    frame[1] = r38._fit(original_flags, w)
    if h < 12 or w < 46 or state.help_open:
        return frame
    obs = physical_rows(bundle)
    panel_height = h - 5
    if w >= 114 and state.show_summary and not state.compact:
        summary_width = 29
        audit = r38._panel(
            'ESTADO / AUDITORIA SSH',
            r38._wrapped(obs + ['','DESARROLLO A1-A10'] + r38.summary_rows(report),
                         summary_width - 4),
            summary_width, panel_height)
        # R38 dispone paneles ALGORITMOS | DETALLE | AUDITORIA. Respetar
        # exactamente sus bordes, incluidas las columnas de resaltado.
        start = w - summary_width
        for index, line in enumerate(audit):
            frame[3 + index] = frame[3 + index][:start] + line
    elif w >= 78 and not state.compact:
        detail_width = w - 35
        detail = r38.detail_rows(report, state.selected)
        if state.show_summary:
            detail = ['SSH HISTORICO, NO A5/A6'] + obs + [''] + detail
        else:
            detail = detail + [''] + obs
        panel = r38._panel(
            report['a10']['stages'][state.selected]['algorithm'] + ' / DETALLE',
            r38._wrapped(detail, detail_width - 4),
            detail_width, panel_height, state.scroll)
        for index, line in enumerate(panel):
            frame[3 + index] = frame[3 + index][:35] + line
    else:
        rows = ([f"ETAPA {report['a10']['stages'][state.selected]['algorithm']}", ''] +
                (r38.summary_rows(report) if state.focus == 'SUMMARY' else
                 r38.detail_rows(report, state.selected)) + [''] + obs)
        panel = r38._panel('R38 / DETALLE + SSH',
                           r38._wrapped(rows, w - 4), w, panel_height, state.scroll)
        frame[3:3 + panel_height] = panel
    need(len(frame) == h and all(len(row) == w for row in frame),
         'layout_geometry_corrupted')
    return frame


def run_tui(report: dict[str, Any], bundle: dict[str, Any]) -> None:
    """Bucle curses de R38: F1-F5, filtros, busca, TAB, selección 1..0."""
    validate_binding(report, bundle)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ClassicDashboardError('tui_requires_interactive_terminal')
    import curses

    def loop(screen: Any) -> None:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.keypad(True)
        colors = False
        if curses.has_colors():
            try:
                curses.start_color()
                curses.use_default_colors()
                curses.init_pair(1, curses.COLOR_CYAN, -1)
                curses.init_pair(2, curses.COLOR_YELLOW, -1)
                curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
                curses.init_pair(4, curses.COLOR_WHITE, -1)
                colors = True
            except curses.error:
                colors = False
        state = r38.DashboardState()
        while True:
            screen.erase()
            rows, cols = screen.getmaxyx()
            frame = render_frame(report, bundle, state, max(24, cols - 1), rows)
            for y, line in enumerate(frame[:rows]):
                attr = (curses.color_pair(4) if colors else 0)
                if colors and y == 0:
                    attr = curses.color_pair(1) | curses.A_BOLD
                elif colors and y == 1:
                    attr = curses.color_pair(2) | curses.A_BOLD
                try:
                    screen.addnstr(y, 0, line, max(0, cols - 1), attr)
                    if colors:
                        span = r38._selected_nav_span(line, state, max(24, cols - 1))
                        if span is not None:
                            left, right = span
                            screen.addnstr(y, left, line[left:right], right - left,
                                           curses.color_pair(3) | curses.A_BOLD)
                except curses.error:
                    pass
            screen.refresh()
            key = r38._key_name(screen.getch(), curses)
            if not state.search_active and not state.help_open and key in ('q', 'Q'):
                return
            state = r38.handle_key(report, state, key)

    curses.wrapper(loop)
