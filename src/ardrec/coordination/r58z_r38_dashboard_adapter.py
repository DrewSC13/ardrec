"""R58-Z-R2: el monitor visual R38 muestra un workspace documental R58-Z.

Solo presentación. `dashboard_tui` R38 es el ÚNICO motor de paneles y
navegación. Ningún dato histórico de red se atribuye a A5/A6/A7/A9.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any
import sys

from ardrec.coordination import dashboard_tui as r38
from ardrec.coordination import r58z_verified_workspace as z


class AdapterError(ValueError):
    """El documento/estado del monitor no es compatible con el contrato."""


def _need(ok: bool, reason: str) -> None:
    if not ok:
        raise AdapterError(reason)


def project_report(doc: dict[str, Any], service_index: int) -> dict[str, Any]:
    """Proyección de SOLO lectura para el motor de navegación R38.

    No es un reporte de desarrollo R26, ni ciclo operacional ni generación A9.
    El identificador es una etiqueta de interfaz derivada del hash documental.
    """
    z.verify_workspace(doc)
    _need(type(service_index) is int and 0 <= service_index < len(z.SERVICES),
          'service_index_invalid')
    group = doc['services'][service_index]
    stages = [dict(
        algorithm=row['algorithm'], status=row['status'],
        source='R58Z_DOCUMENTARY_OBSERVATION_NOT_OPERATIONAL',
        detail=row['detail'],
    ) for row in group['stages']]
    report: dict[str, Any] = {
        'session_id': 'DOCUMENTAL_' + doc['sha256'][:16],
        'sha256': doc['sha256'],
        'session_sha256': doc['sha256'],
        'p8_operational': 'NO-GO',
        'operational_dispatch': False,
        'vm_checks_executed': False,
        'final_risk': None,
        'a10': {'stages': stages},
        'a9': {'published_generation': None,
               'receipt_sha256': 'NO_A9_GENERATION',
               'durable_local_receipt': False},
        'r27': {'a5_state': 'SIN_INICIO', 'a5_start_count': 0,
                'a6_classification': 'ND',
                'selected_actual': None, 'selected_hypothetical': None},
        'r26_units': [],
        'a7': {'hypothetical_rf': 'ND'},
        'a8': {'recommendation': 'NO_APLICADA'},
    }
    r38.validate_dashboard_report(report)
    return report


def physical_audit(doc: dict[str, Any], service_index: int) -> list[str]:
    z.verify_workspace(doc)
    group = doc['services'][service_index]
    rows = [
        'R58-Z / FUENTE R58-Y',
        'SERVICIO: ' + group['service'],
        f"OBSERVACIONES: {group['observation_count']}",
        'TIPO: HISTORICA / DOCUMENTAL',
        'P8: NO-GO',
        'A5: SIN INICIO VINCULADO',
        'A6: ND',
        'A7: Rf NO CONFIRMADO',
        'A9: NO PUBLICADA',
        'SSH/FTPS/SMB: ' + '/'.join(str(g['observation_count'])
                                  for g in doc['services']),
        'SHA DOCUMENTAL:',
        '  ' + doc['sha256'][:20],
    ]
    for obs in group['observations']:
        rows.extend([
            '', 'SSH REAL / NO EN VIVO',
            'RECIBO: ' + obs['record_id'][:18],
            'R42.2: ' + obs['captured_at_utc']['r422'],
            'R42.3: ' + obs['captured_at_utc']['r423'],
            'RUTA: ' + obs['route'],
            'ARP: ' + obs['arp'],
            f"TX: {obs['tx_packets']} RX: {obs['rx_packets']}",
            'AISLAMIENTO: NO ACREDITADO',
        ])
    if not group['observations']:
        rows.extend(['', 'SIN RECIBOS VERIFICADOS', 'No afirmar ausencia de fallos'])
    return rows


def stage_detail(doc: dict[str, Any], service_index: int,
                 stage_index: int) -> list[str]:
    z.verify_workspace(doc)
    _need(type(stage_index) is int and 0 <= stage_index < 10, 'stage_invalid')
    group = doc['services'][service_index]
    row = group['stages'][stage_index]
    lines = [
        f"{row['algorithm']} / {row['status']}",
        row['detail'],
        '',
        'SERVICIO: ' + group['service'],
        f"REGISTROS HISTORICOS: {group['observation_count']}",
        'FUENTE: SQLite R58-Y / R42.2-R42.3',
        'NO ES UNA EJECUCION DE A1-A10',
        'P8: NO-GO  A6: ND  Rf: NO',
        'GEN A9: NO PUBLICADA',
        'SHA DOCUMENTAL:',
        '  ' + doc['sha256'],
    ]
    for obs in group['observations']:
        lines += [
            '', 'OBSERVACION VERIFICADA:',
            obs['record_id'],
            'ORIGEN: ' + obs['origin'],
            'R42.2 UTC: ' + obs['captured_at_utc']['r422'],
            'R42.3 UTC: ' + obs['captured_at_utc']['r423'],
            'R42.2 SHA256: ' + obs['source_r422_sha256'],
            'R42.3 SHA256: ' + obs['source_r423_sha256'],
            'RUTA: ' + obs['route'] + '  ARP: ' + obs['arp'],
            f"TX: {obs['tx_packets']}  RX: {obs['rx_packets']}",
            'NO PRUEBA AISLAMIENTO NI CONDICION A6',
        ]
    if not group['observations']:
        lines += ['', 'NO EXISTEN OBSERVACIONES VERIFICADAS',
                  'NO se infiere ausencia de vulnerabilidades']
    return lines


def render_frame(doc: dict[str, Any], service_index: int,
                 state: r38.DashboardState | None = None,
                 width: int = 120, height: int = 32) -> list[str]:
    """Conserva R38, incluidos 3 paneles, selección y vistas adaptables."""
    report = project_report(doc, service_index)
    if state is None:
        state = r38.DashboardState(selected=9)
    _need(isinstance(state, r38.DashboardState) and
          type(state.selected) is int and 0 <= state.selected < 10,
          'navigation_state_invalid')
    w = max(24, min(int(width), 240))
    h = max(6, min(int(height), 100))
    frame = r38.render_dashboard_frame(report, state, w, h)
    frame[0] = r38._fit(' ARDREC / MONITOR R38 + R58-Z  [SOLO LECTURA]', w)
    frame[1] = r38._fit(
        ' SERVICIO:' + z.SERVICES[service_index] + '  P8:NO-GO'
        + '  A5:SIN INICIO  A6:ND  RF:NO  A9:NO', w)
    if h < 12 or w < 46:
        return frame
    if state.help_open:
        frame[-1] = r38._fit('v/V servicio anterior/siguiente | F1 ayuda | q cerrar', w)
        return frame
    panel_h = h - 5
    rows = stage_detail(doc, service_index, state.selected)
    if w >= 114 and state.show_summary and not state.compact:
        # Conserva el panel R38 de ALGORITMOS y el resaltado en 1..31.
        nav_w, audit_w = 33, 29
        detail_w = w - nav_w - audit_w - 4
        detail_panel = r38._panel(
            report['a10']['stages'][state.selected]['algorithm'] + ' / DETALLE',
            r38._wrapped(rows, detail_w - 4), detail_w, panel_h, state.scroll)
        audit_panel = r38._panel(
            'ESTADO / AUDITORIA',
            r38._wrapped(physical_audit(doc, service_index), audit_w - 4),
            audit_w, panel_h)
        for idx in range(panel_h):
            src = frame[3 + idx]
            frame[3 + idx] = (src[:nav_w+2] + detail_panel[idx]
                              + '  ' + audit_panel[idx])
    elif w >= 78 and not state.compact:
        nav_w = 33
        detail_w = w - nav_w - 2
        full = physical_audit(doc, service_index) + ['', ''] + rows
        detail_panel = r38._panel(
            report['a10']['stages'][state.selected]['algorithm'] + ' / DETALLE',
            r38._wrapped(full if state.show_summary else rows, detail_w - 4),
            detail_w, panel_h, state.scroll)
        for idx in range(panel_h):
            frame[3 + idx] = frame[3 + idx][:nav_w + 2] + detail_panel[idx]
    else:
        full = physical_audit(doc, service_index) if state.focus == 'SUMMARY' else rows
        detail_panel = r38._panel(
            'R38 / DETALLE', r38._wrapped(full, w - 4),
            w, panel_h, state.scroll)
        frame[3:3+panel_h] = detail_panel
    frame[-1] = r38._fit(
        'v/V SERVICIO | 1..9,0 ETAPA | Tab foco | F1-F5 | j/k | q salir', w)
    _need(len(frame) == h and all(len(s) == w for s in frame),
          'r38_frame_geometry_invalid')
    return frame


def handle_event(doc: dict[str, Any], service_index: int,
                 state: r38.DashboardState, key: str) -> tuple[int, r38.DashboardState]:
    """Conserva teclas R38; agrega solamente `v` / `V` para servicio."""
    z.verify_workspace(doc)
    _need(type(service_index) is int and 0 <= service_index < 3 and
          isinstance(state, r38.DashboardState), 'navigation_invalid')
    if not state.search_active and not state.help_open and key in ('v', 'V'):
        direction = 1 if key == 'v' else -1
        return (service_index + direction) % 3, replace(state, scroll=0, query='')
    report = project_report(doc, service_index)
    return service_index, r38.handle_key(report, state, key)


def run_tui(doc: dict[str, Any]) -> None:
    """Mismo renderer y key reducer R38; revalida la instantánea antes de abrir."""
    z.verify_workspace(doc)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise AdapterError('tui_requires_interactive_terminal')
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
        service = 0
        state = r38.DashboardState(selected=9)
        while True:
            screen.erase()
            height, width = screen.getmaxyx()
            fw = max(24, width - 1)
            picture = render_frame(doc, service, state, fw, height)
            for y, line in enumerate(picture[:height]):
                attr = curses.color_pair(4) if colors else 0
                if colors and y == 0:
                    attr = curses.color_pair(1) | curses.A_BOLD
                elif colors and y == 1:
                    attr = curses.color_pair(2) | curses.A_BOLD
                try:
                    screen.addnstr(y, 0, line, max(0, width-1), attr)
                    if colors:
                        span = r38._selected_nav_span(line, state, fw)
                        if span is not None:
                            a, b = span
                            screen.addnstr(y, a, line[a:b], b-a,
                                           curses.color_pair(3) | curses.A_BOLD)
                except curses.error:
                    pass
            screen.refresh()
            key = r38._key_name(screen.getch(), curses)
            if not state.search_active and not state.help_open and key in ('q', 'Q'):
                return
            service, state = handle_event(doc, service, state, key)
    curses.wrapper(loop)
