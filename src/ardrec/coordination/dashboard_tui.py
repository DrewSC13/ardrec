"""P14-R38: monitor TUI curses de solo lectura para el reporte A1-A10.

No ejecuta pruebas, no consulta máquinas ni fuentes externas y no persiste nada.
El tablero usa exclusivamente un reporte de desarrollo previamente verificado.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
import re
import sys
import textwrap
from typing import Any


class DashboardError(ValueError):
    """El reporte o la navegación del monitor no son admisibles."""


@dataclass(frozen=True)
class DashboardState:
    selected: int = 0
    compact: bool = False
    help_open: bool = False
    show_summary: bool = True
    search_active: bool = False
    query: str = ''
    filter_mode: str = 'ALL'  # ALL / PENDING
    focus: str = 'STAGES'  # STAGES / DETAIL / SUMMARY
    scroll: int = 0


def validate_dashboard_report(report: dict[str, Any]) -> None:
    """Fallida-cerrada ante falsas afirmaciones; no recalcula verdad técnica."""
    if type(report) is not dict or type(report.get('a10')) is not dict:
        raise DashboardError('report_schema_invalid')
    stages = report['a10'].get('stages')
    if (type(stages) is not list or len(stages) != 10 or
            [x.get('algorithm') for x in stages if type(x) is dict] !=
            [f'A{i}' for i in range(1, 11)]):
        raise DashboardError('stages_incomplete_or_unordered')
    if any(type(x) is not dict or
           not all(type(x.get(k)) is str for k in ('algorithm', 'source', 'status', 'detail'))
           for x in stages):
        raise DashboardError('stage_fields_invalid')
    if (report.get('p8_operational') != 'NO-GO' or
            report.get('operational_dispatch') is not False or
            report.get('vm_checks_executed') is not False or
            report.get('final_risk') is not None or
            type(report.get('a9')) is not dict or
            report['a9'].get('published_generation') is not None):
        raise DashboardError('false_operational_authority')
    if type(report.get('session_id')) is not str or not report['session_id']:
        raise DashboardError('session_missing')
    if type(report.get('sha256')) is not str or not re.fullmatch(r'[0-9a-f]{64}', report['sha256']):
        raise DashboardError('report_digest_missing')
    if 'a6_import' in report:
        imp = report['a6_import']
        if (type(imp) is not dict or imp.get('admission') != 'ACCEPTED_FOR_DOCUMENTARY_REVIEW' or
                imp.get('classification') != 'ND' or
                report['a10']['stages'][5]['status'] != 'ND_DOCUMENTARY_ACCEPTED'):
            raise DashboardError('import_authority_or_binding_invalid')


def _short(value: Any, length: int = 14) -> str:
    s = 'ND' if value is None else str(value)
    return s if len(s) <= length else s[:length] + '..'


def _flat(value: Any) -> str:
    if value is None:
        return 'NINGUNO'
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    return str(value)


def _filter_match(stage: dict[str, str], index: int, state: DashboardState) -> bool:
    if state.filter_mode == 'PENDING' and index not in (2, 4, 5, 6, 7, 8):
        return False
    if state.query and state.query.casefold() not in ' '.join((
            stage['algorithm'], stage['status'], stage['source'], stage['detail'])).casefold():
        return False
    return True


def visible_indices(report: dict[str, Any], state: DashboardState) -> tuple[int, ...]:
    validate_dashboard_report(report)
    return tuple(i for i, stage in enumerate(report['a10']['stages'])
                 if _filter_match(stage, i, state))


def _navigate_visible(report: dict[str, Any], state: DashboardState, delta: int) -> DashboardState:
    vis = visible_indices(report, state)
    if not vis:
        return state
    if state.selected not in vis:
        return replace(state, selected=vis[0], scroll=0)
    index = vis.index(state.selected)
    return replace(state, selected=vis[(index + delta) % len(vis)], scroll=0)


def handle_key(report: dict[str, Any], state: DashboardState, key: str) -> DashboardState:
    """Reductor puro: ninguna tecla ejecuta A1-A10, red, escritura o despacho."""
    validate_dashboard_report(report)
    if state.search_active:
        if key in ('ENTER', '\n'):
            new = replace(state, search_active=False, scroll=0)
        elif key == 'ESC':
            new = replace(state, search_active=False, query='')
        elif key == 'BACKSPACE':
            new = replace(state, query=state.query[:-1])
        elif len(key) == 1 and key.isprintable() and len(state.query) < 48:
            new = replace(state, query=state.query + key)
        else:
            return state
        vis = visible_indices(report, new)
        return replace(new, selected=vis[0] if vis and new.selected not in vis else new.selected)
    if key in ('?', 'F1', 'H'):
        return replace(state, help_open=not state.help_open)
    if state.help_open:
        return replace(state, help_open=False) if key in ('ESC', 'ENTER', 'q', 'Q') else state
    if key in ('UP', 'k'):
        return replace(state, scroll=max(0, state.scroll - 1)) if state.focus == 'DETAIL' else _navigate_visible(report, state, -1)
    if key in ('DOWN', 'j'):
        return replace(state, scroll=state.scroll + 1) if state.focus == 'DETAIL' else _navigate_visible(report, state, 1)
    if key in ('LEFT', 'h', 'p'):
        return _navigate_visible(report, state, -1)
    if key in ('RIGHT', 'l', 'n'):
        return _navigate_visible(report, state, 1)
    if key in ('F2', 'c'):
        return replace(state, compact=not state.compact, scroll=0)
    if key in ('F3', '/'):
        return replace(state, search_active=True, query='', focus='STAGES')
    if key in ('F4', 'f'):
        new = replace(state, filter_mode='PENDING' if state.filter_mode == 'ALL' else 'ALL', scroll=0)
        vis = visible_indices(report, new)
        return replace(new, selected=vis[0] if vis and new.selected not in vis else new.selected)
    if key in ('F5', 's'):
        return replace(state, show_summary=not state.show_summary)
    if key == 'TAB':
        focuses = ('STAGES', 'DETAIL', 'SUMMARY')
        return replace(state, focus=focuses[(focuses.index(state.focus) + 1) % 3])
    if key == 'd':
        return replace(state, compact=False, show_summary=False, focus='DETAIL')
    if key == 'g':
        vis = visible_indices(report, state)
        return replace(state, selected=vis[0], scroll=0) if vis else state
    if key == 'G':
        vis = visible_indices(report, state)
        return replace(state, selected=vis[-1], scroll=0) if vis else state
    if key in tuple('1234567890'):
        index = 9 if key == '0' else int(key) - 1
        return replace(state, selected=index, scroll=0, filter_mode='ALL', query='')
    # 'r' es solo repintado, NUNCA vuelve a ejecutar pruebas ni importa recibos.
    return state


def detail_rows(report: dict[str, Any], selected: int) -> list[str]:
    """Hechos derivados del informe inmutable, sin completar campos faltantes."""
    validate_dashboard_report(report)
    if type(selected) is not int or not 0 <= selected < 10:
        raise DashboardError('stage_out_of_range')
    stage = report['a10']['stages'][selected]
    out = [f"{stage['algorithm']} / {stage['status']}",
           f"ORIGEN: {stage['source']}", stage['detail'], '']
    if selected in (0, 1, 2):
        out += ['SERVICIOS DEV']
        for u in report.get('r26_units', []):
            out += [f"{u['protocol']}  {u['service_id']}",
                    f"  A1 {u['a1']}  A2 {u['a2']}  A3 {u['a3']}",
                    f"  R0 {u['initial_risk']} (declarado)"]
    elif selected == 3:
        r27 = report['r27']
        out += ['SELECCION CONFIRMADA: ' + _flat(r27['selected_actual']),
                'PROYECCION SINTETICA: ' + _flat(r27['selected_hypothetical']),
                'Sin autoridad de despacho']
    elif selected == 4:
        r27 = report['r27']
        out += ['INTENTO A5: ' + _flat(r27['a5_state']),
                'INICIOS RESERVADOS: ' + _flat(r27['a5_start_count']),
                'No acredita SSH, FTP o SMB']
    elif selected == 5:
        out += ['CLASIFICACION: ' + report['r27']['a6_classification']]
        if 'a6_import' in report:
            imp = report['a6_import']
            out += ['ADMISION: ' + imp['admission'],
                    'REGISTRO: ' + imp['record_id'],
                    'SERVICIO: ' + imp['service_id'],
                    'PROCEDENCIA DECLARADA: ' + imp['source_kind'],
                    'CAPTURADO: ' + imp['captured_at_utc'],
                    'CORTE AS-OF: ' + imp['review_as_of_utc'],
                    'AFIRMACION NO VALIDADA: ' + imp['observed_claim_unverified'],
                    'SHA256 SOPORTE: ' + imp['support_sha256_verified'],
                    'INTEGRIDAD DOCUMENTAL: VERIFICADA',
                    'VERDAD TECNICA: NO ACREDITADA', 'RIESGO FINAL: ND']
        else:
            out += ['IMPORTACION DEFENSIVA: NO', 'VERDAD TECNICA: NO ACREDITADA']
    elif selected == 6:
        out += ['ORACULO HIPOTETICO: ' + report['a7']['hypothetical_rf'],
                'RIESGO CONFIRMADO: ND', 'Oraculo no es Rf operativo']
    elif selected == 7:
        out += ['RECOMENDACION: ' + report['a8']['recommendation'],
                'TRANSICION REAL: NO APLICADA']
    elif selected == 8:
        out += ['RECIBO DE DESARROLLO: ' + report['a9']['receipt_sha256'],
                'DURABLE LOCAL: ' + ('SI' if report['a9']['durable_local_receipt'] else 'NO'),
                'GENERACION A9: NO PUBLICADA']
    else:
        out += ['SHA REPORTE: ' + report['sha256'],
                'SHA SESION: ' + report.get('session_sha256', 'ND'),
                'VM VERIFICADAS: NO', 'P8 OPERACIONAL: NO-GO']
    return out


def summary_rows(report: dict[str, Any]) -> list[str]:
    validate_dashboard_report(report)
    return [
        'SESIÓN: ' + report['session_id'],
        'P8: NO-GO',
        'DESPACHO: NO',
        'RF FINAL: ND',
        'VM: NO VERIFICADAS',
        'VISTAS: 10/10',
        'A5: ' + _short(report['r27']['a5_state'], 17),
        'A6: ' + report['r27']['a6_classification'],
        'IMPORT A6: ' + ('DOCUMENTAL' if 'a6_import' in report else 'NO'),
        'A7 HIPOTETICO: ' + report['a7']['hypothetical_rf'],
        'A8: ' + _short(report['a8']['recommendation'], 15),
        'A9: NO PUBLICADA',
        'SHA INFORME:',
        '  ' + _short(report['sha256'], 20),
        'SHA SESION:',
        '  ' + _short(report.get('session_sha256'), 20),
    ]


def _border(width: int, title: str) -> str:
    label = ' ' + title + ' '
    if len(label) > width - 2:
        label = label[:max(0, width - 2)]
    return '+' + label + '-' * max(0, width - len(label) - 2) + '+'


def _fit(text: str, width: int) -> str:
    text = ''.join(ch if ch.isprintable() else ' ' for ch in str(text))
    return text[:max(0, width)].ljust(max(0, width))


def _panel(title: str, entries: list[str], width: int, height: int, offset: int = 0) -> list[str]:
    if width < 10 or height < 3:
        return [' ' * max(0, width) for _ in range(max(0, height))]
    result = [_border(width, title)]
    capacity = height - 2
    for line in entries[max(0, offset):max(0, offset) + capacity]:
        result.append('| ' + _fit(line, width - 4) + ' |')
    while len(result) < height - 1:
        result.append('| ' + ' ' * (width - 4) + ' |')
    result.append('+' + '-' * (width - 2) + '+')
    return result


def _wrapped(rows: list[str], width: int) -> list[str]:
    result = []
    for line in rows:
        if not line:
            result.append('')
        else:
            result.extend(textwrap.wrap(line, width=max(10, width),
                                        break_long_words=True,
                                        break_on_hyphens=False) or [''])
    return result


def render_dashboard_frame(report: dict[str, Any], state: DashboardState,
                           width: int = 120, height: int = 32) -> list[str]:
    """Fotograma reproducible sin curses, ideal para pruebas y captura."""
    validate_dashboard_report(report)
    width = max(24, min(int(width), 240))
    height = max(6, min(int(height), 100))
    active = report['a10']['stages'][state.selected]
    title = ' ARDREC / MONITOR  ' + report['session_id'] + '  [DESARROLLO]'
    flags = (' P8:NO-GO  DESPACHO:NO  RF:ND  VM:NO  '
             + ('A6:DOCUMENTAL' if 'a6_import' in report else 'A6:SIN IMPORTAR')
             + f"  VISTA:{active['algorithm']}")
    top = [_fit(title, width), _fit(flags, width), '-' * width]
    if height < 12 or width < 46:
        warnings = ['Terminal pequena: ampliar a >=46 columnas y >=12 filas.',
                    'P8:NO-GO  DESPACHO:NO  RF:ND',
                    'q salir; no hay ejecucion operacional']
        return (top + [_fit(s, width) for s in warnings] + [' ' * width] * height)[:height]
    if state.help_open:
        rows = [
            'AYUDA / TECLAS (solo navegación)',
            'ARRIBA/ABAJO j/k  seleccionar etapa / scroll en detalle',
            'IZQUIERDA/DERECHA h/l  etapa anterior/siguiente',
            '1..9, 0  saltar a A1..A10',
            'TAB  cambiar foco  | d  detalle expandido',
            'F2/c  compacto  | F3/  buscar  | F4/f  filtro',
            'F5/s  resumen  | g/G  primera/ultima',
            'F1/?  ayuda  | r  repintar sin ejecutar',
            'q  salir; ESC cierra ayuda',
            'Sin red, sin escritura, sin despacho, sin riesgo acreditado',
        ]
        interior = _panel('AYUDA', _wrapped(rows, width - 6), width, height - 4)
        return top + interior + [_fit('F1 cerrar  |  q cerrar ayuda  |  P8:NO-GO', width)]
    vis = visible_indices(report, state)
    entries = []
    for i in vis:
        stage = report['a10']['stages'][i]
        marker = '>' if i == state.selected else ' '
        status = _short(stage['status'], 20 if not state.compact else 13)
        entries.append(f"{marker} {stage['algorithm']}  {status}")
    if not entries:
        entries = ['(sin coincidencias)', 'F3 o / para buscar', 'F4 para alternar filtro']
    focus = '>' if state.focus == 'STAGES' else ' '
    panel_height = height - 5
    if width >= 114 and state.show_summary and not state.compact:
        nav_width = 33
        summary_width = 29
        detail_width = width - nav_width - summary_width - 4
        nav = _panel(f'{focus} ALGORITMOS', entries, nav_width, panel_height)
        det = _panel(f'{active["algorithm"]} / DETALLE',
                     _wrapped(detail_rows(report, state.selected), detail_width - 4),
                     detail_width, panel_height, state.scroll)
        summary = _panel('ESTADO / AUDITORIA',
                         _wrapped(summary_rows(report), summary_width - 4),
                         summary_width, panel_height)
        body = [a + '  ' + b + '  ' + c for a, b, c in zip(nav, det, summary)]
    elif width >= 78 and not state.compact:
        nav_width = 33
        detail_width = width - nav_width - 2
        nav = _panel(f'{focus} ALGORITMOS', entries, nav_width, panel_height)
        details = detail_rows(report, state.selected)
        if state.show_summary:
            details = ['ESTADO: P8 NO-GO / RF ND / VM NO', ''] + details
        det = _panel(f'{active["algorithm"]} / DETALLE',
                     _wrapped(details, detail_width - 4),
                     detail_width, panel_height, state.scroll)
        body = [a + '  ' + b for a, b in zip(nav, det)]
    else:
        rows = [f'ETAPA {active["algorithm"]}  FILTRO {state.filter_mode}',
                f'NAVEGABLES: {len(vis)}/10', '']
        rows += (summary_rows(report) if state.focus == 'SUMMARY' else
                 detail_rows(report, state.selected))
        body = _panel('DETALLE / COMPACTO', _wrapped(rows, width - 4),
                      width, panel_height, state.scroll)
    mode = ('BUSCAR: ' + state.query + '_' if state.search_active else
            f'FILTRO:{state.filter_mode}  FOCO:{state.focus}')
    footer = ('  UP/DOWN etapa | LEFT/RIGHT mover | TAB foco | F1 ayuda | '
              'F2 compact | F3 buscar | F4 filtro | q salir')
    return (top + body + [_fit(mode + '  SOLO LECTURA', width),
                          _fit(footer, width)])[:height]


def _key_name(code: int, curses_module: Any) -> str:
    keys = {curses_module.KEY_UP: 'UP', curses_module.KEY_DOWN: 'DOWN',
            curses_module.KEY_LEFT: 'LEFT', curses_module.KEY_RIGHT: 'RIGHT',
            curses_module.KEY_ENTER: 'ENTER', 10: 'ENTER', 13: 'ENTER',
            9: 'TAB', 27: 'ESC', 127: 'BACKSPACE', 8: 'BACKSPACE',
            curses_module.KEY_BACKSPACE: 'BACKSPACE'}
    for n in range(1, 6):
        keys[getattr(curses_module, f'KEY_F{n}', curses_module.KEY_F0 + n)] = f'F{n}'
    return keys.get(code, chr(code) if 32 <= code <= 126 else '')



def _selected_nav_span(line: str, state: DashboardState, width: int) -> tuple[int, int] | None:
    """Resaltado SOLO dentro del panel izquierdo; nunca sobre detalle/auditoría."""
    nav_width = 33  # mismo ancho fijo empleado en render_dashboard_frame
    if (state.help_open or state.compact or width < 78 or
            not line.startswith('| > ') or len(line) < nav_width or
            line[nav_width - 1] != '|'):
        return None
    # El primer y último carácter son los bordes del panel.
    return (1, nav_width - 1)


def run_dashboard_tui(report: dict[str, Any]) -> None:
    """Dashboard reactivo a teclas, pero sin temporizadores ni efectos operativos."""
    validate_dashboard_report(report)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise RuntimeError('Dashboard TUI requiere una terminal interactiva real')
    import curses

    def _loop(screen: Any) -> None:
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
                # Texto normal legible en temas oscuros; fondo del usuario intacto.
                curses.init_pair(4, curses.COLOR_WHITE, -1)
                colors = True
            except curses.error:
                colors = False
        state = DashboardState()
        while True:
            screen.erase()
            height, width = screen.getmaxyx()
            frame = render_dashboard_frame(report, state, max(24, width - 1), height)
            for y, line in enumerate(frame[:height]):
                attr = curses.color_pair(4) if colors else 0
                if colors:
                    if y == 0:
                        attr = curses.color_pair(1) | curses.A_BOLD
                    elif y == 1:
                        attr = curses.color_pair(2) | curses.A_BOLD
                try:
                    screen.addnstr(y, 0, line, max(0, width - 1), attr)
                    if colors:
                        span = _selected_nav_span(line, state, max(24, width - 1))
                        if span is not None:
                            start, stop = span
                            screen.addnstr(y, start, line[start:stop], stop - start,
                                           curses.color_pair(3) | curses.A_BOLD)
                except curses.error:
                    pass
            screen.refresh()
            code = screen.getch()
            key = _key_name(code, curses)
            if not state.search_active and not state.help_open and key in ('q', 'Q'):
                break
            state = handle_key(report, state, key)
    curses.wrapper(_loop)
