"""R59-H: R38 three-panel, read-only verified A5-v2 case view.

R38 remains unchanged. Only a source-verified immutable private R59-F record
and its R59-E P7 rule-bridge may be presented. Historical R58-Y observations
remain independent of A5. Neither a declared attempt nor a signed statement
proves physical start or A6 technical truth. No P8/VM/host operations.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import sys
from typing import Any

from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import r58z_r38_dashboard_adapter as old
from ardrec.coordination import dashboard_tui as r38
from ardrec.coordination import r59f_variant_origin as v2
from ardrec.coordination import r59e_a5_a6_family_bridge as e

SERVICE = {'SSH_DEV': 'SSH', 'FTP_DEV': 'FTPS', 'SMB_DEV': 'SMB'}

class CaseViewError(ValueError):
    """The interface refuses unverifiable sources and forged accreditation."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise CaseViewError(reason)


@dataclass(frozen=True)
class VerifiedView:
    workspace: dict[str, Any]
    source_v2_sha256: str
    bridge_sha256: str
    service: str
    session: str
    family: str
    derived_case: str
    attempt: str
    variant: str | None
    outcome: str
    source_kind: str
    catalog_sha256: str
    support_sha256: str | None
    support_bytes: int
    hypothetical_class: str
    hypothetical_reason: str
    unresolved_preconditions: tuple[str, ...]
    unresolved_supports: tuple[str, ...]


def load_view(*, database: Path, v2_root: Path, a5_root: Path,
              a6_root: Path, attempt_id: str) -> VerifiedView:
    """Verify private data at open; never derive from unscreened JSON or logs."""
    workspace = z.from_database(database)
    z.verify_workspace(workspace)
    receipt = v2.verify_stored(v2_root, a5_root, a6_root, attempt_id)
    bridge = e.verify_stored_bridge(a6_root, a5_root,
                                    receipt['legacy_candidate_sha256'])
    intent = receipt['intent']
    outcome = receipt['receipt']
    need(intent['service_id'] in SERVICE and
         receipt['source_bridge_sha256'] == bridge['sha256'] and
         bridge['source_candidate_sha256'] == receipt['legacy_candidate_sha256'] and
         bridge['identity']['attempt_id'] == attempt_id and
         bridge['variant'] == intent['variant'] and
         bridge['source_catalog_sha256'] == intent['source_catalog_sha256'] and
         outcome['v2_intent_sha256'] == intent['sha256'] and
         outcome['declared_outcome'] == bridge['declared_outcome'],
         'CASE_BRIDGE_SOURCE_OR_VARIANT_MISMATCH')
    need(receipt['variant_bound_at_origin'] is True and
         receipt['a5_start_independently_attested'] is False and
         receipt['technical_truth_accredited'] is False and
         receipt['a6_classification'] == 'ND' and
         receipt['published_generation'] is None and
         receipt['confirmed_rf'] is None and
         receipt['operational_dispatch'] is False and
         receipt['p8_operational'] == 'NO-GO' and
         bridge['technical_truth_accredited'] is False and
         bridge['a6_classification'] == 'ND' and
         bridge['confirmed_rf'] is None and
         bridge['published_generation'] is None and
         bridge['p8_operational'] == 'NO-GO',
         'UNAUTHORIZED_AUTHORITY_OR_CLASSIFICATION')
    need(outcome['declared_outcome'] != 'NO_START' or
         (outcome['support_bytes'] == 0 and
          bridge['hypothetical_family_class'] == 'NO_INTENTO_NO_CLASIFICACION'),
         'NO_START_WITH_EVIDENCE_OR_CLASSIFICATION')
    return VerifiedView(
        workspace=workspace,
        source_v2_sha256=receipt['sha256'],
        bridge_sha256=bridge['sha256'],
        service=SERVICE[intent['service_id']],
        session=intent['session_id'],
        family=intent['family_id'],
        derived_case=intent['derived_case_id'],
        attempt=intent['attempt_id'],
        variant=intent['variant'],
        outcome=outcome['declared_outcome'],
        source_kind=outcome['source_kind'],
        catalog_sha256=intent['source_catalog_sha256'],
        support_sha256=outcome['support_sha256'],
        support_bytes=outcome['support_bytes'],
        hypothetical_class=bridge['hypothetical_family_class'],
        hypothetical_reason=bridge['hypothetical_family_reason'],
        unresolved_preconditions=tuple(bridge['unresolved_preconditions']),
        unresolved_supports=tuple(bridge['unresolved_supports']),
    )


def audit_rows(view: VerifiedView, service_index: int) -> list[str]:
    need(type(service_index) is int and service_index in range(3), 'SERVICE_INDEX')
    base = old.physical_audit(view.workspace, service_index)
    if z.SERVICES[service_index] != view.service:
        return base + ['', 'CASO A5 V2 EN OTRO SERVICIO:', view.service]
    return [
        'R59-H / A5 V2 VERIFICADO',
        'FUENTE REABIERTA AL ENTRAR',
        'SERVICIO: ' + view.service,
        'FAMILIA: ' + view.family,
        'VARIANTE: ' + (view.variant or 'BASE'),
        'RESULTADO: ' + view.outcome,
        'A5 FISICO: NO ACREDITADO',
        'A6: ND / Rf: NO',
        'A9: NO PUBLICADA',
        'P8: NO-GO',
        'R58-Y: FUENTE SEPARADA',
        'V2 SHA: '+view.source_v2_sha256[:16],
        'P7 SHA: '+view.catalog_sha256[:16],
        '',
        'R58-Z / OBSERVACIONES:',
        f"CONTADOR: {view.workspace['services'][service_index]['observation_count']}",
        'HISTORICAS NO SON A5',
    ]


def detail_rows(view: VerifiedView, service_index: int, stage_index: int) -> list[str]:
    need(type(stage_index) is int and stage_index in range(10), 'STAGE_INDEX')
    original = old.stage_detail(view.workspace, service_index, stage_index)
    if z.SERVICES[service_index] != view.service:
        return original
    case = [
        'R59-H / A5 DOCUMENTAL V2 - NO OPERACIONAL',
        'FAMILIA: '+view.family+' / VAR: '+(view.variant or 'BASE'),
        'CASO: '+view.derived_case,
        'SESION: '+view.session,
        'INTENTO: '+view.attempt,
        'RESULTADO DECLARADO: '+view.outcome,
        'ORIGEN: '+view.source_kind,
        'A5 FISICO: NO ACREDITADO',
        'A6 OPERACIONAL: ND',
        'A7/Rf: SIN CONFIRMAR',
        'A9: NO PUBLICADA / P8: NO-GO',
        'V2 SHA256: '+view.source_v2_sha256,
        'PUENTE A6 SHA256: '+view.bridge_sha256,
    ]
    if stage_index == 4:
        return ['A5 / IDENTIDAD Y RESULTADO REABIERTO', '', *case,
                '', 'SOPORTE BYTES: '+str(view.support_bytes),
                'SOPORTE SHA256: '+(view.support_sha256 or 'NO_APLICA'),
                '', 'NO IMPLICA QUE EL INTENTO ARRANCO',
                '', *original[:5]]
    if stage_index == 5:
        return [
            'A6 / REGLAS P7 SOLO MODELO', '',
            'FAMILIA: '+view.family+' / VAR: '+(view.variant or 'BASE'),
            'CLASE HIPOTETICA: '+view.hypothetical_class,
            'RAZON MODELO: '+view.hypothetical_reason,
            'A6 ACREDITADA: ND',
            'PRECONDICIONES PENDIENTES: '+str(len(view.unresolved_preconditions)),
            *(' - '+x for x in view.unresolved_preconditions[:14]),
            'SOPORTES PENDIENTES: '+str(len(view.unresolved_supports)),
            *(' - '+x for x in view.unresolved_supports[:16]),
            '', 'CATALOGO P7 SHA256: '+view.catalog_sha256,
            'NO APTO PARA Rf NI A9',
            '', *original[:5]]
    return original + ['', '--- R59-H / CONTEXTO A5 V2 ---', *case[:10]]


def render_frame(view: VerifiedView, service_index: int,
                 state: r38.DashboardState | None = None,
                 width: int = 120, height: int = 32) -> list[str]:
    need(isinstance(view, VerifiedView), 'VIEW_TYPE')
    z.verify_workspace(view.workspace)
    need(type(service_index) is int and 0 <= service_index < 3, 'SERVICE_INDEX')
    if state is None:
        state = r38.DashboardState(selected=4)
    need(isinstance(state, r38.DashboardState) and
         type(state.selected) is int and 0 <= state.selected < 10,
         'R38_NAVIGATION_INVALID')
    w, h = max(24, min(int(width), 240)), max(6, min(int(height), 100))
    frame = old.render_frame(view.workspace, service_index, state, w, h)
    frame[0] = r38._fit(' ARDREC / MONITOR R38 + R59-H [FUENTES PRIVADAS VERIFICADAS]', w)
    frame[1] = r38._fit(' SERVICIO:'+z.SERVICES[service_index]
                        +'  A5 FISICO:NO  A6:ND  Rf:NO  A9:NO  P8:NO-GO', w)
    if h < 12 or w < 46 or state.help_open or z.SERVICES[service_index] != view.service:
        return frame
    panel_h = h-5
    details = detail_rows(view, service_index, state.selected)
    if w >= 114 and state.show_summary and not state.compact:
        nav_w, audit_w = 33, 29
        detail_w = w - nav_w - audit_w - 4
        panel = r38._panel('A'+str(state.selected+1)+' / CASO A5 V2',
                           r38._wrapped(details, detail_w-4),
                           detail_w, panel_h, state.scroll)
        audit = r38._panel('ESTADO / AUDITORIA',
                           r38._wrapped(audit_rows(view,service_index),audit_w-4),
                           audit_w,panel_h)
        for index in range(panel_h):
            frame[3+index] = (frame[3+index][:nav_w+2]+panel[index]+'  '+audit[index])
    elif w >= 78 and not state.compact:
        nav_w = 33
        detail_w = w-nav_w-2
        full = audit_rows(view,service_index)+['']+details if state.show_summary else details
        panel = r38._panel('A'+str(state.selected+1)+' / CASO A5 V2',
                           r38._wrapped(full,detail_w-4),detail_w,panel_h,state.scroll)
        for index in range(panel_h):
            frame[3+index] = frame[3+index][:nav_w+2]+panel[index]
    else:
        data = (audit_rows(view,service_index) if state.focus == 'SUMMARY'
                else details)
        frame[3:3+panel_h] = r38._panel('R38 / CASO A5 V2',
                                        r38._wrapped(data,w-4),w,panel_h,state.scroll)
    frame[-1] = r38._fit('v/V servicio | 1..9,0 etapa | Tab foco | F1-F5 | j/k | q salir',w)
    need(len(frame)==h and all(len(s)==w for s in frame),'FRAME_GEOMETRY_INVALID')
    return frame


def handle_event(view:VerifiedView,service_index:int,state:r38.DashboardState,
                 key:str) -> tuple[int,r38.DashboardState]:
    return old.handle_event(view.workspace,service_index,state,key)


def run_tui(view:VerifiedView) -> None:
    """Use R38 keys, frame navigation and three-panel geometry unchanged."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise CaseViewError('TUI_REQUIRES_INTERACTIVE_TERMINAL')
    import curses

    def loop(screen:Any) -> None:
        try:curses.curs_set(0)
        except curses.error:pass
        screen.keypad(True)
        colors=False
        if curses.has_colors():
            try:
                curses.start_color();curses.use_default_colors()
                curses.init_pair(1,curses.COLOR_CYAN,-1)
                curses.init_pair(2,curses.COLOR_YELLOW,-1)
                curses.init_pair(3,curses.COLOR_WHITE,curses.COLOR_BLUE)
                curses.init_pair(4,curses.COLOR_WHITE,-1)
                colors=True
            except curses.error:colors=False
        selected=z.SERVICES.index(view.service)
        state=r38.DashboardState(selected=4)
        while True:
            screen.erase()
            h,w=screen.getmaxyx()
            fw=max(24,w-1)
            picture=render_frame(view,selected,state,fw,h)
            for y,line in enumerate(picture[:h]):
                attr=curses.color_pair(4) if colors else 0
                if colors and y==0:attr=curses.color_pair(1)|curses.A_BOLD
                elif colors and y==1:attr=curses.color_pair(2)|curses.A_BOLD
                try:
                    screen.addnstr(y,0,line,max(0,w-1),attr)
                    if colors:
                        span=r38._selected_nav_span(line,state,fw)
                        if span is not None:
                            a,b=span
                            screen.addnstr(y,a,line[a:b],b-a,curses.color_pair(3)|curses.A_BOLD)
                except curses.error:pass
            screen.refresh()
            key=r38._key_name(screen.getch(),curses)
            if not state.search_active and not state.help_open and key in ('q','Q'):
                return
            selected,state=handle_event(view,selected,state,key)
    curses.wrapper(loop)
