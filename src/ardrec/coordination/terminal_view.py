"""P14-R28 / A10: TUI real con curses, solo lectura, sin comandos ni red."""
from __future__ import annotations

import textwrap
from typing import Any


def lines_for_page(report: dict[str,Any], index: int, width: int = 78) -> list[str]:
    if type(index) is not int or not 0 <= index < 10:
        raise ValueError('page_out_of_range')
    width=max(36,min(160,width))
    stage=report['a10']['stages'][index]
    out=[f'ARDREC | SESION {report["session_id"]} | DESARROLLO NO-GO',
         '-'*min(width,70),f'{stage["algorithm"]} | {stage["status"]}',
         f'ORIGEN: {stage["source"]}']
    out.extend(textwrap.wrap(stage['detail'],width=width,break_long_words=False))
    out.append('')
    if index < 3:
        for u in report['r26_units']:
            out.append(f"{u['protocol']} / {u['service_id']} | A1={u['a1']} A2={u['a2']} A3={u['a3']}")
    elif index == 3:
        out.append('SELECCION ESTADO: '+str(report['r27']['selected_actual']))
        out.append('PROYECCION: '+str(report['r27']['selected_hypothetical']))
    elif index in (4,5):
        out.append('A5 ESTADO: '+str(report['r27']['a5_state']))
        out.append('A6 CLASE: '+report['r27']['a6_classification'])
        if index == 5 and report.get('a6_import') is not None:
            imported=report['a6_import']
            out.append('A6 ADMISION DOCUMENTAL: '+imported['admission'])
            out.append('REGISTRO: '+imported['record_id']+' / '+imported['service_id'])
            out.append('PROCEDENCIA DECLARADA: '+imported['source_kind'])
            out.append('CAPTURA: '+imported['captured_at_utc'])
            out.append('AS-OF: '+imported['review_as_of_utc'])
            out.append('AFIRMACION NO VERIFICADA: '+imported['observed_claim_unverified'])
            out.append('SOPORTE SHA256: '+imported['support_sha256_verified'][:32]+'...')
            out.append('VERDAD TECNICA: NO ACREDITADA / RF: ND')
    elif index == 6:
        out.append('RF ORACULO HIPOTETICO: '+report['a7']['hypothetical_rf'])
        out.append('RF ACREDITADO: ND')
    elif index == 7:
        out.append('RECOMENDACION: '+report['a8']['recommendation'])
        out.append('TRANSICION APLICADA: NO')
    elif index == 8:
        out.append('RECIBO: '+report['a9']['receipt_sha256'][:32]+'...')
        out.append('GENERACION OPERACIONAL: NO PUBLICADA')
    else:
        out.append('SHA REPORTE: '+report['sha256'])
        out.append('VM OBSERVADAS: NO / P8: NO-GO')
    out.extend(['','[izquierda/derecha o h/l] cambiar | [q] salir',
                f'PAGINA {index+1}/10 | SIN DESPACHO | SIN RIESGO FINAL'])
    return [s[:width] for s in out]


def render_text(report: dict[str,Any]) -> str:
    return '\n\n'.join('\n'.join(lines_for_page(report,i)) for i in range(10))+'\n'


def run_tui(report: dict[str,Any]) -> None:
    import curses
    import sys
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise RuntimeError('TUI requiere una terminal interactiva real')
    def loop(screen):
        try: curses.curs_set(0)
        except curses.error: pass
        page=0
        while True:
            screen.erase()
            height,width=screen.getmaxyx()
            lines=lines_for_page(report,page,max(36,width-1))
            if width < 36 or height < 8:
                lines=['ARDREC: amplia la terminal (min. 36x8)','q para salir']
            for i,line in enumerate(lines[:max(0,height-1)]):
                try: screen.addnstr(i,0,line,max(1,width-1))
                except curses.error: pass
            screen.refresh()
            key=screen.getch()
            if key in (ord('q'),ord('Q'),27): break
            if key in (ord('l'),ord('n'),curses.KEY_RIGHT,curses.KEY_DOWN):
                page=(page+1)%10
            if key in (ord('h'),ord('p'),curses.KEY_LEFT,curses.KEY_UP):
                page=(page-1)%10
    curses.wrapper(loop)
