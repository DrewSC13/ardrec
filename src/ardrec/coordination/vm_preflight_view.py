"""R29: panel adicional de solo lectura, sin alterar las diez paginas A1-A10."""
from __future__ import annotations

import sys
from typing import Any

from ardrec.coordination.terminal_view import lines_for_page, render_text
from ardrec.coordination.vm_host_preflight import verify_report


def vm_lines(vm: dict[str, Any], width: int = 78) -> list[str]:
    verify_report(vm)
    width=max(36,min(160,width))
    lines=['ARDREC | LABORATORIO / INVENTARIO HISTORICO + LIBVIRT',
           '-'*min(width,70),
           'R29 | '+vm['mode'],
           'HOST: '+vm['host']+' | '+vm['libvirt_uri'],
           'RESULTADO: '+vm['summary'],
           '']
    for row in vm['roles']:
        endpoint='--' if row['historical_ipv4'] is None else (
            row['historical_ipv4']+':'+str(row['historical_port']))
        lines.append(f"{row['role'].upper()} {row['domain']}")
        lines.append(f"  HIST: {endpoint} | HOST: {row['state']}")
        if row['layout_matches_historical'] is not None:
            lines.append('  NIC/MAC vs historico: '+str(row['layout_matches_historical']))
    lines += ['','HUELLAS DE FUENTE: '+vm['profile_sha256'][:16]+'...',
              'CONSULTA RED VM: NO | SERVICIOS VM: NO',
              'AUTORIZACION P8: NO-GO | RIESGO FINAL: ND',
              '[v] regresar a A1-A10 | [q] salir']
    return [line[:width] for line in lines]


def render_combined(cycle: dict[str,Any], vm: dict[str,Any]) -> str:
    return render_text(cycle)+'\n'+'\n'.join(vm_lines(vm))+'\n'


def run_combined_tui(cycle: dict[str,Any], vm: dict[str,Any]) -> None:
    import curses
    verify_report(vm)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise RuntimeError('TUI requiere terminal interactiva')
    def loop(screen):
        try: curses.curs_set(0)
        except curses.error: pass
        page=0
        last_page=0
        while True:
            screen.erase()
            height,width=screen.getmaxyx()
            if width < 36 or height < 8:
                lines=['ARDREC: ampliar terminal (min 36x8)', 'q para salir']
            else:
                lines = (vm_lines(vm,width-1) if page==10 else
                         lines_for_page(cycle,page,width-1))
                if page < 10:
                    lines[-2]='[v] consultar VM | '+lines[-2]
            for y,line in enumerate(lines[:max(0,height-1)]):
                try: screen.addnstr(y,0,line,max(1,width-1))
                except curses.error: pass
            screen.refresh()
            key=screen.getch()
            if key in (ord('q'),ord('Q'),27): break
            if key in (ord('v'),ord('V')):
                if page==10: page=last_page
                else: last_page,page=page,10
            elif key in (ord('l'),ord('n'),curses.KEY_RIGHT,curses.KEY_DOWN):
                page=0 if page==10 else (page+1)%10
            elif key in (ord('h'),ord('p'),curses.KEY_LEFT,curses.KEY_UP):
                page=9 if page==10 else (page-1)%10
    curses.wrapper(loop)
