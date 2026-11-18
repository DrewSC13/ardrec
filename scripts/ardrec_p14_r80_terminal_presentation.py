#!/usr/bin/env python3
"""R80: terminal-only, selective tutor presentation from authenticated R79/R75.

Read-only: no subcommands, network, subprocess, VM, A5, state change, or output files.
The presenter verifies R75/R76/R78 and reproduces R79 before displaying anything.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))
import ardrec_p14_r75_integrated_demo as r75
import ardrec_p14_r77_signed_a5_a8_bridge as r77
import ardrec_p14_r79_tutor_walkthrough as r79

SCHEMA = 'ardrec-p14-r80-terminal-readonly-presentation-v1'
STAGES = tuple(f'A{n}' for n in range(1, 11))
PROTOCOLS = {'SSH':'SSH_DEV','FTP':'FTP_DEV','SMB':'SMB_DEV'}
VIEWS = ('resumen','etapas','etapa','familias','familia','evidencias','r38','todo')
LIMIT = 36_000


class R80Error(ValueError):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise R80Error(reason)


def load(receipt_dir: Path, r76_path: Path, r78_path: Path,
         r79_path: Path) -> dict[str, Any]:
    """Reconstruct independent pre-existing reports, without creating anything."""
    need(os.geteuid() != 0 and Path.cwd().resolve() == REPO,
         'NONROOT_CANONICAL_REPO_REQUIRED')
    r76 = r77.read_canonical(r76_path)
    r78 = r77.read_canonical(r78_path)
    report = r77.read_canonical(r79_path)
    need(type(report) is dict and r79.verify(report,receipt_dir,r76,r78),
         'R79_SOURCE_NOT_REPRODUCIBLE')
    need(report.get('stage_count') == 10 and
         tuple(x['algorithm'] for x in report['stages']) == STAGES and
         report.get('r75_synthetic_units') == 54 and
         report.get('r78_mathematical_family_count') == 25 and
         report.get('r75_local_benign_starts') == 1 and
         report.get('a6_classification') == 'ND' and
         report.get('a7_confirmed_rf') is None and
         report.get('a8_applied_transitions') == 0 and
         report.get('a9_new_generations') == 0 and
         report.get('physical_executions') == 0 and
         report.get('operational_dispatch') is False and
         report.get('p8_operational') == 'NO-GO' and
         report.get('experimental_validation') == 'NOT_RUN' and
         report.get('system_functional_acceptance') == 'PENDING' and
         report.get('r77_external_registry_pin_provided') is False,
         'R79_SECURITY_CONTRACT_INVALID')
    return report


def _header() -> list[str]:
    return [
        'ARDREC / R80 / PRESENTACION DE TERMINAL -- SOLO LECTURA',
        'FUENTE: DEV SINTETICO | A6=ND | Rf confirmado=NULL | P8=NO-GO',
        'SIN VM, SIN DESPACHO, SIN NUEVA GENERACION, SIN CAMBIOS DE ESTADO',
        '-' * 79,
    ]


def _summary(doc: dict[str, Any]) -> list[str]:
    return [
        'RESUMEN DEL PROTOTIPO (NO VALIDACION EXPERIMENTAL)',
        'A1-A10: 10 etapas reproducibles | 54 unidades A2 sinteticas',
        'A5: 1 inicio benigno local previo (R75), 25 intenciones sin inicio fisico',
        'A6: 25 casos ND | R77: sin pin de confianza externo',
        'A7: 25 familias (SSH 8 / FTP 8 / SMB 9), E=0,1/2,1 hipoteticos',
        'A8: 0 transiciones aplicadas | A9: GEN1 estructural, GEN2 inexistente',
        'A10: monitor R38 original, 3 paneles y 10 vistas',
        'ACEPTACION_FUNCIONAL=PENDING | VALIDACION_EXPERIMENTAL=NOT_RUN',
        'R79_SHA256=' + doc['sha256'],
    ]


def _stage(doc: dict[str, Any], number: str) -> list[str]:
    need(number in STAGES, 'STAGE_OUT_OF_RANGE')
    row = doc['stages'][int(number[1:])-1]
    need(row['algorithm'] == number, 'STAGE_SOURCE_MISMATCH')
    lines = [
        f'{number} / FUENTE: {row["source"]}',
        'DESCRIPCION: ' + row['detail'],
        'VALIDACION EXPERIMENTAL: ' + row['experimental_validation'],
    ]
    explanations = {
        'A1': 'Tres decisiones R68 de la sesion DEV; no son resultados de red.',
        'A2': 'Las 54 unidades son sinteticas y diferentes de las 25 familias.',
        'A3': 'La guarda verdadera es hipotetica; el despacho real permanece denegado.',
        'A4': 'Seleccion SSH/CASE_REFERENCE solo simulada; ninguna seleccion acreditada.',
        'A5': 'El unico proceso ejecutado fue local benigno; 25 intents no arrancan VM.',
        'A6': 'Las firmas atribuyen documentos, no acreditan verdad tecnica ni servicio.',
        'A7': 'Los tres puntos E se introducen hipoteticamente en el nucleo R58-D.',
        'A8': 'No se aplicaron transiciones; R70 conserva DETENER en GEN1.',
        'A9': 'Existe una GEN1 estructural; no hay GEN2 ni evidencia tecnica publicada.',
        'A10': 'R38 es la fuente de monitor original, no un segundo motor de estados.',
    }
    lines.append('INTERPRETACION: ' + explanations[number])
    lines.append('AUTORIDAD OPERACIONAL: NO-GO / NO ACREDITADA')
    return lines


def _family(doc: dict[str, Any], family_id: str) -> list[str]:
    records = [x for x in doc['families'] if x['family_id']==family_id]
    need(len(records) == 1, 'UNKNOWN_OR_DUPLICATED_FAMILY')
    r = records[0]
    return [
        'FAMILIA: ' + r['family_id'] + ' | SERVICIO: ' + r['service_id'],
        'CASO: ' + r['case_id'],
        'DECLARACION: ' + r['declared_outcome'] + ' (SIN ACREDITACION)',
        'A6: ' + r['a6'],
        'A7 INTERVALO SIN RESOLVER: [' + ', '.join(r['unresolved_interval']) + ']',
        'RIESGO HIPOTETICO E=0:   ' + r['hypothetical_rf_E0'],
        'RIESGO HIPOTETICO E=1/2: ' + r['hypothetical_rf_Ehalf'],
        'RIESGO HIPOTETICO E=1:   ' + r['hypothetical_rf_E1'],
        'Rf CONFIRMADO: NULL | TRANSICION: NO | P8: NO-GO',
    ]


def _families(doc: dict[str, Any], protocol: str | None) -> list[str]:
    need(protocol is None or protocol in PROTOCOLS, 'UNKNOWN_PROTOCOL')
    data = [r for r in doc['families']
            if protocol is None or r['service_id'] == PROTOCOLS[protocol]]
    need(len(data) == (25 if protocol is None else {'SSH':8,'FTP':8,'SMB':9}[protocol]),
         'FAMILY_COUNT_DRIFT')
    lines = ['MATRIZ A7: HIPOTESIS, NO OBSERVACIONES FISICAS',
             'FAMILIA  SERVICIO  A6  E=0     E=1/2   E=1    Rf CONFIRMADO',
             '-' * 65]
    for r in data:
        lines.append(f"{r['family_id']:<8} {r['service_id']:<9} ND  "
                     f"{r['hypothetical_rf_E0']:<7} "
                     f"{r['hypothetical_rf_Ehalf']:<7} "
                     f"{r['hypothetical_rf_E1']:<6} NULL")
    return lines


def _evidence(doc: dict[str, Any]) -> list[str]:
    lines = ['FUENTES ENCADENADAS Y VERIFICADAS (HASH != VERDAD TECNICA)']
    labels = {
        'r75_manifest_sha256':'R75 manifest',
        'r75_gen1_head_sha256':'R75 GEN1 HEAD',
        'r75_shadow_sha256':'R75 shadow',
        'r75_r38_sha256':'R75 R38',
        'r76_report_sha256':'R76 A5-A8',
        'r78_report_sha256':'R78 A7 matematico',
    }
    for key in labels:
        lines.append(labels[key] + ': ' + doc['source_links'][key])
    lines += [
        'R79 reporte: ' + doc['sha256'],
        'R77: sin registro/pin externo independiente ni testigos fisicos',
        'SHA-256 acredita consistencia local del contenido, no procedencia fisica.',
        'A6=ND | Rf CONFIRMADO=NULL | F11 NO AUTORIZADO | P8=NO-GO',
    ]
    return lines


def render(doc: dict[str, Any], view: str, *,
           stage: str | None = None, family: str | None = None,
           protocol: str | None = None, monitor: str | None = None) -> str:
    need(type(doc) is dict and doc.get('schema') == r79.SCHEMA and
         doc.get('source_kind') == r79.SOURCE and
         doc.get('a6_classification') == 'ND' and
         doc.get('a7_confirmed_rf') is None and
         doc.get('p8_operational') == 'NO-GO',
         'SOURCE_NOT_R79_READONLY')
    need(view in VIEWS, 'VIEW_INVALID')
    need((view == 'etapa') == (stage is not None), 'STAGE_OPTION_MISMATCH')
    need((view == 'familia') == (family is not None), 'FAMILY_OPTION_MISMATCH')
    need(protocol is None or view == 'familias', 'PROTOCOL_OPTION_MISMATCH')
    need(monitor is None or view == 'r38', 'MONITOR_OPTION_MISMATCH')
    lines = _header()
    if view == 'resumen':
        lines += _summary(doc)
    elif view == 'etapas':
        lines.append('ETAPAS A1-A10 / ORIGEN Y DESCRIPCION')
        for item in doc['stages']:
            lines.append(f"{item['algorithm']}: {item['source']} | {item['detail']}")
    elif view == 'etapa':
        lines += _stage(doc, stage)
    elif view == 'familias':
        lines += _families(doc, protocol)
    elif view == 'familia':
        lines += _family(doc, family)
    elif view == 'evidencias':
        lines += _evidence(doc)
    elif view == 'r38':
        need(type(monitor) is str and 'ALGORITMOS' in monitor and
             'ESTADO / AUDITORIA' in monitor and 'SOMBRA BENIGNA' in monitor,
             'R38_SOURCE_FRAME_INVALID')
        lines.extend(['R38 / MONITOR ORIGINAL / INSTANTANEA AUTENTICADA',
                      'El monitor corresponde al momento R75, no a una sesion fisica.'])
        lines.append(monitor.rstrip('\n'))
    elif view == 'todo':
        lines += _summary(doc) + [''] + _families(doc, None) + ['']
        lines += _evidence(doc)
    lines.extend(['-' * 79,
                  'R80=PASS_VERIFIED_READONLY',
                  'R80_A6=ND | R80_RF_CONFIRMED=NULL | R80_P8=NO-GO'])
    output = '\n'.join(lines) + '\n'
    need(len(output.encode('utf-8')) < LIMIT, 'OUTPUT_BOUND_EXCEEDED')
    return output


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt-dir',type=Path,required=True)
    ap.add_argument('--r76-report',type=Path,required=True)
    ap.add_argument('--r78-report',type=Path,required=True)
    ap.add_argument('--r79-report',type=Path,required=True)
    ap.add_argument('--vista',required=True,choices=VIEWS)
    ap.add_argument('--etapa',choices=STAGES)
    ap.add_argument('--familia',type=str)
    ap.add_argument('--protocolo',choices=sorted(PROTOCOLS))
    try:
        opt=ap.parse_args(argv)
        doc=load(opt.receipt_dir,opt.r76_report,opt.r78_report,opt.r79_report)
        monitor = None
        if opt.vista == 'r38':
            monitor = r75.read_file(opt.receipt_dir/'reports'/'r38_pantalla.txt').decode('utf-8')
        output=render(doc,opt.vista,stage=opt.etapa,family=opt.familia,
                      protocol=opt.protocolo,monitor=monitor)
        sys.stdout.write(output)
    except (R80Error,r79.R79Error,ValueError,TypeError,KeyError,OSError,UnicodeError,
            RuntimeError) as exc:
        print('R80=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R80_P8=NO-GO',file=sys.stderr)
        return 23
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
