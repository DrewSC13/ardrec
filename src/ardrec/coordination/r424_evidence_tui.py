"""P14-R42.4: unir evidencia física sellada con A1-A10 de desarrollo.

No ejecuta VM, red, comandos externos, procesos ni escritura. La vista muestra
orígenes distintos; nunca convierte un preview sintético en resultado físico.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import curses
import json
from typing import Any

from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r422_independent_packet_witness as r422
from ardrec.coordination import r423_guest_path_inventory as r423
from ardrec.coordination import demo_session
from ardrec.coordination import development_cycle
from ardrec.coordination import dashboard_tui
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r424-readonly-physical-and-development-tui-v1'
MAIN_PIN = 'b67550840b3b30f29361654bfed3d573a7167e59'
R422_PIN = '7816e46d3fd4b24a50bce0171bffd4d3ea307167485f5111529b4b9ed10f3ae6'
R423_PIN = '5e2444b0f4c3c928f887274938eebb2bc085290f20c476d982283a07e2d44dd8'
STAGES = tuple('A'+str(i) for i in range(1,11))


class EvidenceViewError(ValueError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceViewError(code)


def seal(doc: dict[str, Any]) -> dict[str, Any]:
    doc['sha256'] = sha256(r41.canon(doc)).hexdigest()
    return doc


def read_physical(r422_dir: Path, r423_dir: Path) -> dict[str, Any]:
    """Read-once authenticated by the existing receipt and semantic contracts."""
    witness = r422.verify_private_receipt(r422_dir)
    files = verified_directory(r423_dir, frozenset({r423.INTENT, r423.RESULT}))
    route = r365.read_json(files[r423.RESULT])
    intent = r365.read_json(files[r423.INTENT])
    r423.verify_report(route)
    need(witness.get('sha256') == R422_PIN and
         witness.get('status') == 'NO_GUEST_EGRESS_WITNESSED_NO_GO' and
         witness.get('p8_operational') == 'NO-GO' and
         witness.get('isolation_proven') is False, 'r422_source_changed')
    need(route.get('sha256') == R423_PIN and
         route.get('source_r422_report_sha256') == R422_PIN and
         route.get('status') == r423.STATUS_DIRECT and
         route.get('source_main') == r423.MAIN_PIN and
         route.get('p8_operational') == 'NO-GO' and
         route.get('isolation_proven') is False and
         route.get('guest_ping_executed') is False and
         route.get('test_packets_injected') is False, 'r423_source_changed')
    need(type(intent) is dict and intent.get('schema') == r423.INTENT_SCHEMA and
         intent.get('source_r422_report_sha256') == R422_PIN and
         intent.get('exact_paths') == list(r423.READ_PATHS) and
         intent.get('p8_operational') == 'NO-GO' and
         intent.get('no_packet_generators') is True, 'r423_intent_invalid')
    obs=witness['capture_files']
    need(all(obs[key]['observed']['frames'] == 0 for key in ('tap','bridge')) and
         witness['guest_agent_evidence']['exit'].get('transmitted') == 1 and
         witness['guest_agent_evidence']['exit'].get('received') == 0,
         'r422_observation_changed')
    return {
        'source_kind': 'REAL_READONLY_SSH_SNAPSHOT',
        'r422_report_sha256':R422_PIN, 'r423_report_sha256':R423_PIN,
        'route':route['guest_route_state'], 'arp':route['guest_arp_state'],
        'tx_snapshot':route['guest_tx_packets_snapshot'],
        'rx_snapshot':route['guest_rx_packets_snapshot'],
        'tap_frames_r422':obs['tap']['observed']['frames'],
        'bridge_frames_r422':obs['bridge']['observed']['frames'],
        'guest_ping_reported_transmitted_r422':1,
        'isolation_proven':False, 'p8_operational':'NO-GO',
    }


def make_bundle(physical:dict[str,Any], report:dict[str,Any]) -> dict[str,Any]:
    need(type(physical) is dict and physical.get('r422_report_sha256') == R422_PIN and
         physical.get('r423_report_sha256') == R423_PIN and
         physical.get('source_kind') == 'REAL_READONLY_SSH_SNAPSHOT' and
         physical.get('p8_operational') == 'NO-GO' and
         physical.get('isolation_proven') is False and
         physical.get('route') == 'DIRECT_ENS3_EXPECTED' and
         physical.get('arp') in ('ABSENT','INCOMPLETE','RESOLVED') and
         all(type(physical.get(k)) is int and 0 <= physical[k] <= 2**64-1 for k in
             ('tx_snapshot','rx_snapshot')) and
         physical.get('tap_frames_r422') == 0 and
         physical.get('bridge_frames_r422') == 0 and
         physical.get('guest_ping_reported_transmitted_r422') == 1,
         'physical_evidence_contract')
    dashboard_tui.validate_dashboard_report(report)
    development_cycle.verify_development_cycle(report)
    need(report['p8_operational'] == 'NO-GO' and
         report['operational_dispatch'] is False and
         report['vm_checks_executed'] is False and
         report['final_risk'] is None and
         report['a9']['published_generation'] is None,
         'development_claims_operational_authority')
    stages=report['a10']['stages']
    need(type(stages) is list and len(stages)==10 and
         tuple(row['algorithm'] for row in stages) == STAGES and
         all(type(row.get(k)) is str for row in stages for k in ('source','status','detail')),
         'development_stages_invalid')
    # R43: un intento benigno LOCAL confirmado no se etiqueta como 'solo
    # sintetico'. Mantener intacta la identidad del bundle preview R42.4.
    local = report.get('source_kind') == 'SYNTHETIC_AND_LOCAL_BENIGN_ONLY'
    need(report.get('source_kind') in (None,'SYNTHETIC_FIXTURE_ONLY',
             'SYNTHETIC_AND_LOCAL_BENIGN_ONLY'), 'development_source_unknown')
    if local:
        need(report['r27']['a5_state'] == 'RECORDED_LIMITED' and
             report['r27']['a5_start_count'] == 1 and
             report['a9']['durable_local_receipt'] is True and
             stages[4]['source'] == 'LOCAL_BENIGN_FIXTURE' and
             stages[4]['status'] == 'RECORDED_LIMITED' and
             stages[5]['source'] == 'LOCAL_BENIGN_FIXTURE' and
             stages[5]['status'] == 'ND' and
             stages[8]['source'] == 'DEVELOPMENT_LOCAL_RECEIPT_ONLY',
             'local_benign_provenance_invalid')
    development_kind = ('SYNTHETIC_AND_LOCAL_BENIGN_A1_A10_DEVELOPMENT_ONLY'
                        if local else 'SYNTHETIC_A1_A10_DEVELOPMENT_ONLY')
    doc={
        'schema':SCHEMA,'source_main':MAIN_PIN,
        'physical':dict(physical),
        'development':{'source_kind':development_kind,
                       'session_id':report['session_id'],
                       'report_sha256':report['sha256'],
                       'stages':[dict(row) for row in stages]},
        'positive_destination_witness':False,
        'real_pentesting_executed':False,
        'technical_truth_accredited':False,
        'isolation_proven':False,'operational_dispatch':False,
        'published_generation':None,'final_risk':None,
        'p8_operational':'NO-GO',
    }
    if local:
        doc['development']['local_benign_attempt'] = {
            'state':'RECORDED_LIMITED', 'start_count':1,
            'source':'LOCAL_BENIGN_FIXTURE',
            'technical_truth_accredited':False}
    return seal(doc)


def build(r422_dir:Path,r423_dir:Path,fixture:Path)->dict[str,Any]:
    physical=read_physical(r422_dir,r423_dir)
    scenario=demo_session.read_fixed_scenario(fixture)
    cycle=development_cycle.build_development_cycle(scenario)
    return make_bundle(physical,cycle)


def verify_bundle(doc:dict[str,Any])->bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         len(doc['sha256'])==64 and
         doc['sha256']==sha256(r41.canon({k:v for k,v in doc.items() if k!='sha256'})).hexdigest(),
         'bundle_digest_invalid')
    need(doc.get('schema')==SCHEMA and doc.get('source_main')==MAIN_PIN and
         doc.get('p8_operational')=='NO-GO' and
         all(doc.get(k) is False for k in
             ('positive_destination_witness','real_pentesting_executed',
              'technical_truth_accredited','isolation_proven','operational_dispatch')) and
         doc.get('published_generation') is None and doc.get('final_risk') is None,
         'bundle_false_authority')
    p=doc.get('physical'); d=doc.get('development')
    need(type(p) is dict and p.get('source_kind')=='REAL_READONLY_SSH_SNAPSHOT' and
         p.get('r422_report_sha256')==R422_PIN and
         p.get('r423_report_sha256')==R423_PIN and p.get('isolation_proven') is False and
         p.get('p8_operational')=='NO-GO' and
         p.get('route')=='DIRECT_ENS3_EXPECTED' and
         p.get('arp') in ('ABSENT','INCOMPLETE','RESOLVED') and
         all(type(p.get(k)) is int and 0<=p[k]<=2**64-1 for k in
             ('tx_snapshot','rx_snapshot')) and
         p.get('tap_frames_r422')==0 and p.get('bridge_frames_r422')==0 and
         p.get('guest_ping_reported_transmitted_r422')==1,
         'bundle_physical_invalid')
    need(type(d) is dict and d.get('source_kind') in (
             'SYNTHETIC_A1_A10_DEVELOPMENT_ONLY',
             'SYNTHETIC_AND_LOCAL_BENIGN_A1_A10_DEVELOPMENT_ONLY') and
         type(d.get('session_id')) is str and d['session_id']=='DEV_TUTOR_001' and
         type(d.get('report_sha256')) is str and len(d['report_sha256'])==64 and
         type(d.get('stages')) is list and len(d['stages'])==10 and
         tuple(x.get('algorithm') for x in d['stages'])==STAGES and
         all(type(x) is dict and all(type(x.get(k)) is str for k in
             ('source','status','detail')) for x in d['stages']),
         'bundle_development_invalid')
    marker=d.get('local_benign_attempt')
    if d['source_kind']=='SYNTHETIC_AND_LOCAL_BENIGN_A1_A10_DEVELOPMENT_ONLY':
        need(marker == {'state':'RECORDED_LIMITED', 'start_count':1,
                        'source':'LOCAL_BENIGN_FIXTURE',
                        'technical_truth_accredited':False} and
             d['stages'][4]['status']=='RECORDED_LIMITED' and
             d['stages'][4]['source']=='LOCAL_BENIGN_FIXTURE' and
             d['stages'][5]['status']=='ND' and
             d['stages'][5]['source']=='LOCAL_BENIGN_FIXTURE' and
             d['stages'][8]['source']=='DEVELOPMENT_LOCAL_RECEIPT_ONLY',
             'bundle_local_benign_boundary_invalid')
    else:
        need(marker is None and 'local_benign_attempt' not in d,
             'legacy_preview_cannot_claim_local_execution')
    return True


def lines(doc:dict[str,Any],selected:int=0,width:int=104)->list[str]:
    verify_bundle(doc)
    need(type(selected) is int and 0<=selected<10,'tui_selection_invalid')
    need(type(width) is int and 40<=width<=300,'tui_width_invalid')
    p=doc['physical'];d=doc['development']
    full=[
        'ARDREC  |  EVIDENCIA FISICA SSH + A1-A10 DE DESARROLLO',
        'P8 NO-GO  |  Pentesting real NO EJECUTADO  |  Aislamiento NO PROBADO',
        '',
        'SSH FISICO (RECIBOS R42.2 / R42.3; NO EN VIVO)',
        f"Ruta: {p['route']}  |  ARP: {p['arp']}",
        f"ens3 TX: {p['tx_snapshot']}  |  ens3 RX: {p['rx_snapshot']} (fotografia posterior)",
        'PCAP R42.2: TAP=0, BRIDGE=0  |  ping reporto 1 enviado, 0 recibido',
        '',
        'A1-A10 (DESARROLLO SINTETICO; NO RESULTADOS DE VM)',
    ]
    for i,row in enumerate(d['stages']):
        sign='>' if i==selected else ' '
        full.append(f"{sign} {row['algorithm']:<3} {row['status']:<35} {row['source']}")
    full+=['','DETALLE SELECCIONADO: '+d['stages'][selected]['algorithm'],
           d['stages'][selected]['detail'],
           '', 'q: salir  |  j/k o flechas: cambiar algoritmo',
           'La vista NO otorga habilitacion operativa. Recibos privados fuera de Git.']
    return [text[:width] for text in full]


def run_tui(doc:dict[str,Any])->None:
    verify_bundle(doc)
    def app(stdscr:Any)->None:
        stdscr.keypad(True)
        curses.curs_set(0)
        selected=0
        while True:
            stdscr.erase()
            height,width=stdscr.getmaxyx()
            if height<22 or width<70:
                msg='Terminal minima: 70 columnas x 22 filas (q para salir)'
                stdscr.addnstr(0,0,msg,max(1,width-1))
            else:
                for i,line in enumerate(lines(doc,selected,min(300,width-1))[:height-1]):
                    stdscr.addnstr(i,0,line,max(1,width-1))
            stdscr.refresh()
            key=stdscr.getch()
            if key in (ord('q'),ord('Q'),27):return
            if key in (curses.KEY_DOWN,ord('j')):selected=(selected+1)%10
            if key in (curses.KEY_UP,ord('k')):selected=(selected-1)%10
    curses.wrapper(app)
