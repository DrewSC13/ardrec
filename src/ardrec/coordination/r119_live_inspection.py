"""R119: observabilidad operacional basada en capturas READONLY, no autorizador.

R115-F5 lee el estado *real* de libvirt, nftables y filtros mediante comandos
predefinidos (sudo -n - sin shell). R119 lo vincula a la TUI R38 existente,
y, opcionalmente, a un diario R115-F13/F14 ya existente de FTP-T01.

NUNCA arranca invitadas, abre sockets, firma permisos, admite A6 ni publica A9.
La frescura de la lectura no convierte un estado DENY en permiso de tráfico.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import sys

from ardrec.coordination import r115_dev_admission_contract as contract
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r118_postmerge_gate as r118
from ardrec.coordination import dashboard_tui as tui

SCHEMA = 'ARDREC-R119-LIVE-READONLY-A1-A10-VIEW-v1'
SRC = 'R119_REAL_HOST_CAPTURE_READONLY_NOT_RUNTIME_AUTHORITY'
MAX_CAPTURE = 8 * 1024 * 1024
MAX_REPORT = 32768
HEX = re.compile(r'[a-f0-9]{64}\Z')
CLOSURE = Path('lab/operational-controller/r117-f5b-physical-closure-v3.json')
CATALOG = Path('lab/operational-catalog-v1/catalog.json')


class Stop(ValueError):
    """No se puede presentar la captura como resultado verificable."""


def need(test, code):
    if not test:
        raise Stop(code)


def check_closure(raw):
    try:
        c = r118.closure_status(raw)
    except (r118.Stop, ValueError, TypeError) as exc:
        raise Stop('HISTORICAL_F5B_CLOSURE_NOT_VERIFIED') from exc
    return {'closure_sha256': contract.digest(raw),
            'candidate_sha256': c['candidate_sha256'],
            'historical_scope': c['closure_scope'],
            'runtime_installation_attested_now': False}


def _private_regular(path: Path, max_bytes: int) -> bytes:
    need(isinstance(path, Path) and path.is_absolute(), 'RECEIPT_PATH_NOT_ABSOLUTE')
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
         0 < st.st_size <= max_bytes, 'RECEIPT_FILE_UNTRUSTED')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        actual = os.fstat(fd)
        need((actual.st_dev, actual.st_ino, actual.st_size, actual.st_uid) ==
             (st.st_dev, st.st_ino, st.st_size, st.st_uid), 'RECEIPT_RACE')
        raw = os.read(fd, max_bytes + 1)
        need(len(raw) == st.st_size, 'RECEIPT_SIZE_CHANGED')
        after = os.fstat(fd)
        need(after.st_size == actual.st_size and
             after.st_mtime_ns == actual.st_mtime_ns and
             after.st_ctime_ns == actual.st_ctime_ns, 'RECEIPT_MUTATED')
        return raw
    finally:
        os.close(fd)


def replay_capture(folder: Path):
    """Lee exclusivamente el recibo privado intacto de R115-F5."""
    need(isinstance(folder, Path) and folder.is_absolute() and
         folder.parent == f5.ROOT and folder.name.startswith('capture-'),
         'CAPTURE_ROOT_OUTSIDE_F5')
    f13.private_directory(folder.parent)
    f13.private_directory(folder)
    need({p.name for p in folder.iterdir()} ==
         {'capture.json', 'report.json', 'manifest.json'}, 'RECEIPT_ENTRY_SET')
    blobs = {name: _private_regular(folder / name, MAX_CAPTURE if name == 'capture.json' else MAX_REPORT)
             for name in ('capture.json', 'report.json', 'manifest.json')}
    documents = {}
    for name, raw in blobs.items():
        obj = contract.load(raw) if len(raw) <= 200000 else _decode_large(raw)
        need(contract.canonical(obj) == raw, 'RECEIPT_NOT_CANONICAL_'+name)
        documents[name] = obj
    manifest = documents['manifest.json']
    need(type(manifest) is dict and set(manifest) ==
         {'schema', 'files_sha256', 'scope'} and
         manifest['schema'] == 'ARDREC-R115-F5-RECEIPT-v1' and
         manifest['scope'] == 'READ_ONLY_NO_DISPATCH_NO_AUTHORITY' and
         manifest['files_sha256'] == {k: contract.digest(blobs[k]) for k in ('capture.json','report.json')},
         'RECEIPT_MANIFEST_NOT_AUTHENTICATED')
    capture = documents['capture.json']
    try:
        actual = f5.report(capture)
    except (f5.Stop, ValueError, KeyError, TypeError, OSError) as exc:
        raise Stop('F5_REPLAY_NOT_VERIFIABLE') from exc
    need(contract.canonical(actual) == blobs['report.json'], 'F5_REPORT_MISMATCH')
    return capture, actual


def _decode_large(raw):
    """F5 capture can exceed F1 200KiB: preserve duplicate-key protections."""
    import json
    need(type(raw) is bytes and len(raw) <= MAX_CAPTURE, 'CAPTURE_TOO_LARGE')
    try:
        doc = json.loads(raw, object_pairs_hook=contract.unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE')))
    except (UnicodeError, ValueError, RecursionError, TypeError) as exc:
        raise Stop('CAPTURE_INVALID_JSON') from exc
    need(type(doc) is dict, 'CAPTURE_NOT_OBJECT')
    return doc


def _a5_case(folder: Path | None, raw_catalog: bytes):
    if folder is None:
        return None
    try:
        result = f14.build(folder, raw_catalog)
        need(result['a6'] == 'ND' and result['p8'] == 'NO-GO' and
             result['physical_origin_attested'] is False and
             result['accepted_support_count'] == 0 and
             result['a9_published_generation'] is None, 'A5_CANDIDATE_PROMOTION')
    except (f14.Stop, f13.Stop, OSError, ValueError, TypeError, KeyError) as exc:
        raise Stop('F13_F14_A5_CANDIDATE_REJECTED') from exc
    return {'source_case_key': result['source_case_key'],
            'case_id': result['case_id'], 'family_id': result['family_id'],
            'journal_status': result['source_status'],
            'candidate_outcome': result['candidate_outcome'],
            'complete_220_candidate': result['candidate_complete_220'],
            'source_reservation_sha256': result['source_reservation_sha256'],
            'candidate_sha256': result['source_f10_sha256'],
            'a6': 'ND', 'source_attested': False, 'a9_generation': None}


def _pinned_service_catalog(raw: bytes) -> dict:
    """Proyección TUI del catálogo P7 fijado: metadatos, nunca permiso de prueba."""
    need(contract.digest(raw) == f14.CATALOG_SHA256, 'PINNED_P7_CATALOG_MISMATCH')
    try:
        source = json.loads(raw, object_pairs_hook=contract.unique_pairs)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Stop('PINNED_CATALOG_JSON_INVALID') from exc
    want = {'ssh': 8, 'ftp': 8, 'smb': 9}
    need(type(source) is dict and source.get('counts') == {**want, 'total': 25} and
         source.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         source.get('execution_enabled') is False and
         source.get('catalog_frozen') is False and
         type(source.get('families')) is list and len(source['families']) == 25,
         'PINNED_CATALOG_UNEXPECTED')
    groups = {service: [] for service in want}
    fields = ('id', 'source_table', 'condition_es', 'minimum_action_es',
              'interpretation_boundary_es')
    for family in source['families']:
        need(type(family) is dict and family.get('protocol') in groups and
             all(type(family.get(k)) is str and 0 < len(family[k]) <= 320 for k in fields) and
             all(type(family.get(k)) is list and
                 all(type(v) is str and v for v in family[k])
                 for k in ('preconditions', 'required_supports')),
             'PINNED_CATALOG_FAMILY_INVALID')
        groups[family['protocol']].append({k: family[k] for k in fields} | {
            'preconditions': list(family['preconditions']),
            'required_supports': list(family['required_supports'])})
    for service, count in want.items():
        need(len(groups[service]) == count and
             [f['id'] for f in groups[service]] ==
             [f'{service.upper()}-T{i:02}' for i in range(1, count + 1)],
             'PINNED_CATALOG_FAMILY_SEQUENCE')
    return {'sha256': contract.digest(raw),
            'status': source['status'],
            'execution_enabled': False,
            'catalog_frozen': False,
            'counts': dict(want), 'families': groups}


def build(capture: dict, *, closure_raw: bytes, catalog_raw: bytes,
          now: datetime, mode: str, a5_case_folder: Path | None = None) -> dict:
    """Genera una vista a partir de una captura, sin modificar evidencia ni estado."""
    need(mode in ('F5_LIVE_CAPTURE', 'F5_PRIVATE_RECEIPT_REPLAY'), 'MODE_INVALID')
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'CLOCK_UNTRUSTED')
    need(type(catalog_raw) is bytes and contract.digest(catalog_raw) == f14.CATALOG_SHA256,
         'PINNED_P7_CATALOG_MISMATCH')
    closure = check_closure(closure_raw)
    service_catalog = _pinned_service_catalog(catalog_raw)
    try:
        host = f5.report(capture)
    except (f5.Stop, OSError, ValueError, TypeError, KeyError) as exc:
        raise Stop('F5_CAPTURE_REJECTED') from exc
    # f5 uses the existing R115 timestamp validator; replay time is not a live attestation.
    from ardrec.coordination import r115_f4_effective_deny_readback as f4
    captured_at = f4.f3.time_utc(capture['end'], 'R119_END')
    age = (now.astimezone(timezone.utc) - captured_at).total_seconds()
    fresh = mode == 'F5_LIVE_CAPTURE' and -2 <= age <= 120
    a5 = _a5_case(a5_case_folder, catalog_raw)
    blockers = ['P7_DRAFT_NOT_FROZEN',
                'CURRENT_P8_AUTHORITY_AND_REVOCATION_NOT_ATTESTED',
                'A6_INDEPENDENT_PHYSICAL_SUPPORT_NOT_ADMITTED',
                'A9_NEW_GENERATION_NOT_PUBLISHED']
    if not fresh:
        blockers.append('CAPTURE_REPLAY_OR_NOT_FRESH')
    if host['lifecycle_stage'] not in ('OFFLINE_DENY_BASELINE_MATCH',
                                      'RUNNING_SIX_DENY_BINDINGS_MATCH'):
        blockers.append('R115_F5_LIFECYCLE_NOT_VERIFIED')
    if host['nft'] != 'MATCH' or host['helper'] != 'MATCH' or host['f11_hook'] != 'MATCH':
        blockers.append('F11_R34_CURRENT_DENY_UNVERIFIED')
    if any(x != 'MATCH' for x in host['vm_definitions'].values()):
        blockers.append('VM_DEFINITION_UNVERIFIED')
    if a5 is None:
        blockers.append('A5_JOURNAL_NOT_SELECTED')
    else:
        blockers.append('A5_F13_CANDIDATE_NOT_PROVEN_PHYSICAL')
    if host['states']['ftp'] == 'OFF' or host['states']['runner'] == 'OFF':
        blockers.append('FTP_OR_RUNNER_OFFLINE')
    # No runtime permit can be derived from a source closure or capture.
    a5_status = a5['journal_status'] if a5 is not None else 'NOT_SELECTED'
    labels = [
        ('NOT_AUTHENTICATED', 'A1 verified rules unavailable to the host capture'),
        ('SOURCE_ONLY', 'F5B V3 source closure pinned; not live installation proof'),
        ('NO_GO', f"F5 lifecycle {host['lifecycle_stage']}; A3 signed scope ND"),
        ('NOT_ELIGIBLE', 'No A4 dispatch while current P8 is NO-GO'),
        (a5_status, 'F13/F14 journal review only; does not create a new socket'),
        ('ND', 'No independently admitted physical evidence'),
        ('RF_ND', 'No recalculated confirmed risk from the capture'),
        ('NOT_APPLIED', 'No A8 state mutation'),
        ('NOT_PUBLISHED', 'No new A9 confirmed generation'),
        ('READONLY_'+('LIVE' if fresh else 'REPLAY'), 'Real-host capture reader; no traffic or guest start'),
    ]
    stages = [{'algorithm': 'A'+str(i), 'status': s,
               'source': 'R115-F5' if i in (3, 10) else
                         'R115-F13/F14' if i == 5 else 'R119-READONLY',
               'detail': detail} for i,(s,detail) in enumerate(labels, 1)]
    data = {'capture_sha256': contract.digest(contract.canonical(capture)),
            'captured_at_utc': captured_at.isoformat().replace('+00:00', 'Z'),
            'replay_mode': mode, 'captured_fresh_for_display': fresh,
            'age_seconds_at_render': int(age),
            'host': host, 'source': closure, 'a5': a5,
            'catalog': service_catalog,
            'blockers': sorted(set(blockers)),
            'current_operational_authority_attested': False,
            'p7_catalog_frozen': False,
            'connections_by_r119': 0, 'guest_starts_by_r119': 0,
            'firewall_changes_by_r119': 0}
    report = {'schema': SCHEMA, 'source_kind': SRC,
              'session_id': 'R119_LIVE_HOST_READONLY',
              'p8_operational': 'NO-GO', 'operational_dispatch': False,
              'vm_checks_executed': False,  # TUI did no checks: capture was separate.
              'final_risk': None, 'a9': {'published_generation': None},
              'a10': {'stages': stages}, 'r119_live': data}
    report['sha256'] = contract.digest(contract.canonical(report))
    return report


def verify_view(report):
    """Enforce safe invariant for this view; source authenticity is intake-only."""
    need(type(report) is dict and report.get('schema') == SCHEMA and
         report.get('source_kind') == SRC and
         report.get('p8_operational') == 'NO-GO' and
         report.get('operational_dispatch') is False and
         report.get('vm_checks_executed') is False and
         report.get('final_risk') is None and
         report.get('a9') == {'published_generation': None} and
         type(report.get('r119_live')) is dict, 'VIEW_SCHEMA')
    data = report['r119_live']
    need(type(data.get('capture_sha256')) is str and HEX.fullmatch(data['capture_sha256']),
         'VIEW_CAPTURE_SHA')
    need(data.get('current_operational_authority_attested') is False and
         data.get('p7_catalog_frozen') is False and
         data.get('connections_by_r119') == 0 and
         data.get('guest_starts_by_r119') == 0 and
         data.get('firewall_changes_by_r119') == 0 and
         data.get('host', {}).get('p8') == 'NO-GO' and
         data.get('host', {}).get('a6') == 'ND' and
         type(data.get('blockers')) is list and data['blockers'] and
         report.get('sha256') == contract.digest(contract.canonical({k:v for k,v in report.items() if k!='sha256'})),
         'VIEW_NOT_FAIL_CLOSED')
    host = data['host']
    need(type(host) is dict and set(host.get('states', {})) == set(f5.VMS) and
         type(host.get('lifecycle_stage')) is str and
         host['lifecycle_stage'] in ('OFFLINE_DENY_BASELINE_MATCH',
                                     'RUNNING_SIX_DENY_BINDINGS_MATCH',
                                     'DRIFT_NO_GO', 'INCOMPLETE_OR_TRANSITION_NO_GO'),
         'VIEW_HOST_SCHEMA')
    # Una vista de navegación P7 no acredita disponibilidad operacional.
    catalog = data.get('catalog')
    need(type(catalog) is dict and
         catalog.get('sha256') == f14.CATALOG_SHA256 and
         catalog.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         catalog.get('execution_enabled') is False and
         catalog.get('catalog_frozen') is False and
         catalog.get('counts') == {'ssh': 8, 'ftp': 8, 'smb': 9} and
         type(catalog.get('families')) is dict and
         set(catalog['families']) == {'ssh', 'ftp', 'smb'},
         'VIEW_CATALOG_UNTRUSTED')
    for service, amount in catalog['counts'].items():
        families = catalog['families'][service]
        need(type(families) is list and len(families) == amount and
             [v.get('id') for v in families if type(v) is dict] ==
             [f'{service.upper()}-T{i:02}' for i in range(1, amount + 1)],
             'VIEW_CATALOG_FAMILY_SET')
        for family in families:
            need(all(type(family.get(k)) is str for k in
                     ('source_table', 'condition_es', 'minimum_action_es',
                      'interpretation_boundary_es')) and
                 all(type(family.get(k)) is list and
                     all(type(v) is str for v in family[k])
                     for k in ('preconditions', 'required_supports')),
                 'VIEW_CATALOG_FAMILY_FIELDS')
    case = data.get('a5')
    if case is not None:
        need(type(case) is dict and case.get('a6') == 'ND' and
             case.get('source_attested') is False and
             case.get('a9_generation') is None and
             case.get('journal_status') in (
                 'RESERVED_NO_RETRY', 'ATTEMPT_CONSUMED_UNRESOLVED',
                 'RESULT_CANDIDATE_ONLY', 'FAILED_NO_RETRY'),
             'VIEW_A5_CANDIDATE_INVALID')
    need(type(report.get('a10')) is dict and
         type(report['a10'].get('stages')) is list and
         len(report['a10']['stages']) == 10, 'VIEW_STAGE_COUNT')
    statuses = ['NOT_AUTHENTICATED', 'SOURCE_ONLY', 'NO_GO',
                'NOT_ELIGIBLE', case['journal_status'] if case else 'NOT_SELECTED',
                'ND', 'RF_ND', 'NOT_APPLIED', 'NOT_PUBLISHED',
                'READONLY_LIVE' if data.get('captured_fresh_for_display') is True
                else 'READONLY_REPLAY']
    for i, (stage, status) in enumerate(zip(report['a10']['stages'], statuses), 1):
        need(type(stage) is dict and stage.get('algorithm') == 'A'+str(i) and
             stage.get('status') == status and
             type(stage.get('detail')) is str and
             type(stage.get('source')) is str, 'VIEW_STAGE_INVALID')
    need(type(data.get('replay_mode')) is str and
         data['replay_mode'] in ('F5_LIVE_CAPTURE','F5_PRIVATE_RECEIPT_REPLAY') and
         (data['replay_mode'] == 'F5_LIVE_CAPTURE' or
          data.get('captured_fresh_for_display') is False),
         'VIEW_CAPTURE_MODE_INVALID')
    return True


def _read_baseline(repo: Path):
    need(repo.resolve() == Path('/home/cicada/Development/GitHub/ardrec') or
         (repo / CLOSURE).is_file(), 'REPO_BASELINE_MISSING')
    closure_raw = (repo / CLOSURE).read_bytes()
    catalog_raw = (repo / CATALOG).read_bytes()
    return closure_raw, catalog_raw


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='ARDREC R119: lectura VM/F11/F13 a TUI R38, NO-GO')
    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument('--capturar', action='store_true', help='real host read-only R115-F5')
    action.add_argument('--reproducir', type=Path, metavar='RECIBO_F5', help='historical private F5 capture')
    out = p.add_mutually_exclusive_group(required=True)
    out.add_argument('--texto', action='store_true')
    out.add_argument('--tui', action='store_true')
    p.add_argument('--caso-a5', type=Path, help='optional R115-F13 private case journal')
    p.add_argument('--repo', type=Path, default=Path.cwd())
    args = p.parse_args(argv)
    try:
        need(os.geteuid() != 0, 'ROOT_INTERACTIVE_FORBIDDEN')
        closure, catalog = _read_baseline(args.repo)
        if args.capturar:
            capture = f5.capture()
            host = f5.report(capture)
            folder = f5.save_private(capture, host)
            mode = 'F5_LIVE_CAPTURE'
        else:
            folder = args.reproducir
            capture, host = replay_capture(folder)
            mode = 'F5_PRIVATE_RECEIPT_REPLAY'
        view = build(capture, closure_raw=closure, catalog_raw=catalog,
                     mode=mode, now=datetime.now(timezone.utc),
                     a5_case_folder=args.caso_a5)
        need(view['r119_live']['host'] == host, 'HOST_REPLAY_DRIFT')
        verify_view(view)
        tui.validate_dashboard_report(view)
    except (Stop, f5.Stop, f13.Stop, f14.Stop, contract.Rejected,
            OSError, ValueError, TypeError, KeyError) as exc:
        print('R119_STOP=' + str(exc), file=sys.stderr)
        return 2
    print('R119_CAPTURE_ROOT='+str(folder))
    print('R119_CAPTURE_SHA256='+view['r119_live']['capture_sha256'])
    print('R119_CAPTURE_MODE='+mode)
    print('R119_LIFECYCLE='+host['lifecycle_stage'])
    for role, state in sorted(host['states'].items()):
        print('R119_VM_'+role.upper()+'='+state)
    print('R119_F11_R34='+host['nft']+'/'+host['helper']+'/'+host['f11_hook'])
    print('R119_A5='+view['a10']['stages'][4]['status'])
    print('R119_A6=ND')
    print('R119_RF=ND')
    print('R119_A9=NOT_PUBLISHED')
    print('R119_P8=NO-GO')
    print('R119_BLOCKERS='+','.join(view['r119_live']['blockers']))
    if args.tui:
        try:
            tui.run_dashboard_tui(view)
        except (RuntimeError, KeyboardInterrupt) as exc:
            print('R119_TUI_STOP='+str(exc), file=sys.stderr)
            return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
