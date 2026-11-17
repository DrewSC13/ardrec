#!/usr/bin/env python3
"""R60-E1: ejecuta tres contratos offline existentes y reconcilia sus salidas.

No implementa pruebas físicas ni acredita vinculación de casos entre contratos.
Solo lectura del checkout; escribe evidencia privada fuera del repositorio.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

REPO = Path('/home/cicada/Development/GitHub/ardrec')
LAB = Path('/home/cicada/ardrec-lab')
BASE = 'ce9478eb04fb9e6607af534fa415542e7cbf24cd'
SCHEMA = 'ardrec-r60e1-offline-integration-report-v1'
MAX_OUTPUT = 1_500_000
KNOWN_NEW = frozenset({
    'scripts/ardrec_p14_r60e1_integracion_offline.py',
    'lab/tests/test_p14_r60e1_integracion_offline.py',
    'docs/development/p14-r60e1-integracion-offline.md',
})
GIT_PINS = {
    'scripts/ardrec_p14_r58k_unified_family_demo.py': 'a04cd14b9268386f5b5669974c84f3d0aee3a36b',
    'scripts/ardrec_p14_r58v_a5_a6_handoff_demo.py': 'ba93ef747451748b1a0db6b115258ed44e52e16d',
    'scripts/ardrec_p14_r58o_a1_a10_trace_demo.py': 'c5e417d687061c46dd826c45bb387b9984dfe977',
    'lab/operational-catalog-v1/catalog.json': '1f201f5559b589933e3dad3ac76de3d2e37a246d',
    'lab/p14-r26-session-v1/scenario.json': 'cf64c0a279700e41c1719b5842540b03938338d6',
}
DEMOS = (
    ('R58K', 'scripts/ardrec_p14_r58k_unified_family_demo.py'),
    ('R58V', 'scripts/ardrec_p14_r58v_a5_a6_handoff_demo.py'),
    ('R58O', 'scripts/ardrec_p14_r58o_a1_a10_trace_demo.py'),
)
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


class Blocked(ValueError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise Blocked(code)


def canonical(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes) -> dict:
    need(len(raw) <= MAX_OUTPUT, 'DEMO_OUTPUT_SIZE')
    def pairs(rows):
        d = {}
        for k, v in rows:
            need(k not in d, 'JSON_DUPLICATE_KEY')
            d[k] = v
        return d
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                         parse_constant=lambda v: (_ for _ in ()).throw(Blocked('NONFINITE')))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Blocked('INVALID_DEMO_JSON') from exc
    need(type(obj) is dict, 'DEMO_JSON_NOT_OBJECT')
    return obj


def finite_hex(value: Any) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def validate_k(doc: dict) -> dict:
    need(doc.get('unit_count') == 29 and type(doc['unit_count']) is int, 'K_UNITS_NOT_29_FIXTURE')
    need(doc.get('covered_family_count') == 25, 'K_FAMILY_COVERAGE')
    need(doc.get('count_by_service') == {'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11}, 'K_SERVICE_COUNTS')
    need(doc.get('a6_classification') == 'ND', 'K_A6_FALSE_CLAIM')
    need(doc.get('confirmed_final_risk') is None and doc.get('published_generation') is None,
         'K_RISK_PUBLICATION_FALSE_CLAIM')
    need(doc.get('p8_operational') == 'NO-GO', 'K_P8_FALSE_CLAIM')
    need(doc.get('technical_truth_accredited') in (None, False), 'K_TECHNICAL_TRUTH')
    need(doc.get('a8_applied_transition') is None, 'K_APPLIED_TRANSITION')
    decisions = doc.get('decisions')
    need(type(decisions) is list and len(decisions) == 29, 'K_DECISION_COUNT')
    ids = set()
    for d in decisions:
        need(type(d) is dict and d.get('a6_classification') == 'ND', 'K_DECISION_A6')
        need(d.get('a8_recommendation') == 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
             'K_A8_RECOMMENDATION')
        need(type(d.get('service_id')) is str and type(d.get('derived_case_id')) is str,
             'K_CASE_IDENTITY')
        ident = (d['service_id'], d['derived_case_id'], d.get('variant'))
        need(ident not in ids, 'K_DUPLICATE_CASE_VARIANT')
        ids.add(ident)
    need(finite_hex(doc.get('sha256')) and finite_hex(doc.get('catalog_sha256')) and
         finite_hex(doc.get('a6_a7_a8_bridge_sha256')), 'K_SOURCE_DIGESTS')
    return {'case_count':29, 'families':25, 'service_counts':doc['count_by_service'],
            'sha256':doc['sha256'], 'catalog_sha256':doc['catalog_sha256'],
            'a6_a7_a8_bridge_sha256':doc['a6_a7_a8_bridge_sha256']}


def validate_v(doc: dict) -> dict:
    need(doc.get('case_count') == 29 and type(doc['case_count']) is int, 'V_UNITS_NOT_29_FIXTURE')
    need(doc.get('family_count') == 25, 'V_FAMILY_COVERAGE')
    need(doc.get('source_denials_preserved') is True, 'V_SOURCE_DENIALS')
    need(doc.get('source_t1_unchanged') is True and doc.get('source_overlay_unchanged') is True,
         'V_SOURCE_INTEGRITY')
    need(doc.get('a5_intents_submitted') == 0 and doc.get('a5_attempts_reserved') == 0 and
         doc.get('a5_attempts_started') == 0 and doc.get('a6_accredited_evidence_count') == 0,
         'V_REAL_ATTEMPT_OR_EVIDENCE')
    need(doc.get('a6_classification') == 'ND' and doc.get('p8_operational') == 'NO-GO',
         'V_A6_OR_P8_CLAIM')
    need(doc.get('confirmed_final_risk') is None and doc.get('published_generation') is None,
         'V_RISK_OR_GENERATION')
    need(doc.get('operational_dispatch') is False and doc.get('operational_transitions_applied') == 0,
         'V_DISPATCH_OR_TRANSITIONS')
    need(doc.get('handoff_verification') == 'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6',
         'V_HANDOFF_REOPEN')
    need(finite_hex(doc.get('sha256')), 'V_SOURCE_DIGEST')
    return {'case_count':29, 'families':25, 'sha256':doc['sha256'],
            'model_handoff_verified':True, 'actual_attempts':0}


def validate_o(doc: dict) -> dict:
    need(doc.get('stage_count') == 10 and type(doc['stage_count']) is int,
         'O_STAGE_COUNT')
    need(doc.get('stages') == ['A'+str(i) for i in range(1,11)], 'O_STAGE_ORDER')
    need(doc.get('a1_a3_service_count') == 3 and doc.get('a1_a3_event_count') == 9,
         'O_SERVICE_FIXTURE')
    need(doc.get('a4_a8_case_count') == 29 and doc.get('a4_a8_family_count') == 25,
         'O_CASE_FIXTURE')
    need(doc.get('a5_local_fixture_start_intent_count') == 0, 'O_START_INTENT')
    need(doc.get('a9_local_declared_receipt_verified') is True, 'O_DECLARED_RECEIPT')
    for name in ('a1_a3_to_family_case_binding_attested','independent_physical_case_binding_attested',
                 'a1_a10_implementation_complete','experimental_hypothesis_validated',
                 'operational_dispatch'):
        need(doc.get(name) is False, 'O_FALSE_AUTHORITY_' + name)
    need(doc.get('confirmed_final_risk') is None and doc.get('published_generation') is None and
         doc.get('applied_state_transition') is None, 'O_APPLIED_OR_PUBLISHED')
    need(doc.get('a6_classification') == 'ND' and doc.get('p8_operational') == 'NO-GO',
         'O_A6_OR_P8')
    need(finite_hex(doc.get('sha256')) and finite_hex(doc.get('stage_ledger_head_sha256')),
         'O_SOURCE_DIGESTS')
    return {'stage_count':10, 'case_count':29, 'families':25,
            'sha256':doc['sha256'], 'stage_head_sha256':doc['stage_ledger_head_sha256'],
            'case_binding_attested':False}


def reconcile(results: dict) -> dict:
    need(set(results) == {'R58K','R58V','R58O'}, 'INCOMPLETE_SCOPES')
    k = validate_k(results['R58K'])
    v = validate_v(results['R58V'])
    o = validate_o(results['R58O'])
    need(k['case_count'] == v['case_count'] == o['case_count'] == 29, 'CROSS_COUNT_CASE')
    need(k['families'] == v['families'] == o['families'] == 25, 'CROSS_COUNT_FAMILIES')
    return {'scope': 'THREE_SEPARATE_SYNTHETIC_CONTRACTS_NOT_ONE_PHYSICAL_SESSION',
            'model_demo_case_count':29, 'model_case_capacity':54,
            'remaining_capacity_not_demonstrated':25,
            'families_in_demos':25, 'ten_stage_trace_present':True,
            'per_case_cross_contract_identity_attested':False,
            'a1_a10_full_execution_complete':False,
            'r34_f11_receipts_consumed':False,
            'a5_physical_attempts_accredited':0, 'a6_classification':'ND',
            'confirmed_final_risk':None, 'published_generation':None,
            'operational_dispatch':False, 'p8_operational':'NO-GO',
            'source_summaries':{'R58K':k,'R58V':v,'R58O':o}}


def git_read(repo: Path, args: list[str]) -> str:
    cp = subprocess.run(['git','-C',str(repo),*args], capture_output=True,
                        timeout=20, check=False)
    need(cp.returncode == 0 and len(cp.stdout) < 100000, 'GIT_COMMAND_FAILED')
    return cp.stdout.decode('utf-8', errors='strict').strip()


def validate_checkout(repo: Path) -> dict:
    need(repo == REPO and repo.is_dir() and Path.cwd().resolve() == REPO,
         'REPO_ROOT_MISMATCH')
    need(git_read(repo, ['rev-parse', 'HEAD']) == BASE, 'REPO_HEAD_MISMATCH')
    status = git_read(repo, ['status','--porcelain=v1','--untracked-files=all'])
    for row in status.splitlines():
        need(row.startswith('?? ') and row[3:] in KNOWN_NEW, 'REPO_STATUS_DRIFT')
    pins = {}
    for rel, expected in GIT_PINS.items():
        path = repo / rel
        need(path.is_file() and not path.is_symlink(), 'PINNED_SOURCE_ABSENT')
        observed = git_read(repo, ['hash-object', '--', rel])
        need(observed == expected, 'PINNED_GIT_BLOB_DRIFT:'+rel)
        pins[rel] = {'git_blob_sha1':observed, 'sha256':sha(path.read_bytes())}
    return pins


def private_root() -> Path:
    need(LAB.is_dir() and not LAB.is_symlink(), 'PRIVATE_LAB_DIR_MISSING')
    st = LAB.stat()
    need(st.st_uid == os.geteuid() and not (stat.S_IMODE(st.st_mode) & 0o077),
         'PRIVATE_LAB_PERMISSIONS')
    return LAB


def write_once(root: Path, name: str, data: bytes) -> Path:
    need('/' not in name and name not in ('.','..'), 'INVALID_EVIDENCE_NAME')
    path = root / name
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os,'O_NOFOLLOW',0), 0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        raise
    return path


def run_demo(repo: Path, name: str, script: str) -> dict:
    cmd = [sys.executable, '-I','-B',str(repo / script), '--synthetic-offline']
    try:
        cp = subprocess.run(cmd, cwd=repo, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=90, check=False)
    except subprocess.TimeoutExpired as exc:
        raise Blocked('DEMO_TIMEOUT_'+name) from exc
    need(cp.returncode == 0, 'DEMO_FAILED_'+name+'_RC_'+str(cp.returncode)+
         '_STDERR_'+cp.stderr.decode('utf-8',errors='replace')[:160])
    need(len(cp.stdout) <= MAX_OUTPUT and len(cp.stderr) <= 4096,
         'DEMO_OUTPUT_LIMIT_'+name)
    return strict_json(cp.stdout)


def build_report(pins: dict, docs: dict) -> dict:
    combined = reconcile(docs)
    sources = {name:{'script':script,'git_blob_sha1':pins[script]['git_blob_sha1'],
                     'source_sha256':pins[script]['sha256'],
                     'demo_output_sha256':sha(canonical(docs[name]))}
               for name, script in DEMOS}
    report = {
        'schema':SCHEMA, 'repo_head':BASE,
        'mode':'SYNTHETIC_OFFLINE_REPRODUCIBLE_NO_PHYSICAL_EXECUTION',
        'source_pins':pins, 'components':sources,
        'integration':combined,
        'host_mutations':0, 'vm_start_requests':0, 'nft_writes':0,
        'p8_operational':'NO-GO',
    }
    report['sha256'] = sha(canonical(report))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    try:
        need(args.run, 'EXPLICIT_RUN_REQUIRED')
        need(os.geteuid() != 0, 'NON_ROOT_REQUIRED')
        pins = validate_checkout(REPO)
        lab = private_root()
        evidence = Path(tempfile.mkdtemp(prefix='r60e1-',dir=str(lab)))
        results = {}
        previous = None
        events = []
        for i,(name,script) in enumerate(DEMOS,1):
            doc = run_demo(REPO, name, script)
            results[name] = doc
            contents = canonical(doc)
            write_once(evidence, name+'.json', contents)
            event = {'ordinal':i,'component':name,
                     'demo_output_sha256':sha(contents),
                     'previous_sha256':previous}
            event['event_sha256'] = sha(canonical(event))
            previous = event['event_sha256']
            events.append(event)
        report = build_report(pins,results)
        report['event_chain'] = events
        report['event_chain_head'] = previous
        report['sha256'] = sha(canonical({k:v for k,v in report.items() if k!='sha256'}))
        write_once(evidence,'integrated.json', canonical(report))
        manifest={'schema':'ardrec-r60e1-evidence-manifest-v1',
                  'paths':{p.name:sha(p.read_bytes()) for p in sorted(evidence.iterdir())}}
        write_once(evidence,'manifest.json',canonical(manifest))
        print('R60E1=PASS_THREE_OFFLINE_CONTRACTS_RECONCILED')
        print('R60E1_MODEL_CASES=29; R60E1_CASE_CAPACITY=54; R60E1_FAMILIES=25; R60E1_STAGES=10')
        print('R60E1_CROSS_CASE_BINDING=NOT_ATTESTED; A5=NO_REAL_START; A6=ND; A9=NOT_PUBLISHED')
        print('R60E1_HOST_MUTATIONS=0; R60E1_VM_STARTS=0; P8=NO-GO')
        print('R60E1_REPORT='+str(evidence/'integrated.json'))
        print('R60E1_SHA256='+sha((evidence/'integrated.json').read_bytes()))
        print('R60E1_MANIFEST='+str(evidence/'manifest.json'))
        return 0
    except (Blocked, OSError, UnicodeError, subprocess.SubprocessError, KeyError, TypeError, ValueError) as exc:
        print('R60E1=BLOCKED:'+type(exc).__name__+':'+str(exc)[:220],file=sys.stderr)
        print('R60E1_NO_HOST_MUTATION; P8=NO-GO',file=sys.stderr)
        return 23

if __name__ == '__main__':
    raise SystemExit(main())
