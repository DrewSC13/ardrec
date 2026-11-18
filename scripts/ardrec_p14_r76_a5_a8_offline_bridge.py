#!/usr/bin/env python3
"""R76: unir R75 + R59D A5 + R58E A6-A8 exclusivamente en modo sintético.

No usa subprocess, red, libvirt, systemd, nft, sudo, VM, ni despacha perfiles.
NO accredita resultados A5, A6, Rf confirmado, ni publicaciones A9.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination.r58e_evidence_risk_bridge import build_unit_bridge, verify_unit_bridge
from ardrec.persistence.codec import canonical, digest, parse
import ardrec_p14_r75_integrated_demo as r75

SCHEMA = 'ardrec-p14-r76-a5-a8-offline-conservative-bridge-v1'
SOURCE = 'SYNTHETIC_DECLARATIONS_ONLY_NOT_PHYSICAL_EVIDENCE'
MAX_REPORT_BYTES = 1_000_000
FAMILIES = (('SSH_DEV', 'SSH', 8), ('FTP_DEV', 'FTP', 8), ('SMB_DEV', 'SMB', 9))
# Deliberately mutually inconsistent synthetic assertions, all UNVERIFIED.
CLAIMS = {('SSH_DEV', 1): 'OBSERVADO_POSITIVO',
          ('FTP_DEV', 1): 'OBSERVADO_NEGATIVO',
          ('SMB_DEV', 1): 'INCONCLUSO'}
START = '2026-11-18T00:00:00Z'
END = '2026-11-18T00:00:01Z'


class R76Error(ValueError):
    pass


def need(value: bool, code: str) -> None:
    if not value:
        raise R76Error(code)


def build(receipt_dir: Path) -> dict[str, Any]:
    """Read existing authenticated R75: no output files, no A5 execution."""
    need(os.geteuid() != 0 and Path.cwd().resolve() == ROOT,
         'canonical_nonroot_checkout_required')
    base = r75.verify(receipt_dir)
    gen = parse(r75.read_file(receipt_dir / 'reports' / 'gen1.json').rstrip(b'\n'))
    scenario = read_fixed_scenario(ROOT / 'lab/p14-r26-session-v1/scenario.json')
    records = {x['id']: x for x in scenario['services']}
    need(set(records) == {x[0] for x in FAMILIES} and
         gen['record_id'] == scenario['session_id'],
         'r75_scenario_binding_invalid')
    candidates: list[dict[str, Any]] = []
    units: list[dict[str, Any]] = []
    counts = {'SSH_DEV':0, 'FTP_DEV':0, 'SMB_DEV':0}
    for service_id, protocol, count in FAMILIES:
        row = records[service_id]
        for n in range(1, count + 1):
            family_id = f'{protocol}-T{n:02d}'
            case = f'{protocol}-T{n:02d}-S01-01'
            intent = a5.build_intent(
                service_id=service_id,
                session_id=gen['record_id'],
                family_id=family_id,
                derived_case_id=case,
                assessment_index=0,
                attempt_id=f'ATT_R76_{protocol}_T{n:02d}',
                configuration_sha256=gen['configuration_sha256'],
                method_id=a5.SERVICES[service_id][2],
            )
            claim = CLAIMS.get((service_id, n), 'NO_START')
            support = (f'R76_SYNTHETIC_UNVERIFIED:{family_id}:{claim}\n'.encode('ascii')
                       if claim != 'NO_START' else b'')
            receipt = a5.make_receipt(
                intent,
                outcome=claim,
                source_kind='EXTERNAL_UNVERIFIED' if support else 'LOCAL_BENIGN_FIXTURE',
                support=support,
                start_utc=START if support else None,
                finish_utc=END if support else None,
            )
            candidate = a5.build_candidate(intent, receipt, support)
            a5.verify_candidate(candidate, support)
            need(candidate['a6_classification'] == 'ND' and
                 candidate['a5_physical_start_accredited'] is False and
                 candidate['a6_technical_truth_accredited'] is False and
                 candidate['a7_confirmed_rf'] is None and
                 candidate['p8_operational'] == 'NO-GO',
                 'candidate_promoted_to_evidence')
            # A7's IDs use fixed, typed identifiers. Derivation is injective.
            safe_case = 'CASE_' + case.replace('-', '_')
            units.append({
                'service_id':service_id, 'case_id':safe_case,
                'assessment_index':0,
                'initial_risk':row['initial_risk'],
                'normalized_criticality':row['normalized_criticality'],
                'replacement_risk':row['initial_risk'],
                'evidence':[],
            })
            candidates.append({
                'service_id':service_id, 'family_id':family_id,
                'derived_case_id':case, 'a7_case_id':safe_case,
                'claim_source':'FIXED_SYNTHETIC_UNTRUSTED',
                'declared_outcome':claim,
                'support_sha256':receipt['support_sha256'],
                'support_bytes':len(support),
                'a5_intent':intent,
                'a5_candidate':candidate,
                'a6_classification':'ND',
                'physical_start_accredited':False,
            })
            counts[service_id] += 1
    bridge = build_unit_bridge(units, [])
    verify_unit_bridge(bridge)
    keys = {(r['service_id'],r['case_id'],r['assessment_index'])
            for r in bridge['decisions']}
    need(len(keys) == 25 and
         keys == {(r['service_id'],r['a7_case_id'],0) for r in candidates} and
         bridge['unit_count'] == 25 and
         bridge['all_a6_nd'] is True and
         bridge['technical_truth_accredited'] is False and
         bridge['confirmed_final_risk'] is None and
         bridge['published_generation'] is None and
         bridge['p8_operational'] == 'NO-GO',
         'a5_a7_binding_or_authority_invalid')
    for decision in bridge['decisions']:
        need(decision['a6_status'] == 'MISSING_DOCUMENTARY_ADMISSION' and
             decision['a6_classification'] == 'ND' and
             decision['a7_interval_source'] == 'MATHEMATICAL_ONLY_FULL_UNRESOLVED' and
             decision['confirmed_rf'] is None and
             decision['a8_applied_transition'] is None,
             'undocumented_A6_admission_or_A8_transition')
    doc: dict[str, Any] = {
        'schema':SCHEMA, 'source_kind':SOURCE,
        'r75_manifest_sha256':hashlib.sha256(r75.read_file(receipt_dir/'MANIFEST.json')).hexdigest(),
        'r75_r70_head_sha256':base['source_links']['r70_head_sha256'],
        'r75_r71_shadow_sha256':base['source_links']['r71_shadow_sha256'],
        'service_family_counts':counts, 'family_count':25,
        'synthetic_declared_nonstart_count':22,
        'synthetic_unverified_claim_count':3,
        'physical_a5_starts_accredited':0,
        'a6_technical_truth_accredited':False,
        'a6_classification':'ND',
        'a7_confirmed_rf':None,
        'a8_applied_transitions':0,
        'a9_new_generations':0,
        'p8_operational':'NO-GO',
        'operational_dispatch':False,
        'candidates':candidates, 'conservative_bridge':bridge,
    }
    doc['sha256'] = digest(canonical(doc))
    need(len(canonical(doc)) <= MAX_REPORT_BYTES, 'oversized_report')
    return doc


def verify(doc: dict[str, Any], receipt_dir: Path) -> bool:
    expected = build(receipt_dir)
    need(type(doc) is dict and set(doc) == set(expected) and
         canonical(doc) == canonical(expected),
         'report_or_authenticated_r75_mismatch')
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt-dir',required=True,type=Path)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--json',action='store_true')
    mode.add_argument('--texto',action='store_true')
    mode.add_argument('--verify-json',type=Path)
    opt = ap.parse_args(argv)
    try:
        if opt.verify_json:
            st = opt.verify_json.lstat()
            import stat
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                 st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and
                 st.st_size <= MAX_REPORT_BYTES, 'untrusted_report_file')
            need(not any(p.is_symlink() for p in opt.verify_json.parents),
                 'untrusted_report_parent_symlink')
            raw = opt.verify_json.read_bytes()
            need(raw.endswith(b'\n') and raw.count(b'\n') == 1,
                 'report_noncanonical_newlines')
            data = parse(raw[:-1])
            need(raw == canonical(data)+b'\n', 'report_not_canonical')
            verify(data, opt.receipt_dir)
            print('R76=PASS_VERIFIED_NO_EXECUTION')
            print('R76_SHA256='+data['sha256'])
        else:
            report = build(opt.receipt_dir)
            if opt.json:
                sys.stdout.buffer.write(canonical(report)+b'\n')
            else:
                print('R76=PASS_SYNTHETIC_BRIDGE')
                print('R76_A5=25_TYPED_INTENTS_3_UNVERIFIED_DECLARATIONS')
                print('R76_A6=ND_ALL_25')
                print('R76_A7=EXACT_UNRESOLVED_INTERVALS_25')
                print('R76_A8=NO_APPLIED_TRANSITIONS')
                print('R76_A9=NO_NEW_GENERATION')
                print('R76_SHA256='+report['sha256'])
        print('R76_PHYSICAL_EXECUTIONS=0',file=sys.stderr)
        print('R76_P8=NO-GO',file=sys.stderr)
    except (R76Error, ValueError, TypeError, KeyError, OSError, RuntimeError) as exc:
        print('R76=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R76_P8=NO-GO',file=sys.stderr)
        return 23
    return 0


if __name__=='__main__':
    raise SystemExit(main())
