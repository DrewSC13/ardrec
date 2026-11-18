#!/usr/bin/env python3
"""R79: una vista académica reproducible, exclusivamente lectura R75/R76/R78.

NO subprocess, SSH, FTP, SMB, VM, cambios del host, A5 ni autoridad P8.
El vínculo R77 se expone como frontera documental sin pin externo acreditado.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from fractions import Fraction
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))

from ardrec.persistence.codec import canonical, digest, parse
import ardrec_p14_r75_integrated_demo as r75
import ardrec_p14_r76_a5_a8_offline_bridge as r76
import ardrec_p14_r77_signed_a5_a8_bridge as r77
import ardrec_p14_r78_a7_whatif_sensitivity as r78

SCHEMA = 'ardrec-p14-r79-tutor-readonly-a1-a10-25-families-v1'
SOURCE = 'DERIVED_FROM_AUTHENTICATED_SYNTHETIC_DEV_REPORTS_ONLY'
BASE = '9f18ee6cda972acc9714a03734b9dba95b332cab'
MAX_REPORT_BYTES = 250_000

class R79Error(ValueError):
    pass


def need(valid: bool, code: str) -> None:
    if not valid:
        raise R79Error(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build(receipt_dir: Path, r76_doc: dict[str, Any],
          r78_doc: dict[str, Any]) -> dict[str, Any]:
    """Verifica todo antes de derivar la vista; jamás inicia un proceso A5."""
    need(os.geteuid() != 0 and Path.cwd().resolve() == REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    need(type(r76_doc) is dict and type(r78_doc) is dict,
         'SOURCE_DOCUMENT_TYPE_INVALID')
    # Los tres verificadores reconstruyen contra sus fuentes, no confían
    # simplemente en los campos SHA-256 autocontenidos.
    manifest = r75.verify(receipt_dir)
    need(r76.verify(r76_doc, receipt_dir), 'R76_SOURCE_INVALID')
    need(r78.verify(r78_doc, receipt_dir, r76_doc), 'R78_SOURCE_INVALID')
    gen = r77.read_canonical(receipt_dir/'reports'/'gen1.json')
    shadow = r77.read_canonical(receipt_dir/'reports'/'shadow.json')
    # R75 conserva r38_report.json en bytes canónicos SIN salto final.
    r38_raw = r75.read_file(receipt_dir/'reports'/'r38_report.json')
    r38 = parse(r38_raw)
    need(canonical(r38) == r38_raw, 'R38_CANONICAL_SOURCE_REQUIRED')
    need(gen['generation'] == 1 and shadow['r70_head_sha256'] == gen['head_sha256'] and
         shadow['a5_local_benign_starts'] == 1 and
         shadow['a7_hypothetical_rf'] == '5/12' and
         r38['a10']['stages'][0]['algorithm'] == 'A1' and
         [x['algorithm'] for x in r38['a10']['stages']] ==
             [f'A{i}' for i in range(1,11)] and
         r38['p8_operational'] == 'NO-GO',
         'R75_R38_INTEGRATED_SOURCE_INVALID')
    need(r76_doc['synthetic_unverified_claim_count'] == 3 and
         r76_doc['synthetic_declared_nonstart_count'] == 22 and
         r76_doc['a6_classification'] == 'ND' and
         r76_doc['a7_confirmed_rf'] is None and
         r76_doc['a8_applied_transitions'] == 0 and
         r76_doc['a9_new_generations'] == 0 and
         r76_doc['physical_a5_starts_accredited'] == 0,
         'R76_UNACCREDITED_DECLARATIONS_REQUIRED')
    need(r78_doc['family_count'] == 25 and
         r78_doc['r77_external_pin_provided'] is False and
         r78_doc['r77_technical_truth_accredited'] is False and
         r78_doc['a6_classification'] == 'ND' and
         r78_doc['a7_confirmed_rf'] is None and
         r78_doc['a8_applied_transitions'] == 0 and
         r78_doc['a9_new_generations'] == 0 and
         r78_doc['physical_executions'] == 0 and
         r78_doc['p8_operational'] == 'NO-GO',
         'R78_NO_AUTHORITY_REQUIRED')
    candidates = {r['family_id']:r for r in r76_doc['candidates']}
    need(len(candidates) == 25, 'R76_FAMILY_UNIQUENESS')
    families=[]
    for case in r78_doc['cases']:
        candidate=candidates.get(case['family_id'])
        need(candidate is not None and candidate['service_id'] == case['service_id'] and
             candidate['a7_case_id'] == case['case_id'] and
             candidate['a6_classification'] == 'ND' and
             candidate['physical_start_accredited'] is False and
             case['a6'] == 'ND' and
             case['technical_truth_accredited'] is False and
             case['a7_confirmed_rf'] is None and
             case['a8_applied_transition'] is None and
             case['whatif_point_is_technical_evidence'] is False,
             'FAMILY_SOURCE_BINDING_OR_FALSE_ACCREDITATION')
        a, b, c = (Fraction(case[k]) for k in
                     ('whatif_E_0_rf','whatif_E_half_rf','whatif_E_1_rf'))
        need(a <= b <= c and
             str(Fraction(case['rf_unresolved_lower'])) == str(a) and
             str(Fraction(case['rf_unresolved_upper'])) == str(c),
             'R78_EXACT_INTERVAL_DISCREPANCY')
        families.append({
            'family_id':case['family_id'],
            'service_id':case['service_id'],
            'case_id':case['case_id'],
            'declared_outcome':candidate['declared_outcome'],
            'a6':'ND',
            'unresolved_interval':[str(a),str(c)],
            'hypothetical_rf_E0':str(a),
            'hypothetical_rf_Ehalf':str(b),
            'hypothetical_rf_E1':str(c),
            'confirmed_rf':None,
            'operational_authority':False,
        })
    families.sort(key=lambda r:(r['service_id'],r['family_id']))
    need(len(families) == 25 and len({x['family_id'] for x in families}) == 25,
         'R79_FAMILY_COUNT')
    count={sid:sum(x['service_id']==sid for x in families)
           for sid in ('SSH_DEV','FTP_DEV','SMB_DEV')}
    need(count == {'SSH_DEV':8,'FTP_DEV':8,'SMB_DEV':9}, 'R79_PROTOCOL_COUNTS')
    # Estatus académico por algoritmo: no confundir el escenario R75 de tres
    # servicios, las 54 unidades A2 y las 25 familias de R76/R78.
    stage_specs = [
        ('A1','R75_GEN0','3 decisiones sintéticas recuperadas; configuración fijada'),
        ('A2','R75_54_SYNTHETIC','54 unidades sintéticas, separadas del caso durable'),
        ('A3','R75_R71_SHADOW','Guarda hipotética; despacho operacional bloqueado'),
        ('A4','R75_R71_SHADOW','SSH/CASE_REFERENCE hipotético; sin selección confirmada'),
        ('A5','R75_BENIGN_R76_INTENTS','1 inicio local benigno + 25 intenciones sin inicio físico acreditado'),
        ('A6','R76_R77_BOUNDARY','25 clasificaciones ND; firma documental no acredita verdad técnica'),
        ('A7','R78_R58D','25 intervalos exactos y tres niveles hipotéticos; Rf confirmado nulo'),
        ('A8','R76_R78','0 transiciones aplicadas; DETENER en GEN1'),
        ('A9','R75_GEN1','GEN1 estructural publicada; sin GEN2 ni evidencia técnica'),
        ('A10','R75_R38','10 vistas y 3 paneles; solo lectura'),
    ]
    stages=[{'algorithm':a,'source':source,'detail':detail,
             'experimental_validation':'NOT_RUN'}
            for a,source,detail in stage_specs]
    manifest_bytes=r75.read_file(receipt_dir/'MANIFEST.json')
    report = {
        'schema':SCHEMA,
        'source_kind':SOURCE,
        'scope':'ACADEMIC_READONLY_TUTOR_WALKTHROUGH',
        'source_links':{
            'r75_manifest_sha256':_sha(manifest_bytes),
            'r75_gen1_head_sha256':gen['head_sha256'],
            'r75_shadow_sha256':shadow['sha256'],
            'r75_r38_sha256':r38['sha256'],
            'r76_report_sha256':r76_doc['sha256'],
            'r78_report_sha256':r78_doc['sha256'],
        },
        'stage_count':10,
        'stages':stages,
        'r75_structural_generation':1,
        'r75_synthetic_units':54,
        'r75_synthetic_case_references':108,
        'r75_local_benign_starts':1,
        'r76_typed_intents':25,
        'r76_unverified_claims':3,
        'r76_declared_nonstarts':22,
        'r77_external_registry_pin_provided':False,
        'r77_external_independent_witness_attested':False,
        'r78_mathematical_family_count':25,
        'family_counts':count,
        'hypothetical_evidence_levels':['0','1/2','1'],
        'families':families,
        'a6_classification':'ND',
        'a7_confirmed_rf':None,
        'a8_applied_transitions':0,
        'a9_new_generations':0,
        'physical_executions':0,
        'operational_dispatch':False,
        'p8_operational':'NO-GO',
        'system_functional_acceptance':'PENDING',
        'experimental_validation':'NOT_RUN',
    }
    need(manifest['a6']=='ND' and manifest['confirmed_rf'] is None and
         len(canonical(report)) <= MAX_REPORT_BYTES,'ACADEMIC_SCOPE_INVALID')
    report['sha256']=digest(canonical(report))
    return report


def verify(report: dict[str, Any], receipt_dir: Path,
           r76_doc: dict[str, Any], r78_doc: dict[str, Any]) -> bool:
    need(type(report) is dict and canonical(report) == canonical(build(receipt_dir,r76_doc,r78_doc)),
         'WALKTHROUGH_NOT_REPRODUCIBLE')
    return True


def render_text(report: dict[str, Any]) -> str:
    lines=['ARDREC / R79 / RECORRIDO ACADEMICO REPRODUCIBLE',
           'FUENTE=SINTETICA  P8=NO-GO  A6=ND  RF_CONFIRMADO=NULL  VM=NO',
           'SECUENCIA A1-A10 (FUENTES AUTENTICADAS, NO EXPERIMENTO)',
           '-------------------------------------------------------']
    for item in report['stages']:
        lines.append(f"{item['algorithm']:>3}  {item['source']:<24} {item['detail']}")
    lines += ['','MATRIZ R78 / FRACCIONES EXACTAS HIPOTETICAS (NO TECNICAS)',
              'FAMILIA   SERVICIO  RECLAMO                  A6  RF_E0   RF_E1/2  RF_E1   Rf CONF.',
              '--------------------------------------------------------------------------']
    for f in report['families']:
        lines.append(f"{f['family_id']:<9} {f['service_id']:<9} "
                     f"{f['declared_outcome']:<24} ND  "
                     f"{f['hypothetical_rf_E0']:<7} "
                     f"{f['hypothetical_rf_Ehalf']:<8} "
                     f"{f['hypothetical_rf_E1']:<7} ND")
    lines += ['','INTEGRIDAD Y LIMITES',
              'R75_GEN1_HEAD='+report['source_links']['r75_gen1_head_sha256'],
              'R76_SHA256='+report['source_links']['r76_report_sha256'],
              'R78_SHA256='+report['source_links']['r78_report_sha256'],
              'R79_SHA256='+report['sha256'],
              'F11=AUTORIZACION_FISICA_PENDIENTE',
              'ACEPTACION_FUNCIONAL=PENDING  VALIDACION_EXPERIMENTAL=NOT_RUN',
              'R79=PASS_DERIVED_READONLY', 'R79_P8=NO-GO']
    return '\n'.join(lines)+'\n'


def main(argv=None) -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt-dir',type=Path,required=True)
    ap.add_argument('--r76-report',type=Path,required=True)
    ap.add_argument('--r78-report',type=Path,required=True)
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--json',action='store_true')
    modes.add_argument('--texto',action='store_true')
    modes.add_argument('--verify-json',type=Path)
    opt=ap.parse_args(argv)
    try:
        source76=r77.read_canonical(opt.r76_report)
        source78=r77.read_canonical(opt.r78_report)
        if opt.verify_json:
            previous=r77.read_canonical(opt.verify_json)
            verify(previous,opt.receipt_dir,source76,source78)
            print('R79=PASS_VERIFIED_NO_EXECUTION')
            print('R79_SHA256='+previous['sha256'])
        else:
            report=build(opt.receipt_dir,source76,source78)
            if opt.json:
                sys.stdout.buffer.write(canonical(report)+b'\n')
            else:
                sys.stdout.write(render_text(report))
        print('R79_A6=ND',file=sys.stderr)
        print('R79_RF_CONFIRMED=NULL',file=sys.stderr)
        print('R79_PHYSICAL_EXECUTIONS=0',file=sys.stderr)
        print('R79_P8=NO-GO',file=sys.stderr)
    except (R79Error,ValueError,OSError,KeyError,TypeError,RuntimeError) as exc:
        print('R79=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R79_P8=NO-GO',file=sys.stderr)
        return 23
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
