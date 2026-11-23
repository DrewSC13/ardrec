"""R58-D A7 exact interval kernel, source-only and mathematically bounded.

No provenance is attested by this kernel. Inputs are synthetic or hypothetical,
never enough to publish Rf, transition a state, or authorize VM execution.
"""
from __future__ import annotations

from fractions import Fraction
from typing import Any
import re

from ardrec.analytics.exact_preview import canonical, digest, rational, preview_bounds, verify_bounds

SCHEMA = 'ardrec-r58d-a7-exact-risk-interval-kernel-v1'
SOURCE = 'SYNTHETIC_MATHEMATICAL_ONLY'
MAX_UNITS = 54
MAX_EVIDENCE = 25
MAX_BYTES = 262144
SERVICES = frozenset(('SSH_DEV', 'FTP_DEV', 'SMB_DEV'))
IDENT = re.compile(r'[A-Z][A-Z0-9_]{0,63}\Z', re.ASCII)
# F13/B10: case_id conserva guiones canónicos FTP-T01.
# evidence_id mantiene la gramática IDENT original.
CASE_IDENT = re.compile(r'[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*\Z', re.ASCII)
UNIT_KEYS = frozenset(('service_id', 'case_id', 'assessment_index', 'initial_risk',
                       'normalized_criticality', 'replacement_risk', 'evidence'))
EVIDENCE_KEYS = frozenset(('evidence_id', 'kind', 'lower', 'upper'))
KINDS = frozenset(('SYNTHETIC_FIXED', 'UNRESOLVED'))


class IntervalError(ValueError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise IntervalError(code)


def _ident(value: Any) -> bool:
    return type(value) is str and IDENT.fullmatch(value) is not None


def _case_ident(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) <= 64
        and CASE_IDENT.fullmatch(value) is not None
    )


def _weights(value: Any) -> tuple[str, str, str]:
    need(type(value) is tuple and len(value) == 3, 'WEIGHTS_SCHEMA')
    ww = tuple(rational(x) for x in value)
    need(all(x > 0 for x in ww) and sum(ww) == 1, 'WEIGHTS_NOT_SIMPLEX')
    return value


def _normalized_evidence(items: Any) -> list[dict[str, Any]]:
    need(type(items) is list and len(items) <= MAX_EVIDENCE, 'EVIDENCE_COUNT')
    seen: set[str] = set()
    result = []
    for raw in items:
        need(type(raw) is dict and set(raw) == EVIDENCE_KEYS, 'EVIDENCE_SCHEMA')
        eid = raw['evidence_id']
        need(_ident(eid) and eid not in seen, 'EVIDENCE_DUPLICATE_OR_ID')
        seen.add(eid)
        kind = raw['kind']
        need(type(kind) is str and kind in KINDS, 'EVIDENCE_KIND')
        lower, upper = rational(raw['lower']), rational(raw['upper'])
        need(lower <= upper, 'EVIDENCE_INTERVAL_REVERSED')
        if kind == 'UNRESOLVED':
            # No unproven upper bound narrower than 1 may masquerade as an assurance.
            need(lower == 0 and upper == 1, 'UNKNOWN_MUST_BE_FULL_INTERVAL')
        else:
            need(lower == upper, 'SYNTHETIC_FIXED_NOT_POINT')
        result.append({'evidence_id':eid,'kind':kind,
                       'lower':str(lower),'upper':str(upper)})
    return sorted(result,key=lambda x:x['evidence_id'])


def _normalize_row(raw: Any) -> dict[str, Any]:
    need(type(raw) is dict and set(raw) == UNIT_KEYS, 'UNIT_SCHEMA')
    sid, cid, index = raw['service_id'], raw['case_id'], raw['assessment_index']
    need(type(sid) is str and sid in SERVICES, 'SERVICE_UNSUPPORTED')
    need(_case_ident(cid), 'CASE_ID')
    need(type(index) is int and 0 <= index < 2**31, 'ASSESSMENT_INDEX')
    r0 = rational(raw['initial_risk'])
    cn = rational(raw['normalized_criticality'])
    replacement = rational(raw['replacement_risk'])
    need(replacement <= r0, 'REPLACEMENT_EXCEEDS_INITIAL')
    return {'service_id':sid,'case_id':cid,'assessment_index':index,
            'initial_risk':str(r0),'normalized_criticality':str(cn),
            'replacement_risk':str(replacement),
            'evidence':_normalized_evidence(raw['evidence'])}


def build_intervals(units: list[dict[str, Any]], *,
                    weights: tuple[str, str, str] = ('1/3','1/3','1/3')) -> dict[str, Any]:
    """Compute exact, permutation-invariant A7 uncertainty envelopes.

    The observed contribution is never inferred from untrusted documents. Each
    UNRESOLVED item means a full [0,1] mathematical uncertainty interval.
    A SYNTHETIC_FIXED item is only a simulated point, not proven real evidence.
    """
    ww = _weights(weights)
    need(type(units) is list and 0 < len(units) <= MAX_UNITS, 'UNIT_COUNT')
    normalized = [_normalize_row(row) for row in units]
    pairs = [(r['service_id'],r['case_id'],r['assessment_index']) for r in normalized]
    need(len(set(pairs)) == len(pairs), 'DUPLICATE_CASE_WINDOW')
    normalized.sort(key=lambda x:(x['service_id'],x['case_id'],x['assessment_index']))
    outputs = []
    for row in normalized:
        low = max([Fraction(0)] + [rational(e['lower']) for e in row['evidence']])
        high = max([Fraction(0)] + [rational(e['upper']) for e in row['evidence']])
        lo = preview_bounds(row['initial_risk'],row['normalized_criticality'],
                            [] if low == 0 else [str(low)],row['replacement_risk'],ww)
        hi = preview_bounds(row['initial_risk'],row['normalized_criticality'],
                            [] if high == 0 else [str(high)],row['replacement_risk'],ww)
        verify_bounds(lo)
        verify_bounds(hi)
        need(rational(lo['hypothetical_rf']) <= rational(hi['hypothetical_rf']),
             'NON_MONOTONE_INTERVAL')
        outputs.append({'service_id':row['service_id'],'case_id':row['case_id'],
                        'assessment_index':row['assessment_index'],
                        'evidence_lower':str(low),'evidence_upper':str(high),
                        'rf_lower':lo['hypothetical_rf'],
                        'rf_upper':hi['hypothetical_rf'],
                        'point_identified':low == high,
                        'lower_oracle_sha256':lo['sha256'],
                        'upper_oracle_sha256':hi['sha256'],
                        'source_kind':'MATHEMATICAL_ONLY',
                        'confirmed_rf':None})
    doc = {'schema':SCHEMA,'source_kind':SOURCE,'weights':list(ww),
           'inputs':normalized,'results':outputs,
           'unit_count':len(normalized),'technical_truth_accredited':False,
           'confirmed_final_risk':None,'published_generation':None,
           'operational_dispatch':False,'p8_operational':'NO-GO'}
    need(len(canonical(doc)) < MAX_BYTES, 'REPORT_TOO_LARGE')
    doc['sha256'] = digest(doc)
    return doc


def verify_intervals(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str, 'REPORT_SCHEMA')
    need(type(doc.get('weights')) is list and len(doc['weights']) == 3,
         'REPORT_WEIGHTS')
    expected = build_intervals(doc.get('inputs'),weights=tuple(doc['weights']))
    need(canonical(expected) == canonical(doc), 'REPORT_NOT_REPRODUCIBLE')
    return True
