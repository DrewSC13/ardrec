"""R58-E: conservative, purely functional A6 -> A7 -> A8 per-unit bridge.

Only documentary A6 admissions and exact R58-D mathematical envelopes are
consumed.  No source here accredits physical evidence, publishes A9 generations,
executes a guest, or transitions the authoritative state machine.
"""
from __future__ import annotations

from typing import Any
import re

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.analytics.r58d_interval_kernel import (
    build_intervals, verify_intervals, UNIT_KEYS, MAX_UNITS,
)
from ardrec.evidence.defensive_import import validate_admission
from ardrec.stopping.development_stop import preview_stop, verify_stop

SCHEMA = 'ardrec-r58e-a6-a7-a8-conservative-unit-binding-v1'
SOURCE = 'DOCUMENTARY_ONLY_NO_INDEPENDENT_TECHNICAL_ATTESTATION'
HEX = re.compile(r'[0-9a-f]{64}\Z')
ADMISSION_FIELDS = frozenset((
    'schema', 'admission', 'record_id', 'session_id', 'service_id',
    'case_id', 'source_kind', 'method_id', 'captured_at_utc',
    'review_as_of_utc', 'observed_claim_unverified',
    'configuration_sha256_declared', 'support_sha256_verified',
    'receipt_sha256', 'provenance_independently_attested',
    'classification', 'technical_truth_accredited', 'confirmed_rf',
    'reason', 'sha256',
))


class BridgeError(ValueError):
    """A stable, fail-closed contract failure."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise BridgeError(code)


def _key(row: dict[str, Any]) -> tuple[str, str, int]:
    return row['service_id'], row['case_id'], row['assessment_index']


def _source_key(row: dict[str, Any]) -> tuple[str, str]:
    return row['service_id'], row['case_id']


def _admissions(raw: Any, keys: set[tuple[str, str, int]]) -> list[dict[str, Any]]:
    need(type(raw) is list and len(raw) <= 16, 'A6_BATCH_SIZE')
    record_ids: set[str] = set()
    by_case: dict[tuple[str, str], str] = {}
    result: list[dict[str, Any]] = []
    pair_count: dict[tuple[str, str], int] = {}
    for sid, cid, _ in keys:
        pair_count[(sid, cid)] = pair_count.get((sid, cid), 0) + 1
    for admission in raw:
        validate_admission(admission)
        need(type(admission) is dict and set(admission) == ADMISSION_FIELDS,
             'A6_ADMISSION_SCHEMA_DRIFT')
        aid = admission['record_id']
        need(type(aid) is str and aid not in record_ids, 'A6_DUPLICATE_RECORD')
        record_ids.add(aid)
        pair = _source_key(admission)
        need(pair in pair_count, 'A6_UNBOUND_UNIT')
        # R37 admissions do not contain an assessment window. Never guess one.
        need(pair_count[pair] == 1, 'A6_AMBIGUOUS_ASSESSMENT_WINDOW')
        if pair in by_case:
            need(by_case[pair] == admission['observed_claim_unverified'],
                 'A6_CONFLICTING_CLAIMS')
            need(False, 'A6_DUPLICATE_UNIT_ADMISSION')
        by_case[pair] = admission['observed_claim_unverified']
        result.append(dict(admission))
    return sorted(result, key=lambda a: (a['service_id'], a['case_id'], a['record_id']))


def build_unit_bridge(units: list[dict[str, Any]], admissions: list[dict[str, Any]], *,
                      weights: tuple[str, str, str] = ('1/3', '1/3', '1/3')) -> dict[str, Any]:
    """Reject promoted A6 claims; retain full unresolved [0,1] for every unit.

    Input unit evidence MUST be empty: the caller cannot smuggle simulated
    points or user-asserted measurements into the mathematical envelope.
    """
    need(type(units) is list and 0 < len(units) <= MAX_UNITS, 'UNIT_COUNT')
    for row in units:
        need(type(row) is dict and set(row) == UNIT_KEYS, 'UNIT_SCHEMA')
        need(type(row['evidence']) is list and row['evidence'] == [],
             'UNACCREDITED_A7_EVIDENCE_INJECTION')
    # Canonicalize and validate identities and rational magnitudes with R58-D.
    baseline = build_intervals(units, weights=weights)
    source_rows = baseline['inputs']
    keys = {_key(u) for u in source_rows}
    approved = _admissions(admissions, keys)
    by_case = {_source_key(a): a for a in approved}
    unresolved = []
    for row in source_rows:
        unresolved.append({**row, 'evidence': [
            {'evidence_id': 'E_A6_UNRESOLVED', 'kind': 'UNRESOLVED',
             'lower': '0', 'upper': '1'},
        ]})
    math = build_intervals(unresolved, weights=weights)
    verify_intervals(math)
    decisions = []
    for row, interval in zip(source_rows, math['results']):
        need(_key(row) == _key(interval), 'A7_UNIT_BINDING_MISMATCH')
        a6 = by_case.get(_source_key(row))
        if a6 is None:
            # The lack of admission is not proof that the evidence is zero.
            source_sha = digest({'key': list(_key(row)), 'a6': 'NO_ADMISSION'})
            a6_status = 'MISSING_DOCUMENTARY_ADMISSION'
            admission_sha = None
            claim = None
        else:
            source_sha = a6['sha256']
            a6_status = 'DOCUMENTARY_ADMITTED_TECHNICAL_TRUTH_UNVERIFIED'
            admission_sha = a6['sha256']
            claim = a6['observed_claim_unverified']
        stop = preview_stop(a6_classification='ND', accredited=False,
                            vm_checked=False, operational_dispatch=False,
                            source_sha256=source_sha)
        verify_stop(stop)
        decisions.append({
            'service_id': row['service_id'], 'case_id': row['case_id'],
            'assessment_index': row['assessment_index'],
            'a6_status': a6_status, 'a6_classification': 'ND',
            'a6_admission_sha256': admission_sha,
            'a6_observed_claim_unverified': claim,
            'a7_rf_lower': interval['rf_lower'],
            'a7_rf_upper': interval['rf_upper'],
            'a7_interval_source': 'MATHEMATICAL_ONLY_FULL_UNRESOLVED',
            'a8_recommendation': stop['recommendation'],
            'a8_source_sha256': source_sha,
            'a8_stop_sha256': stop['sha256'],
            'a8_applied_transition': None,
            'confirmed_phase': None,
            'confirmed_rf': None,
            'technical_truth_accredited': False,
        })
    report = {
        'schema': SCHEMA, 'source_kind': SOURCE,
        'inputs': source_rows, 'a6_inputs': approved,
        'weights': list(weights), 'a7': math,
        'decisions': decisions,
        'unit_count': len(source_rows),
        'documentary_admission_count': len(approved),
        'missing_documentary_admission_count': len(source_rows) - len(approved),
        'all_a6_nd': True,
        'operational_dispatch': False,
        'vm_checks_executed': False,
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'published_generation': None,
        'applied_state_transition': None,
        'p8_operational': 'NO-GO',
    }
    # A6 is specific to one R37 case; distinct assessment windows need
    # explicit provenance instead of a dangerous guessed association.
    need(len(canonical(report)) <= 262144, 'BRIDGE_REPORT_TOO_LARGE')
    report['sha256'] = digest(report)
    return report


def verify_unit_bridge(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         HEX.fullmatch(doc['sha256']) is not None, 'BRIDGE_REPORT_SCHEMA')
    need(type(doc.get('weights')) is list and len(doc['weights']) == 3,
         'BRIDGE_REPORT_WEIGHTS')
    expected = build_unit_bridge(doc.get('inputs'), doc.get('a6_inputs'),
                                 weights=tuple(doc['weights']))
    need(canonical(doc) == canonical(expected), 'BRIDGE_REPORT_NOT_REPRODUCIBLE')
    return True
