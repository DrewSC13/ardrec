"""R58-J: conservative trivalent previews for nine thesis-grounded SMB families.

Offline rule evaluations are not technical truth, admissible A6 evidence,
A7 contributions, A8 transitions, A9 publication, or P8 execution authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.evidence.r58h_ssh_family_logic import (
    CATALOG_SHA256, THESIS_SHA256, CATALOG_PATH, _reject_dupes,
    _guard, TRUTH, OUTCOMES, CLASSES, SESSION,
)

SCHEMA = 'ardrec-r58j-a6-smb-family-trivalent-preview-v1'
FAMILY_IDS = tuple(f'SMB-T{i:02}' for i in range(1, 10))
DERIVED = re.compile(r'SMB-T0[1-9]-S\d{2}-\d{2}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
MAX_UNITS = 54
MAX_BYTES = 262144
UNIT_FIELDS = frozenset(('family_id', 'derived_case_id', 'assessment_index',
                         'session_id', 'phase', 'variant', 'preconditions',
                         'supports', 'integrity', 'provenance', 'cleanup', 'outcome'))
VARIANTS = {'SMB-T03': ('SIGNING', 'ENCRYPTION'),
            'SMB-T09': ('READ', 'WRITE')}
VARIANT_PRECONDITIONS = {
    ('SMB-T09', 'WRITE'): ('WRITE_FIXTURE_PREPARED', 'CLEANUP_VERIFIABLE'),
}
VARIANT_SUPPORTS = {
    ('SMB-T09', 'WRITE'): ('MARKER_CREATED', 'MARKER_VERIFIED', 'CLEANUP_CONFIRMED'),
}
PHASES = frozenset(('PREPARADO', 'PENDIENTE', 'ACTIVO', 'VALIDACION',
                    'ACTUALIZADO', 'PAUSADO', 'CERRADO', 'DETENIDO'))


class SMBFamilyError(ValueError):
    """Stable fail-closed error for SMB family preview intake."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise SMBFamilyError(code)


def _specs(families: Any) -> list[dict[str, Any]]:
    need(type(families) is list, 'FAMILIES_NOT_LIST')
    chosen = []
    for family in families:
        need(type(family) is dict, 'FAMILY_NOT_DICT')
        if family.get('protocol') != 'smb':
            continue
        fid = family.get('id')
        need(type(fid) is str and fid in FAMILY_IDS, 'SMB_FAMILY_UNKNOWN')
        for field in ('preconditions', 'required_supports', 'acceptance_supports'):
            values = family.get(field)
            need(type(values) is list and bool(values) and
                 all(type(v) is str and
                     re.fullmatch(r'[A-Z0-9_]{2,80}', v, re.ASCII) for v in values) and
                 len(values) == len(set(values)), 'CATALOG_' + field.upper())
        need(set(family['acceptance_supports']) <= set(family['required_supports']),
             'CATALOG_ACCEPTANCE_NOT_REQUIRED')
        cleanup = family.get('cleanup')
        expected_cleanup = ('VERIFY_THEN_REMOVE_MARKER' if fid == 'SMB-T08' else
                            'CONDITIONAL_WRITE_MARKER_CLEANUP' if fid == 'SMB-T09'
                            else 'NO_MUTATION')
        need(cleanup == expected_cleanup, 'CATALOG_CLEANUP')
        variants = family.get('variants')
        precedence = family.get('precedence')
        if fid in VARIANTS:
            expected = ({'SIGNING': 3, 'ENCRYPTION': 3} if fid == 'SMB-T03'
                        else {'READ': 3, 'WRITE': 4})
            dimension = 'protection' if fid == 'SMB-T03' else 'operation_class'
            need(type(variants) is dict and set(variants) ==
                 {'dimension', 'precedence_by_option'} and
                 variants['dimension'] == dimension and
                 variants['precedence_by_option'] == expected and
                 precedence == (3 if fid == 'SMB-T03' else [3, 4]), 'CATALOG_VARIANTS')
            by_variant = expected
        else:
            need(variants is None and type(precedence) is int and
                 1 <= precedence <= 4, 'CATALOG_PRECEDENCE')
            by_variant = {None: precedence}
        chosen.append({'id': fid, 'preconditions': list(family['preconditions']),
                       'required_supports': list(family['required_supports']),
                       'acceptance_supports': list(family['acceptance_supports']),
                       'cleanup': cleanup, 'precedence_by_variant': by_variant})
    chosen.sort(key=lambda f: f['id'])
    need([f['id'] for f in chosen] == list(FAMILY_IDS),
         'SMB_FAMILIES_NOT_EXACTLY_NINE')
    return chosen


def load_pinned_smb_catalog() -> list[dict[str, Any]]:
    """Load the original P7 catalogue, refusing edits or alternative sources."""
    need(CATALOG_PATH.is_file() and not CATALOG_PATH.is_symlink(),
         'CATALOG_NOT_REGULAR')
    try:
        body = CATALOG_PATH.read_bytes()
    except OSError as exc:
        raise SMBFamilyError('CATALOG_UNREADABLE') from exc
    need(0 < len(body) <= 131072, 'CATALOG_SIZE')
    need(hashlib.sha256(body).hexdigest() == CATALOG_SHA256,
         'CATALOG_PIN_MISMATCH')
    try:
        doc = json.loads(body, object_pairs_hook=_reject_dupes)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SMBFamilyError('CATALOG_JSON_INVALID') from exc
    need(type(doc) is dict and doc.get('thesis_sha256') == THESIS_SHA256 and
         doc.get('counts') == {'ssh': 8, 'ftp': 8, 'smb': 9, 'total': 25} and
         doc.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         doc.get('execution_enabled') is False, 'CATALOG_METADATA_MISMATCH')
    return _specs(doc.get('families'))


def _requirements(family: dict[str, Any], variant: str | None):
    fid = family['id']
    if fid in VARIANTS:
        need(type(variant) is str and variant in VARIANTS[fid],
             'VARIANT_EXPLICIT_REQUIRED')
    else:
        need(variant is None, 'UNEXPECTED_VARIANT')
    need(variant in family['precedence_by_variant'], 'VARIANT_PRECEDENCE_MISSING')
    pre = tuple(dict.fromkeys([*family['preconditions'],
                               *VARIANT_PRECONDITIONS.get((fid, variant), ())]))
    required = list(family['required_supports'])
    accepted = list(family['acceptance_supports'])
    if fid == 'SMB-T03':
        # Signing is NOT encryption.  A selected variant must not silently
        # assert, require, or infer evidence of the other protection property.
        selected = 'SMB_SIGNATURE' if variant == 'SIGNING' else 'SMB_ENCRYPTION'
        required = [v for v in required if v not in ('SMB_SIGNATURE', 'SMB_ENCRYPTION')]
        required.append(selected)
        accepted.append(selected)
    required = tuple(dict.fromkeys([*required,
                                    *VARIANT_SUPPORTS.get((fid, variant), ())]))
    accepted = tuple(dict.fromkeys([*accepted,
                                    *VARIANT_SUPPORTS.get((fid, variant), ())]))
    need(set(accepted) <= set(required), 'VARIANT_ACCEPTANCE_INVALID')
    cleanup_required = fid == 'SMB-T08' or (fid == 'SMB-T09' and variant == 'WRITE')
    return pre, required, accepted, family['precedence_by_variant'][variant], cleanup_required


def _unit(value: Any, family: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    need(type(value) is dict and set(value) == UNIT_FIELDS, 'UNIT_SCHEMA')
    fid = value['family_id']
    need(fid == family['id'], 'FAMILY_BINDING')
    cid = value['derived_case_id']
    need(type(cid) is str and DERIVED.fullmatch(cid) is not None and
         cid.startswith(fid + '-'), 'DERIVED_CASE_ID')
    idx = value['assessment_index']
    need(type(idx) is int and 0 <= idx < 2**31, 'ASSESSMENT_INDEX')
    session = value['session_id']
    need(type(session) is str and SESSION.fullmatch(session) is not None,
         'SESSION_ID')
    need(type(value['phase']) is str and value['phase'] in PHASES, 'PHASE')
    variant = value['variant']
    pre, required, accepted, precedence, cleanup_required = _requirements(family, variant)
    pc, supports = value['preconditions'], value['supports']
    need(type(pc) is dict and set(pc) == set(pre), 'PRECONDITION_SCHEMA')
    need(type(supports) is dict and set(supports) <= set(required), 'SUPPORT_SCHEMA')
    for mapping in (pc, supports):
        need(all(type(v) is str and v in TRUTH for v in mapping.values()),
             'TRIVALENT_VALUES')
    for field in ('integrity', 'provenance'):
        need(type(value[field]) is str and value[field] in TRUTH,
             field.upper() + '_VALUE')
    cleanup = value['cleanup']
    need(type(cleanup) is str and
         (cleanup in TRUTH if cleanup_required else cleanup == 'NO_APLICA'),
         'CLEANUP_VALUE')
    need(type(value['outcome']) is str and value['outcome'] in OUTCOMES, 'OUTCOME')
    normalized = {**value, 'preconditions': {k: pc[k] for k in sorted(pc)},
                  'supports': {k: supports[k] for k in sorted(supports)}}
    guard = _guard([pc[k] for k in pre])
    absent = [k for k in required if k not in supports]
    unknown = [k for k in required if supports.get(k, 'ND') == 'ND']
    contradicted = [k for k in required if supports.get(k) == 'FALSO']
    if value['phase'] != 'PENDIENTE':
        classification, reason = 'NO_ADMITIDO', 'SERVICE_NOT_PENDING'
    elif guard != 'VERDADERO':
        classification, reason = 'NO_ADMITIDO', ('PRECONDITION_FALSE' if guard == 'FALSO' else 'PRECONDITION_ND')
    elif value['integrity'] == 'FALSO' or value['provenance'] == 'FALSO':
        classification, reason = 'INVALIDO', 'INTEGRITY_OR_PROVENANCE_CONTRADICTED'
    elif value['integrity'] == 'ND' or value['provenance'] == 'ND':
        classification, reason = 'INCONCLUSO', 'INTEGRITY_OR_PROVENANCE_UNRESOLVED'
    elif cleanup_required and cleanup != 'VERDADERO':
        if supports.get('CLEANUP_CONFIRMED') == 'VERDADERO':
            classification, reason = 'INVALIDO', 'CLEANUP_SUPPORT_CONTRADICTS_STATUS'
        elif cleanup == 'FALSO':
            classification, reason = 'INCIDENCIA', 'MARKER_CLEANUP_FAILED'
        else:
            classification, reason = 'INCONCLUSO', 'MARKER_CLEANUP_UNRESOLVED'
    elif cleanup_required and supports.get('CLEANUP_CONFIRMED') == 'FALSO':
        classification, reason = 'INVALIDO', 'CLEANUP_STATUS_CONTRADICTS_SUPPORT'
    elif contradicted:
        classification, reason = 'INVALIDO', 'REQUIRED_SUPPORT_CONTRADICTED'
    elif unknown:
        classification, reason = 'INCONCLUSO', 'REQUIRED_SUPPORT_UNRESOLVED'
    elif value['outcome'] == 'INCIDENCIA':
        classification, reason = 'INCIDENCIA', 'SIMULATED_OPERATIONAL_INCIDENT'
    elif value['outcome'] == 'INCONCLUSO':
        classification, reason = 'INCONCLUSO', 'SIMULATED_OUTCOME_UNRESOLVED'
    elif value['outcome'] == 'OBSERVADO_POSITIVO':
        classification, reason = 'POSITIVO_VALIDO', 'HYPOTHETICAL_POSITIVE_ALL_SUPPORTS'
    else:
        classification, reason = 'NEGATIVO_VALIDO', 'HYPOTHETICAL_NEGATIVE_EXPLICITLY_OBSERVED'
    need(classification in CLASSES, 'CLASS_UNKNOWN')
    return normalized, {
        'family_id': fid, 'derived_case_id': cid, 'session_id': session,
        'assessment_index': idx, 'variant': variant, 'precedence': precedence,
        'service_id': 'SMB_DEV', 'phase_assumed': value['phase'],
        'required_preconditions': list(pre), 'required_supports': list(required),
        'acceptance_supports': list(accepted),
        'missing_required_supports': absent, 'unresolved_required_supports': unknown,
        'contradicted_required_supports': contradicted,
        'cleanup_required': cleanup_required, 'guard_simulated': guard,
        'hypothetical_result_class': classification, 'hypothetical_reason': reason,
        'hypothetical_condition_truth': ('VERDADERO' if classification == 'POSITIVO_VALIDO' else
                                        'FALSO' if classification == 'NEGATIVO_VALIDO' else 'ND'),
        'a6_classification': 'ND', 'technical_truth_accredited': False,
        'technical_contribution': None, 'confirmed_rf': None,
        'applied_transition': None, 'published_generation': None,
    }


def build_smb_simulation(units: list[dict[str, Any]], *,
                         _test_families: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Deterministic 54-unit-cap SMB logic; test fixture injection is labelled."""
    families = (load_pinned_smb_catalog() if _test_families is None else
                _specs(_test_families))
    need(type(units) is list and 0 < len(units) <= MAX_UNITS, 'UNIT_COUNT')
    by_id = {f['id']: f for f in families}
    normalized, decisions, seen = [], [], set()
    for row in units:
        need(type(row) is dict, 'UNIT_NOT_DICT')
        fid = row.get('family_id')
        need(type(fid) is str and fid in by_id, 'FAMILY_OUT_OF_SCOPE')
        unit, decision = _unit(row, by_id[fid])
        # Each SIGNING/ENCRYPTION and READ/WRITE variant is a distinct case ID.
        key = (unit['session_id'], unit['derived_case_id'], unit['assessment_index'])
        need(key not in seen, 'DUPLICATE_CASE_OR_VARIANT_WINDOW')
        seen.add(key)
        normalized.append(unit)
        decisions.append(decision)
    order = lambda d: (d['session_id'], d['derived_case_id'], d['assessment_index'])
    normalized.sort(key=order)
    decisions.sort(key=order)
    doc = {
        'schema': SCHEMA, 'mode': 'SYNTHETIC_RULE_EVALUATION_ONLY',
        'source_catalog_sha256': CATALOG_SHA256 if _test_families is None else None,
        'source_thesis_sha256': THESIS_SHA256,
        'catalog_source': ('FULL_FILE_SHA256_PINNED' if _test_families is None
                           else 'TEST_FIXTURE_NOT_PINNED'),
        'smb_family_ids': list(FAMILY_IDS),
        'inputs': normalized, 'decisions': decisions, 'unit_count': len(normalized),
        'a6_classification': 'ND', 'technical_truth_accredited': False,
        'confirmed_final_risk': None, 'published_generation': None,
        'applied_state_transition': None, 'operational_dispatch': False,
        'host_mutations': 0, 'p8_operational': 'NO-GO',
    }
    need(len(canonical(doc)) <= MAX_BYTES, 'REPORT_TOO_LARGE')
    doc['sha256'] = digest(doc)
    return doc


def verify_smb_simulation(report: dict[str, Any], *,
                          _test_families: list[dict[str, Any]] | None = None) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None, 'REPORT_SCHEMA')
    expected = build_smb_simulation(report.get('inputs'), _test_families=_test_families)
    need(canonical(report) == canonical(expected), 'REPORT_NOT_REPRODUCIBLE')
    return True
