"""R58-K: one A6 synthetic intake over SSH/FTP/SMB and conservative A7/A8.

This source-only coordinator cannot certify evidence or authorize host actions.
Results from R58-H/I/J are hypothetical rule classifications, never A6 truth.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58e_evidence_risk_bridge import build_unit_bridge, verify_unit_bridge
from ardrec.evidence.r58h_ssh_family_logic import (
    CATALOG_SHA256, THESIS_SHA256, FAMILY_IDS as SSH_IDS,
    build_ssh_simulation, verify_ssh_simulation,
)
from ardrec.evidence.r58i_ftp_family_logic import (
    FAMILY_IDS as FTP_IDS, build_ftp_simulation, verify_ftp_simulation,
)
from ardrec.evidence.r58j_smb_family_logic import (
    FAMILY_IDS as SMB_IDS, build_smb_simulation, verify_smb_simulation,
)

SCHEMA = 'ardrec-r58k-a6-unified-25-family-synthetic-bridge-v1'
SERVICES = ('SSH_DEV', 'FTP_DEV', 'SMB_DEV')
PREFIXES = {'SSH_DEV': 'SSH-', 'FTP_DEV': 'FTP-', 'SMB_DEV': 'SMB-'}
FAMILY_IDS = {'SSH_DEV': tuple(SSH_IDS), 'FTP_DEV': tuple(FTP_IDS),
              'SMB_DEV': tuple(SMB_IDS)}
BUILDERS = {'SSH_DEV': build_ssh_simulation, 'FTP_DEV': build_ftp_simulation,
            'SMB_DEV': build_smb_simulation}
VERIFIERS = {'SSH_DEV': verify_ssh_simulation, 'FTP_DEV': verify_ftp_simulation,
             'SMB_DEV': verify_smb_simulation}
RISK_FIELDS = frozenset(('initial_risk', 'normalized_criticality', 'replacement_risk'))
ENVELOPE_FIELDS = frozenset(('service_id', 'unit', 'risk'))
HEX = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
MAX_UNITS = 54
MAX_BYTES = 786432


class UnifiedFamilyError(ValueError):
    """Fail closed on inconsistent identities, report or risk-to-case links."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise UnifiedFamilyError(reason)


def _key(service: str, unit: dict[str, Any]) -> tuple[str, str, str, int]:
    return (service, unit['session_id'], unit['derived_case_id'],
            unit['assessment_index'])


def _case_id(key: tuple[str, str, str, int]) -> str:
    """A7 identifiers cannot contain hyphens; bind the entire A6 identity."""
    service, session, case, idx = key
    payload = {'service_id': service, 'session_id': session,
               'derived_case_id': case, 'assessment_index': idx}
    h = hashlib.sha256(b'ARDREC-R58K-A6-A7-CASE-V1\x00' + canonical(payload)).hexdigest()
    return 'CASE_' + h[:48].upper()


def build_unified_preview(envelopes: list[dict[str, Any]], *,
                          weights: tuple[str, str, str] = ('1/3', '1/3', '1/3')) -> dict[str, Any]:
    """Evaluate up to 54 synthetic case-windows, without any evidence admission.

    Per-case risk is only an input to the R58-E full-[0,1] mathematical envelope;
    callers cannot inject an A6 contribution or bypass R58-E's conservative stop.
    """
    need(type(envelopes) is list and 0 < len(envelopes) <= MAX_UNITS,
         'ENVELOPE_COUNT')
    need(type(weights) is tuple and len(weights) == 3, 'WEIGHTS_FORMAT')
    grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in SERVICES}
    copied: list[dict[str, Any]] = []
    risk_units: list[dict[str, Any]] = []
    identities: dict[tuple[str, str, str, int], str] = {}
    case_ids: set[str] = set()
    bare_case_ids: set[tuple[str, str, int]] = set()

    for raw in envelopes:
        need(type(raw) is dict and set(raw) == ENVELOPE_FIELDS,
             'ENVELOPE_SCHEMA')
        service, unit, risk = raw['service_id'], raw['unit'], raw['risk']
        need(type(service) is str and service in SERVICES, 'SERVICE_UNSUPPORTED')
        need(type(unit) is dict and type(risk) is dict and
             set(risk) == RISK_FIELDS, 'RISK_OR_UNIT_SCHEMA')
        fid = unit.get('family_id')
        need(type(fid) is str and fid in FAMILY_IDS[service] and
             fid.startswith(PREFIXES[service]), 'FAMILY_SERVICE_MISMATCH')
        for k in ('session_id', 'derived_case_id', 'assessment_index'):
            need(k in unit, 'MISSING_CASE_IDENTITY')
        need(type(unit['session_id']) is str and
             type(unit['derived_case_id']) is str and
             type(unit['assessment_index']) is int,
             'IDENTITY_TYPES')
        key = _key(service, unit)
        bare = (unit['session_id'], unit['derived_case_id'], unit['assessment_index'])
        need(key not in identities, 'DUPLICATE_CASE_WINDOW')
        need(bare not in bare_case_ids, 'CROSS_SERVICE_CASE_REUSE')
        cid = _case_id(key)
        need(cid not in case_ids, 'HASHED_CASE_ID_COLLISION')
        identities[key] = cid
        case_ids.add(cid)
        bare_case_ids.add(bare)
        grouped[service].append(unit)
        copied.append({'service_id': service, 'unit': unit, 'risk': risk})
        risk_units.append({'service_id': service, 'case_id': cid,
                           'assessment_index': unit['assessment_index'],
                           'initial_risk': risk['initial_risk'],
                           'normalized_criticality': risk['normalized_criticality'],
                           'replacement_risk': risk['replacement_risk'],
                           'evidence': []})

    # R58-H/I/J perform full catalogue SHA pinning, variant and support checks.
    protocol_reports: dict[str, dict[str, Any] | None] = {}
    decisions: list[dict[str, Any]] = []
    covered: set[str] = set()
    class_counts: Counter[str] = Counter()
    for service in SERVICES:
        subset = grouped[service]
        if not subset:
            protocol_reports[service] = None
            continue
        report = BUILDERS[service](subset)
        VERIFIERS[service](report)
        need(report['unit_count'] == len(subset) and
             report['source_catalog_sha256'] == CATALOG_SHA256 and
             report['source_thesis_sha256'] == THESIS_SHA256 and
             report['catalog_source'] == 'FULL_FILE_SHA256_PINNED' and
             report['a6_classification'] == 'ND' and
             report['technical_truth_accredited'] is False and
             report['confirmed_final_risk'] is None and
             report['published_generation'] is None and
             report['operational_dispatch'] is False and
             report['p8_operational'] == 'NO-GO',
             'CHILD_REPORT_AUTHORITY_OR_CATALOG_MISMATCH')
        protocol_reports[service] = report
        for child in report['decisions']:
            key = _key(service, child)
            need(key in identities and child['a6_classification'] == 'ND' and
                 child['technical_truth_accredited'] is False and
                 child['confirmed_rf'] is None and
                 child['technical_contribution'] is None and
                 child['applied_transition'] is None and
                 child['published_generation'] is None,
                 'CHILD_DECISION_NOT_CONSERVATIVE')
            covered.add(child['family_id'])
            class_counts[child['hypothetical_result_class']] += 1
            decisions.append({
                'service_id': service, 'session_id': child['session_id'],
                'derived_case_id': child['derived_case_id'],
                'assessment_index': child['assessment_index'],
                'case_id_a7': identities[key],
                'family_id': child['family_id'],
                'variant': child.get('variant'),
                'precedence': child['precedence'],
                'phase_assumed': child['phase_assumed'],
                'guard_simulated': child['guard_simulated'],
                'hypothetical_result_class': child['hypothetical_result_class'],
                'hypothetical_condition_truth': child['hypothetical_condition_truth'],
                'hypothetical_reason': child['hypothetical_reason'],
                'a6_classification': 'ND',
                'technical_truth_accredited': False,
                'technical_contribution': None,
                'confirmed_rf': None, 'applied_transition': None,
                'published_generation': None,
            })

    need(len(decisions) == len(envelopes), 'DROPPED_OR_EXTRA_FAMILY_DECISION')
    decisions.sort(key=lambda d: (d['service_id'], d['session_id'],
                                   d['derived_case_id'], d['assessment_index']))
    copied.sort(key=lambda e: (e['service_id'], e['unit']['session_id'],
                               e['unit']['derived_case_id'], e['unit']['assessment_index']))
    bridge = build_unit_bridge(risk_units, [], weights=weights)
    verify_unit_bridge(bridge)
    bridge_by_case = {(d['service_id'], d['case_id'], d['assessment_index']): d
                      for d in bridge['decisions']}
    need(len(bridge_by_case) == len(decisions), 'A7_DUPLICATE_BRIDGE_RESULT')
    for decision in decisions:
        k = (decision['service_id'], decision['case_id_a7'],
             decision['assessment_index'])
        need(k in bridge_by_case, 'A6_A7_CASE_BINDING_MISSING')
        bound = bridge_by_case[k]
        need(bound['a6_classification'] == 'ND' and
             bound['a7_interval_source'] == 'MATHEMATICAL_ONLY_FULL_UNRESOLVED' and
             bound['a8_recommendation'] == 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA' and
             bound['confirmed_rf'] is None and
             bound['a8_applied_transition'] is None and
             bound['technical_truth_accredited'] is False,
             'A7_A8_PROMOTION_REFUSED')
        decision['a7_rf_lower'] = bound['a7_rf_lower']
        decision['a7_rf_upper'] = bound['a7_rf_upper']
        decision['a8_recommendation'] = bound['a8_recommendation']
        decision['a8_stop_sha256'] = bound['a8_stop_sha256']
    need(len(bridge['a6_inputs']) == 0 and
         bridge['documentary_admission_count'] == 0 and
         bridge['technical_truth_accredited'] is False and
         bridge['confirmed_final_risk'] is None and
         bridge['published_generation'] is None,
         'BRIDGE_UNTRUSTED_AUTHORITY')

    report = {
        'schema': SCHEMA, 'mode': 'SYNTHETIC_RULE_COORDINATION_ONLY',
        'source_catalog_sha256': CATALOG_SHA256,
        'source_thesis_sha256': THESIS_SHA256,
        'family_registry': {service: list(FAMILY_IDS[service]) for service in SERVICES},
        'supported_family_count': 25,
        'covered_families_in_batch': sorted(covered),
        'covered_family_count_in_batch': len(covered),
        'inputs': copied, 'protocol_reports': protocol_reports,
        'a6_a7_a8_bridge': bridge,
        'weights': list(weights), 'decisions': decisions,
        'unit_count': len(decisions),
        'count_by_service': {s: len(grouped[s]) for s in SERVICES},
        'hypothetical_class_counts': {k: class_counts[k] for k in sorted(class_counts)},
        'case_id_derivation': 'SHA256_DOMAIN_SEPARATED_FULL_IDENTITY_48_HEX',
        'source_kind': 'OFFLINE_SYNTHETIC_NO_INDEPENDENT_ATTESTATION',
        'all_a6_nd': True, 'a6_classification': 'ND',
        'technical_truth_accredited': False,
        'confirmed_final_risk': None, 'published_generation': None,
        'applied_state_transition': None, 'operational_dispatch': False,
        'vm_checks_executed': False, 'host_mutations': 0,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) <= MAX_BYTES, 'UNIFIED_REPORT_TOO_LARGE')
    report['sha256'] = digest(report)
    return report


def verify_unified_preview(report: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None, 'UNIFIED_REPORT_SCHEMA')
    need(type(report.get('weights')) is list and len(report['weights']) == 3,
         'UNIFIED_REPORT_WEIGHTS')
    expected = build_unified_preview(report.get('inputs'),
                                     weights=tuple(report['weights']))
    need(canonical(report) == canonical(expected), 'UNIFIED_REPORT_NOT_REPRODUCIBLE')
    return True
