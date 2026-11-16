"""R58-O: cross-contract audit of A1-A10 over two SYNTHETIC contexts.

R26/R28 cover 3 service-level A1-A3 fixtures; R58-L/N cover 29 family-case
previews. Matching session IDs do NOT attest an A3-to-case operational link.
This module reads and verifies existing contracts, never executes or persists.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.demo_session import (
    build_development_session, normalize_scenario,
)
from ardrec.coordination.development_cycle import (
    build_development_cycle, verify_development_cycle,
)
from ardrec.coordination.r58l_a4_a5_family_review import verify_a4_a5_review
from ardrec.coordination.r58n_durable_case_binding import (
    build_binding, verify_persisted,
)

SCHEMA = 'ardrec-r58o-a1-a10-cross-contract-synthetic-audit-v1'
BASE = '53f5715b280caf19519d76b046ed11f8068ca789'
MAX_REPORT_BYTES = 65536
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
STAGE_STATUSES = (
    'R26_A1_TYPED_SYNTHETIC',
    'R26_A2_PREPARED_SYNTHETIC',
    'R26_A3_NO_OPERATIONAL_AUTHORITY',
    'R58L_A4_HYPOTHETICAL_SELECTION',
    'R58N_A5_DECLARED_LOCAL_JOURNAL',
    'R58K_A6_HYPOTHETICAL_ND',
    'R58E_A7_MATHEMATICAL_UNCERTAINTY',
    'R58L_A8_CONSERVATIVE_PAUSE',
    'R58N_A9_LOCAL_DECLARED_RECEIPT',
    'R28_A10_READ_ONLY_REPORT',
)


class CrossContractError(ValueError):
    """Fail closed on changed source documents, identities, or authority."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise CrossContractError(code)


def _sha(value: Any) -> str:
    need(type(value) is str and HEX.fullmatch(value) is not None,
         'SOURCE_SHA_INVALID')
    return value


def _ledger_stage(ordinal: int, status: str, source_sha: str,
                  previous: str | None, *, scope: str) -> dict[str, Any]:
    entry = {
        'ordinal': ordinal,
        'algorithm': 'A' + str(ordinal),
        'status': status,
        'scope': scope,
        'source_sha256': _sha(source_sha),
        'previous_stage_sha256': previous,
        'technical_truth_accredited': False,
        'operational_dispatch': False,
        'published_generation': None,
    }
    entry['event_sha256'] = digest(entry)
    return entry


def build_cross_contract_trace(scenario: dict[str, Any],
                               review: dict[str, Any],
                               journal_root: Path, receipt_root: Path,
                               request_id: str) -> dict[str, Any]:
    """Read-only reproducible A1-A10 status trace; NEVER a full engine claim.

    The case identity in R58-N is a declared sidecar, not independent proof.
    No A3 control is mapped to a 25-family case with operational authority.
    A9 is a verified local receipt, not a published technical generation.
    """
    need(isinstance(journal_root, Path) and journal_root.is_absolute() and
         isinstance(receipt_root, Path) and receipt_root.is_absolute(),
         'ABSOLUTE_PATHS_REQUIRED')
    fixture = normalize_scenario(scenario)
    session = build_development_session(fixture)
    session.verify()
    cycle = build_development_cycle(fixture)
    verify_development_cycle(cycle)
    verify_a4_a5_review(review)
    persisted = verify_persisted(receipt_root, review, journal_root, request_id)
    binding = build_binding(review, journal_root, request_id)

    need(type(review) is dict and type(binding) is dict and
         type(persisted) is dict, 'SOURCE_SCHEMA')
    need(review['session_id'] == fixture['session_id'] == cycle['session_id'] and
         cycle['session_sha256'] == session.sha256 and
         review['source_catalog_sha256'] == review['unified']['source_catalog_sha256'] and
         review['source_thesis_sha256'] == review['unified']['source_thesis_sha256'],
         'SESSION_OR_CATALOG_LINK_MISMATCH')
    need(cycle['r26_event_count'] == 9 and
         len(session.document['events']) == 9 and
         len(cycle['r26_units']) == 3 and
         review['unit_count'] <= 54 and review['unit_count'] > 0 and
         review['covered_family_count'] <= 25,
         'SERVICE_OR_CASE_COUNT')
    need([stage['algorithm'] for stage in cycle['a10']['stages']] ==
         ['A'+str(n) for n in range(1, 11)] and
         cycle['r27']['selected_actual'] is None and
         cycle['a9']['durable_local_receipt'] is False and
         cycle['a9']['technical_generation_published'] is False and
         cycle['a7']['confirmed_rf'] is None,
         'R28_CYCLE_FALSE_AUTHORITY')
    need(binding['sha256'] == persisted['receipt_sha256'] and
         persisted['persisted_verification'] == 'PASS_DECLARED_ONLY_NO_AUTHORITY' and
         persisted['retry_allowed'] is False and
         binding['declared_request_id'] == request_id and
         binding['a4_selected_identity'] == review['a4_selected_identity'] and
         review['attempt_intent'] is not None and
         review['attempt_intent']['attempt_id'] == request_id,
         'DURABLE_RECEIPT_OR_INTENT_MISMATCH')
    need(binding['identity_declaration_independently_attested'] is False and
         binding['physical_case_binding_accredited'] is False and
         binding['a6_classification'] == 'ND' and
         binding['technical_truth_accredited'] is False and
         binding['confirmed_final_risk'] is None and
         binding['applied_state_transition'] is None and
         binding['published_generation'] is None and
         binding['operational_dispatch'] is False and
         binding['p8_operational'] == 'NO-GO',
         'BINDING_AUTHORITY_REFUSED')
    need(review['a4_operational_selection'] is None and
         review['a5']['actual_attempts_started'] == 0 and
         review['a5']['actual_attempt_reservations'] == 0 and
         review['a6_classification'] == 'ND' and
         review['technical_truth_accredited'] is False and
         review['confirmed_final_risk'] is None and
         review['applied_state_transition'] is None and
         review['published_generation'] is None and
         review['operational_dispatch'] is False and
         review['p8_operational'] == 'NO-GO',
         'REVIEW_AUTHORITY_REFUSED')
    need(cycle['operational_dispatch'] is False and
         cycle['vm_checks_executed'] is False and
         cycle['final_risk'] is None and
         cycle['p8_operational'] == 'NO-GO', 'R28_OPERATIONAL_CLAIM')
    need(review['unified']['a6_a7_a8_bridge']['confirmed_final_risk'] is None and
         all(row['a8_recommendation'] == 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'
             and row['a6_classification'] == 'ND' and
             row['confirmed_rf'] is None and
             row['applied_transition'] is None
             for row in review['unified']['decisions']),
         'A6_A8_PROMOTION_REFUSED')

    stage_sources = (
        session.document['sources_sha256']['rules'],
        session.document['sources_sha256']['integrated'],
        session.document['sources_sha256']['guard'],
        review['a4']['sha256'],
        binding['a5_fixture_journal_sha256'],
        review['unified']['sha256'],
        review['unified']['a6_a7_a8_bridge']['sha256'],
        cycle['a8']['sha256'],
        binding['sha256'],
        cycle['sha256'],
    )
    ledger: list[dict[str, Any]] = []
    previous = None
    for i, (status, source_sha) in enumerate(zip(STAGE_STATUSES, stage_sources), 1):
        entry = _ledger_stage(i, status, source_sha, previous, scope=(
            'R26_THREE_SERVICE_SYNTHETIC' if i <= 3 else
            'R58L_N_25_FAMILY_SYNTHETIC' if i <= 9 else
            'R28_READ_ONLY_DEVELOPMENT'))
        ledger.append(entry)
        previous = entry['event_sha256']

    result = {
        'schema': SCHEMA, 'source_base_commit': BASE,
        'mode': 'OFFLINE_CROSS_CONTRACT_AUDIT_NOT_FULL_EXECUTION',
        'session_id': fixture['session_id'],
        'r26_session_sha256': session.sha256,
        'r28_development_cycle_sha256': cycle['sha256'],
        'r58l_review_sha256': review['sha256'],
        'r58n_receipt_sha256': binding['sha256'],
        'journal_snapshot_sha256': binding['a5_fixture_journal_sha256'],
        'source_catalog_sha256': review['source_catalog_sha256'],
        'source_thesis_sha256': review['source_thesis_sha256'],
        'source_scopes': {
            'a1_a3': 'R26_THREE_SYNTHETIC_SERVICES_NO_DISPATCH',
            'a4_a8': 'R58L_N_25_FAMILY_SIMULATION_NO_DISPATCH',
            'a9': 'DECLARED_SIDE_CAR_RECEIPT_NOT_TECHNICAL_GENERATION',
            'a10': 'READ_ONLY_STATUS_AND_HASH_CHAIN',
        },
        'a1_a3_service_count': 3,
        'a1_a3_event_count': 9,
        'a4_a8_case_count': review['unit_count'],
        'a4_a8_family_count': review['covered_family_count'],
        'a4_selected_hypothetical': review['a4_selected_identity'],
        'a4_operational_selection': None,
        'a5_local_fixture_state': binding['a5_fixture_state'],
        'a5_local_fixture_start_intent_count': binding['a5_fixture_start_intent_count'],
        'a5_real_operational_attempts': 0,
        'a6_classification': 'ND',
        'a7_uncertainty_only': True,
        'a8_recommendation': 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
        'a9_local_declared_receipt_verified': True,
        'a10_stage_count': 10,
        'stage_ledger': ledger,
        'ledger_head_sha256': previous,
        'a1_a3_to_family_case_binding_attested': False,
        'independent_physical_case_binding_attested': False,
        'a1_a10_implementation_complete': False,
        'experimental_hypothesis_validated': False,
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'applied_state_transition': None,
        'published_generation': None,
        'vm_checks_executed': False,
        'operational_dispatch': False,
        'host_mutations': 0,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(result)) < MAX_REPORT_BYTES, 'TRACE_TOO_LARGE')
    result['sha256'] = digest(result)
    return result


def verify_cross_contract_trace(report: dict[str, Any],
                                scenario: dict[str, Any],
                                review: dict[str, Any],
                                journal_root: Path, receipt_root: Path,
                                request_id: str) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None, 'TRACE_SCHEMA')
    need(digest({k: v for k, v in report.items() if k != 'sha256'}) ==
         report['sha256'], 'TRACE_DIGEST')
    expected = build_cross_contract_trace(scenario, review, journal_root,
                                          receipt_root, request_id)
    need(canonical(expected) == canonical(report), 'TRACE_NOT_REPRODUCIBLE')
    return True
