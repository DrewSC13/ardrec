"""R58-G: pin-registry campaign policy around R58-F signed witnesses.

Never promotes a statement, regardless of signature, to technical accreditation.
This function performs no I/O, state transition, VM operation, or publication.
"""
from __future__ import annotations

from typing import Any
import re

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58f_signed_bridge import (
    build_signed_bridge, verify_signed_bridge,
)
from ardrec.evidence.r58g_trust_registry import (
    RegistryError, validate_registry, trusted_for_capture,
    identifier, utc, hex256, registry_digest,
)

SCHEMA = 'ardrec-r58g-a6-pinned-registry-signed-bridge-v1'
MAX_BUNDLES = 16


class RegistryBridgeError(ValueError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise RegistryBridgeError(code)


def _unit_key(row: dict[str, Any]) -> tuple[str, str, int]:
    return row['service_id'], row['case_id'], row['assessment_index']


def build_registry_bridge(units: list[dict[str, Any]], bundles: list[dict[str, Any]], *,
                          registry: dict[str, Any], pinned_registry_sha256: str,
                          as_of_utc: str, prior_record_ids: tuple[str, ...]) -> dict[str, Any]:
    """Use separately pinned governance input and explicit historical record IDs.

    The historical record set MUST come from a trusted independent ledger;
    this stateless function does NOT guarantee replay prevention across runs.
    """
    validate_registry(registry, pinned_sha256=pinned_registry_sha256)
    need(registry['campaign_id'] == registry['session_id'],
         'CAMPAIGN_MUST_BE_SIGNED_SESSION')
    need(registry['session_id'] == 'DEV_TUTOR_001',
         'R58F_ONLY_DEV_TUTOR_001_SUPPORTED')
    need(type(prior_record_ids) is tuple and all(identifier(v) for v in prior_record_ids)
         and tuple(sorted(set(prior_record_ids))) == prior_record_ids,
         'PRIOR_RECORDS_NOT_CANONICAL')
    need(type(bundles) is list and len(bundles) <= MAX_BUNDLES, 'BUNDLE_COUNT')
    expected_keys = {_unit_key(u) for u in registry['scope']}
    need(type(units) is list and len(units) == len(expected_keys), 'CAMPAIGN_SCOPE_COUNT_MISMATCH')
    # R58-F/R58-E validate each input's identity and the exact per-unit model.
    need(all(type(u) is dict and {'service_id','case_id','assessment_index'} <= set(u)
             for u in units), 'UNIT_IDENTITY')
    need({_unit_key(u) for u in units} == expected_keys,
         'CAMPAIGN_SCOPE_MISMATCH')
    hashes = {_unit_key(s): s['configuration_sha256'] for s in registry['scope']}
    methods = {_unit_key(s): s['method_id'] for s in registry['scope']}
    by_role = {a['role']: a for a in registry['authorities']}
    need(len(by_role) == 2, 'REGISTRY_AUTHORITY_DUPLICATE')
    seen = set()
    for bundle in bundles:
        need(type(bundle) is dict and set(bundle) == {'statement', 'signatures', 'support'},
             'UNTRUSTED_BUNDLE_SCHEMA')
        s = bundle['statement']
        need(type(s) is dict and {'service_id','case_id','assessment_index','record_id',
             'captured_at_utc','method_id','session_id'} <= set(s), 'STATEMENT_IDENTITY')
        k = _unit_key(s)
        need(k in expected_keys and s['method_id'] == methods[k], 'STATEMENT_NOT_IN_CAMPAIGN')
        need(s['session_id'] == registry['session_id'], 'SIGNED_SESSION_NOT_CAMPAIGN')
        rid = s['record_id']
        need(identifier(rid) and rid not in prior_record_ids and rid not in seen,
             'REPLAY_OR_DUPLICATE_RECORD')
        seen.add(rid)
        # These checks apply per capture, so a key revoked later in the batch
        # cannot be retained by accidentally reusing a stale trust decision.
        trusted_for_capture(registry, pinned_sha256=pinned_registry_sha256,
                            captured_at_utc=s['captured_at_utc'], review_at_utc=as_of_utc)
    trust = {role: {'key_id': authority['key_id'],
                    'public_key_pem': authority['public_key_pem'].encode('ascii')}
             for role, authority in by_role.items()}
    bridge = build_signed_bridge(units, bundles, configuration_hashes=hashes,
                                  trusted_authorities=trust, as_of_utc=as_of_utc)
    verify_signed_bridge(bridge, units, bundles, configuration_hashes=hashes,
                         trusted_authorities=trust, as_of_utc=as_of_utc)
    decision = {
        'schema': SCHEMA,
        'campaign_id': registry['campaign_id'],
        'session_id': registry['session_id'],
        'registry_sha256': registry_digest(registry),
        'registry_pin_matched_caller_parameter': True,
        'registry_pin_provenance_independently_attested': False,
        'review_at_utc': as_of_utc,
        'policy': 'PINNED_DOCUMENTARY_REGISTRY_NO_TECHNICAL_AUTHORITY',
        'registered_roles': ['observer', 'reviewer'],
        'registered_owner_separation_claim_checked': True,
        'physical_safety_and_signer_independence_attested': False,
        'historical_record_ids_sha256': digest(list(prior_record_ids)),
        'verified_new_record_ids': sorted(seen),
        'replay_guard_scope': 'CALLER_SUPPLIED_HISTORICAL_LEDGER_ONLY',
        'r58f_bridge_sha256': bridge['sha256'],
        'signed_witness_count': bridge['signed_witness_count'],
        'unit_count': bridge['unit_count'],
        'decisions': bridge['decisions'],
        'a7': bridge['a7'],
        'a6_classification': 'ND',
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'applied_state_transition': None,
        'published_generation': None,
        'operational_dispatch': False,
        'vm_checks_executed': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(decision)) <= 262144, 'REGISTRY_REPORT_TOO_LARGE')
    decision['sha256'] = digest(decision)
    return decision


def verify_registry_bridge(report: dict[str, Any], units: list[dict[str, Any]],
                           bundles: list[dict[str, Any]], *, registry: dict[str, Any],
                           pinned_registry_sha256: str, as_of_utc: str,
                           prior_record_ids: tuple[str, ...]) -> bool:
    need(type(report) is dict and hex256(report.get('sha256')), 'REGISTRY_REPORT_SCHEMA')
    expected = build_registry_bridge(units, bundles, registry=registry,
                                     pinned_registry_sha256=pinned_registry_sha256,
                                     as_of_utc=as_of_utc,
                                     prior_record_ids=prior_record_ids)
    need(canonical(expected) == canonical(report), 'REGISTRY_REPORT_NOT_REPRODUCIBLE')
    return True
