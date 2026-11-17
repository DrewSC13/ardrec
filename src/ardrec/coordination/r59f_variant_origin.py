"""R59-F: versioned A5 intent that binds FTP/SMB variant at creation.

Backward-compatible projection into R59-D and R59-E, with no revision of old
receipts. The pinned P7 catalogue is consulted on creation and readback.
No authority for attempt dispatch or A6 truth is granted by this module.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import os
import json

from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59e_a5_a6_family_bridge as e

SCHEMA_INTENT = 'ardrec-r59f-a5-variant-origin-intent-v2'
SCHEMA_RECEIPT = 'ardrec-r59f-a5-variant-origin-result-v2'
SCHEMA_REPORT = 'ardrec-r59f-variant-bound-a5-a6-projection-v1'
MODE = 'VERSIONED_VARIANT_ORIGIN_UNACCREDITED_LEGACY_PROJECTION'
IDENTITY = ('service_id', 'session_id', 'family_id', 'derived_case_id',
            'assessment_index', 'attempt_id', 'configuration_sha256', 'method_id')
INTENT_FIELDS = frozenset((*IDENTITY, 'schema', 'variant',
    'source_catalog_sha256', 'requirements_sha256', 'legacy_intent_sha256',
    'model_phase', 'source_mode', 'p8_operational', 'sha256'))
RECEIPT_FIELDS = frozenset((set(d.RECEIPT_FIELDS) - {'schema', 'intent_sha256'}) |
                          {'schema', 'v2_intent_sha256', 'legacy_intent_sha256',
                           'variant', 'sha256'})
REPORT_FIELDS = frozenset({'schema', 'mode', 'intent', 'receipt',
    'legacy_candidate_sha256', 'legacy_intent_sha256', 'source_bridge_sha256',
    'source_catalog_sha256', 'source_requirements_sha256',
    'variant_bound_at_origin', 'legacy_projection_not_original_v2',
    'a5_start_independently_attested', 'a6_classification', 'technical_truth_accredited',
    'confirmed_rf', 'published_generation', 'operational_dispatch',
    'p8_operational', 'sha256'})
MAX_REPORT = 65536


class VariantOriginError(ValueError):
    """Strict identity and immutable replay validation failure."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise VariantOriginError(reason)


def _catalogue(service: str, family: str, variant: str | None):
    pinned, engines = e._sources()
    need(service in engines, 'SERVICE_UNKNOWN')
    engine, specs, _, _ = engines[service]
    requirements = e._requirements(service, family, variant, specs, engine)
    return pinned, requirements


def build_intent(*, variant: str | None, **identity: Any) -> dict[str, Any]:
    """New v2 intent: variant precedes any projected receipt or review."""
    need(set(identity) == set(IDENTITY), 'INTENT_IDENTITY_FIELDS')
    legacy = d.build_intent(**identity)
    catalogue, requirements = _catalogue(identity['service_id'], identity['family_id'], variant)
    doc = {'schema': SCHEMA_INTENT, **{k: legacy[k] for k in IDENTITY},
           'variant': variant, 'source_catalog_sha256': catalogue,
           'requirements_sha256': d.digest(requirements),
           'legacy_intent_sha256': legacy['sha256'],
           'model_phase': 'PENDIENTE',
           'source_mode': 'V2_VARIANT_DECLARED_BEFORE_RESULT_NO_EXECUTION_AUTHORITY',
           'p8_operational': 'NO-GO'}
    doc['sha256'] = d.digest(doc)
    need(set(doc) == INTENT_FIELDS, 'INTENT_INTERNAL_FIELDS')
    return doc


def verify_intent(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and set(doc) == INTENT_FIELDS and
         d._hex(doc.get('sha256')), 'INTENT_SCHEMA')
    expected = build_intent(variant=doc['variant'], **{k:doc[k] for k in IDENTITY})
    need(d.canonical(doc) == d.canonical(expected), 'INTENT_SEMANTICS_OR_CATALOG_DRIFT')
    return True


def _legacy(intent: dict[str, Any]):
    verify_intent(intent)
    result = d.build_intent(**{k:intent[k] for k in IDENTITY})
    need(result['sha256'] == intent['legacy_intent_sha256'],
         'LEGACY_INTENT_PROJECTION_DRIFT')
    return result


def make_receipt(intent: dict[str, Any], *, outcome: str = 'NO_START',
                 source_kind: str = 'LOCAL_BENIGN_FIXTURE', support: bytes = b'',
                 start_utc: str | None = None,
                 finish_utc: str | None = None) -> dict[str, Any]:
    legacy = _legacy(intent)
    old = d.make_receipt(legacy, outcome=outcome, source_kind=source_kind,
                         support=support, start_utc=start_utc, finish_utc=finish_utc)
    # Validate the projected receipt in the already tested R59-D kernel.
    d.build_candidate(legacy, old, support)
    result = {'schema': SCHEMA_RECEIPT,
              **{k: v for k, v in old.items() if k not in ('schema', 'intent_sha256')},
              'v2_intent_sha256': intent['sha256'],
              'legacy_intent_sha256': legacy['sha256'],
              'variant': intent['variant']}
    result['sha256'] = d.digest(result)
    need(set(result) == RECEIPT_FIELDS, 'RECEIPT_INTERNAL_FIELDS')
    return result


def _project_receipt(intent: dict[str, Any], receipt: dict[str, Any],
                     support: bytes):
    need(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS and
         d._hex(receipt.get('sha256')), 'RECEIPT_SCHEMA')
    expected = make_receipt(intent, outcome=receipt['declared_outcome'],
                            source_kind=receipt['source_kind'], support=support,
                            start_utc=receipt['declared_started_at_utc'],
                            finish_utc=receipt['declared_finished_at_utc'])
    need(d.canonical(expected) == d.canonical(receipt),
         'RECEIPT_IDENTITY_VARIANT_OR_HASH_DRIFT')
    old_intent = _legacy(intent)
    old_receipt = d.make_receipt(old_intent, outcome=receipt['declared_outcome'],
                                 source_kind=receipt['source_kind'], support=support,
                                 start_utc=receipt['declared_started_at_utc'],
                                 finish_utc=receipt['declared_finished_at_utc'])
    return old_intent, old_receipt


def _name(attempt_id: str) -> str:
    # A single v2 record per attempt identifier within this private store,
    # independently of changing case, family, variant or session declarations.
    need(type(attempt_id) is str and d.ATTEMPT.fullmatch(attempt_id) is not None,
         'ATTEMPT_ID_INVALID')
    return 'r59f-attempt-' + d.sha(b'ARDREC-R59F-ATTEMPT-ID-V1\0' +
                                    attempt_id.encode('ascii')) + '.json'


def _roots(output: Path, a5_root: Path, a6_root: Path) -> None:
    for root in (output, a5_root, a6_root):
        d._private_root(root)
    ids = {(p.stat().st_dev, p.stat().st_ino) for p in (output,a5_root,a6_root)}
    need(len(ids) == 3, 'THREE_PRIVATE_ROOTS_MUST_DIFFER')


def _report(intent: dict[str, Any], receipt: dict[str, Any],
            legacy_candidate: dict[str, Any], bridge: dict[str, Any]) -> dict[str, Any]:
    need(legacy_candidate['intent']['sha256'] == intent['legacy_intent_sha256'] and
         bridge['source_candidate_sha256'] == legacy_candidate['sha256'] and
         bridge['source_intent_sha256'] == intent['legacy_intent_sha256'] and
         bridge['variant'] == intent['variant'] and
         bridge['source_catalog_sha256'] == intent['source_catalog_sha256'] and
         bridge['variant_in_original_a5_intent'] is False,
         'LEGACY_BRIDGE_BINDING_DRIFT')
    need(legacy_candidate['a6_classification'] == bridge['a6_classification'] == 'ND' and
         legacy_candidate['a5_physical_start_accredited'] is False and
         bridge['a5_physical_start_accredited'] is False and
         bridge['technical_truth_accredited'] is False and
         legacy_candidate['a7_confirmed_rf'] is None and
         bridge['confirmed_rf'] is None and
         bridge['published_generation'] is None and
         legacy_candidate['p8_operational'] == bridge['p8_operational'] == 'NO-GO',
         'LEGACY_UNAUTHORIZED_PROMOTION')
    doc = {'schema': SCHEMA_REPORT, 'mode': MODE,
           'intent': intent, 'receipt': receipt,
           'legacy_candidate_sha256': legacy_candidate['sha256'],
           'legacy_intent_sha256': intent['legacy_intent_sha256'],
           'source_bridge_sha256': bridge['sha256'],
           'source_catalog_sha256': intent['source_catalog_sha256'],
           'source_requirements_sha256': intent['requirements_sha256'],
           'variant_bound_at_origin': True,
           'legacy_projection_not_original_v2': True,
           'a5_start_independently_attested': False,
           'a6_classification': 'ND', 'technical_truth_accredited': False,
           'confirmed_rf': None, 'published_generation': None,
           'operational_dispatch': False, 'p8_operational': 'NO-GO'}
    need(len(d.canonical(doc)) < MAX_REPORT - 100, 'REPORT_SIZE_LIMIT')
    doc['sha256'] = d.digest(doc)
    need(set(doc) == REPORT_FIELDS, 'REPORT_INTERNAL_FIELDS')
    return doc


def persist(root: Path, a5_root: Path, a6_root: Path,
            intent: dict[str, Any], receipt: dict[str, Any],
            support: bytes) -> dict[str, Any]:
    """Strict V2 replay. Parent stores are never rewritten or upgraded.

    Source & bridge persisted first, then a single immutable v2 record.
    Crash before final write may leave idempotently recoverable child sources;
    this is not an atomic transaction spanning three directories.
    """
    _roots(root, a5_root, a6_root)
    old_intent, old_receipt = _project_receipt(intent, receipt, support)
    target = root / _name(intent['attempt_id'])
    need(not target.is_symlink(), 'V2_RECORD_SYMLINK')
    if target.exists():
        previous = _read_record(root, intent['attempt_id'])
        need(previous['intent'] == intent and previous['receipt'] == receipt,
             'ATTEMPT_ID_REUSE_WITH_CHANGED_CASE_VARIANT_OR_RESULT')
    persisted = d.persist_candidate(a5_root, old_intent, old_receipt, support)
    candidate_sha = persisted['report_sha256']
    persisted_bridge = e.persist_bridge(a6_root,a5_root,candidate_sha,
                                        variant=intent['variant'])
    legacy = d.verify_stored_candidate(a5_root, candidate_sha)
    bridge = e.verify_stored_bridge(a6_root,a5_root,candidate_sha)
    need(persisted_bridge['bridge_sha256'] == bridge['sha256'],
         'BRIDGE_PERSISTENCE_DRIFT')
    doc = _report(intent, receipt, legacy, bridge)
    result = d._store_once(target,d.canonical(doc)+b'\n',MAX_REPORT)
    fd = os.open(root, os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try: os.fsync(fd)
    finally: os.close(fd)
    verify_stored(root,a5_root,a6_root,intent['attempt_id'])
    return {'status':result, 'v2_report_sha256':doc['sha256'],
            'legacy_candidate_sha256':candidate_sha,
            'bridge_sha256':bridge['sha256'],
            'variant':intent['variant'],'a6_classification':'ND',
            'p8_operational':'NO-GO'}


def _read_record(root: Path, attempt_id: str) -> dict[str, Any]:
    raw = d._read_private(root/_name(attempt_id), MAX_REPORT)
    try: doc = json.loads(raw, object_pairs_hook=d._pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise VariantOriginError('STORED_RECORD_INVALID_JSON') from exc
    need(type(doc) is dict and raw == d.canonical(doc)+b'\n',
         'STORED_RECORD_NOT_CANONICAL')
    return doc


def verify_stored(root: Path, a5_root: Path, a6_root: Path,
                  attempt_id: str) -> dict[str, Any]:
    _roots(root,a5_root,a6_root)
    doc = _read_record(root,attempt_id)
    need(set(doc) == REPORT_FIELDS and d._hex(doc.get('sha256')) and
         doc['intent']['attempt_id'] == attempt_id,
         'STORED_REPORT_FIELDS_OR_ID')
    intent, receipt = doc['intent'], doc['receipt']
    need(type(receipt) is dict and
         receipt['support_sha256'] == doc.get('receipt',{}).get('support_sha256'),
         'STORED_RECEIPT_INVALID')
    candidate = d.verify_stored_candidate(a5_root,doc['legacy_candidate_sha256'])
    bridge = e.verify_stored_bridge(a6_root,a5_root,doc['legacy_candidate_sha256'])
    support = (b'' if candidate['receipt']['support_bytes']==0 else
               d._read_private(a5_root/('r59d-support-'+candidate['receipt']['support_sha256']+'.bin'),d.MAX_SUPPORT))
    old_intent, old_receipt = _project_receipt(intent,receipt,support)
    need(candidate['intent'] == old_intent and candidate['receipt'] == old_receipt,
         'STORED_LEGACY_PROJECTION_DRIFT')
    expected = _report(intent,receipt,candidate,bridge)
    need(d.canonical(doc) == d.canonical(expected), 'STORED_V2_REPORT_OR_SOURCE_DRIFT')
    return doc
