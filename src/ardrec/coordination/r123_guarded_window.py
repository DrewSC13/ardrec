"""R123: FTP-T01 60s watchdog *contract* and one-shot lifecycle model.

SOURCE_ONLY. No privileged root transition, systemd timer creation, nftables,
VM boot, sockets, or executor dispatch. A modeled autonomous DENY closure is
not proof that a physical watchdog is installed or will run after a crash.

The module binds the verifiable R122 host/case report to a strictly bounded
monotonic protocol and refuses any positive operational assertion. It is the
interface to be implemented by a separately audited, root-owned supervisor.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r122_operational_boundary as r122

SCHEMA = 'ARDREC-R123-FTP-T01-MONOTONIC-DENY-WATCHDOG-CONTRACT-v1'
TRACE_SCHEMA = SCHEMA + '-trace-v1'
REPORT_SCHEMA = SCHEMA + '-inspection-v1'
MAX_WINDOW_SECONDS = 60
GUARD_RESTORE_TARGET_SECONDS = 45  # 15s reserved for restoration/verification
MAX_NANOSECONDS = 60 * 1_000_000_000
GIT_SHA = re.compile(r'[0-9a-f]{40}\Z')
HEX_SHA = re.compile(r'[0-9a-f]{64}\Z')
STAGES = ('PREPARED', 'DENY_GUARD_ARMED', 'SESSION_CLOSED', 'DENY_READBACK_VERIFIED')
TRUST = 'INDEPENDENT_ROOT_SUPERVISOR_REQUIRED_NOT_INSTALLED'


class Stop(ValueError):
    """Stable refusal: failure must never be interpreted as authority."""


def need(value: bool, code: str) -> None:
    if not value:
        raise Stop(code)


def _exact(obj: Any, names: set[str], code: str) -> dict:
    need(type(obj) is dict and set(obj) == names, code)
    return obj


def _utc(now: datetime) -> datetime:
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None and now.microsecond == 0, 'CLOCK_UNTRUSTED')
    return now.astimezone(timezone.utc)


def _ns(value: Any) -> int:
    need(type(value) is int and 0 <= value < 2**63, 'MONOTONIC_NS_INVALID')
    return value


def guard_model(*, plan_sha256: str, events: list[dict],
                root_supervisor_proof: bool = False) -> dict:
    """Verify synthetic/recorded *ordering*; never attest that root acted.

    Root proof is deliberately refused: an independently provisioned root
    supervisor must enforce and attest a real session in a future release.
    """
    need(type(plan_sha256) is str and HEX_SHA.fullmatch(plan_sha256) is not None,
         'PLAN_SHA_INVALID')
    need(root_supervisor_proof is False, 'ROOT_PROOF_NOT_SUPPORTED')
    need(type(events) is list and 1 <= len(events) <= len(STAGES),
         'TRACE_EVENT_COUNT')
    accepted = []
    prev = -1
    start = None
    for idx, event in enumerate(events):
        item = _exact(event, {'stage','at_monotonic_ns','plan_sha256',
                              'firewall_allow','network_connections','vm_starts'},
                      'TRACE_EVENT_FIELDS')
        need(item['stage'] == STAGES[idx] and
             item['plan_sha256'] == plan_sha256, 'TRACE_ORDER_OR_BINDING')
        when = _ns(item['at_monotonic_ns'])
        need(when >= prev, 'MONOTONIC_REGRESSION')
        prev = when
        need(item['firewall_allow'] is False and
             type(item['network_connections']) is int and
             item['network_connections'] == 0 and
             type(item['vm_starts']) is int and item['vm_starts'] == 0,
             'PHYSICAL_ACTION_FORBIDDEN')
        if idx == 0:
            start = when
        else:
            need(when - start <= MAX_NANOSECONDS, 'DEADLINE_EXCEEDED')
        if idx == 1:
            need(when - start <= GUARD_RESTORE_TARGET_SECONDS*1_000_000_000,
                 'GUARD_ARMING_TOO_LATE')
        accepted.append(item['stage'])
    is_complete = len(accepted) == len(STAGES)
    need(not is_complete or events[-1]['at_monotonic_ns'] - start <= MAX_NANOSECONDS,
         'RESTORE_OUTSIDE_60S')
    return {
        'schema': TRACE_SCHEMA,
        'plan_sha256': plan_sha256,
        'stages_seen': accepted,
        'monotonic_protocol_complete': is_complete,
        'root_supervisor_independently_attested': False,
        'physical_deny_reapplied': False,
        'a5_dispatch_authorized': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }


def plan(*, boundary: dict, catalog_raw: bytes, now: datetime,
         duration_seconds: int = GUARD_RESTORE_TARGET_SECONDS,
         pilot_bundle: tuple[bytes, bytes, bytes] | None = None,
         pilot_reviewer=f15.signed_pilot_review) -> dict:
    """Reverify R122 receipts, consume no attempt, issue no operational grant.

    A documentary signed pilot F15 status can be supplied by an independent
    reviewer, but is never promoted to physical authority. No implicit
    fallback from unsigned local inputs to allow-traffic is possible.
    """
    instant = _utc(now)
    need(type(duration_seconds) is int and
         1 <= duration_seconds <= GUARD_RESTORE_TARGET_SECONDS,
         'WINDOW_DURATION_UNSAFE')
    try:
        r122.verify(boundary, catalog_raw)
    except (r122.Stop, ValueError, TypeError, OSError, KeyError) as exc:
        raise Stop('R122_SOURCE_CHAIN_INVALID') from exc
    need(type(boundary.get('head')) is str and
         GIT_SHA.fullmatch(boundary['head']) is not None,
         'SOURCE_HEAD_INVALID')
    need(boundary.get('p8') == 'NO-GO' and
         boundary.get('a6') == 'ND' and
         boundary.get('a9_generation') is None and
         boundary.get('dispatch_authorized') is False and
         boundary.get('physical_origin_attested') is False,
         'BOUNDARY_PROMOTED')
    need(type(boundary.get('blockers')) is list and boundary['blockers'],
         'NO_BOUNDARY_BLOCKERS')
    status = 'NOT_PROVIDED'
    pilot_sha = None
    if pilot_bundle is not None:
        need(type(pilot_bundle) is tuple and len(pilot_bundle) == 3 and
             all(type(x) is bytes and 0 < len(x) <= 65536 for x in pilot_bundle),
             'PILOT_DOCUMENT_INPUTS')
        try:
            signed = pilot_reviewer(*pilot_bundle, now=now,
                                    head=boundary['head'], catalog_raw=catalog_raw)
        except (f15.Stop, ValueError, OSError, TypeError, KeyError) as exc:
            raise Stop('INDEPENDENT_SIGNED_DOCUMENT_REJECTED') from exc
        need(type(signed) is dict and
             signed.get('document_status') in ('DOCUMENT_SIGNED','REVOKED') and
             signed.get('head') == boundary['head'] and
             signed.get('family_id') == 'FTP-T01' and
             type(signed.get('pilot_sha256')) is str and
             HEX_SHA.fullmatch(signed['pilot_sha256']) is not None and
             signed.get('p8') == 'NO-GO' and
             signed.get('authorized_to_connect_by_module') is False and
             signed.get('physical_pilot_session_attested') is False,
             'SIGNED_PILOT_REVIEW_INVARIANT')
        status = signed['document_status']
        pilot_sha = signed['pilot_sha256']
    blockers = set(boundary['blockers'])
    try:
        assessed = datetime.strptime(boundary['evaluated_at_utc'],
                                     '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise Stop('R122_TIME_INVALID') from exc
    assessment_age = (instant - assessed).total_seconds()
    if not (-2 <= assessment_age <= 60):
        blockers.add('R122_BOUNDARY_EVALUATION_NOT_FRESH')
    blockers.update({
        'P7_DRAFT_NOT_FROZEN',
        'ROOT_AUTONOMOUS_60S_DENY_GUARD_NOT_PROVISIONED',
        'ROOT_OPERATIONAL_PERMIT_NOT_VERIFIED',
        'FRESH_INDEPENDENT_REVOCATION_NOT_ATTESTED',
        'A3_F11_F16_PHYSICAL_PREFLIGHT_REQUIRED',
        'PILOT_DOCUMENT_NOT_A_PHYSICAL_EXECUTION_PERMIT',
        'A5_A6_A9_AUTHORITATIVE_PIPELINE_BLOCKED',
    })
    out = {
        'schema': SCHEMA,
        'head': boundary['head'],
        'boundary_sha256': boundary['sha256'],
        'case_id': boundary['case_id'],
        'capture_sha256': boundary['capture_sha256'],
        'host_lifecycle': boundary['host_lifecycle'],
        'pilot_document_status': status,
        'pilot_document_sha256': pilot_sha,
        'checked_at_utc': instant.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'max_window_seconds': MAX_WINDOW_SECONDS,
        'deny_restore_target_seconds': duration_seconds,
        'guard_clock': 'CLOCK_MONOTONIC_REQUIRED',
        'root_guard_status': TRUST,
        'guard_installed': False,
        'guard_armed': False,
        'root_permit_authenticated': False,
        'autonomous_deny_verified': False,
        'one_shot_attempt_consumed': False,
        'guest_starts': 0, 'network_connections': 0, 'firewall_changes': 0,
        'a5': 'NO-GO', 'a6': 'ND', 'a7_confirmed_rf': None,
        'a8_authoritative_transition': None,
        'a9_generation': None, 'p8': 'NO-GO',
        'blockers': sorted(blockers),
    }
    out['sha256'] = f1.digest(f1.canonical(out))
    return out


def verify_plan(result: dict, *, boundary: dict, catalog_raw: bytes,
                pilot_bundle: tuple[bytes, bytes, bytes] | None = None,
                pilot_reviewer=f15.signed_pilot_review) -> bool:
    """Recompute from R122 sources (not merely a locally supplied digest)."""
    need(type(result) is dict and type(result.get('checked_at_utc')) is str,
         'PLAN_SCHEMA')
    try:
        when = datetime.strptime(result['checked_at_utc'],
                                 '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        expected = plan(boundary=boundary, catalog_raw=catalog_raw,
                        now=when, duration_seconds=result['deny_restore_target_seconds'],
                        pilot_bundle=pilot_bundle, pilot_reviewer=pilot_reviewer)
    except (ValueError, KeyError, TypeError, OSError, r122.Stop) as exc:
        raise Stop('PLAN_REPLAY_SOURCE_REJECTED') from exc
    need(f1.canonical(result) == f1.canonical(expected), 'PLAN_REPLAY_DRIFT')
    return True


def capabilities() -> dict:
    return {
        'schema': SCHEMA+'-capabilities',
        'source_bound_r122_replay': True,
        'f15_document_projection_never_authority': True,
        'modeled_monotonic_watchdog_trace': True,
        'max_window_seconds': MAX_WINDOW_SECONDS,
        'target_restore_seconds': GUARD_RESTORE_TARGET_SECONDS,
        'physical_root_watchdog_installed': False,
        'independent_root_guard_p8': False,
        'one_shot_physical_pilot_executed': False,
        'a6': 'ND','a9_generation': None,'p8': 'NO-GO',
        'vm_starts': 0,'network_connections': 0,'firewall_changes': 0,
    }
