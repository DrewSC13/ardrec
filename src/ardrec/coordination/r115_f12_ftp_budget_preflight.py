"""R115-F12: enforce F11 recv-call/byte budgets on an injected FTP socket.

No socket creation, connect, send, VM or firewall operation. There is NO
execution-authorizing path here: P7 remains a draft; the receiving caller must
be a separately approved root/P8 dispatcher that owns the already-connected
socket and the independent current-P8 guard. Offline review cannot freeze P7.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f10_ftp_a5_transport as f10
from ardrec.coordination import r115_f11_p8_signed_window as f11
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f9_authority_handoff as f9

SCHEMA = 'ARDREC-R115-F12-FTP-T01-RECV-BUDGET-v1'
ROOT = Path('/home/cicada/ardrec-lab/r115-f12-prepilot-v1')
CATALOG = Path('lab/operational-catalog-v1/catalog.json')
SOURCE = 'src/ardrec/coordination/r115_f12_ftp_budget_preflight.py'
SCRIPT = 'scripts/ardrec_p14_r115_f12_ftp_budget_preflight.py'
# Conservative candidate, NOT an approved physical pilot or frozen catalogue.
DRAFT_BUDGET = dict(f11.BUDGET_CAPS)


class Stop(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def validate_profile(budget, contract=None):
    """Finite profile for review, never an operational P7 approval."""
    need(type(budget) is dict and set(budget) == f11.BUDGET_KEYS,
         'BUDGET_FIELDS')
    for key, ceiling in f11.BUDGET_CAPS.items():
        value = budget[key]
        need(type(value) is int and 0 <= value <= ceiling, 'BUDGET_INVALID_' + key)
        if key != 'additional_attempts':
            need(value > 0, 'BUDGET_EMPTY_' + key)
    need(budget['max_connections'] == 1 and budget['ordinary_attempts'] == 1 and
         budget['additional_attempts'] == 0, 'NO_RETRY_ONE_CONNECTION')
    need(budget['read_size'] <= f10.MAX_RECV and
         budget['read_size'] <= budget['max_recv_bytes'] and
         budget['max_recv_calls'] * budget['read_size'] >= budget['max_recv_bytes'],
         'RECEIVE_DIMENSIONS_INCONSISTENT')
    need(budget['max_recv_bytes'] <= f10.MAX_BYTES and
         budget['timeout_seconds'] <= f10.MAX_SECONDS and
         budget['max_lines'] <= f10.MAX_LINES, 'F10_CAP_MISMATCH')
    if contract is not None:
        try:
            f11.validate_budget(budget, contract)
        except (f11.Stop, f1.Rejected) as exc:
            raise Stop('CONTRACT_BUDGET_REJECTED') from exc
    return dict(budget)


class MeteredSocket:
    """Decorates a connected socket; enforces calls/bytes BEFORE each recv.

    Does not create or own a connection; does not validate current P8. Both
    responsibilities remain with the external authorized dispatcher. F10 may
    call `recv` through this decorator and its supplied current-P8 guard.
    """
    __slots__ = ('_sock', '_profile', '_calls', '_bytes', '_sealed')

    def __init__(self, connected_socket, profile):
        need(connected_socket is not None, 'SOCKET_MISSING')
        self._sock = connected_socket
        self._profile = validate_profile(profile)
        self._calls = 0
        self._bytes = 0
        self._sealed = False

    @property
    def family(self):
        return self._sock.family

    @property
    def type(self):
        return self._sock.type

    def getpeername(self):
        return self._sock.getpeername()

    def settimeout(self, seconds):
        need(not self._sealed, 'SOCKET_SEALED')
        need(type(seconds) in (int, float) and 0 < seconds <=
             self._profile['timeout_seconds'] + 1e-6,
             'SOCKET_TIMEOUT_EXCEEDS_BUDGET')
        return self._sock.settimeout(seconds)

    def recv(self, size):
        need(not self._sealed, 'SOCKET_SEALED')
        need(type(size) is int and 0 < size <= self._profile['read_size'],
             'REQUEST_SIZE_EXCEEDS_BUDGET')
        need(self._calls < self._profile['max_recv_calls'],
             'RECV_CALL_BUDGET_EXHAUSTED')
        need(size <= self._profile['max_recv_bytes'] - self._bytes,
             'RECV_BYTE_BUDGET_EXHAUSTED')
        # Consumed BEFORE the physical call. Even timeout/failed reads cost a call.
        self._calls += 1
        data = self._sock.recv(size)
        need(type(data) is bytes and len(data) <= size,
             'SOCKET_RETURNED_INVALID_BYTES')
        self._bytes += len(data)
        need(self._bytes <= self._profile['max_recv_bytes'],
             'RECV_BYTE_OVERRUN')
        return data

    def seal(self):
        need(not self._sealed, 'METER_ALREADY_SEALED')
        self._sealed = True
        return {'recv_calls': self._calls, 'received_bytes': self._bytes,
                'budget_sha256': f1.digest(f1.canonical(self._profile))}


def audit_f10_candidate(result, usage, profile):
    """Offline provenance-neutral consistency audit, never A6 admission.

    Receives F10's result and the meter's sealed counters. The external dispatcher
    must still bind its own verifiable receipt to the physical socket and P8.
    """
    budget = validate_profile(profile)
    need(type(usage) is dict and set(usage) ==
         {'recv_calls', 'received_bytes', 'budget_sha256'}, 'USAGE_FIELDS')
    need(usage['budget_sha256'] == f1.digest(f1.canonical(budget)),
         'USAGE_BUDGET_CHANGED')
    need(type(usage['recv_calls']) is int and
         0 <= usage['recv_calls'] <= budget['max_recv_calls'] and
         type(usage['received_bytes']) is int and
         0 <= usage['received_bytes'] <= budget['max_recv_bytes'],
         'USAGE_OUT_OF_BOUNDS')
    need(type(result) is dict and
         type(result.get('recv_calls')) is int and
         type(result.get('received_bytes')) is int and
         result['recv_calls'] == usage['recv_calls'] and
         result['received_bytes'] == usage['received_bytes'],
         'F10_METER_MISMATCH')
    limits = result.get('limits')
    need(type(limits) is dict and limits == {
        'timeout_seconds': budget['timeout_seconds'],
        'max_bytes': budget['max_recv_bytes'],
        'max_lines': budget['max_lines'],
        'read_size': budget['read_size']}, 'F10_PROFILE_CHANGED')
    need(type(result.get('elapsed_seconds')) in (int,float) and
         0 <= result['elapsed_seconds'] <= budget['timeout_seconds'] + 0.01,
         'F10_DURATION_INVALID')
    need(len(f1.canonical(result)) <= budget['max_output_bytes'],
         'F10_OUTPUT_TOO_LARGE')
    try:
        candidate = f11.validate_transport_candidate(
            result, max_bytes=budget['max_recv_bytes'])
    except (f11.Stop, f10.Stop, f1.Rejected) as exc:
        raise Stop('F10_INTEGRITY_OR_CLASSIFICATION') from exc
    need(candidate['transport_origin_attested'] is False and
         candidate['a6'] == 'ND' and candidate['p8'] == 'NO-GO',
         'UNAUTHORIZED_PROMOTION')
    return {
        'schema': SCHEMA+'-candidate-audit',
        'family_id': 'FTP-T01',
        'candidate_f10_sha256': candidate['f10_sha256'],
        'profile_sha256': f1.digest(f1.canonical(budget)),
        'received_bytes': usage['received_bytes'],
        'recv_calls': usage['recv_calls'],
        'reply_complete_220': candidate['observed_220'],
        'physical_origin_attested': False,
        'pilot_completed': False, 'p8': 'NO-GO', 'a6': 'ND',
        'a7': None, 'a8': None, 'a9': None, 'a10': None,
        'scope': 'CANDIDATE_ONLY_NOT_PHYSICAL_PROOF'
    }


def prepilot_review(catalog_raw, profile=None, *, head):
    """Record a finite proposed profile, not an empirical calibration."""
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'HEAD_INVALID')
    cat = f1.load(catalog_raw)
    need(cat.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         cat.get('execution_enabled') is False and
         cat.get('pilot_completed') is False and
         cat.get('catalog_frozen') is False, 'CATALOG_NOT_DRAFT')
    families = cat.get('families')
    need(type(families) is list and len(families) == 25, 'FAMILY_COUNT')
    ids = [x.get('id') if type(x) is dict else None for x in families]
    need(len(set(ids)) == 25 and
         set(ids) == ({f'SSH-T{i:02d}' for i in range(1, 9)} |
                      {f'FTP-T{i:02d}' for i in range(1, 9)} |
                      {f'SMB-T{i:02d}' for i in range(1, 10)}),
         'FAMILY_INVENTORY')
    family = next(x for x in families if x['id'] == 'FTP-T01')
    need(family.get('preconditions') == list(f1.GATES) and
         family.get('required_supports') == list(f1.SUPPORTS) and
         family.get('cleanup') == 'NO_MUTATION', 'FTP_T01_CONTRACT_DRIFT')
    budget = validate_profile(DRAFT_BUDGET if profile is None else profile)
    return {
        'schema': SCHEMA+'-prepilot-review',
        'head': head, 'catalog_sha256': f1.digest(catalog_raw),
        'family_id': 'FTP-T01', 'candidate_profile': budget,
        'profile_sha256': f1.digest(f1.canonical(budget)),
        'requires_external_scope_and_boot_authority': True,
        'requires_independent_physical_pilot_evidence': True,
        'requires_p7_freeze_review_after_real_pilot': True,
        'physical_measurements': [], 'synthetic_measurements': [],
        'pilot_completed': False, 'catalog_frozen': False,
        'execution_enabled': False, 'a3': 'ND', 'a5': 'NO-GO',
        'a6': 'ND', 'p8': 'NO-GO',
        'connections_created': 0, 'guest_starts': 0,
        'status': 'PROFILE_PROPOSED_NOT_CALIBRATED',
    }


def persist(review, root=ROOT):
    need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
    need(type(review) is dict and review.get('schema') == SCHEMA+'-prepilot-review' and
         review.get('p8') == 'NO-GO' and review.get('pilot_completed') is False and
         review.get('connections_created') == 0 and review.get('guest_starts') == 0,
         'UNSAFE_PREPILOT_REPORT')
    folder = f7._create(root, 'review-')
    raw = f1.canonical(review)
    f2.exclusive(folder/'report.json',raw)
    f2.exclusive(folder/'manifest.json', f1.canonical({
        'schema': SCHEMA+'-manifest', 'report_sha256': f1.digest(raw),
        'type': 'PREPILOT_NO_NETWORK_NOT_AUTHORITY',
    }))
    return folder


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='ARDREC R115-F12 offline FTP-T01 finite-budget prepilot (NO-GO)')
    parser.add_argument('--review',required=True,action='store_true')
    args=parser.parse_args(argv)
    try:
        head=f9.source_guard()
        need(f7._run(('git','ls-files','--error-unmatch',SOURCE))['rc'] == 0 and
             f7._run(('git','ls-files','--error-unmatch',SCRIPT))['rc'] == 0,
             'F12_SOURCES_NOT_COMMITTED')
        review=prepilot_review(CATALOG.read_bytes(),head=head)
        path=persist(review)
        print('R115_F12_RECEIPT='+str(path))
        print('R115_F12_HEAD='+head)
        print('R115_F12_CATALOG_SHA256='+review['catalog_sha256'])
        print('R115_F12_PROFILE_SHA256='+review['profile_sha256'])
        print('R115_F12_STATUS='+review['status'])
        print('R115_F12_RECV_CALLS_MAX='+str(review['candidate_profile']['max_recv_calls']))
        print('R115_F12_RECV_BYTES_MAX='+str(review['candidate_profile']['max_recv_bytes']))
        print('R115_F12_PILOT_COMPLETED=False')
        print('R115_F12_CATALOG_MUTATIONS=0')
        print('R115_F12_A5=NO-GO')
        print('R115_F12_A6=ND')
        print('R115_F12_P8=NO-GO')
        print('R115_F12_NETWORK_CONNECTIONS=0')
        print('R115_F12_VM_STARTS=0')
        return 0
    except (Stop, f1.Rejected, f11.Stop, f7.Stop, f9.Stop,
            OSError, ValueError, TypeError, KeyError) as exc:
        print('R115_F12_STOP='+type(exc).__name__+':'+str(exc)[:160])
        print('R115_F12_P8=NO-GO')
        return 23


if __name__=='__main__':
    raise SystemExit(main())
