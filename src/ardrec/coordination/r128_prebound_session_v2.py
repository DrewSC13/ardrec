"""R128-B9: irrevocable F13 handoff for ONE independently authorized guest probe.

No network, root privilege, guest launch, nft command, or grant issuance. A
prebound F13 intent is spent BEFORE external root staging; spent never means a
physical connection occurred. An independent operator must seal/approve the
handoff under a separately signed, root-owned traffic permit.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f13_ftp_a5_journal as f13

SCHEMA = 'ARDREC-R128-B9-PREBOUND-F13-ROOT-HANDOFF-v1'
SESSION = re.compile(r'[0-9a-f]{16}\Z')


class Stop(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def digest(value):
    return f1.digest(f1.canonical(value))


def build(*, journal: Path, head: str, session: str) -> dict:
    """Recompute binding to the already-spent journal, never trust a claim."""
    need(isinstance(journal, Path) and journal.is_absolute(), 'JOURNAL_ABSOLUTE_REQUIRED')
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'HEAD_INVALID')
    need(type(session) is str and SESSION.fullmatch(session), 'SESSION_INVALID')
    state = f13.inspect(journal)
    need(state['status'] == 'ATTEMPT_CONSUMED_UNRESOLVED',
         'F13_SPENT_BEFORE_ROOT_STAGING_REQUIRED')
    reservation = f13._read_json(journal, 'reservation.json')
    spent = f13._read_json(journal, 'spent.json')
    intent = reservation['intent']
    need(intent['session_id'] == session and intent['head'] == head,
         'F13_SESSION_OR_HEAD_NOT_PREBOUND')
    need(spent['reservation_sha256'] == state['reservation_sha256'] and
         spent['status'] == 'ATTEMPT_CONSUMED_NO_RETRY', 'F13_SPENT_MISMATCH')
    value = {'schema': SCHEMA, 'head': head, 'session': session,
             'case_id': intent['case_id'], 'case_key': state['case_key'],
             'assessment_index': intent['assessment_index'],
             'attempt_id': intent['attempt_id'],
             'contract_sha256': intent['contract_sha256'],
             'scope_authorization_sha256': intent['scope_authorization_sha256'],
             'window_sha256': intent['p8_window_sha256'],
             'reservation_sha256': state['reservation_sha256'],
             'spent_sha256': digest(spent),
             'budget_sha256': digest(reservation['profile']),
             'target': {'ip': '10.203.31.2', 'port': 21},
             'once_consumed_without_physical_claim': True,
             'root_approval_issued': False, 'a6': 'ND', 'p8': 'NO-GO'}
    value['sha256'] = digest(value)
    return value


def spend_before_root(*, journal: Path, head: str, session: str) -> dict:
    """Write spent marker DURABLY before any privileged operator handoff.

    Interruptions leave RESERVED or SPENT permanently non-retryable. This is
    intentionally not F13.consume_reserved: there is no second socket reader.
    """
    need(os.geteuid() != 0, 'NONROOT_REQUIRED')
    need(isinstance(journal, Path) and journal.is_absolute(), 'JOURNAL_ABSOLUTE_REQUIRED')
    need(type(session) is str and SESSION.fullmatch(session), 'SESSION_INVALID')
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'HEAD_INVALID')
    state = f13.inspect(journal)
    need(state['status'] == 'RESERVED_NO_RETRY', 'ALREADY_SPENT_NO_RETRY')
    reservation = f13._read_json(journal, 'reservation.json')
    intent = reservation['intent']
    need(intent['head'] == head and intent['session_id'] == session,
         'F13_SESSION_OR_HEAD_NOT_PREBOUND')
    spent = {'schema': f13.SCHEMA+'-spent',
             'reservation_sha256': state['reservation_sha256'],
             'status': 'ATTEMPT_CONSUMED_NO_RETRY', 'a6': 'ND', 'p8': 'NO-GO'}
    spent_sha = f13._save(journal, 'spent.json', spent)
    f13._save(journal, 'spent.manifest.json', {
        'schema': f13.SCHEMA+'-manifest', 'file': 'spent.json',
        'sha256': spent_sha, 'case_key': state['case_key'], 'p8': 'NO-GO'})
    return build(journal=journal, head=head, session=session)


def validate_handoff(value: dict, *, session: str, head: str,
                     case_id: str, window_sha256: str,
                     contract_sha256: str, scope_sha256: str,
                     budget_sha256: str) -> bool:
    """Root-side frozen handoff schema, only when separately signed by authority."""
    need(type(value) is dict and set(value) == {'schema','head','session',
         'case_id','case_key','assessment_index','attempt_id','contract_sha256',
         'scope_authorization_sha256','window_sha256','reservation_sha256',
         'spent_sha256','budget_sha256','target',
         'once_consumed_without_physical_claim','root_approval_issued',
         'a6','p8','sha256'}, 'HANDOFF_EXACT_FIELDS')
    need(value['schema'] == SCHEMA and
         value['session'] == session and SESSION.fullmatch(session) and
         value['head'] == head and f1.GIT_SHA.fullmatch(head) and
         value['case_id'] == case_id and
         value['contract_sha256'] == contract_sha256 and
         value['scope_authorization_sha256'] == scope_sha256 and
         value['window_sha256'] == window_sha256 and
         value['budget_sha256'] == budget_sha256 and
         value['target'] == {'ip': '10.203.31.2', 'port': 21} and
         value['once_consumed_without_physical_claim'] is True and
         value['root_approval_issued'] is False and
         value['a6'] == 'ND' and value['p8'] == 'NO-GO' and
         type(value['assessment_index']) is int and 0 <= value['assessment_index'] < 2**31 and
         type(value['attempt_id']) is str and f13.ATTEMPT.fullmatch(value['attempt_id']) and
         type(value['case_key']) is str and f1.SHA.fullmatch(value['case_key']) and
         type(value['reservation_sha256']) is str and f1.SHA.fullmatch(value['reservation_sha256']) and
         type(value['spent_sha256']) is str and f1.SHA.fullmatch(value['spent_sha256']) and
         value['sha256'] == digest({k: v for k,v in value.items() if k != 'sha256'}),
         'HANDOFF_IDENTITY_OR_INTEGRITY_INVALID')
    return True


def capabilities():
    return {'schema': SCHEMA+'-capabilities',
            'f13_spent_before_root_staging': True,
            'no_second_socket_reader': True,
            'session_prebound': True,
            'spent_means_physical_probe_completed': False,
            'root_authorization_created': False,
            'opens_traffic': False, 'a6': 'ND', 'a9': None, 'p8': 'NO-GO'}
