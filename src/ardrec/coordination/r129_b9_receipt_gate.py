"""R129-B10: replay B9's one guest result as an A5 candidate, NEVER A6/A9.

The inputs are exported copies.  Content hashes do not establish root ownership,
root authority or technical truth.  The F13 journal is independently replayed
and its irreversible spent marker must precede the exported B9 receipt.

No socket, guest, nft or privileged operation is available in this module.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r128_prebound_session_v2 as f13v2
from ardrec.coordination import r115_f13_ftp_a5_journal as f13

SCHEMA = 'ARDREC-R129-B10-B9-RECEIPT-A5-GATE-v1'
B9 = 'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1'
GUEST = 'ARDREC-R116-F3-FTP-T01-PILOT-PROBE-v1'
SESSION = re.compile(r'[0-9a-f]{16}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_GUEST = 8192
MAX_BANNER = 256

class Stop(ValueError):
    """Stable refusal; a positive A6 or global A9 is never issued here."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def digest(doc: dict) -> str:
    return f1.digest(f1.canonical(doc))


def exact(doc: Any, fields: set[str], code: str) -> dict:
    need(type(doc) is dict and set(doc)==fields, code)
    return doc


def guest_review(guest: dict, qga: dict, *, case_id: str) -> dict:
    """Replay exactly the result of ONE QGA guest-exec-status; no connection."""
    need(type(guest) is dict and
         {'schema','src','dst','port','case_id','tcp','response','response_hex'} <= set(guest) and
         set(guest) <= {'schema','src','dst','port','case_id','tcp','response',
                        'response_hex','error','read_error'},
         'GUEST_FIELDS')
    need(guest['schema']==GUEST and guest['src']=='10.203.31.1' and
         guest['dst']=='10.203.31.2' and type(guest['port']) is int and
         guest['port']==21 and guest['case_id']==case_id and
         guest['tcp'] in ('CONNECTED','FAILED') and
         guest['response'] in ('RECEIVED','EMPTY','READ_ERROR','CONNECT_ERROR') and
         type(guest['response_hex']) is str and
         len(guest['response_hex']) <= MAX_BANNER*2,
         'GUEST_IDENTITY_OR_RESPONSE')
    try:
        banner=bytes.fromhex(guest['response_hex'])
    except (ValueError,TypeError) as exc:
        raise Stop('GUEST_RESPONSE_NOT_HEX') from exc
    need(len(banner)<=MAX_BANNER and banner.count(b'\r\n')<=16,
         'GUEST_BANNER_BUDGET')
    if guest['tcp']=='FAILED':
        need(guest['response']=='CONNECT_ERROR' and not banner and
             set(guest)=={'schema','src','dst','port','case_id','tcp',
                          'response','response_hex','error'} and
             type(guest['error']) is str and 0<len(guest['error'])<=80,
             'GUEST_CONNECT_ERROR_CONTRADICTORY')
    elif guest['response']=='READ_ERROR':
        need(not banner and 'read_error' in guest and
             type(guest['read_error']) is str and 0<len(guest['read_error'])<=80 and
             'error' not in guest,'GUEST_READ_ERROR_CONTRADICTORY')
    else:
        need(guest['tcp']=='CONNECTED' and
             ('error' not in guest and 'read_error' not in guest) and
             ((guest['response']=='RECEIVED')==bool(banner)),
             'GUEST_TCP_OR_RESPONSE_CONTRADICTORY')
    exact(qga,{'return'},'QGA_ENVELOPE')
    entry=qga['return']
    need(type(entry) is dict and set(entry)=={'exited','exitcode','out-data','err-data'} and
         entry['exited'] is True and type(entry['exitcode']) is int and
         entry['exitcode']==0 and entry['err-data'] in (None,'') and
         type(entry['out-data']) is str and len(entry['out-data'])<=MAX_GUEST*2,
         'QGA_TERMINAL_NOT_SUCCESSFUL')
    try:
        plain=base64.b64decode(entry['out-data'],validate=True)
        need(0<len(plain)<=MAX_GUEST,'QGA_OUTPUT_BUDGET')
        def no_dupes(pairs):
            data={}
            for k,v in pairs:
                need(k not in data,'QGA_JSON_DUPLICATE_FIELD')
                data[k]=v
            return data
        decoded=json.loads(plain,object_pairs_hook=no_dupes,
            parse_constant=lambda _: (_ for _ in ()).throw(Stop('QGA_NONFINITE')))
    except Stop:
        raise
    except (binascii.Error,ValueError,TypeError,UnicodeError) as exc:
        raise Stop('QGA_OUTPUT_INVALID') from exc
    need(decoded==guest,'QGA_AND_GUEST_RESULT_DIVERGE')
    return {'guest_sha256':digest(guest),
            'qga_sha256':digest(qga),
            'banner_sha256':hashlib.sha256(banner).hexdigest(),
            'banner_is_complete_220':bool(banner.startswith(b'220 ') and
                b'\r\n' in banner and banner.endswith(b'\r\n')),
            'tcp':guest['tcp'], 'response':guest['response']}


def review(*, journal: Path, handoff:dict, intent:dict, receipt:dict,
           guest:dict|None=None, qga:dict|None=None) -> dict:
    """Recompute F13 and verify the exported B9 chain, fail closed.

    Never assert root file ownership from caller-provided bytes.  Even a full
    220 greeting remains an unaccredited A5 *candidate*, never vulnerability.
    """
    need(isinstance(journal,Path) and journal.is_absolute() and
         type(handoff) is dict and type(intent) is dict and type(receipt) is dict,
         'RECEIPT_INPUT_TYPES')
    session=handoff.get('session')
    head=handoff.get('head')
    need(type(session) is str and SESSION.fullmatch(session) and
         type(head) is str and f1.GIT_SHA.fullmatch(head),
         'F13_SESSION_OR_HEAD_INVALID')
    try:
        expected=f13v2.build(journal=journal,head=head,session=session)
        state=f13.inspect(journal)
    except (f13v2.Stop,f13.Stop,OSError,ValueError,TypeError,KeyError) as exc:
        raise Stop('F13_DURABLE_SOURCE_UNAVAILABLE') from exc
    need(handoff==expected and state['status']=='ATTEMPT_CONSUMED_UNRESOLVED',
         'F13_PRESPENT_SOURCE_NOT_REPLAYABLE')
    exact(intent,{'schema','session','head','f13_handoff_sha256',
         'root_traffic_grant_sha256','root_deny_grant_sha256','boot_id',
         'a6','p8'},'B9_INTENT_FIELDS')
    need(intent['schema']==B9+'-intent' and intent['session']==session and
         intent['head']==head and intent['f13_handoff_sha256']==digest(handoff) and
         type(intent['root_traffic_grant_sha256']) is str and
         HEX64.fullmatch(intent['root_traffic_grant_sha256']) and
         type(intent['root_deny_grant_sha256']) is str and
         HEX64.fullmatch(intent['root_deny_grant_sha256']) and
         type(intent['boot_id']) is str and 1<=len(intent['boot_id'])<=128 and
         intent['a6']=='ND' and intent['p8']=='NO-GO',
         'B9_ROOT_INTENT_NOT_BOUND')
    exact(receipt,{'schema','session','head','case_id',
         'f13_handoff_sha256','root_traffic_grant_sha256',
         'denies_restored_and_verified','timer_armed','traffic_window_opened',
         'guest_result_sha256','elapsed_monotonic_ns','result','error',
         'a6','a9','p8'},'B9_RECEIPT_FIELDS')
    need(receipt['schema']==B9+'-receipt' and
         receipt['session']==session and receipt['head']==head and
         receipt['case_id']==handoff['case_id'] and
         receipt['f13_handoff_sha256']==digest(handoff) and
         receipt['root_traffic_grant_sha256']==intent['root_traffic_grant_sha256'] and
         type(receipt['timer_armed']) is bool and
         type(receipt['traffic_window_opened']) is bool and
         type(receipt['denies_restored_and_verified']) is bool and
         type(receipt['elapsed_monotonic_ns']) is int and
         0<=receipt['elapsed_monotonic_ns']<2**63 and
         receipt['result'] in ('FTP_GUEST_CANDIDATE_ONLY','NO_GO_ATTEMPT_CONSUMED') and
         (receipt['error'] is None or
          (type(receipt['error']) is str and 0<len(receipt['error'])<=160)) and
         receipt['a6']=='ND' and receipt['a9'] is None and receipt['p8']=='NO-GO',
         'B9_RECEIPT_IDENTITY_OR_SAFETY')
    positive=receipt['result']=='FTP_GUEST_CANDIDATE_ONLY'
    if positive:
        need(receipt['timer_armed'] and receipt['traffic_window_opened'] and
             receipt['denies_restored_and_verified'] and receipt['error'] is None and
             receipt['elapsed_monotonic_ns']<=60_000_000_000,
             'B9_SUCCESS_WITHOUT_DENY_RESTORATION')
    else:
        need(not(receipt['timer_armed'] and receipt['traffic_window_opened'] and
             receipt['denies_restored_and_verified'] and receipt['error'] is None and
             receipt['elapsed_monotonic_ns']<=60_000_000_000),
             'B9_FALSE_FAILURE_STATUS')
    if receipt['guest_result_sha256'] is None:
        need(guest is None and qga is None and not positive,
             'B9_GUEST_SOURCE_MISSING')
        result=None
    else:
        need(type(receipt['guest_result_sha256']) is str and
             HEX64.fullmatch(receipt['guest_result_sha256']) and
             type(guest) is dict and type(qga) is dict,
             'B9_GUEST_OUTPUT_INCOMPLETE')
        result=guest_review(guest,qga,case_id=handoff['case_id'])
        need(result['guest_sha256']==receipt['guest_result_sha256'],
             'B9_GUEST_RESULT_SHA_DRIFT')
    out={'schema':SCHEMA,'head':head,'case_id':handoff['case_id'],
         'case_key':handoff['case_key'],'session':session,
         'f13_reservation_sha256':state['reservation_sha256'],
         'f13_spent_sha256':handoff['spent_sha256'],
         'f13_handoff_sha256':digest(handoff),
         'root_intent_candidate_sha256':digest(intent),
         'root_receipt_candidate_sha256':digest(receipt),
         'guest_result_candidate_sha256':None if result is None else result['guest_sha256'],
         'qga_candidate_sha256':None if result is None else result['qga_sha256'],
         'banner_is_complete_220':False if result is None else result['banner_is_complete_220'],
         'root_receipt_status':receipt['result'],
         'local_source_hashes_replayed':True,
         'independent_root_origin_verified':False,
         'independent_r127_crash_witness_verified':False,
         'independent_a6_technical_truth_accredited':False,
         'a5':'EXPORTED_ROOT_GUEST_CANDIDATE_ONLY' if positive else
              'UNRESOLVED_OR_FAILED_SINGLE_ATTEMPT',
         'a6':'ND','a7_confirmed_rf':None,'a8_applied':None,
         'a9':None,'a9_durable_store_opened':False,
         'a10':'EXTERNAL_RECEIPT_REPLAY_NOT_PHYSICAL_PROOF',
         'p8':'NO-GO'}
    out['sha256']=digest(out)
    return out


def a9_barrier(*, candidate:dict, journal:Path, handoff:dict,
               intent:dict, receipt:dict,
               guest:dict|None=None,qga:dict|None=None)->dict:
    """R129 guard BEFORE any DurableStore.open()/publish() call.

    Current R58-E never accredits technical truth from such receipts, hence
    publishing these candidates is categorically forbidden.  This function
    intentionally has no storage argument and cannot write a global HEAD.
    """
    expected=review(journal=journal,handoff=handoff,intent=intent,
                    receipt=receipt,guest=guest,qga=qga)
    need(candidate==expected,'A9_CANDIDATE_MUTATED')
    return {'schema':SCHEMA+'-a9-barrier',
            'case_key':candidate['case_key'],
            'candidate_sha256':candidate['sha256'],
            'a6':'ND','a7_confirmed_rf':None,'a8_applied':None,'a9':None,
            'durable_store_opened':False,'generation_written':False,
            'decision':'BLOCKED_MISSING_INDEPENDENT_A6_TRUTH_AND_R127',
            'p8':'NO-GO'}


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'f13_durable_spent_replayed':True,
            'b9_intent_receipt_qga_integrity_replayed':True,
            'root_owned_bytes_not_proven_by_copied_json':True,
            'r127_signed_crash_witness_required_for_physical_acceptance':True,
            'ftp_220_does_not_prove_vulnerability':True,
            'a6_independent_technical_truth_required':True,
            'global_durable_store_write':False,
            'network_connections':0,'nft_writes':0,'vm_starts':0,
            'p8':'NO-GO','a6':'ND','a9':None}
