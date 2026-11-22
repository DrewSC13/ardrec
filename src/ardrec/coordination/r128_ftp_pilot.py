"""R128: bounded FTP-T01 reservation and independent-result reconciliation.

This module binds an A5 journal to documented independent closure evidence.
It NEVER creates a socket/guest or opens nftables; a root-enforced dispatcher
must separately verify the current, signed pilot grant *before* any network IO.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r126_operational_controller as r126
from ardrec.coordination import r127_closure_witness as r127
from ardrec.coordination import r127_failure_observer as b6

SCHEMA='ARDREC-R128-FTP-T01-ONE-SHOT-SOURCE-INTAKE-v1'

class Stop(ValueError):
    """Stable fail-closed candidate/physical boundary."""


def need(ok: bool, code: str) -> None:
    if not ok: raise Stop(code)


def prepare(*, handoff: dict, intent: dict, profile: dict) -> dict:
    """Validate the provenance of an A5 reservation before any network code.

    The returned plan is deliberately NOT a P8 permit. It only authorizes
    constructing the durable reservation using F13's existing unique key.
    """
    need(type(handoff) is dict and handoff.get('schema')==r126.SCHEMA and
         handoff.get('family_id')=='FTP-T01' and handoff.get('p8')=='NO-GO' and
         handoff.get('dispatch') is False and
         handoff.get('root_enforced_grant_verified') is False and
         handoff.get('sha256') == r126.sha({k:v for k,v in handoff.items() if k!='sha256'}),
         'HANDOFF_NOT_SOURCE_BOUND')
    try:
        f13.check_intent(intent)
        from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
        validated=f12.validate_profile(profile)
    except (f13.Stop,ValueError,TypeError,KeyError) as exc:
        raise Stop('F13_INTENT_OR_BUDGET_REJECTED') from exc
    need(intent['head']==handoff['head'] and
         intent['family_id']=='FTP-T01',
         'INTENT_NOT_BOUND_TO_HANDOFF')
    out={'schema':SCHEMA+'-preparation','head':handoff['head'],
         'handoff_sha256':handoff['sha256'],
         'intent_sha256':r126.sha(intent),
         'case_key':f13.key_for_case(intent),
         'budget_sha256':r126.sha(validated),
         'reserve_before_any_external_connect':True,
         'one_shot_no_retry':True,'dispatch':False,
         'a6':'ND','a9':None,'p8':'NO-GO'}
    out['sha256']=r126.sha(out)
    return out


def reserve_prepared(*, preparation: dict, intent: dict,
                     profile: dict, root: Path) -> Path:
    """Write the unique F13 reservation once, WITHOUT initiating a socket.

    This is NOT an operational dispatch and does not imply a physical pilot.
    """
    need(type(preparation) is dict and
         preparation.get('schema')==SCHEMA+'-preparation' and
         preparation.get('intent_sha256')==r126.sha(intent) and
         preparation.get('case_key')==f13.key_for_case(intent) and
         preparation.get('dispatch') is False and
         preparation.get('p8')=='NO-GO' and
         preparation.get('sha256')==r126.sha({k:v for k,v in preparation.items() if k!='sha256'}),
         'PREPARATION_NOT_AUTHENTIC')
    try:
        from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
        need(r126.sha(f12.validate_profile(profile))==preparation['budget_sha256'],
             'BUDGET_CHANGED_AFTER_PREPARATION')
        return f13.reserve(intent,profile,root=root)
    except (f13.Stop,ValueError,TypeError,OSError,KeyError) as exc:
        raise Stop('F13_RESERVATION_REJECTED_NO_RETRY') from exc


def reconcile(*, preparation: dict, journal: Path, catalog_raw: bytes,
              root_witness: dict | None = None, now: datetime | None = None,
              observer_folder: Path | None = None) -> dict[str,Any]:
    """Read F13+F14, bind a post-session R127 receipt if supplied.

    A root closure witness alone cannot attest the FTP bytes or admit A6.
    """
    need(type(preparation) is dict and
         preparation.get('schema')==SCHEMA+'-preparation' and
         preparation.get('sha256')==r126.sha({k:v for k,v in preparation.items() if k!='sha256'}),
         'PREPARATION_INVALID')
    try:
        journal_state=f13.inspect(journal)
        reservation=f13._read_json(journal,'reservation.json')
        review=f14.build(journal,catalog_raw)
        f14.replay(review,catalog_raw)
    except (f13.Stop,f14.Stop,ValueError,OSError,TypeError,KeyError) as exc:
        raise Stop('A5_SOURCE_REPLAY_FAILED') from exc
    need(reservation['intent']['head']==preparation['head'] and
         r126.sha(reservation['intent'])==preparation['intent_sha256'] and
         journal_state['case_key']==preparation['case_key'] and
         review['source_case_key']==journal_state['case_key'] and
         review['a6']=='ND' and
         review['physical_origin_attested'] is False and
         review['a9_published_generation'] is None,
         'A5_SOURCE_PROVENANCE_OR_PROMOTION')
    physical_closure=False
    witness_sha=None
    if root_witness is not None:
        need(type(root_witness) is dict and
             set(root_witness)=={'envelope','pre','post'} and
             type(now) is datetime, 'ROOT_WITNESS_INPUTS_REQUIRED')
        try:
            verified=r127.verify_root_anchored(envelope=root_witness['envelope'],
                    pre=root_witness['pre'],post=root_witness['post'],now=now)
        except (r127.Stop,ValueError,KeyError,TypeError,OSError) as exc:
            raise Stop('INDEPENDENT_CLOSURE_RECEIPT_NOT_VALIDATED') from exc
        need(verified['head']==preparation['head'] and
             verified['case_id']==review['case_id'],
             'ROOT_WITNESS_NOT_THIS_CASE')
        physical_closure=True
        witness_sha=verified['sha256']
    observer_sha=None
    observer_status=None
    if observer_folder is not None:
        # Local telemetry is never promoted to an independent root witness.
        try:
            observed=b6.verify_persisted(observer_folder)
        except (b6.Stop,ValueError,TypeError,KeyError,OSError) as exc:
            raise Stop('R127_B6_OBSERVER_NOT_REPLAYABLE') from exc
        need(observed['head']==preparation['head'] and
             observed['session'] == reservation['intent']['session_id'] and
             observed['session_timer_seen_active'] is True and
             observed['verified_physical_60s_restore'] is False and
             observed['independent_signed_root_witness'] is False,
             'R127_OBSERVER_NOT_LINKED_TO_F13_SESSION')
        observer_sha=observed['sha256']
        observer_status=observed['status']
    out={'schema':SCHEMA,'head':preparation['head'],
         'case_key':journal_state['case_key'],
         'case_id':review['case_id'],
         'journal_status':journal_state['status'],
         'journal_reservation_sha256':journal_state['reservation_sha256'],
         'f14_sha256':r126.sha(review),
         'preparation_sha256':preparation['sha256'],
         'root_closure_receipt_sha256':witness_sha,
         'r127_observation_sha256':observer_sha,
         'r127_observation_status':observer_status,
         'r127_observation_is_root_authority':False,
         'autonomous_root_deny_recovered':physical_closure,
         'source_bytes_independently_attested':False,
         'a5':'CANDIDATE_ONLY','a6':'ND','a7_confirmed_rf':None,
         'a8_applied':None,'a9_generation':None,
         'network_connections_by_r128':0,'vm_starts_by_r128':0,
         'p7':'DRAFT','p8':'NO-GO',
         'blockers':['INDEPENDENT_FTP_SOURCE_WITNESS_NOT_ADMITTED',
                     'A6_TECHNICAL_SUPPORTS_NOT_ADMITTED',
                     'A9_AUTHORITATIVE_PUBLICATION_NOT_PERFORMED']}
    out['sha256']=r126.sha(out)
    return out


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities','f13_reserve_only_once':True,
            'f14_replay_validation':True,
            'r127_independent_closure_link':True,
            'r127_b6_unsigned_observation_link':True,
            'physical_ftp_socket_dispatch_implemented':False,
            'a6_independent_source_admitted':False,
            'p8':'NO-GO','a9':None}
