"""R128–R129 B7: one-case A5->A10 reconciliation and crash-safe private recovery.

This is a **non-dispatching** reconciler. F13 owns its one-shot journal, F14
classifies supports conservatively, R121 delegates exact arithmetic to R58-E,
and R129 creates/recovers a private A10 archive.  No packet is sent and no
root authority can be created by this module. Offline unit tests separately
exercise F13's real bounded receive with an injected fake socket.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import os

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r126_operational_controller as r126
from ardrec.coordination import r127_failure_observer as observer
from ardrec.coordination import r128_ftp_pilot as r128
from ardrec.coordination import r129_a6_a10_recovery as r129

SCHEMA = 'ARDREC-R128-R129-B7-FTP-T01-END-TO-END-RECONCILIATION-v1'
STAGES = tuple(f'A{i}' for i in range(1,11))
GOOD_JOURNAL = frozenset(('RESERVED_NO_RETRY', 'ATTEMPT_CONSUMED_UNRESOLVED',
                          'RESULT_CANDIDATE_ONLY', 'FAILED_NO_RETRY'))
MAX_BYTES=131072


class Stop(ValueError):
    """Fail-closed readback with stable reasons."""


def need(value: bool, reason: str) -> None:
    if not value:
        raise Stop(reason)


def digest(value: dict) -> str:
    return f1.digest(f1.canonical(value))


def reconcile(*, preparation: dict, journal: Path, declared_unit: dict,
              catalog_raw: bytes, observer_folder: Path | None = None) -> dict[str, Any]:
    """Recompute all sources; never trust pre-computed A6, Rf or A9 claims."""
    need(isinstance(journal,Path) and journal.is_absolute() and
         type(preparation) is dict and type(declared_unit) is dict and
         type(catalog_raw) is bytes,'EXACT_INPUTS_REQUIRED')
    need(type(preparation.get('head')) is str and
         type(preparation.get('sha256')) is str and
         preparation.get('p8') == 'NO-GO' and
         preparation.get('dispatch') is False,'PREPARATION_NOT_FAIL_CLOSED')
    try:
        intake = r128.reconcile(preparation=preparation, journal=journal,
                    catalog_raw=catalog_raw, observer_folder=observer_folder)
        case = r121.build(journal, catalog_raw, declared_unit)
        final = r129.reconcile(intake=intake, case=case, catalog_raw=catalog_raw)
        r121.verify(case,catalog_raw)
        r129.validate_replay(final,intake=intake,case=case,catalog_raw=catalog_raw)
        state=f13.inspect(journal)
        source=f14.build(journal,catalog_raw)
        f14.replay(source,catalog_raw)
    except (r128.Stop,r121.Stop,r129.Stop,f13.Stop,f14.Stop,
            ValueError,OSError,KeyError,TypeError) as exc:
        raise Stop('RECOMPUTED_SOURCE_CHAIN_REJECTED') from exc
    need(state['status'] in GOOD_JOURNAL and
         state['case_key']==preparation['case_key']==intake['case_key']==case['case_key']==final['case_key'] and
         case['declared_unit'].get('service_id') == 'FTP_DEV' and
         intake['head']==preparation['head']==final['head'] and
         intake['a6']=='ND' and final['a6']=='ND' and
         intake['a7_confirmed_rf'] is None and final['a7_confirmed_rf'] is None and
         final['a8_authoritative_transition'] is None and
         final['a9_global_generation'] is None and
         intake['a9_generation'] is None and
         final['a9_durable_store_opened'] is False and
         final['p8']=='NO-GO' and intake['p8']=='NO-GO' and
         final['r127_observation_is_authoritative'] is False and
         source['physical_origin_attested'] is False and
         source['accepted_support_count']==0,
         'NON_AUTHORITATIVE_CHAIN_BROKEN')
    # A one-shot reservation is NOT evidence that a socket was consumed.
    terminal=state['status']
    observed_sha=intake.get('r127_observation_sha256')
    if observer_folder is not None:
        need(type(observed_sha) is str and len(observed_sha)==64,
             'R127_OBSERVER_REPLAY_REQUIRED')
        need(observer.verify_persisted(observer_folder)['sha256']==observed_sha,
             'R127_OBSERVER_CHANGED')
    else:
        need(observed_sha is None,'R127_OBSERVER_MISSING')
    statuses={x['algorithm']:x['status'] for x in case['stages']}
    need(tuple(statuses)==STAGES and
         statuses['A6']=='ND_NO_ADMITTED_PHYSICAL_SUPPORT' and
         statuses['A9']=='NO_GENERATION_PUBLISHED', 'A1_A10_SEQUENCE_INVALID')
    chain=[]
    parent=None
    for index,label in enumerate(STAGES,1):
        origin=case['stages'][index-1]
        row={'ordinal':index,'algorithm':label,'status':statuses[label],
             'source_r121_stage_sha256':origin['sha256'],
             'previous_sha256':parent,
             'operational_execution_attested':False}
        row['sha256']=digest(row)
        parent=row['sha256']

        chain.append(row)
    out={'schema':SCHEMA,'head':preparation['head'],
         'case_id':case['case_id'],'case_key':state['case_key'],
         'journal_status':terminal,'journal_reservation_sha256':state['reservation_sha256'],
         'preparation_sha256':preparation['sha256'],
         'f14_sha256':digest(source),'r121_sha256':case['sha256'],
         'r128_sha256':intake['sha256'],'r129_sha256':final['sha256'],
         'r127_observation_sha256':observed_sha,
         'a5_attempt_consumed':terminal!='RESERVED_NO_RETRY',
         'a5_result_candidate':terminal=='RESULT_CANDIDATE_ONLY',
         'a6':'ND','a6_supports_accepted':0,
         'a7_exact_interval':[case['a7_lower'],case['a7_upper']],
         'a7_confirmed_rf':None,'a8_candidate':case['a8_recommendation'],
         'a8_transition_applied':None,'a9_global_generation':None,
         'a10':'PRIVATE_REPLAY_ONLY',
         'stages':chain,'chain_head_sha256':parent,
         'root_witness_accepted':False,'ftp_origin_independently_attested':False,
         'traffic_enabled_by_b7':False,'network_connections_by_b7':0,
         'vm_starts_by_b7':0,'nft_writes_by_b7':0,'p8':'NO-GO'}
    need(len(f1.canonical(out))<MAX_BYTES,'E2E_REPORT_TOO_LARGE')
    out['sha256']=digest(out)
    return out


def verify(report: dict, *, preparation: dict, journal: Path,
           declared_unit: dict, catalog_raw: bytes,
           observer_folder: Path | None = None) -> bool:
    need(type(report) is dict,'REPORT_NOT_OBJECT')
    again=reconcile(preparation=preparation,journal=journal,
                    declared_unit=declared_unit,catalog_raw=catalog_raw,
                    observer_folder=observer_folder)
    need(report==again,'E2E_REPORT_TAMPERED_OR_STALE')
    return True


def persist_a10(*, preparation:dict, journal:Path, declared_unit:dict,
                catalog_raw:bytes, audit_root:Path,
                observer_folder:Path | None=None) -> dict:
    """A10 recoverable, never A9: write via R129 and re-open immediately."""
    need(os.geteuid()!=0,'ROOT_RECONCILIATION_FORBIDDEN')
    need(isinstance(audit_root,Path) and audit_root.is_absolute(),
         'ABSOLUTE_PRIVATE_AUDIT_ROOT_REQUIRED')
    report=reconcile(preparation=preparation,journal=journal,
                     declared_unit=declared_unit,catalog_raw=catalog_raw,
                     observer_folder=observer_folder)
    # Fresh replay before persistence; this intentionally rejects a changed
    # source after a long inspection and before an A10 archive is created.
    verify(report,preparation=preparation,journal=journal,
           declared_unit=declared_unit,catalog_raw=catalog_raw,
           observer_folder=observer_folder)
    intake=r128.reconcile(preparation=preparation,journal=journal,
                           catalog_raw=catalog_raw,observer_folder=observer_folder)
    case=r121.build(journal,catalog_raw,declared_unit)
    obs=None if observer_folder is None else observer.verify_persisted(observer_folder)
    try:
        folder=r129.store_private(r129.reconcile(intake=intake,case=case,
                          catalog_raw=catalog_raw),intake=intake,case=case,
                          catalog_raw=catalog_raw,root=audit_root,
                          observer_report=obs)
        recovered=r129.verify_private(folder,catalog_raw)
    except (r129.Stop,r121.Stop,f13.Stop,OSError,ValueError,TypeError,KeyError) as exc:
        raise Stop('A10_DURABILITY_OR_RECOVERY_FAILED') from exc
    need(recovered['a6']=='ND' and recovered['a9_global_generation'] is None and
         recovered['a9_durable_store_opened'] is False and
         recovered['intake_sha256']==intake['sha256'] and
         recovered['r121_sha256']==case['sha256'] and
         report['r128_sha256']==intake['sha256'] and
         report['r129_sha256']==recovered['sha256'],
         'A10_RECOVERED_CONTENT_INVALID')
    return {'schema':SCHEMA+'-a10-private-recovery',
            'head':report['head'],'case_key':report['case_key'],
            'end_to_end_sha256':report['sha256'],
            'a10_folder':str(folder),
            'recovered_r129_sha256':digest(recovered),
            'source_journal_status':report['journal_status'],
            'a5_attempt_consumed':report['a5_attempt_consumed'],
            'a6':'ND','a7_confirmed_rf':None,'a8_applied':None,
            'a9_generation':None,'global_durable_store_opened':False,
            'p8':'NO-GO'}


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'f13_durable_reservation_and_consume_replayed':True,
            'f14_supports_recomputed':True,
            'r121_r58e_exact_interval_recomputed':True,
            'r128_r129_source_sha_recomputed':True,
            'r127_observation_optional_but_never_authoritative':True,
            'a10_private_store_recovered':True,
            'network_connections_created':0,'guest_starts':0,'nft_writes':0,
            'p8':'NO-GO','a6':'ND','a9':None,
            'physical_ftp_dispatch_implemented':False,
            'independent_physical_admission_implemented':False,
            'global_a9_publication_performed':False}
