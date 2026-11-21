"""R125: unified FTP pilot acceptance and 54-unit coverage, fail closed.

This connects existing R122/R123/R124 verifiers and the P7 catalogue. It is
NOT a root executor, an operational permit, an independent stopwatch, a
physical proof, or a DurableStore publication. An untrusted event trace is
never sufficient to promote an A5 candidate into A6 or A9. Safe to replay.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import re
import stat
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123
from ardrec.coordination import r124_root_deny_readback as r124

SCHEMA = 'ARDREC-R125-INTEGRATED-FTP-AND-54-UNIT-ACCEPTANCE-v1'
ROOT = Path('/home/cicada/ardrec-lab/r125-integration-audit-v1')
GIT = re.compile(r'[0-9a-f]{40}\Z')
CAPACITY = {'SSH': 18, 'FTP': 18, 'SMB': 18}
FAMILIES = {'SSH': 8, 'FTP': 8, 'SMB': 9}
MATRIX_STATUS = 'PLANNED_SLOT_UNASSIGNED_NO_PHYSICAL_CASE'
LIMIT = 262144

class Stop(ValueError):
    """Fail-closed, stable error code."""


def need(cond: bool, code: str) -> None:
    if not cond:
        raise Stop(code)


def _clock(value: datetime) -> str:
    need(type(value) is datetime and value.tzinfo is not None and
         value.utcoffset() is not None and value.microsecond == 0,
         'CLOCK_UNTRUSTED')
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _sha(doc: dict) -> str:
    return f1.digest(f1.canonical(doc))


def coverage(catalog_raw: bytes) -> dict[str, Any]:
    """54 *unassigned positions*, never invented scenarios or cases."""
    need(type(catalog_raw) is bytes and
         f1.digest(catalog_raw) == f14.CATALOG_SHA256,
         'CATALOG_PIN_CHANGED')
    doc = f1.load(catalog_raw)
    need(doc.get('schema_version') == '1.0' and
         doc.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         doc.get('execution_enabled') is False and
         doc.get('catalog_frozen') is False and
         doc.get('derived_real_cases') == 0 and
         doc.get('pilot_completed') is False and
         doc.get('counts') == {'ssh': 8, 'ftp': 8, 'smb': 9, 'total': 25},
         'P7_NOT_THE_DRAFT_CATALOG')
    families = doc.get('families')
    need(type(families) is list and len(families) == 25, 'FAMILIES_MISSING')
    ids = [f.get('id') for f in families if type(f) is dict]
    need(len(ids) == 25 and len(set(ids)) == 25 and
         {key: sum(x.startswith(key+'-') for x in ids) for key in CAPACITY}
         == FAMILIES, 'FAMILY_SET_DRIFT')
    slots = [
        {'protocol': protocol, 'planning_position': index,
         'case_id': None, 'scenario_id': None, 'family_id': None,
         'physical_attempt_id': None, 'evidence_sha256': None,
         'confirmed_risk': None, 'a9_generation': None,
         'status': MATRIX_STATUS}
        for protocol in ('SSH', 'FTP', 'SMB')
        for index in range(1, CAPACITY[protocol] + 1)
    ]
    need(len(slots) == 54 and
         len({(s['protocol'], s['planning_position']) for s in slots}) == 54,
         'CAPACITY_DRIFT')
    out = {'schema': SCHEMA+'-coverage', 'catalog_sha256': f1.digest(catalog_raw),
           'expected_by_protocol': CAPACITY.copy(),
           'family_counts_by_protocol': FAMILIES.copy(),
           'family_ids': sorted(ids), 'planned_unit_count': 54,
           'assigned_real_unit_count': 0, 'executed_real_unit_count': 0,
           'accepted_real_unit_count': 0, 'slots': slots,
           'p7': 'DRAFT_NOT_FROZEN', 'p8': 'NO-GO'}
    out['sha256'] = _sha(out)
    return out


def root_check(report: dict, *, head: str) -> dict:
    """Confirm a R124 *readback*, never use it as timer/permit authority."""
    need(type(report) is dict and report.get('schema') == r124.SCHEMA and
         report.get('head') == head and
         report.get('root_guard_sha256') == r124.PIN and
         report.get('root_guard') == 'PINNED_INSTALLED_DENY_CHECK_OK' and
         report.get('denied') is True and report.get('p8') == 'NO-GO' and
         report.get('a6') == 'ND' and report.get('a9') is None and
         report.get('r34_is_session_45s_watchdog') is False and
         report.get('root_60s_deadline_verified') is False and
         report.get('session_autonomous_closure_verified') is False and
         report.get('f13_physical_attempt_admitted') is False and
         type(report.get('network_connections_by_r124')) is int and
         report['network_connections_by_r124'] == 0 and
         type(report.get('guest_starts_by_r124')) is int and
         report['guest_starts_by_r124'] == 0 and
         type(report.get('nft_writes_by_r124')) is int and
         report['nft_writes_by_r124'] == 0,
         'R124_BOUNDARY_INVALID')
    need(type(report.get('sha256')) is str and
         _sha({key: value for key,value in report.items() if key != 'sha256'})
         == report['sha256'], 'R124_REPORT_HASH_MISMATCH')
    host = report.get('host')
    need(type(host) is dict and
         host.get('stage') in ('OFFLINE_DENY_MATCH',
                               'TRANSITION_DENY_MATCH', 'FIVE_ONE_DENY_MATCH') and
         type(host.get('states')) is dict and
         set(host['states']) == {'ssh','ftp','smb','runner'} and
         type(host.get('active_count')) is int and
         type(host.get('absent_count')) is int and
         host['active_count'] + host['absent_count'] == 6,
         'R124_HOST_NOT_DENY')
    expected = {'OFFLINE_DENY_MATCH': 0, 'TRANSITION_DENY_MATCH': None,
                'FIVE_ONE_DENY_MATCH': 5}
    need(expected[host['stage']] is None or
         host['active_count'] == expected[host['stage']], 'R124_STAGE_INVALID')
    return {'sha256': report['sha256'], 'status':host['stage'],
            'session_marker_consumed': report['session_marker_consumed'],
            'session_timer_state': report['session_timer_state'],
            'periodic_r34_state': report['r34_timer_state'],
            'guard_sha256': r124.PIN,
            'independent_60s_closure_attested': False}


def candidate_trace(plan_sha256: str, events: list[dict]) -> dict:
    """Check R123 event shape/monotonic time, not physical authorship."""
    try:
        item = r123.guard_model(plan_sha256=plan_sha256, events=events,
                                root_supervisor_proof=False)
    except (r123.Stop, ValueError, TypeError, KeyError) as exc:
        raise Stop('R123_EVENT_TRACE_REJECTED') from exc
    need(type(item) is dict and
         item.get('root_supervisor_independently_attested') is False and
         item.get('physical_deny_reapplied') is False,
         'EVENT_TRACE_UNAUTHORIZED_PROMOTION')
    return {'schema':SCHEMA+'-candidate-timing',
            'trace_sha256':_sha({'events':events}),
            'r123_trace_sha256':_sha(item),
            'root_origin_attested':False,
            'physical_60s_closure_verified':False,
            'interpretation':'MODEL_ONLY_NOT_ROOT_WITNESS'}


def build(*, head: str, catalog_raw: bytes, now: datetime,
          boundary: dict, plan: dict, root_report: dict,
          timing_events: list[dict] | None = None) -> dict:
    """Recompute source linkage and gate ALL requested R125 acceptance goals.

    Does not dispatch; no self-issued authority, no F13 replays as live A5,
    no confirmed A6/A7/A8 and no A9 global publication.
    """
    need(type(head) is str and GIT.fullmatch(head) is not None, 'HEAD_INVALID')
    stamp = _clock(now)
    c = coverage(catalog_raw)
    try:
        r122.verify(boundary, catalog_raw)
        r123.verify_plan(plan, boundary=boundary, catalog_raw=catalog_raw)
    except (r122.Stop,r123.Stop,ValueError,OSError,TypeError,KeyError) as exc:
        raise Stop('R122_R123_SOURCE_CHAIN_REJECTED') from exc
    need(boundary['head'] == plan['head'] == head and
         boundary['sha256'] == plan['boundary_sha256'] and
         boundary['p8'] == plan['p8'] == 'NO-GO' and
         boundary['a6'] == plan['a6'] == 'ND' and
         boundary['a9_generation'] is None and plan['a9_generation'] is None and
         plan['guard_armed'] is False and
         plan['root_permit_authenticated'] is False,
         'CASE_BOUNDARY_PROMOTION')
    host = root_check(root_report, head=head)
    _clock(datetime.strptime(root_report['observed_at_utc'], '%Y-%m-%dT%H:%M:%SZ')
           .replace(tzinfo=timezone.utc))
    age = (now.astimezone(timezone.utc)-
           datetime.strptime(root_report['observed_at_utc'], '%Y-%m-%dT%H:%M:%SZ')
           .replace(tzinfo=timezone.utc)).total_seconds()
    need(-2 <= age <= 60, 'ROOT_READBACK_NOT_FRESH')
    closure = None if timing_events is None else candidate_trace(plan['sha256'], timing_events)
    blockers = set(boundary['blockers']) | set(plan['blockers']) | set(root_report['blockers'])
    blockers.update({'ROOT_SESSION_CLOSURE_NOT_INDEPENDENTLY_ATTESTED',
                     'CURRENT_P8_PHYSICAL_AUTHORITY_MISSING',
                     'P7_PILOT_AND_FREEZE_NOT_COMPLETED',
                     'INDEPENDENT_FTP_T01_RESULT_WITNESS_MISSING',
                     'A6_A7_A8_A9_AUTHORITATIVE_CHAIN_NOT_EXECUTED',
                     '54_REAL_EXPERIMENTAL_UNITS_NOT_ASSIGNED'})
    if boundary['case_id'] is None:
        blockers.add('F13_NO_SOURCE_CASE_SELECTED')
    if host['status'] != 'FIVE_ONE_DENY_MATCH':
        blockers.add('FTP_FIVE_ONE_NOT_OBSERVED')
    if root_report['session_timer_state'] != 'active':
        blockers.add('SESSION_TIMER_NOT_CURRENTLY_ACTIVE')
    if closure is not None:
        blockers.add('TIMING_TRACE_NOT_INDEPENDENT_ROOT_PROOF')
    checks = [
        ('INDEPENDENT_SCOPE_AND_REVOCATION','BLOCKED'),
        ('SESSION_SPECIFIC_ROOT_TIMER','BLOCKED'),
        ('PHYSICAL_60S_RESTORE_AND_CRASH_TEST','BLOCKED'),
        ('ROOT_RECEIPT_AND_MONOTONIC_PROVENANCE','BLOCKED'),
        ('NO_DISPATCH_ON_ANY_GATE_FAILURE','ENFORCED_BY_R125'),
        ('ROOT_AUTONOMOUS_WATCHDOG_DEPLOYMENT','NOT_ATTESTED'),
        ('HOST_F11_R34_TOPOLOGY','OBSERVED_READONLY_DENY'),
        ('CURRENT_P8_AUTHORITY','BLOCKED'),
        ('FTP_T01_PHYSICAL_A5','NOT_EXECUTED_BY_R125'),
        ('A6_A7_A8_A9_A10_AUTHORITATIVE','BLOCKED'),
        ('SSH_SMB_54_UNIT_EXPANSION','PLANNED_NOT_ALLOCATED'),
    ]
    actions=[]
    last=None
    for ordinal,(name,status) in enumerate(checks,1):
        line={'ordinal':ordinal,'gate':name,'status':status,
              'previous_sha256':last,'dispatch':False}
        line['sha256']=_sha(line)
        actions.append(line)
        last=line['sha256']
    out={
        'schema':SCHEMA,'head':head,'observed_at_utc':stamp,
        'catalog_sha256':c['catalog_sha256'],
        'coverage_sha256':c['sha256'],
        'planned_units':54,'assigned_real_units':0,
        'family_counts':FAMILIES.copy(),
        'boundary_sha256':boundary['sha256'],
        'watchdog_plan_sha256':plan['sha256'],
        'root_readback_sha256':root_report['sha256'],
        'root_status':host,'closure_timing_candidate':closure,
        'ftp_case_id':boundary['case_id'],
        'ftp_case_sha256':boundary['case_sha256'],
        'a5':'NOT_AUTHORIZED_FOR_NEW_DISPATCH',
        'a6':'ND','a7_interval':boundary['a7_interval'],
        'a7_confirmed_rf':None,
        'a8_proposal':boundary['a8_recommendation'],
        'a8_applied_transition':None,
        'a9_global_generation':None,
        'a10':'SOURCE_BOUND_READONLY_AUDIT',
        'p7':'DRAFT','p8':'NO-GO',
        'network_connections':0,'vm_starts':0,'firewall_changes':0,
        'physical_60s_closure_attested':False,
        'root_operational_permit_attested':False,
        'one_shot_attempt_consumed_by_r125':False,
        'gates':actions,'gate_chain_sha256':last,
        'blockers':sorted(blockers),
    }
    need(len(f1.canonical(out)) < LIMIT,'REPORT_TOO_LARGE')
    out['sha256']=_sha(out)
    return out


def verify(report: dict, *, catalog_raw: bytes, boundary: dict, plan: dict,
           root_report: dict, timing_events: list[dict] | None = None) -> bool:
    need(type(report) is dict and type(report.get('observed_at_utc')) is str,
         'REPORT_SCHEMA')
    try:
        when=datetime.strptime(report['observed_at_utc'], '%Y-%m-%dT%H:%M:%SZ')
        when=when.replace(tzinfo=timezone.utc)
        expected=build(head=report['head'],now=when,
                       catalog_raw=catalog_raw,boundary=boundary,
                       plan=plan,root_report=root_report,
                       timing_events=timing_events)
    except (Stop,ValueError,KeyError,TypeError,OSError) as exc:
        raise Stop('REPLAY_SOURCES_CHANGED_OR_INVALID') from exc
    need(report == expected, 'R125_REPORT_TAMPERED')
    return True


def capabilities() -> dict:
    return {
        'schema':SCHEMA+'-capabilities',
        'host_r124_live_deny_readback':True,
        'f13_f14_r121_r122_r123_bound_case':True,
        'plan_54_unassigned_with_25_catalog_families':True,
        'modeled_timing_is_never_physical_proof':True,
        'physical_root_watchdog_session_attested':False,
        'independent_p8_operational_permit':False,
        'a6_admitted_physical':False,
        'a9_global_generation':None,
        'p8':'NO-GO','network_connections':0,'vm_starts':0,'firewall_changes':0,
    }


def persist(report: dict, *, catalog_raw: bytes, boundary: dict,
            plan: dict, root_report: dict, root: Path = ROOT) -> Path:
    """Append-only private A10 candidate. Does NOT open global A9 store."""
    need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
    verify(report, catalog_raw=catalog_raw, boundary=boundary,
           plan=plan, root_report=root_report)
    need(isinstance(root, Path) and root.is_absolute() and
         root.parent.is_dir() and not root.parent.is_symlink() and
         not root.is_symlink(), 'PRIVATE_AUDIT_ROOT')
    r121._private(root.parent)
    if not root.exists():
        root.mkdir(mode=0o700)
        f13._fsync_directory(root.parent)
    r121._private(root)
    folder=f7._create(root,'audit-')
    entries={'report.json':report, 'boundary.json':boundary,
             'plan.json':plan, 'root-readback.json':root_report}
    for name, obj in entries.items():
        f2.exclusive(folder/name, f1.canonical(obj))
    manifest={'schema':SCHEMA+'-manifest',
              'entry_sha256':{name:_sha(obj) for name,obj in entries.items()},
              'head':report['head'],'root_global_store_modified':False,
              'physical_proof_claimed':False,'p8':'NO-GO','a9':None}
    f2.exclusive(folder/'manifest.json',f1.canonical(manifest))
    f13._fsync_directory(folder)
    f13._fsync_directory(root)
    return folder


def _read_audit(folder: Path, name: str) -> dict:
    need(name in ('report.json','boundary.json','plan.json',
                  'root-readback.json','manifest.json'), 'AUDIT_FILE_UNTRUSTED')
    r121._private(folder)
    path=folder/name
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
         st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         0 < st.st_size < LIMIT, 'AUDIT_FILE_MODE_OR_SIZE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fst=os.fstat(fd)
        need((fst.st_dev,fst.st_ino,fst.st_size,fst.st_uid)==
             (st.st_dev,st.st_ino,st.st_size,st.st_uid), 'AUDIT_FILE_RACE')
        raw=os.read(fd,LIMIT)
        need(len(raw)==st.st_size, 'AUDIT_FILE_SHORT_READ')
    finally:
        os.close(fd)
    value=f1.load(raw)
    need(f1.canonical(value)==raw, 'AUDIT_NONCANONICAL_FILE')
    return value


def verify_persisted(folder: Path, catalog_raw: bytes) -> dict:
    """Reopen original F5/F13 sources; reject local audit drift."""
    need(isinstance(folder, Path) and folder.is_absolute(), 'AUDIT_PATH_REQUIRED')
    r121._private(folder.parent)
    r121._private(folder)
    expected={'report.json','boundary.json','plan.json',
              'root-readback.json','manifest.json'}
    need({p.name for p in folder.iterdir()}==expected, 'AUDIT_ENTRY_SET')
    files={name:_read_audit(folder,name) for name in expected}
    manifest=files.pop('manifest.json')
    need(type(manifest) is dict and set(manifest)=={
         'schema','entry_sha256','head','root_global_store_modified',
         'physical_proof_claimed','p8','a9'} and
         manifest['schema']==SCHEMA+'-manifest' and
         manifest.get('head')==files['report.json'].get('head') and
         type(files['report.json'].get('head')) is str and
         manifest['root_global_store_modified'] is False and
         manifest['physical_proof_claimed'] is False and
         manifest['p8']=='NO-GO' and manifest['a9'] is None and
         manifest['entry_sha256']=={name:_sha(obj) for name,obj in files.items()},
         'AUDIT_MANIFEST_MISMATCH')
    verify(files['report.json'],catalog_raw=catalog_raw,
           boundary=files['boundary.json'],plan=files['plan.json'],
           root_report=files['root-readback.json'])
    return files['report.json']
