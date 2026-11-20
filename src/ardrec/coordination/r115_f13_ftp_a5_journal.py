"""R115-F13: durable, once-per-case FTP-T01 A5 candidate journal.

Reserve BEFORE an external dispatcher creates its socket. Consume BEFORE
reading that dispatcher-owned, connected socket. Reuse F10 and F12, never
connect/start VM/change nftables. This journal does NOT authenticate the P8
callback, grant A3, admit A6, publish A9 or certify physical provenance.

A unique case identity cannot evade the spent reservation by changing attempt_id
or HEAD. No retry/cleanup/recovery code deletes a reservation. An interrupted
operation is terminal/uncertain until an independent reconciliation procedure.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f10_ftp_a5_transport as f10
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12

SCHEMA = 'ARDREC-R115-F13-FTP-T01-ONE-ATTEMPT-JOURNAL-v1'
ROOT = Path('/home/cicada/ardrec-lab/r115-f13-ftp-a5-once-v1')
INTENT_FIELDS = frozenset(('schema','case_id','session_id','assessment_index',
                            'attempt_id','head','contract_sha256',
                            'scope_authorization_sha256','p8_window_sha256',
                            'target','family_id'))
CASE = re.compile(r'FTP-T01-S[0-9]{2}-[0-9]{2}\Z', re.ASCII)
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z', re.ASCII)
ATTEMPT = re.compile(r'ATT_[A-Z0-9_]{1,76}\Z', re.ASCII)
MAX_FILE = 20000

class Stop(ValueError):
    """Stable fail-closed error, not permission to run or retry."""


def need(ok, code):
    if not ok:
        raise Stop(code)


def key_for_case(intent):
    """Identity excludes attempt ID, HEAD, profile and authorization hashes."""
    need(type(intent) is dict, 'INTENT_NOT_OBJECT')
    return f1.digest(f1.canonical({k: intent[k] for k in
        ('case_id','session_id','assessment_index')}))


def make_intent(*, case_id, session_id, assessment_index, attempt_id,
                head, contract_sha256, scope_authorization_sha256,
                p8_window_sha256):
    need(type(case_id) is str and CASE.fullmatch(case_id), 'CASE_INVALID')
    need(type(session_id) is str and SESSION.fullmatch(session_id), 'SESSION_INVALID')
    need(type(assessment_index) is int and 0 <= assessment_index < 2**31,
         'ASSESSMENT_INVALID')
    need(type(attempt_id) is str and ATTEMPT.fullmatch(attempt_id),
         'ATTEMPT_INVALID')
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'HEAD_INVALID')
    for value, field in ((contract_sha256,'CONTRACT'),
                         (scope_authorization_sha256,'SCOPE_AUTH'),
                         (p8_window_sha256,'P8_WINDOW')):
        need(type(value) is str and f1.SHA.fullmatch(value), field+'_SHA_INVALID')
    return {'schema': SCHEMA+'-intent','case_id':case_id,
            'session_id':session_id,'assessment_index':assessment_index,
            'attempt_id':attempt_id,'head':head,
            'contract_sha256':contract_sha256,
            'scope_authorization_sha256':scope_authorization_sha256,
            'p8_window_sha256':p8_window_sha256,
            'family_id':'FTP-T01',
            'target':{'ip':f10.TARGET_IP,'port':f10.TARGET_PORT}}


def check_intent(intent):
    need(type(intent) is dict and set(intent) == INTENT_FIELDS,
         'INTENT_FIELDS')
    again = make_intent(**{key:intent[key] for key in (
        'case_id','session_id','assessment_index','attempt_id','head',
        'contract_sha256','scope_authorization_sha256','p8_window_sha256')})
    need(intent == again, 'INTENT_SEMANTICS_CHANGED')
    return intent


def private_directory(path):
    need(isinstance(path,Path) and path.is_absolute(), 'PRIVATE_PATH_INVALID')
    st=path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700,
         'PRIVATE_DIR_OWNER_MODE')
    return path


def _fsync_directory(folder):
    fd=os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _read_json(folder, name):
    need(name in ('reservation.json','spent.json','result.json','failure.json',
                  'reservation.manifest.json','spent.manifest.json',
                  'result.manifest.json','failure.manifest.json'),
         'FILE_NAME_NOT_ALLOWED')
    private_directory(folder)
    p=folder/name
    st=p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and
         0 < st.st_size <= MAX_FILE,'PRIVATE_FILE_MODE_OR_SIZE')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        now=os.fstat(fd)
        need((now.st_dev,now.st_ino,now.st_size,now.st_uid)==
             (st.st_dev,st.st_ino,st.st_size,st.st_uid),'RECEIPT_RACE')
        raw=os.read(fd,MAX_FILE+1)
        need(len(raw)==st.st_size,'RECEIPT_TRUNCATED')
    finally: os.close(fd)
    obj=f1.load(raw)
    need(raw==f1.canonical(obj),'RECEIPT_NOT_CANONICAL')
    return obj


def _save(folder,name,doc):
    private_directory(folder)
    raw=f1.canonical(doc)
    need(0 < len(raw) <= MAX_FILE,'RECEIPT_TOO_LARGE')
    f2.exclusive(folder/name,raw)
    _fsync_directory(folder)
    return f1.digest(raw)


def reserve(intent, profile, *, root=ROOT):
    """Irrevocably reserve one case-window BEFORE creating a socket elsewhere.

    A failed/crashed reservation is never removed automatically. Root and files
    must be private, owned by the nonroot calling user; the authority references
    are *claims* for binding only, not signatures or approval verification.
    """
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    check_intent(intent)
    budget=f12.validate_profile(profile)
    need(isinstance(root,Path) and root.is_absolute(),'ROOT_PATH_REQUIRED')
    need(not root.is_symlink() and root.parent.is_dir() and
         not root.parent.is_symlink(),'ROOT_PARENT_INVALID')
    if not root.exists():
        root.mkdir(mode=0o700)
        _fsync_directory(root.parent)
    private_directory(root)
    folder=root/('case-'+key_for_case(intent))
    # Atomic uniqueness across processes. A new attempt_id cannot bypass it.
    folder.mkdir(mode=0o700)
    _fsync_directory(root)
    res={'schema':SCHEMA+'-reservation','intent':intent,'profile':budget,
         'case_key':key_for_case(intent),
         'role':'A5_CANDIDATE_ONLY_NOT_AN_EXECUTION_PERMIT',
         'p8':'NO-GO','a6':'ND','physical_provenance_attested':False,
         'attempt_budget_consumed_at_reservation':True,
         'network_connections_created_by_module':0}
    reserved_sha=_save(folder,'reservation.json',res)
    _save(folder,'reservation.manifest.json',{
        'schema':SCHEMA+'-manifest','file':'reservation.json',
        'sha256':reserved_sha,'case_key':res['case_key'],'p8':'NO-GO'})
    return folder


def inspect(folder):
    """Pure readback of a private receipt; never makes an A6 admission."""
    need(isinstance(folder,Path) and folder.is_absolute(), 'RECEIPT_PATH_REQUIRED')
    private_directory(folder.parent)
    private_directory(folder)
    entries={p.name for p in folder.iterdir()}
    allowed={x+suffix for x in ('reservation','spent','result','failure')
                         for suffix in ('.json','.manifest.json')}
    need(entries <= allowed and
         {'reservation.json','reservation.manifest.json'} <= entries,
         'RECEIPT_ENTRY_SET')
    for prefix in ('reservation','spent','result','failure'):
        present=(prefix+'.json' in entries)
        need(present == (prefix+'.manifest.json' in entries),
             'RECEIPT_MANIFEST_MISSING_'+prefix)
        if present:
            rec=_read_json(folder,prefix+'.json')
            meta=_read_json(folder,prefix+'.manifest.json')
            need(type(meta) is dict and set(meta)=={
                  'schema','file','sha256','case_key','p8'} and
                  meta['schema']==SCHEMA+'-manifest' and
                  meta['file']==prefix+'.json' and
                  meta['sha256']==f1.digest(f1.canonical(rec)) and
                  type(meta['case_key']) is str and
                  meta['case_key']==folder.name.removeprefix('case-') and
                  meta['p8']=='NO-GO','RECEIPT_MANIFEST_DRIFT_'+prefix)
    r=_read_json(folder,'reservation.json')
    need(type(r) is dict and set(r)=={'schema','intent','profile','case_key',
         'role','p8','a6','physical_provenance_attested',
         'attempt_budget_consumed_at_reservation',
         'network_connections_created_by_module'} and
         r['schema']==SCHEMA+'-reservation' and
         r['role']=='A5_CANDIDATE_ONLY_NOT_AN_EXECUTION_PERMIT' and
         r['p8']=='NO-GO' and r['a6']=='ND' and
         r['physical_provenance_attested'] is False and
         r['attempt_budget_consumed_at_reservation'] is True and
         r['network_connections_created_by_module']==0,
         'RESERVATION_UNTRUSTED')
    check_intent(r['intent'])
    f12.validate_profile(r['profile'])
    need(r['case_key']==key_for_case(r['intent']) and
         folder.name=='case-'+r['case_key'],'RESERVATION_BINDING')
    spent = _read_json(folder,'spent.json') if 'spent.json' in entries else None
    if spent is not None:
        need(type(spent) is dict and set(spent)=={'schema','reservation_sha256',
             'status','a6','p8'} and spent['schema']==SCHEMA+'-spent' and
             spent['status']=='ATTEMPT_CONSUMED_NO_RETRY' and
             spent['reservation_sha256']==f1.digest(f1.canonical(r)) and
             spent['a6']=='ND' and spent['p8']=='NO-GO',
             'SPENT_RECEIPT_DRIFT')
    need(not ('result.json' in entries and 'failure.json' in entries),
         'TWO_TERMINAL_RECORDS')
    need(spent is not None or not (entries & {'result.json','failure.json'}),
         'TERMINAL_WITHOUT_SPENT')
    for field in ('result.json','failure.json'):
        if field in entries:
            record=_read_json(folder,field)
            need(type(record) is dict and record.get('schema')==SCHEMA+'-terminal' and
                 record.get('reservation_sha256')==f1.digest(f1.canonical(r)) and
                 record.get('spent_sha256')==f1.digest(f1.canonical(spent)) and
                 record.get('a6')=='ND' and record.get('p8')=='NO-GO' and
                 record.get('physical_provenance_attested') is False,
                 'TERMINAL_BINDING_DRIFT')
            if field=='result.json':
                need(record.get('status')=='RESULT_CANDIDATE_ONLY' and
                     record.get('a7') is None and record.get('a8') is None and
                     record.get('a9') is None and record.get('a10') is None,
                     'INVALID_A5_TERMINAL')
                try:
                    audit=f12.audit_f10_candidate(record['f10'],record['meter'],r['profile'])
                except (f12.Stop, f1.Rejected, KeyError, TypeError) as exc:
                    raise Stop('A5_CANDIDATE_REPLAY_REJECTED') from exc
                need(record['audit']==audit,'A5_CANDIDATE_REPLAY_MISMATCH')
            else:
                need(record.get('status')=='FAILED_NO_RETRY' and
                     type(record.get('error_code')) is str and
                     record['error_code'].isascii() and
                     re.fullmatch('[A-Z0-9_]{3,100}',record['error_code']),
                     'FAILURE_RECORD_INVALID')
    return {'schema':SCHEMA+'-readback','case_key':r['case_key'],
            'status':('RESULT_CANDIDATE_ONLY' if 'result.json' in entries else
                      'FAILED_NO_RETRY' if 'failure.json' in entries else
                      'ATTEMPT_CONSUMED_UNRESOLVED' if spent is not None else
                      'RESERVED_NO_RETRY'),
            'reservation_sha256':f1.digest(f1.canonical(r)),
            'a6':'ND','p8':'NO-GO','a7':None,'a8':None,'a9':None,'a10':None,
            'physical_provenance_attested':False}


def consume_reserved(folder, connected_socket, *, current_p8_guard,
                     monotonic=None):
    """Read via F10/F12; journaling cannot certify provenance or current P8.

    The caller is responsible for independently authorizing and connecting a
    socket, honoring the single connection budget, and verifying root policies.
    Invoking this method is not a substitute for those mandatory prerequisites.
    """
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    need(callable(current_p8_guard),'P8_GUARD_MISSING')
    state=inspect(folder)
    need(state['status']=='RESERVED_NO_RETRY','ATTEMPT_ALREADY_SPENT')
    reservation=_read_json(folder,'reservation.json')
    spent={'schema':SCHEMA+'-spent','reservation_sha256':state['reservation_sha256'],
           'status':'ATTEMPT_CONSUMED_NO_RETRY','a6':'ND','p8':'NO-GO'}
    # Durable BEFORE even checking peer or invoking a socket method.
    spent_sha=_save(folder,'spent.json',spent)
    _save(folder,'spent.manifest.json',{
        'schema':SCHEMA+'-manifest','file':'spent.json',
        'sha256':spent_sha,'case_key':reservation['case_key'],'p8':'NO-GO'})
    profile=reservation['profile']
    try:
        metered=f12.MeteredSocket(connected_socket,profile)
        limits=f10.Limits(timeout_seconds=profile['timeout_seconds'],
                          max_bytes=profile['max_recv_bytes'],
                          max_lines=profile['max_lines'],read_size=profile['read_size'])
        opts={'current_p8_guard':current_p8_guard,'limits':limits}
        if monotonic is not None:
            need(callable(monotonic),'CLOCK_INVALID')
            opts['monotonic']=monotonic
        result=f10.receive_control_reply(metered,**opts)
        usage=metered.seal()
        audit=f12.audit_f10_candidate(result,usage,profile)
        terminal={'schema':SCHEMA+'-terminal',
                  'status':'RESULT_CANDIDATE_ONLY',
                  'reservation_sha256':state['reservation_sha256'],
                  'spent_sha256':f1.digest(f1.canonical(spent)),
                  'f10':result,'meter':usage,'audit':audit,
                  'a6':'ND','p8':'NO-GO','a7':None,'a8':None,'a9':None,'a10':None,
                  'physical_provenance_attested':False}
        terminal_sha=_save(folder,'result.json',terminal)
        _save(folder,'result.manifest.json',{
            'schema':SCHEMA+'-manifest','file':'result.json',
            'sha256':terminal_sha,'case_key':reservation['case_key'],'p8':'NO-GO'})
    except Exception as exc:
        # Errors still consume the reserved attempt; the exact class is retained
        # without copying potentially sensitive exception messages to receipts.
        code=type(exc).__name__.upper().replace('ERROR','_ERROR')
        code=re.sub(r'[^A-Z0-9_]', '_', code)[:96]
        fail={'schema':SCHEMA+'-terminal','status':'FAILED_NO_RETRY',
              'reservation_sha256':state['reservation_sha256'],
              'spent_sha256':f1.digest(f1.canonical(spent)),
              'error_code':code,'a6':'ND','p8':'NO-GO',
              'physical_provenance_attested':False}
        # If the terminal result was written, do not create a conflicting
        # failure entry; a subsequent independent inspection decides validity.
        if not (folder/'result.json').exists():
            failure_sha=_save(folder,'failure.json',fail)
            _save(folder,'failure.manifest.json',{
                'schema':SCHEMA+'-manifest','file':'failure.json',
                'sha256':failure_sha,'case_key':reservation['case_key'],
                'p8':'NO-GO'})
        raise Stop('A5_CAPTURE_FAILED_NO_RETRY') from exc
    return inspect(folder)


def capabilities():
    return {'schema':SCHEMA+'-capabilities','family_id':'FTP-T01',
            'atomic_reservation_before_external_connect':True,
            'one_attempt_per_case_window':True,
            'recv_meters_f10_f12':True,'replay_validation':True,
            'opens_sockets':False,'boots_guests':False,'changes_firewall':False,
            'issues_authority':False,'a5_physical_source_attested':False,
            'a6':'ND','p8':'NO-GO'}
