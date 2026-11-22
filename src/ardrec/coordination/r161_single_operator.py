"""R161: single-operator DEV control plane for installed, signed FTP-T01 executor.

No installation, guest boot, firewall writes or direct FTP socket. The only
physical operation delegates one attempt to the unchanged root B9 executor,
which must independently accept all of its existing signed guards.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SCHEMA='ARDREC-R161-SINGLE-OPERATOR-LAB-v1'
AGENT='/var/lib/ardrec/r128-one-session-v2/root-executor.py'
ROOT_PYTHON='/usr/bin/python3'
OPERATOR_ACTION='DEVELOPMENT_SINGLE_OPERATOR_FTP_T01'
MAGIC_CONFIRM='AUTORIZO_UN_INTENTO_FTP_T01_DESARROLLO'
HEAD_RE=re.compile(r'[0-9a-f]{40}\Z')
TREE_RE=HEAD_RE
BOOT_RE=re.compile(r'[a-f0-9-]{36}\Z')
SESSION_RE=re.compile(r'[a-f0-9]{16}\Z')
HEX_RE=re.compile(r'[a-f0-9]{64}\Z')
MAX_JSON=64*1024

class Stop(ValueError):
    pass

def need(condition, message):
    if not condition: raise Stop(message)

def canon(obj):
    return (json.dumps(obj,sort_keys=True,separators=(',',':'),
         ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def nodup(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,'JSON_DUPLICATE_KEY')
        result[key]=value
    return result

def parse(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_JSON,'JSON_SIZE_INVALID')
    try:
        doc=json.loads(raw,object_pairs_hook=nodup,
            parse_constant=lambda _:need(False,'NONFINITE_JSON'))
        need(type(doc) is dict and canon(doc)==raw,'JSON_NOT_CANONICAL')
        return doc
    except (ValueError,UnicodeError,TypeError,OverflowError) as exc:
        raise Stop('JSON_INVALID') from exc

def instant(text):
    need(type(text) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',text),
         'UTC_TIME_INVALID')
    try:return datetime.strptime(text,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:raise Stop('UTC_TIME_INVALID') from exc

def utc(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def consent_document(*,head,tree,boot_id,operator_uid,session,now,minutes=10):
    need(type(head) is str and HEAD_RE.fullmatch(head),'GIT_HEAD_INVALID')
    need(type(tree) is str and TREE_RE.fullmatch(tree),'GIT_TREE_INVALID')
    need(type(boot_id) is str and BOOT_RE.fullmatch(boot_id),'BOOT_ID_INVALID')
    need(type(operator_uid) is int and operator_uid>0,'NONROOT_OPERATOR_REQUIRED')
    need(type(session) is str and SESSION_RE.fullmatch(session),'SESSION_INVALID')
    need(type(now) is datetime and now.tzinfo is not None,'TIME_INVALID')
    need(type(minutes) is int and 1<=minutes<=10,'TTL_INVALID')
    value={'schema':SCHEMA+'-consent','head':head,'tree':tree,'boot_id':boot_id,
        'operator_uid':operator_uid,'operator_mode':'SELF_ATTESTED_DEVELOPMENT',
        'independent_authority':False,'independent_rubric_verified':False,
        'session':session,'action':OPERATOR_ACTION,'case':'FTP-T01',
        'grants_root_privileges':False,'grants_network_traffic':False,
        'grants_vm_start':False,'root_executor_still_requires_its_own_signed_release':True,
        'issued_at':utc(now),'expires_at':utc(now+timedelta(minutes=minutes)),
        'p7':'DRAFT_NOT_FROZEN','p8':'NO-GO','a6':'ND','a9':'NOT_PUBLISHED'}
    return value

def validate_consent(doc,*,head,tree,boot_id,operator_uid,now):
    need(type(doc) is dict and set(doc)==set(consent_document(
         head='0'*40,tree='0'*40,boot_id='00000000-0000-0000-0000-000000000000',
         operator_uid=1,session='0'*16,now=datetime.now(timezone.utc))),
         'CONSENT_FIELDS_INVALID')
    need(doc['schema']==SCHEMA+'-consent' and
         doc['head']==head and doc['tree']==tree and doc['boot_id']==boot_id and
         doc['operator_uid']==operator_uid and
         doc['operator_mode']=='SELF_ATTESTED_DEVELOPMENT' and
         doc['independent_authority'] is False and
         doc['independent_rubric_verified'] is False and
         doc['action']==OPERATOR_ACTION and doc['case']=='FTP-T01' and
         doc['grants_root_privileges'] is False and
         doc['grants_network_traffic'] is False and
         doc['grants_vm_start'] is False and
         doc['root_executor_still_requires_its_own_signed_release'] is True and
         doc['p7']=='DRAFT_NOT_FROZEN' and doc['p8']=='NO-GO' and
         doc['a6']=='ND' and doc['a9']=='NOT_PUBLISHED',
         'CONSENT_AUTHORITY_SCOPE_INVALID')
    need(type(doc['session']) is str and SESSION_RE.fullmatch(doc['session']),
         'CONSENT_SESSION_INVALID')
    start,end=instant(doc['issued_at']),instant(doc['expires_at'])
    need(type(now) is datetime and now.tzinfo is not None and
         start<=now<end and 0<(end-start).total_seconds()<=600,
         'CONSENT_EXPIRED_OR_INVALID')
    return doc

def validate_b9_preflight(raw,*,expected_head,expected_session,now):
    doc=parse(raw)
    need(doc.get('schema')=='ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-preflight',
         'B9_PREFLIGHT_SCHEMA_INVALID')
    need(doc.get('head')==expected_head and doc.get('session')==expected_session,
         'B9_PREFLIGHT_IDENTITY_INVALID')
    need(doc.get('host_changes')==0 and doc.get('traffic_opened') is False and
         doc.get('a6')=='ND' and doc.get('p8')=='NO-GO',
         'B9_PREFLIGHT_UNSAFE')
    need(type(doc.get('traffic_grant_sha256')) is str and
         HEX_RE.fullmatch(doc['traffic_grant_sha256']) and
         type(doc.get('root_deny_grant_sha256')) is str and
         HEX_RE.fullmatch(doc['root_deny_grant_sha256']) and
         type(doc.get('f13_handoff_sha256')) is str and
         HEX_RE.fullmatch(doc['f13_handoff_sha256']),
         'B9_SIGNED_EVIDENCE_MISSING')
    need(instant(doc.get('traffic_permit_until'))>now+timedelta(seconds=5),
         'B9_TRAFFIC_WINDOW_TOO_SHORT')
    budget=doc.get('budget')
    need(type(budget) is dict and bool(budget),'B9_BUDGET_MISSING')
    need(type(doc.get('case_id')) is str and doc['case_id'].startswith('FTP-T01-'),
         'B9_CASE_INVALID')
    return doc

def safe_directory(path):
    need(isinstance(path,Path) and path.is_absolute() and not path.is_symlink(),
         'PRIVATE_DIRECTORY_PATH_INVALID')
    st=path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
         stat.S_IMODE(st.st_mode)==0o700,'PRIVATE_DIRECTORY_INVALID')

def private_read(path,limit=MAX_JSON):
    need(isinstance(path,Path) and path.is_absolute() and
         not path.is_symlink(),'FILE_PATH_INVALID')
    safe_directory(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
             0<st.st_size<=limit,'PRIVATE_FILE_INVALID')
        chunks=[];remaining=st.st_size
        while remaining:
            part=os.read(fd,remaining)
            need(bool(part),'SHORT_READ')
            chunks.append(part);remaining-=len(part)
        after=os.fstat(fd)
        need((st.st_ino,st.st_ctime_ns,st.st_mtime_ns,st.st_size)==
             (after.st_ino,after.st_ctime_ns,after.st_mtime_ns,after.st_size),
             'FILE_CHANGED_DURING_READ')
        return b''.join(chunks)
    finally:os.close(fd)

def private_create(path,payload):
    need(type(payload) is bytes and 0<len(payload)<=MAX_JSON,'PRIVATE_OUTPUT_INVALID')
    safe_directory(path.parent)
    need(not path.exists() and not path.is_symlink(),'ONE_SHOT_ALREADY_EXISTS')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as out:
            out.write(payload);out.flush();os.fsync(out.fileno())
        dirfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:os.close(fd)

def validate_root_agent(path=Path(AGENT)):
    need(path==Path(AGENT),'ROOT_EXECUTOR_PATH_NOT_PINNED')
    # Source-only repository code is not a privileged runner.
    need(path.is_file() and not path.is_symlink(),'B9_ROOT_EXECUTOR_ABSENT')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o600,'ROOT_EXECUTOR_METADATA_INVALID')
    parent=path.parent
    for ancestor in reversed(parent.parents):
        st_ancestor=ancestor.lstat()
        need(not ancestor.is_symlink() and stat.S_ISDIR(st_ancestor.st_mode) and
             st_ancestor.st_uid==0 and not(st_ancestor.st_mode & 0o022),
             'ROOT_EXECUTOR_ANCESTOR_UNSAFE')
    st=parent.lstat()
    need(not parent.is_symlink() and st.st_uid==0 and
         stat.S_IMODE(st.st_mode)==0o700,'ROOT_EXECUTOR_DIR_INVALID')

def agent_command(mode):
    need(mode in ('--inspect-root','--execute-pilot'),'UNSUPPORTED_B9_ACTION')
    return ('/usr/bin/sudo','-n','--',ROOT_PYTHON,'-I','-B',AGENT,mode)

def root_call(mode,*,timeout,runner=None):
    need(mode in ('--inspect-root','--execute-pilot'),'UNSUPPORTED_B9_ACTION')
    need(type(timeout) is int and 1<=timeout<=80,'ROOT_CALL_TIMEOUT_INVALID')
    if runner is None:
        validate_root_agent()
        def runner(argv,timeout):
            return subprocess.run(argv,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=timeout,check=False,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
    return runner(agent_command(mode),timeout)

def validate_b9_receipt(raw,*,head,session):
    doc=parse(raw)
    need(doc.get('schema')=='ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-receipt',
         'B9_RECEIPT_SCHEMA_INVALID')
    need(doc.get('head')==head and doc.get('session')==session,
         'B9_RECEIPT_IDENTITY_INVALID')
    need(doc.get('a6')=='ND' and doc.get('p8')=='NO-GO' and doc.get('a9') is None,
         'B9_RECEIPT_AUTHORITY_INVALID')
    need(doc.get('denies_restored_and_verified') is True and
         doc.get('timer_armed') is True and
         doc.get('result')=='FTP_GUEST_CANDIDATE_ONLY' and
         type(doc.get('guest_result_sha256')) is str and
         HEX_RE.fullmatch(doc['guest_result_sha256']) and
         type(doc.get('elapsed_monotonic_ns')) is int and
         0<=doc['elapsed_monotonic_ns']<=60_000_000_000 and
         doc.get('error') is None,
         'B9_DENY_RESTORATION_OR_RESULT_UNVERIFIED')
    return doc

def run_session(*,folder,consent_raw,head,tree,boot_id,operator_uid,now,
                confirmation,runner=None):
    need(confirmation==MAGIC_CONFIRM,'PHYSICAL_OPERATOR_CONFIRMATION_REQUIRED')
    need(os.geteuid()!=0,'ROOT_OPERATOR_FORBIDDEN')
    safe_directory(folder)
    doc=validate_consent(parse(consent_raw),head=head,tree=tree,
         boot_id=boot_id,operator_uid=operator_uid,now=now)
    # Inspection has no root changes; a failed inspection must not consume an attempt.
    first=root_call('--inspect-root',timeout=20,runner=runner)
    need(first.returncode==0 and 0<len(first.stdout)<=MAX_JSON,
         'B9_ROOT_PREFLIGHT_REFUSED')
    reviewed=validate_b9_preflight(first.stdout,
         expected_head=head,expected_session=doc['session'],now=now)
    intent_path=folder/('attempt-'+doc['session']+'.json')
    private_create(intent_path,canon({'schema':SCHEMA+'-attempt',
         'head':head,'session':doc['session'],'self_authorized':True,
         'independent_authority':False,'b9_preflight_sha256':sha(first.stdout),
         'root_grant_sha256':reviewed['traffic_grant_sha256'],
         'p8':'NO-GO','issued_at':utc(now)}))
    # Never retry. B9 itself claims before any actual host mutation and restores DENY.
    try:
        result=root_call('--execute-pilot',timeout=80,runner=runner)
        trusted=(False)
        if result.returncode==0 and 0<len(result.stdout)<=MAX_JSON:
            try:
                checked=validate_b9_receipt(result.stdout,
                    head=head,session=doc['session'])
                trusted=True
            except Stop:
                trusted=False
        status=('B9_REPORTED_CANDIDATE_WITH_DENY_RESTORED' if trusted
                 else 'B9_DENIED_OR_UNKNOWN_MANUAL_DENY_REVIEW')
        receipt={'schema':SCHEMA+'-operator-receipt','session':doc['session'],
             'head':head,'self_authorized':True,'independent_authority':False,
             'b9_exit_code':result.returncode,'b9_stdout_sha256':sha(result.stdout),
             'b9_stderr_sha256':sha(result.stderr),
             'b9_stdout_bytes':len(result.stdout),'b9_stderr_bytes':len(result.stderr),
             'result':status,'physical_result_independently_verified':False,
             'b9_claimed_deny_restored':trusted,
             'p7':'DRAFT_NOT_FROZEN','p8':'NO-GO','a6':'ND','a9':'NOT_PUBLISHED'}
    except (OSError,subprocess.TimeoutExpired) as exc:
        receipt={'schema':SCHEMA+'-operator-receipt','session':doc['session'],
             'head':head,'self_authorized':True,'independent_authority':False,
             'result':'B9_EXECUTION_UNKNOWN_MANUAL_DENY_REVIEW',
             'error_class':type(exc).__name__,'physical_result_independently_verified':False,
             'p8':'NO-GO','a6':'ND','a9':'NOT_PUBLISHED'}
    private_create(folder/('receipt-'+doc['session']+'.json'),canon(receipt))
    return receipt
