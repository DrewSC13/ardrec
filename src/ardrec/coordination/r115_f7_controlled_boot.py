"""R115-F7: signed one-start DEV guest activation under existing F11/R34 DENY.

This is a new source-pinned R115 implementation: R112 immutable pure audit
algorithms are reused; their obsolete branch/receipt-bound host executors are
never patched, monkeypatched, or run. An installation or --inspect NEVER boots.

--plan requires an independently signed FTP-T01 scope. --boot additionally
requires a distinct, root-trusted, fresh, signed role-specific boot permit,
a separately signed revocation assertion, explicit CLI consent, a committed
trusted source and a fresh host re-audit. Any uncertainty after the one-use
marker means STOP/no retry/no automatic cleanup. All stages preserve P8 NO-GO.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import sys
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile
import time

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r112_f12_postreboot_boot as f12
from ardrec.coordination import r112_f10_targets_boot as f10

SCHEMA = 'ARDREC-R115-F7-ONE-BOOT-DENY-v1'
PLAN_SCHEMA = SCHEMA+'-plan'
ROOT = Path('/home/cicada/ardrec-lab/r115-f7-one-boot-deny-v1')
REPO = Path('/home/cicada/Development/GitHub/ardrec')
BRANCH = 'feat/p14-r115-a3-p7-a6-real'
BASE = '6ce42a1143d50f7adf69ea3159b56c0e993c45cb'
# R138: nueva línea de desarrollo. La historia R115 original conserva
# sus identidades y sigue válida solo bajo las mismas guardas.
ACTIVE_BRANCH = 'feat/ardrec-cierre-operacional-experimental'
ACTIVE_BASE = 'b43b9488ad7f89d728ea24430b789342f758c4a0'
ORDER = ('ssh','runner','ftp')
ALL = ('ssh','runner','ftp','smb')
PERMIT_TRUST = Path('/etc/ardrec/r115-boot-trust-v1.json')
PERMIT_REVOCATION = Path('/etc/ardrec/r115-boot-revocation-v1.json')
PERMIT_PREFIX = b'ARDREC-R115-F7-BOOT-ONE-START-v1\x00'
REVOKE_PREFIX = b'ARDREC-R115-F7-BOOT-REVOCATION-v1\x00'
MAX_PLAN_AGE = 86400
MAX_BOOT_PERMIT_SEC = 120
MAX_REVOCATION_AGE = 90

class Stop(ValueError):
    pass

def need(ok, reason):
    if not ok: raise Stop(reason)

def utcnow(): return datetime.now(timezone.utc)

def digest(obj): return f1.digest(f1.canonical(obj))

def command(role):
    need(type(role) is str and role in ORDER,'UNKNOWN_ROLE')
    if role=='ftp': return tuple(f10.start(role))
    return tuple(f12.command(role))

def guest(role): return 'ardrec-r33-dev-'+role

def pre_states(role):
    need(role in ORDER,'UNKNOWN_STAGE')
    return {r:('RUNNING' if r in ORDER[:ORDER.index(role)] else 'OFF')
            for r in ALL}

def post_states(role):
    states=pre_states(role)
    states[role]='RUNNING'
    return states

def state_gate(capture, role, *, after=False):
    """Independent strict F5 proof for a partial boot sequence.

    F5's all-off/all-on aggregate is intentionally not used for intermediate
    states. Every currently running guest MUST have each DENY binding.
    """
    need(role in ORDER,'UNKNOWN_ROLE')
    rec=f5.report(capture)
    need(rec['nft']=='MATCH' and rec['helper']=='MATCH' and
         rec['f11_hook']=='MATCH','DENY_OR_F11_NOT_ATTESTED')
    need(all(v=='MATCH' for v in rec['vm_definitions'].values()),'VM_DEFINITION_DRIFT')
    want=post_states(role) if after else pre_states(role)
    need(rec['states']==want,'WRONG_RUNNING_GUEST_SET')
    for key,(guest_role,_,_,_) in f5.six.ROLES.items():
        desired='DENY_MATCH' if want[guest_role]=='RUNNING' else 'ABSENT_WHILE_OFF'
        need(rec['bindings'][key]==desired,'DENY_BINDING_NOT_VERIFIED_'+key)
    need(rec['a5_dispatch']=='NO-GO' and rec['p8']=='NO-GO' and
         rec['authority_attested'] is False,'FORBIDDEN_A5_OR_P8_STATE')
    return {'role':role,'phase':'AFTER' if after else 'BEFORE',
            'states':want,'all_deny':'MATCH','f5_capture_sha256':rec['capture_sha256'],
            'p8':'NO-GO'}

def _run(argv, *, timeout=20, runner=subprocess.run):
    need(type(argv) in (tuple,list) and argv and
         all(type(x) is str for x in argv),'COMMAND_ARGUMENTS')
    try:
        p=runner(list(argv),stdin=subprocess.DEVNULL,capture_output=True,
                 shell=False,check=False,timeout=timeout,
                 env={'LC_ALL':'C','LANG':'C','PATH':'/usr/sbin:/usr/bin:/bin'})
        out,err,rc,to=p.stdout,p.stderr,p.returncode,False
    except subprocess.TimeoutExpired as exc:
        out,err,rc,to=exc.stdout or b'',exc.stderr or b'',None,True
    except (OSError,ValueError) as exc:
        out,err,rc,to=b'',str(type(exc).__name__).encode(),None,False
    need(type(out) is bytes and type(err) is bytes,'COMMAND_RESULT_BYTES')
    return {'argv':list(argv),'rc':rc,'timeout':to,
            'truncated':len(out)>65536 or len(err)>8192,
            'stdout':out[:65536].decode('utf-8','replace'),
            'stderr':err[:8192].decode('utf-8','replace')}

def ok(result, code):
    need(result['rc']==0 and result['timeout'] is False and
         result['truncated'] is False,code)
    return result['stdout'].strip()

def git_guard(*, for_boot=False, runner=subprocess.run):
    need(Path.cwd().resolve()==REPO,'WRONG_REPOSITORY_DIRECTORY')
    need(ok(_run(('git','rev-parse','--show-toplevel'),runner=runner),'GIT_ROOT')==str(REPO),
         'GIT_ROOT_MISMATCH')
    branch=ok(_run(('git','branch','--show-current'),runner=runner),'GIT_BRANCH')
    need(branch in (BRANCH,ACTIVE_BRANCH),'GIT_BRANCH_MISMATCH')
    head=ok(_run(('git','rev-parse','HEAD'),runner=runner),'GIT_HEAD')
    need(f1.GIT_SHA.fullmatch(head),'INVALID_HEAD')
    need(_run(('git','merge-base','--is-ancestor',BASE,head),runner=runner)['rc']==0,
         'SIGNED_F1_F6_BASE_NOT_ANCESTOR')
    # La nueva rama exige, adicionalmente, el cierre R136 firmado como
    # ancestro exacto. No acepta cualquier rama que derive de R115.
    if branch==ACTIVE_BRANCH:
        need(_run(('git','merge-base','--is-ancestor',ACTIVE_BASE,head),runner=runner)['rc']==0,
             'SIGNED_R136_BASE_NOT_ANCESTOR')
    need(ok(_run(('git','status','--porcelain=v1','--untracked-files=all'),runner=runner),
            'GIT_STATUS')=='','SOURCE_TREE_NOT_CLEAN')
    sig=ok(_run(('git','log','-1','--format=%G?'),runner=runner),'GIT_SIGNATURE')
    need(sig=='G','UNTRUSTED_OR_UNSIGNED_HEAD')
    if for_boot:
        for path in ('src/ardrec/coordination/r115_f7_controlled_boot.py',
                     'scripts/ardrec_p14_r115_f7_controlled_boot.py'):
            need(_run(('git','ls-files','--error-unmatch',path),runner=runner)['rc']==0,
                 'F7_SOURCE_NOT_COMMITTED_'+path)
            need(_run(('git','diff','--quiet','HEAD','--',path),runner=runner)['rc']==0,
                 'F7_SOURCE_CHANGED_'+path)
    return head

def _secure_root(path):
    need(path in (PERMIT_TRUST, PERMIT_REVOCATION),'UNALLOWLISTED_ROOT_POLICY')
    for parent in (Path('/'),Path('/etc'),Path('/etc/ardrec')):
        st=parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
             not(st.st_mode & 0o022),'UNSAFE_ROOT_POLICY_DIRECTORY')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         not(st.st_mode&0o022) and 0<st.st_size<=8192,'UNTRUSTED_ROOT_FILE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        now=os.fstat(fd)
        need(now.st_dev==st.st_dev and now.st_ino==st.st_ino and
             now.st_uid==0 and now.st_nlink==1 and now.st_size==st.st_size,
             'POLICY_FILE_RACE')
        data=os.read(fd,8193)
        need(len(data)==st.st_size,'ROOT_POLICY_READ_INCOMPLETE')
        return data
    finally: os.close(fd)

def _instant(value): return f1._instant(value,'F7_TIMESTAMP')

def signed_boot_permit(plan,contract_raw,authorization_raw,permit_raw,*,now,
                       root_loader=_secure_root):
    """Distinct independent boot signers + signed current revocation, no self-grants."""
    need(f1.digest(contract_raw)==plan['contract_sha256'] and
         f1.digest(authorization_raw)==plan['authorization_sha256'],
         'AUTHORIZATION_BYTES_CHANGED')
    trust=f1.load(root_loader(PERMIT_TRUST))
    rev=f1.load(root_loader(PERMIT_REVOCATION))
    f3.exact(trust,{'schema','boot_signer','revocation_signer'},'BOOT_TRUST_FIELDS')
    need(trust['schema']=='ARDREC-R115-F7-EXTERNAL-BOOT-TRUST-v1','BOOT_TRUST_SCHEMA')
    f3.trust_check({'schema':f3.TRUST_SCHEMA,'scope_signer':trust['boot_signer'],
                    'revocation_signer':trust['revocation_signer']})
    permit=f1.load(permit_raw)
    f3.exact(permit,{'statement','signer_key_id','signature_b64'},'BOOT_PERMIT_WRAPPER')
    stmt=permit['statement']
    f3.exact(stmt,{'schema','permit_id','role','guest','head','plan_sha256',
                   'contract_sha256','authorization_sha256','valid_from','valid_until',
                   'action','network_traffic_authorized'},'BOOT_PERMIT_FIELDS')
    need(stmt['schema']=='ARDREC-R115-F7-ONE-BOOT-PERMIT-v1' and
         type(stmt['permit_id']) is str and f1.ID.fullmatch(stmt['permit_id']) and
         stmt['role']==plan['role'] and stmt['guest']==guest(plan['role']) and
         stmt['head']==plan['head'] and
         stmt['plan_sha256']==digest(plan) and
         stmt['contract_sha256']==plan['contract_sha256'] and
         stmt['authorization_sha256']==plan['authorization_sha256'] and
         stmt['action']=='SINGLE_DENY_BOOT_ONLY' and
         stmt['network_traffic_authorized'] is False,'BOOT_SCOPE_MISMATCH')
    a,b=_instant(stmt['valid_from']),_instant(stmt['valid_until'])
    need(a<b and (b-a).total_seconds()<=MAX_BOOT_PERMIT_SEC and a<=now<b,
         'BOOT_PERMIT_EXPIRED_OR_FUTURE')
    f3.verified_signature(permit,stmt,trust['boot_signer'],PERMIT_PREFIX)
    f3.exact(rev,{'statement','signer_key_id','signature_b64'},'BOOT_REVOCATION_WRAPPER')
    r=rev['statement']
    f3.exact(r,{'schema','permit_sha256','permit_id','issued_at','valid_until',
                'revoked','reason_code'},'BOOT_REVOCATION_FIELDS')
    need(r['schema']=='ARDREC-R115-F7-BOOT-REVOCATION-v1' and
         r['permit_sha256']==digest(permit) and r['permit_id']==stmt['permit_id'] and
         type(r['revoked']) is bool and type(r['reason_code']) is str and
         f1.ID.fullmatch(r['reason_code']), 'BOOT_REVOCATION_SCOPE')
    f3.verified_signature(rev,r,trust['revocation_signer'],REVOKE_PREFIX)
    r0,r1=_instant(r['issued_at']),_instant(r['valid_until'])
    need(r0<=now<r1 and 0<=(now-r0).total_seconds()<=MAX_REVOCATION_AGE and
         r1>r0,'BOOT_REVOCATION_NOT_CURRENT')
    need(r['revoked'] is False,'BOOT_PERMIT_REVOKED')
    return {'boot_permit_sha256':digest(permit),
            'boot_revocation_sha256':digest(rev),
            'role':plan['role'],'valid_until':stmt['valid_until']}

def scope_required(contract_raw,authorization_raw,*,now):
    result=f6.scope(contract_raw,authorization_raw,
                    catalog_raw=f6.CATALOG.read_bytes(),now=now)
    need(result[0]=='VERDADERO','SIGNED_CASE_SCOPE_NOT_AUTHORIZED_'+result[0])
    return result

def _ticket(role):
    moment=int(time.time())
    if role=='ftp': return f10.ticket(role,moment,secrets.token_hex(32))
    return f12.ticket(role,moment,secrets.token_hex(32))

def _lease(role):
    if role=='ftp': return f10.lease(role),f10.markers(role),f10.LEASE_ROOT
    return f12.lease(role),f12.markers(role),f12.ROOT_LEASE

def _no_markers(role,*,runner=subprocess.run):
    lease,markers,_=_lease(role)
    for path in (lease,*markers.values()):
        for flag in ('!','-L'):
            argv=('sudo','-n','test','!', '-e',path) if flag=='!' else ('sudo','-n','test','!', '-L',path)
            ok(_run(argv,runner=runner),'STALE_LEASE_OR_MARKER_'+role)

def _private(path):
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    return f2.private_parent(path)

def _create(root,prefix):
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    need(root.parent.is_dir() and not root.parent.is_symlink(),
         'RECEIPT_PARENT_MISSING_OR_SYMLINK')
    if not root.exists(): root.mkdir(mode=0o700)
    _private(root)
    folder=Path(tempfile.mkdtemp(prefix=prefix,dir=root))
    _private(folder)
    return folder

def _save(path,data): f2.exclusive(path,f1.canonical(data) if type(data) is dict else data)

def _read_large(path):
    need(path.is_absolute() and not path.is_symlink(),'LARGE_RECEIPT_PATH')
    _private(path.parent)
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
         st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         0<st.st_size<=8000000,'LARGE_RECEIPT_SIZE_OR_MODE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        now=os.fstat(fd)
        need(now.st_dev==st.st_dev and now.st_ino==st.st_ino and
             now.st_size==st.st_size,'LARGE_RECEIPT_RACE')
        raw=os.read(fd,8000001)
        need(len(raw)==now.st_size,'LARGE_RECEIPT_TRUNCATED')
    finally: os.close(fd)
    return raw

def _load(path):
    raw=_read_large(path)
    need(len(raw)<=8000000,'JSON_TOO_LARGE')
    try:
        obj=json.loads(raw,object_pairs_hook=f1.unique_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE')))
        need(type(obj) is dict,'JSON_OBJECT_REQUIRED')
        need(f1.canonical(obj)==raw,'JSON_NONCANONICAL')
        return obj
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise Stop('INVALID_JSON_RECEIPT') from exc

def expected_predecessor(role, prior):
    need(role in ORDER,'UNKNOWN_ROLE')
    if role=='ssh':
        need(prior is None,'UNEXPECTED_PREDECESSOR')
        return None
    need(type(prior) is dict and set(prior)=={'role','receipt_sha256','receipt'},
         'MISSING_PREDECESSOR')
    need(prior['role']==ORDER[ORDER.index(role)-1] and
         type(prior['receipt_sha256']) is str and f1.SHA.fullmatch(prior['receipt_sha256'])
         and type(prior['receipt']) is str and prior['receipt'].startswith(str(ROOT)+'/boot-'),
         'PREDECESSOR_INVALID')
    # Physical predecessor verification is performed again before the boot.
    return prior

def proposal(*,role,head,contract_raw,authorization_raw,pre,prior=None,now=None):
    now=now or utcnow()
    check=state_gate(pre,role)
    predecessor=expected_predecessor(role,prior)
    return {'schema':PLAN_SCHEMA,'head':head,'role':role,'guest':guest(role),
            'command':list(command(role)),'created_at':f2.iso(now),
            'expires_at':f2.iso(now+timedelta(seconds=MAX_PLAN_AGE)),
            'f5_snapshot_sha256':f1.digest(f1.canonical(pre)),
            'f5_preflight':check,'contract_sha256':f1.digest(contract_raw),
            'authorization_sha256':f1.digest(authorization_raw),
            'predecessor':predecessor,
            'traffic_authorized':False,'a5':'NO-GO','a6':'ND','p8':'NO-GO'}

def verify_plan(plan,pre,*,now,head):
    need(type(plan) is dict and set(plan)=={'schema','head','role','guest','command',
         'created_at','expires_at','f5_snapshot_sha256','f5_preflight',
         'contract_sha256','authorization_sha256','predecessor',
         'traffic_authorized','a5','a6','p8'},'PLAN_FIELDS')
    need(plan['schema']==PLAN_SCHEMA and plan['head']==head and
         plan['guest']==guest(plan['role']) and
         plan['command']==list(command(plan['role'])) and
         plan['traffic_authorized'] is False and plan['a5']=='NO-GO' and
         plan['a6']=='ND' and plan['p8']=='NO-GO','PLAN_SCOPE')
    a,b=_instant(plan['created_at']),_instant(plan['expires_at'])
    need(a<=now<b and 0<(b-a).total_seconds()<=MAX_PLAN_AGE,
         'PLAN_EXPIRED_OR_FUTURE')
    need(plan['f5_snapshot_sha256']==f1.digest(f1.canonical(pre)) and
         plan['f5_preflight']==state_gate(pre,plan['role']),
         'PLAN_PHYSICAL_INPUT_CHANGED')
    expected_predecessor(plan['role'],plan['predecessor'])
    return plan

def read_only(*,role='ssh',runner=subprocess.run,clock=utcnow):
    """Read live F11/R34/six bindings; never creates a plan or starts a VM."""
    capture=f5.capture(runner=runner,clock=clock)
    report=f5.report(capture)
    try:
        candidate=state_gate(capture,role)
        status='DENY_STAGE_READY_NO_BOOT_AUTHORITY'
        reason='BOOT_SCOPE_AND_PERMIT_NOT_EVALUATED'
    except Stop as exc:
        status='NO-GO'
        reason=str(exc)
        candidate=None
    return {'schema':SCHEMA+'-inspection','role':role,'status':status,
            'reason':reason,'candidate':candidate,'f5':report,
            'vm_starts':0,'traffic_authorized':False,'a5':'NO-GO',
            'a6':'ND','p8':'NO-GO'}


def _audit_legacy(snapshot,role,*,after=False):
    """Reuse the original R112 pure 29-probe audit, not its historical CLI."""
    import ardrec_p14_r112_f6_hook_lifecycle as original_f6
    import ardrec_p14_r111_legacy_host_snapshot as legacy
    import ardrec_p14_r112_f4_isolated_networks as f4
    from ardrec.coordination import r112_f8_ssh_positive_boot as f8
    from ardrec.coordination import r112_f9_runner_boot as f9
    if role=='ssh':
        f8.audited(snapshot,ssh_running=after,legacy=legacy,f4=f4,f6=original_f6)
    elif role=='runner':
        f9.audited(snapshot,runner_running=after,legacy=legacy,f4=f4)
    elif role=='ftp':
        f10.audited(snapshot,role,after=after,legacy=legacy,f4=f4)
    else: raise Stop('UNKNOWN_LEGACY_ROLE')
    return True

def _capture_legacy():
    import ardrec_p14_r112_f6_hook_lifecycle as original_f6
    return original_f6.capture()

def _old_classifier_ssh(before,after,started,live,ticket,grant,claims):
    from ardrec.coordination import r112_f8_ssh_positive_boot as f8
    import ardrec_p14_r112_f6_hook_lifecycle as original_f6
    import ardrec_p14_r111_legacy_host_snapshot as legacy
    import ardrec_p14_r112_f4_isolated_networks as f4
    return f8.classify(before,after,started,live,ticket,grant,claims,
                       legacy,f4,original_f6)

def _read_plan(folder):
    need(type(folder) is Path and folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith('plan-'),'INVALID_PLAN_PATH')
    _private(ROOT);_private(folder)
    expected={'plan.json','before-f5.json','before-r112.json','manifest.json'}
    found={p.name for p in folder.iterdir()}
    need(found in (expected,expected|{'boot.once'}),'INVALID_PLAN_FILE_SET')
    manifest=_load(folder/'manifest.json')
    need(manifest['schema']==SCHEMA+'-manifest' and
         set(manifest)=={'schema','file_sha256'} and
         set(manifest['file_sha256'])==expected-{'manifest.json'},
         'PLAN_MANIFEST')
    raw={name:_read_large(folder/name) for name in expected-{'manifest.json'}}
    need(all(f1.digest(raw[name])==manifest['file_sha256'][name]
             for name in raw),'PLAN_FILE_TAMPERED')
    plan=f1.load(raw['plan.json'])
    before=_load(folder/'before-f5.json')
    legacy=_load(folder/'before-r112.json')
    need(plan['f5_snapshot_sha256']==f1.digest(raw['before-f5.json']) and
         plan['legacy_snapshot_sha256']==f1.digest(raw['before-r112.json']),
         'PLAN_SNAPSHOT_HASH_DRIFT')
    need(plan['role']=='ssh','F7_PHYSICAL_BOOT_SUPPORTS_SSH_ONLY')
    _audit_legacy(legacy,'ssh')
    return plan,before,legacy

def _plan_ssh(contract,authorization,*,clock=utcnow):
    head=git_guard(for_boot=True)
    now=clock()
    source=f2.private_read(contract)
    auth=f2.private_read(authorization)
    scope_required(source,auth,now=now)
    snap=f5.capture()
    gated=state_gate(snap,'ssh')
    before=_capture_legacy()
    _audit_legacy(before,'ssh')
    _no_markers('ssh')
    plan=proposal(role='ssh',head=head,contract_raw=source,
                  authorization_raw=auth,pre=snap,now=now)
    plan['legacy_snapshot_sha256']=f1.digest(f1.canonical(before))
    # A signed permit is bound to this canonical plan and must be issued
    # by an independent boot authority, never by this application.
    folder=_create(ROOT,'plan-')
    raw={'before-f5.json':f1.canonical(snap),
         'before-r112.json':f1.canonical(before),
         'plan.json':f1.canonical(plan)}
    for name,value in raw.items(): f2.exclusive(folder/name,value)
    _save(folder/'manifest.json',{'schema':SCHEMA+'-manifest',
                                   'file_sha256':{key:f1.digest(value) for key,value in raw.items()}})
    return folder,plan

def _boot_ssh(folder,contract,authorization,permit,*,runner=subprocess.run,clock=utcnow):
    """One physical boot only; incident is durable and never retried or cleaned."""
    head=git_guard(for_boot=True,runner=runner)
    plan,before,legacy_before=_read_plan(folder)
    need(plan['head']==head,'PLAN_HEAD_CHANGED')
    now=clock()
    # Plan freshness must not turn into indefinite approval.
    verify_plan({k:v for k,v in plan.items() if k!='legacy_snapshot_sha256'},
                before,now=now,head=head)
    source,auth,permit_raw=(f2.private_read(p) for p in (contract,authorization,permit))
    scope_required(source,auth,now=now)
    grant_review=signed_boot_permit(plan,source,auth,permit_raw,now=now)
    need(not (folder/'boot.once').exists(),'ALREADY_ATTEMPTED_NO_RETRY')
    fresh=f5.capture(runner=runner,clock=clock)
    state_gate(fresh,'ssh')
    before_new=_capture_legacy()
    _audit_legacy(before_new,'ssh')
    import ardrec_p14_r112_f6_hook_lifecycle as original_f6
    import ardrec_p14_r111_legacy_host_snapshot as hist
    import ardrec_p14_r112_f4_isolated_networks as original_f4
    f12.boundary(legacy_before,before_new,'ssh',hist,original_f4,original_f6)
    _no_markers('ssh',runner=runner)
    # Re-review the permit's finite window as close to the irreversible
    # action as possible. No additional root commands may bypass this check.
    # The operator may revoke the boot permit at any point before the claim.
    scope_required(source,auth,now=clock())
    grant_review=signed_boot_permit(plan,source,auth,permit_raw,now=clock())
    need(clock()<_instant(grant_review['valid_until']),'BOOT_PERMIT_EXPIRED')
    attempt=_create(ROOT,'boot-')
    intent={'schema':SCHEMA+'-intent','plan_sha256':digest(plan),
            'permit_sha256':grant_review['boot_permit_sha256'],
            'before_sha256':f1.digest(f1.canonical(before_new)),
            'role':'ssh','command':list(command('ssh')),
            'traffic_authorized':False,'a5':'NO-GO','p8':'NO-GO'}
    _save(attempt/'intent.json',intent)
    _save(attempt/'preflight-r112.json',before_new)
    _save(attempt/'preflight-f5.json',fresh)
    # Exact-once durable claim BEFORE any root write or QEMU start.
    f2.exclusive(folder/'boot.once',b'ATTEMPTED\n')
    ticket=_ticket('ssh')
    _save(attempt/'ticket.json',ticket)
    lease,markers,lease_root=_lease('ssh')
    try:
        # Three privileged writes total: directory, one lease, one VM start.
        d=_run(('sudo','-n','install','-d','-o','root','-g','root','-m','0700',lease_root),runner=runner)
        _save(attempt/'root-dir-command.json',d)
        ok(d,'ROOT_LEASE_DIR_UNCERTAIN')
        granted=_run(('sudo','-n','install','-o','root','-g','root','-m','0600',
                      str(attempt/'ticket.json'),lease),runner=runner)
        _save(attempt/'root-lease-command.json',granted)
        ok(granted,'ROOT_LEASE_WRITE_UNCERTAIN')
        rd=ok(_run(('sudo','-n','stat','-Lc','%u:%g %a %n',lease_root),runner=runner),'ROOT_LEASE_PARENT_STAT')
        rs=ok(_run(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',lease),runner=runner),'ROOT_LEASE_STAT')
        rh=ok(_run(('sudo','-n','sha256sum',lease),runner=runner),'ROOT_LEASE_SHA')
        grant={'directory_stat':rd,'lease_stat':rs,'lease_sha256':rh.split()[0]}
        need(grant['lease_sha256']==f1.digest(f1.canonical(ticket)),
             'ROOT_LEASE_HASH_NOT_ATTESTED')
        _save(attempt/'grant.json',grant)
        need(clock()<_instant(grant_review['valid_until']) and
             int(time.time())<ticket['expires_at']-30,'BOOT_PERMIT_OR_TICKET_EXPIRED')
        physical=_run(command('ssh'),timeout=90,runner=runner)
        _save(attempt/'start-command.json',physical)
        # No second start, even when this fails or times out.
        ok(physical,'PHYSICAL_START_FAILED_OR_UNCERTAIN')
        after_f5=f5.capture(runner=runner,clock=clock)
        state_gate(after_f5,'ssh',after=True)
        _save(attempt/'after-f5.json',after_f5)
        after_legacy=_capture_legacy()
        _save(attempt/'after-r112.json',after_legacy)
        live=_run(('virsh','--readonly','-c','qemu:///system','dumpxml',guest('ssh')),runner=runner)
        _save(attempt/'live-xml-command.json',live)
        xml=ok(live,'LIVE_SSH_XML_UNATTESTED')
        claims={}
        for kind,path in markers.items():
            content=ok(_run(('sudo','-n','cat',path),runner=runner),'F11_CLAIM_READ_'+kind)+'\n'
            st=ok(_run(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path),runner=runner),'F11_CLAIM_STAT_'+kind)
            claims[kind]={'content':content,'stat':st}
        _save(attempt/'claims.json',claims)
        start_result={k:physical[k] for k in ('rc','stdout','stderr','timeout','truncated')}
        proof=_old_classifier_ssh(before_new,after_legacy,start_result,xml,ticket,grant,claims)
        _save(attempt/'r112-proof.json',proof)
        receipt={'schema':SCHEMA+'-receipt','plan_sha256':digest(plan),
                 'intent_sha256':digest(intent),
                 'preflight_r112_sha256':digest(before_new),
                 'preflight_f5_sha256':digest(fresh),
                 'f5_after_sha256':digest(after_f5),
                 'r112_proof_sha256':digest(proof),'f11_ticket_sha256':digest(ticket),
                 'role':'ssh','vm_starts':1,'state':'SSH_RUNNING_DENY_ATTESTED',
                 'traffic_authorized':False,'a5':'NO-GO','a6':'ND','p8':'NO-GO'}
        _save(attempt/'receipt.json',receipt)
        return attempt,receipt
    except (Stop,f1.Rejected,f2.Stop,f5.Stop,f12.Stop,OSError,ValueError,KeyError,TypeError) as exc:
        # Durable uncertain incident: every preexisting file retained.
        _save(attempt/'incident.json',{'schema':SCHEMA+'-incident',
             'reason':type(exc).__name__+':'+str(exc)[:160],
             'retry_permitted':False,'auto_cleanup':False,
             'p8':'NO-GO'})
        raise Stop('PHYSICAL_ATTEMPT_NOT_ATTESTED_RECEIPT_'+str(attempt)) from exc

def _replay_ssh(plan_dir,attempt_dir):
    plan,before,legacy_before=_read_plan(plan_dir)
    _private(attempt_dir)
    need(attempt_dir.parent==ROOT and attempt_dir.name.startswith('boot-'),'BOOT_DIR_SCOPE')
    needed={'intent.json','ticket.json','preflight-f5.json','preflight-r112.json',
            'root-dir-command.json','root-lease-command.json',
            'grant.json','start-command.json','after-f5.json','after-r112.json',
            'live-xml-command.json','claims.json','r112-proof.json','receipt.json'}
    need({p.name for p in attempt_dir.iterdir()}==needed,'BOOT_RECEIPT_FILE_SET')
    need(f2.private_read(plan_dir/'boot.once')==b'ATTEMPTED\n','MISSING_ONE_START_MARKER')
    docs={name:_load(attempt_dir/name) for name in needed}
    intent=docs['intent.json']
    need(intent['plan_sha256']==digest(plan) and intent['role']=='ssh' and
         intent['traffic_authorized'] is False and intent['p8']=='NO-GO',
         'INTENT_CHANGED')
    started=docs['start-command.json']
    need(started['argv']==list(command('ssh')),'COMMAND_CHANGED')
    ok(started,'START_NOT_ATTESTED')
    state_gate(docs['preflight-f5.json'],'ssh')
    state_gate(docs['after-f5.json'],'ssh',after=True)
    _audit_legacy(docs['preflight-r112.json'],'ssh')
    live=docs['live-xml-command.json']
    need(live['argv']==['virsh','--readonly','-c','qemu:///system','dumpxml',guest('ssh')],
         'LIVE_XML_COMMAND_CHANGED')
    proof=_old_classifier_ssh(
        docs['preflight-r112.json'],
        docs['after-r112.json'],
        {k:started[k] for k in ('rc','stdout','stderr','timeout','truncated')},
        ok(live,'LIVE_XML_NOT_ATTESTED'),docs['ticket.json'],docs['grant.json'],docs['claims.json'])
    need(proof==docs['r112-proof.json'],'LEGACY_PROOF_MISMATCH')
    rec=docs['receipt.json']
    need(rec=={'schema':SCHEMA+'-receipt','plan_sha256':digest(plan),
               'intent_sha256':digest(intent),
               'preflight_r112_sha256':digest(docs['preflight-r112.json']),
               'preflight_f5_sha256':digest(docs['preflight-f5.json']),
               'f5_after_sha256':digest(docs['after-f5.json']),
               'r112_proof_sha256':digest(proof),'f11_ticket_sha256':digest(docs['ticket.json']),
               'role':'ssh','vm_starts':1,'state':'SSH_RUNNING_DENY_ATTESTED',
               'traffic_authorized':False,'a5':'NO-GO','a6':'ND','p8':'NO-GO'},
         'RECEIPT_TAMPERED')
    return rec

def main(argv=None):
    import argparse
    ap=argparse.ArgumentParser(description='R115-F7: signed one-shot SSH boot + DENY-only stage inspections')
    action=ap.add_mutually_exclusive_group(required=True)
    action.add_argument('--inspect',action='store_true')
    action.add_argument('--plan',action='store_true')
    action.add_argument('--boot',action='store_true')
    action.add_argument('--replay',action='store_true')
    ap.add_argument('--role',choices=ORDER,default='ssh')
    ap.add_argument('--contract',type=Path)
    ap.add_argument('--authorization',type=Path)
    ap.add_argument('--permit',type=Path)
    ap.add_argument('--plan-dir',type=Path)
    ap.add_argument('--boot-dir',type=Path)
    ap.add_argument('--i-authorize-one-physical-ssh-boot-deny-only',action='store_true')
    a=ap.parse_args(argv)
    try:
        need(os.geteuid()!=0,'NO_ROOT_SHELL')
        if a.inspect:
            need(not any((a.contract,a.authorization,a.permit,a.plan_dir,a.boot_dir)) and
                 not a.i_authorize_one_physical_ssh_boot_deny_only,'INSPECT_EXTRA_ARGS')
            report=read_only(role=a.role)
            receipt=_create(ROOT,'inspect-')
            _save(receipt/'report.json',report)
            _save(receipt/'manifest.json',{'schema':SCHEMA+'-inspection-manifest',
                                          'report_sha256':digest(report),'read_only':True})
            print('R115_F7_RECEIPT='+str(receipt))
            print('R115_F7_ROLE='+a.role.upper())
            print('R115_F7_STAGE='+report['status'])
            print('R115_F7_REASON='+report['reason'])
            print('R115_F7_F5_LIFECYCLE='+report['f5']['lifecycle_stage'])
            print('R115_F7_DENY='+report['f5']['nft'])
            print('R115_F7_F11='+report['f5']['f11_hook'])
            print('R115_F7_VM_STARTS=0')
        elif a.plan:
            need(a.role=='ssh' and a.contract and a.authorization and
                 not a.permit and not a.plan_dir and not a.boot_dir and
                 not a.i_authorize_one_physical_ssh_boot_deny_only,
                 'PLAN_SCOPE_AND_SIGNED_INPUT_REQUIRED')
            folder,plan=_plan_ssh(a.contract,a.authorization)
            print('R115_F7_PLAN='+str(folder))
            print('R115_F7_PLAN_SHA256='+digest(plan))
            print('R115_F7_ROLE=SSH')
            print('R115_F7_PLAN_STATUS=SIGNED_SCOPE_BOUND_NOT_BOOT_PERMISSION')
        elif a.boot:
            need(a.role=='ssh' and a.contract and a.authorization and a.permit and
                 a.plan_dir and not a.boot_dir and
                 a.i_authorize_one_physical_ssh_boot_deny_only,
                 'EXPLICIT_SSH_BOOT_CONSENT_AND_SIGNATURES_REQUIRED')
            folder,rec=_boot_ssh(a.plan_dir,a.contract,a.authorization,a.permit)
            print('R115_F7_BOOT_RECEIPT='+str(folder))
            print('R115_F7_BOOT_RECEIPT_SHA256='+digest(rec))
            print('R115_F7_VM_STARTS=ONE_ATTESTED')
        else:
            need(a.role=='ssh' and a.plan_dir and a.boot_dir and
                 not any((a.contract,a.authorization,a.permit)) and
                 not a.i_authorize_one_physical_ssh_boot_deny_only,
                 'REPLAY_ARGUMENT_SCOPE')
            rec=_replay_ssh(a.plan_dir,a.boot_dir)
            print('R115_F7_REPLAY=PASS')
            print('R115_F7_BOOT_RECEIPT_SHA256='+digest(rec))
        print('R115_F7_TRAFFIC=0')
        print('R115_F7_A5=NO-GO')
        print('R115_F7_A6=ND')
        print('R115_F7_P8=NO-GO')
        return 0
    except (Stop,f2.Stop,f5.Stop,f6.Stop,f1.Rejected,OSError,ValueError,KeyError,TypeError) as exc:
        print('R115_F7_STOP='+type(exc).__name__+':'+str(exc)[:190])
        print('R115_F7_ACTION=NO_RETRY_NO_AUTO_RECOVERY')
        print('R115_F7_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
