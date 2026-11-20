#!/usr/bin/env python3
"""R116-F3 root-only, one-shot FTP-T01 pilot window. NEVER run by source install.

Separate explicitly authorized root staging and independently signed 60-second
pilot are prerequisites. The root process freshly validates signed documents,
DENY 5/1, boot provenance, watchdog and one-shot marker; it does NOT issue a
permit, start VMs, update P7, admit A6, or enable ordinary P8.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime,timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

ROOT=Path('/var/lib/ardrec/r116-f3-ftp-pilot-root-v1')
SRC=ROOT/'runtime'
MANIFEST=ROOT/'manifest.json'
EXEC=ROOT/'root-pilot.py'
F1=Path('/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py')
F114=Path('/var/lib/ardrec/r114-f5-ftp-t01-root-v1/root-window.py')
VIRSH=('/usr/bin/virsh','-c','qemu:///system')
SYSENV={'LC_ALL':'C','LANG':'C','PATH':'/usr/sbin:/usr/bin:/bin'}
DOCS=('contract.json','scope-authorization.json','pilot-permit.json')
ONE='pilot-attempted.once'
SCHEMA='ARDREC-R116-F3-ROOT-FTP-PILOT-v1'
MAX_READ=524288

class Stop(ValueError):pass

def need(ok,code):
    if not ok:raise Stop(code)

def canon(o):return (json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
def sha(raw):return hashlib.sha256(raw).hexdigest()

def safe(path, *, limit=MAX_READ):
    need(not path.is_symlink(), 'ROOT_FILE_IS_SYMLINK')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and
             stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=limit,
             'ROOT_FILE_OWNER_MODE_INVALID')
        data=os.read(fd,limit+1)
        need(len(data)==s.st_size,'ROOT_FILE_MUTATED')
        return data
    finally:os.close(fd)

def valid_dir(path,mode=None):
    s=path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and
         not s.st_mode&0o022 and not path.is_symlink(), 'ROOT_DIR_UNTRUSTED')
    if mode is not None:need(stat.S_IMODE(s.st_mode)==mode,'ROOT_DIR_MODE')

def staged():
    need(os.geteuid()==0 and Path(__file__).resolve()==EXEC,
         'ROOT_AND_STAGED_CODE_REQUIRED')
    for p in (Path('/'),Path('/var'),Path('/var/lib'),Path('/var/lib/ardrec'),ROOT,SRC,
              SRC/'ardrec',SRC/'ardrec/coordination',SRC/'ardrec/evidence'):
        valid_dir(p,0o700 if p==ROOT else None)
    need(not (ROOT/ONE).is_symlink(),'ONCE_MARKER_SYMLINK')
    m=json.loads(safe(MANIFEST,limit=16384))
    need(type(m) is dict and set(m)=={'schema','head','base','source_sha256','p8',
           'window_seconds','authority_paths','network_automatic','a6','catalog_sha256'},
         'ROOT_MANIFEST_FIELDS')
    need(m['schema']==SCHEMA+'-root-bundle' and
         re.fullmatch('[0-9a-f]{40}',m['head']) and
         m['base']=='e193b1dcf97f72ba4245fc7dfc6d0d4b9814eecc' and
         m['p8']=='NO-GO' and m['a6']=='ND' and m['window_seconds']==60 and
         m['authority_paths']==list(DOCS) and m['network_automatic'] is False and
         m['catalog_sha256']=='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e',
         'ROOT_MANIFEST_SCOPE')
    pins=m['source_sha256']
    need(type(pins) is dict and 'root-pilot.py' in pins and len(pins)>=30,
         'SOURCE_HASH_SET_INCOMPLETE')
    for name,digest in pins.items():
        need(type(name) is str and re.fullmatch(r'(root-pilot\.py|runtime/ardrec/(?:coordination|evidence)/[a-z0-9_]+\.py)',name) and
             type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest),
             'UNEXPECTED_STAGED_SOURCE')
        path=ROOT/name
        need(path==EXEC or SRC in path.parents,'SOURCE_PATH_ESCAPE')
        need(sha(safe(path))==digest,'STAGED_SOURCE_TAMPERED_'+name[-45:])
    need(set(x.name for x in ROOT.iterdir())<=
         {'manifest.json','root-pilot.py','runtime','authority','catalog.json',ONE,'lock'}|
         {x for x in (p.name for p in ROOT.iterdir()) if re.fullmatch(r'pilot-[0-9a-f]{16}',x)},
         'UNEXPECTED_ROOT_BUNDLE_ENTRIES')
    valid_dir(ROOT/'authority',0o700)
    need(sha(safe(ROOT/'catalog.json'))==m['catalog_sha256'],'ROOT_CATALOG_DRIFT')
    for name in ('__init__.py',):
        # Namespace package directories have NO .py init code.
        need(not (SRC/'ardrec'/name).exists(), 'ROOT_PACKAGE_INITIALIZER_FORBIDDEN')
    return m

def run(cmd, *, input=None, timeout=10):
    need(type(cmd) in (tuple,list) and all(type(x) is str for x in cmd) and
         cmd and cmd[0] in ('/usr/bin/python3','/usr/sbin/nft','/usr/bin/virsh',
                            '/usr/bin/systemctl'), 'HOST_BINARY_NOT_ALLOWED')
    p=subprocess.run(list(cmd),input=input,capture_output=True,check=False,
        stdin=subprocess.DEVNULL if input is None else None,timeout=timeout,
        close_fds=True,env=SYSENV)
    need(p.returncode==0 and type(p.stdout) is bytes and len(p.stdout)<MAX_READ and
         type(p.stderr) is bytes and len(p.stderr)<32768,
         'HOST_COMMAND_FAILED_'+cmd[0].split('/')[-1])
    return p.stdout

def root_guard(flag):
    need(flag in ('--check','--restore-deny'), 'F1_FLAG_INVALID')
    doc=json.loads(run(('/usr/bin/python3',str(F1),flag),timeout=40))
    need(type(doc) is dict,'F1_GUARD_RESULT')
    return doc

def f1_arm(token):
    need(re.fullmatch('[0-9a-f]{16}',token), 'TOKEN_INVALID')
    doc=json.loads(run(('/usr/bin/python3',str(F1),'--arm-deny',token),timeout=25))
    need(doc.get('timer_verified') is True and
         doc.get('duration_seconds')==60 and
         doc.get('opens_ports') is False,'DENY_TIMER_ARM_NOT_VERIFIED')
    return doc

def timer(unit):
    need(type(unit) is str and re.fullmatch('ardrec-r116-f1-deny-[0-9a-f]{16}',unit),
         'TIMER_UNIT_INVALID')
    raw=run(('/usr/bin/systemctl','show',unit+'.timer','--no-pager',
          '-p','LoadState','-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic'))
    return dict(line.split('=',1) for line in raw.decode('ascii').splitlines() if '=' in line)

def read_doc(name):
    need(name in DOCS,'DOCUMENT_NAME_INVALID')
    return safe(ROOT/'authority'/name,limit=128000)

def modules():
    sys.path.insert(0,str(SRC))
    from ardrec.coordination import r116_f3_pilot_session_policy as policy
    from ardrec.coordination import r116_f2_current_pilot_gate as g
    from ardrec.coordination import r115_dev_admission_contract as f1
    from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
    from ardrec.coordination import r115_f15_p7_independent_pilot as f15
    return policy,g,f1,f6,f15

def independent_review(m, *, now=None):
    policy,g,f1,f6,f15=modules()
    now=datetime.now(timezone.utc) if now is None else now
    cr,ar,pr=[read_doc(n) for n in DOCS]
    catalog=safe(ROOT/'catalog.json',limit=128000) if (ROOT/'catalog.json').exists() else None
    need(catalog is not None,'ROOT_CATALOG_NOT_STAGED')
    review=g.signed_pilot(cr,ar,pr,head=m['head'],catalog_raw=catalog,
                          now=now,scope_loader=f6.secure_root_file,
                          pilot_loader=f15._root_read)
    permit=f1.load(pr)
    valid_until=f1._instant(permit['statement']['valid_until'],'PILOT_END')
    bound=policy.signed_grant(review,head=m['head'],catalog_sha=g.CATALOG_SHA,
                              now=now,permit_expiry=valid_until)
    return policy,review,bound,valid_until

def check_physical(policy):
    doc=root_guard('--check')
    policy.five_one(doc)
    return doc

def old_ftp_material(policy):
    # Only read older root-owned *data*, do not invoke its 120s dispatcher.
    valid_dir(F114.parent,0o700)
    raw=safe(F114,limit=200000)
    spec=importlib.util.spec_from_file_location('ardrec_r116_pinned_r114_ftp',F114)
    need(spec is not None and spec.loader is not None,'R114_SOURCE_LOADER_UNAVAILABLE')
    module=importlib.util.module_from_spec(spec)
    # Its own auth_bundle strictly validates all historical root data.
    spec.loader.exec_module(module)
    bundle=module.auth_bundle()
    need(raw==safe(F114,limit=200000),'R114_SOURCE_CHANGED')
    policy.candidate_rules(bundle['r34-ftp-only.nft'])
    return module,bundle

def review_boot_provenance(m):
    """Replay historical F8 records as the *unprivileged owner*, never as root.

    A user-owned replay is NOT a traffic grant; signatures and actual guest
    DENY are independently enforced by root. These receipts are traceability
    only and cannot override the trusted gate.
    """
    path=ROOT/'authority'/'ftp-boot-paths.json'
    doc=json.loads(safe(path,limit=8192))
    need(type(doc) is dict and set(doc)=={'schema','plan','boot'} and
         doc['schema']==SCHEMA+'-f8-boot-reference', 'F8_BOOT_REFERENCE_INVALID')
    root=Path('/home/cicada/ardrec-lab/r115-f8-runner-ftp-deny-v1')
    plan,boot=Path(doc['plan']),Path(doc['boot'])
    need(plan.is_absolute() and boot.is_absolute() and
         plan.parent==root and boot.parent==root and
         re.fullmatch(r'plan-[a-z0-9_-]+',plan.name) and
         re.fullmatch(r'boot-[a-z0-9_-]+',boot.name),
         'F8_BOOT_PATHS_OUT_OF_SCOPE')
    # Source is unprivileged, and the results are never permission alone.
    code=("import json,sys\n"
          "from pathlib import Path\n"
          "sys.path.insert(0,'/home/cicada/Development/GitHub/ardrec/src')\n"
          "sys.path.insert(0,'/home/cicada/Development/GitHub/ardrec/scripts')\n"
          "from ardrec.coordination import r115_f16_physical_pilot_controller as f16\n"
          "proof=f16.boot_chain(Path(sys.argv[1]),Path(sys.argv[2]))\n"
          "print(json.dumps(proof,sort_keys=True,separators=(',',':')))\n")
    cmd=['/usr/sbin/runuser','-u','cicada','--','/usr/bin/python3',
         '-B','-c',code,str(plan),str(boot)]
    p=subprocess.run(cmd,capture_output=True,check=False,stdin=subprocess.DEVNULL,
                     timeout=35,env=SYSENV,close_fds=True)
    need(p.returncode==0 and len(p.stdout)<8192 and len(p.stderr)<8192,
         'UNPRIVILEGED_F8_REPLAY_FAILED')
    result=json.loads(p.stdout)
    need(result.get('ftp_boot_attributed_to_ssh_runner_ftp_replay') is True and
         result.get('traffic_authorized') is False and
         result.get('p8')=='NO-GO' and
         re.fullmatch('[0-9a-f]{64}',result.get('boot_receipt_sha256','')),
         'F8_BOOT_REPLAY_NOT_PROVEN')
    return {'boot_receipt_sha256':result['boot_receipt_sha256'],
            'traceability_only':True,'root_verified_physical_deny_separately':True}

def save(folder,name,raw):
    need(re.fullmatch('[a-z0-9._-]{1,100}',name) and type(raw) is bytes and
         len(raw)<MAX_READ,'RECEIPT_INVALID')
    fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as h:h.write(raw);h.flush();os.fsync(h.fileno())
    df=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(df)
    finally:os.close(df)

def verify_binding_pair(f6,bundle,key):
    tap=f6.ROLES[key][2]
    got=run((*VIRSH,'nwfilter-binding-dumpxml',tap))
    need(f6.xml_equal(got,bundle[key+'-candidate.xml']),
         'CANDIDATE_BINDING_NOT_EXACT_'+key)
    return True

def transition_to_ftp_candidate(guard_module, bundle, policy, check_time):
    # R34 stays DENY until BOTH exact candidate bindings are installed.
    check_time()
    f6,_=guard_module.historical()
    for key in ('runner_ftp','ftp'):
        check_time()
        tap=f6.ROLES[key][2]
        # Only known original DENY can be replaced.
        current=run((*VIRSH,'nwfilter-binding-dumpxml',tap))
        need(f6.xml_equal(current,bundle[key+'-original.xml']),
             'ORIGINAL_DENY_NOT_CURRENT_'+key)
        run((*VIRSH,'nwfilter-binding-delete',tap),timeout=8)
        run((*VIRSH,'nwfilter-binding-create',str(guard_module.PREVIOUS/(key+'-candidate.xml'))),
            timeout=8)
        verify_binding_pair(f6,bundle,key)
    check_time()

def execute_one_guest_probe(folder, check_time, *, budget, case_id):
    """Single guest TCP/21 probe; no login, commands, brute force or retries."""
    check_time()
    guest='ardrec-r33-dev-runner'
    # A fixed, peer- and budget-bounded guest source. No user-supplied code.
    need(type(budget) is dict and all(type(v) is int for v in budget.values()),
         'GUEST_BUDGET_INVALID')
    receive=min(256,budget['read_size'],budget['max_recv_bytes'])
    timeout=min(3,budget['timeout_seconds'])
    need(1<=receive<=256 and 1<=timeout<=3 and
         budget['max_connections']==1 and budget['ordinary_attempts']==1 and
         budget['additional_attempts']==0 and budget['max_recv_calls']>=1 and
         0<budget['max_output_bytes']<=8192 and 0<budget['memory_mib']<=512 and
         type(case_id) is str and re.fullmatch('[A-Za-z0-9_-]{3,80}',case_id),
         'GUEST_BUDGET_OR_CASE_NOT_ALLOWED')
    source=("import socket,json,resource\n"
       "d={'schema':'ARDREC-R116-F3-FTP-T01-PILOT-PROBE-v1','src':'10.203.31.1','dst':'10.203.31.2','port':21,'case_id':"+repr(case_id)+"}\n"
       "resource.setrlimit(resource.RLIMIT_AS,("+repr(budget['memory_mib']*1048576)+","+repr(budget['memory_mib']*1048576)+"))\n"
       "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout("+repr(timeout)+")\n"
       "try:\n"
       " s.bind(('10.203.31.1',0));s.connect(('10.203.31.2',21));d['tcp']='CONNECTED'\n"
       " try:\n"
       "  b=s.recv("+repr(receive)+");d['response_hex']=b.hex();d['response']='RECEIVED' if b else 'EMPTY'\n"
       " except (OSError,TimeoutError) as e:\n"
       "  d['response_hex']='';d['response']='READ_ERROR';d['read_error']=type(e).__name__\n"
       "except (OSError,TimeoutError) as e:\n"
       " d['tcp']='FAILED';d['response_hex']='';d['response']='CONNECT_ERROR';d['error']=type(e).__name__\n"
       "finally:s.close()\nprint(json.dumps(d,sort_keys=True,separators=(',',':')))\n")
    qga={'execute':'guest-exec','arguments':{'path':'/usr/bin/python3',
        'arg':['-c',source],'capture-output':True}}
    result=json.loads(run((*VIRSH,'qemu-agent-command',guest,canon(qga).decode().strip()),timeout=7))
    pid=result.get('return',{}).get('pid')
    need(type(pid) is int and pid>0,'GUEST_PROBE_NOT_STARTED')
    for i in range(1,12):
        check_time()
        time.sleep(.3)
        query={'execute':'guest-exec-status','arguments':{'pid':pid}}
        raw=run((*VIRSH,'qemu-agent-command',guest,canon(query).decode().strip()),timeout=5)
        info=json.loads(raw).get('return',{})
        if info.get('exited') is True:
            need(info.get('exitcode')==0,'GUEST_PROBE_EXIT_FAILED')
            out=base64.b64decode(info.get('out-data',''),validate=True)
            err=base64.b64decode(info.get('err-data',''),validate=True)
            need(not err and 0<len(out)<=budget['max_output_bytes'],
                 'GUEST_PROBE_OUTPUT_INVALID')
            doc=json.loads(out)
            need(type(doc) is dict and doc.get('schema')=='ARDREC-R116-F3-FTP-T01-PILOT-PROBE-v1' and
                 doc.get('src')=='10.203.31.1' and doc.get('dst')=='10.203.31.2' and
                 doc.get('port')==21 and doc.get('case_id')==case_id and doc.get('tcp') in ('CONNECTED','FAILED') and
                 doc.get('response') in ('RECEIVED','EMPTY','READ_ERROR','CONNECT_ERROR'),
                 'GUEST_RESULT_IDENTITY_INVALID')
            b=bytes.fromhex(doc['response_hex'])
            need(len(b)<=receive and b.count(b'\r\n')<=budget['max_lines'] and
                 (doc['response']=='RECEIVED')==(len(b)>0) and
                 (doc['tcp']=='FAILED')==(doc['response']=='CONNECT_ERROR'),
                 'GUEST_RESULT_CONTRADICTORY')
            save(folder,'guest-result.json',canon(doc))
            save(folder,'guest-qga.json',raw)
            return doc
    raise Stop('ONE_PROBE_TIMEOUT_NO_RETRY')

def root_guard_library():
    need(F1.is_file(),'F1_ROOT_GUARD_NOT_STAGED')
    sp=importlib.util.spec_from_file_location('ardrec_r116_root_f1',F1)
    need(sp is not None and sp.loader is not None,'F1_ROOT_SOURCE_MISSING')
    module=importlib.util.module_from_spec(sp);sp.loader.exec_module(module)
    module.protect_root()  # verifies its own manifest and source SHA
    return module

def lock_file():
    fd=os.open(ROOT/'lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    return fd

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    selection=parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--capabilities',action='store_true')
    selection.add_argument('--inspect-root',action='store_true')
    selection.add_argument('--execute-pilot',action='store_true')
    args=parser.parse_args(argv)
    os.umask(0o077)
    if args.capabilities:
        print(canon({'schema':SCHEMA+'-capabilities','physical_window_available_only_after_root_stage':True,
            'one_guest_connection':True,'window_max_seconds':60,'a6':'ND',
            'p8':'NO-GO','source_install_opens_traffic':False}).decode().strip())
        return 0
    folder=None;armed=False;opened=False;result=None;error=None;final_deny=False
    try:
        m=staged()
        fd=lock_file()
        try:
            policy,review,bound,expiry=independent_review(m)
            guard_check=check_physical(policy)
            g114,bundle=old_ftp_material(policy)
            boot=review_boot_provenance(m)
            f1=root_guard_library()
            if args.inspect_root:
                print(canon({'schema':SCHEMA+'-inspection','scope_signed':True,
                    'ftp_denies':'FIVE_ONE_MATCH','r114_policy_authenticated':True,
                    'a5':'NOT_ATTEMPTED','p8':'NO-GO','a6':'ND',
                    'pilot_authorized_to_connect_by_inspection':False,
                    'boot_receipt_sha256':boot['boot_receipt_sha256']}).decode().strip())
                return 0
            need(not (ROOT/ONE).exists() and not (f1.ROOT/f1.MARKER).exists(),
                 'PILOT_ALREADY_ATTEMPTED')
            # ONE-SHOT durability precedes all mutations, even a failed timer.
            token=secrets.token_hex(8)
            save(ROOT,ONE,canon({'session':token,'intent':'ONE_GUEST_FTP_21',
                                 'signed_pilot_sha256':bound['pilot_sha256'],
                                 'p8':'NO-GO'}))
            folder=ROOT/('pilot-'+token)
            folder.mkdir(mode=0o700)
            save(folder,'signed-context.json',canon(bound))
            save(folder,'boot-context.json',canon(boot))
            timer_doc=f1_arm(token)
            armed=True
            unit=timer_doc['unit']
            def gate():
                clock=datetime.now(timezone.utc)
                # Independent signatures and fresh revocation checked repeatedly.
                _,newreview,_,end=independent_review(m,now=clock)
                need(newreview['pilot_sha256']==bound['pilot_sha256'],
                     'PILOT_SIGNATURE_CHANGED_AFTER_ARM')
                remaining=policy.timer_remaining(timer(unit),
                            monotonic_seconds=time.monotonic(),expected_unit=unit)
                policy.permit_margin(now=clock,permit_expiry=end,timer_seconds=remaining)
            gate()
            run(('/usr/sbin/nft','--check','--file','-'),input=bundle['r34-ftp-only.nft'],timeout=8)
            # `old_ftp_material` authenticates only the old DATA, never its dispatcher.
            prior,bundle6=f1.historical()
            transition_to_ftp_candidate(f1,bundle6,policy,gate)
            gate()
            run(('/usr/sbin/nft','-f','-'),input=bundle['r34-ftp-only.nft'],timeout=8)
            opened=True
            save(folder,'ftp-only-window-open.once',b'ONE_FTP_TCP21_PILOT_WINDOW_NFT\n')
            g114.audit_live_nft(run(('/usr/sbin/nft','-j','-a','list','table',
                                    'bridge','ardrec_r34_guard')))
            gate()
            from ardrec.coordination import r115_dev_admission_contract as fbase
            current_contract=fbase.load(read_doc('contract.json'))
            result=execute_one_guest_probe(folder,gate,budget=bound['budget'],
                                           case_id=current_contract['case_id'])
        finally:
            os.close(fd)
    except Exception as exc:
        error=type(exc).__name__+':'+str(exc)[:150]
    finally:
        # Independent timer remains active; do NOT cancel it even after success.
        if folder is not None or armed or opened:
            try:
                restored=root_guard('--restore-deny')
                need(restored.get('status')=='DENY_RESTORED','DENY_RESTORE_NOT_ATTESTED')
                check=root_guard('--check')
                five,_g,_f1,_f6,_f15=modules()
                five.five_one(check)
                final_deny=True
            except Exception as exc:
                error='CRITICAL_RESTORATION_NOT_ATTESTED:'+type(exc).__name__+':'+str(exc)[:130]
        if folder is not None:
            try:
                receipt={'schema':SCHEMA+'-receipt','status':(
                    'FTP_CANDIDATE_RECORDED' if final_deny and result is not None and error is None else
                    'NO_GO_ATTEMPT_CONSUMED'), 'opened':opened,'backup_timer_armed':armed,
                    'denies_restored_and_verified':final_deny,
                    'result_sha256':sha(canon(result)) if result else None,
                    'error':error,'a6':'ND','p8':'NO-GO',
                    'p7_calibrated':False,'a9_published':False}
                save(folder,'receipt.json',canon(receipt))
                print('R116_F3_ROOT_RECEIPT='+str(folder),flush=True)
                print('R116_F3_ROOT_RECEIPT_SHA256='+sha(canon(receipt)),flush=True)
            except Exception as exc:
                error='CRITICAL_RECEIPT_WRITE:'+type(exc).__name__
    print('R116_F3_RESULT='+('CANDIDATE_ONLY_NO_A6' if result is not None and final_deny and
                           error is None else 'NO-GO'),flush=True)
    print('R116_F3_A6=ND',flush=True)
    print('R116_F3_P8=NO-GO',flush=True)
    if error:print('R116_F3_STOP='+error,flush=True)
    return 0 if result is not None and final_deny and error is None else 23

if __name__=='__main__':raise SystemExit(main())
