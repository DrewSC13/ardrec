#!/usr/bin/env python3
"""R117-F1: explicit root F12 migration; inspect/apply, fail closed, no traffic.

IMPORTANT: source installation/CI must NOT execute this with --apply.
Requires verified R116 merge ancestry, a signed R117 commit, and an offline
host in exact DENY 0/6 before replacing the F8-staged F1/F3 source closures.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ROOT = Path('/var/lib/ardrec')
F1 = ROOT / 'r116-f1-five-one-deny-v1'
F3 = ROOT / 'r116-f3-ftp-pilot-root-v1'
R113 = ROOT / 'r113-six-deny-guard-v1'
R114 = ROOT / 'r114-f5-ftp-t01-root-v1'
EVIDENCE = ROOT / 'r117-f1-root-f12-migration-v1'
BRANCH = 'feat/p14-r117-piloto-real-a5-a10'
BASE = 'fdb6efa0c297ce18b28cddb9494514f51d88bdb4'
OLD = '217154fb92400542f788a4a8cfb6ad81e9845537'
CATALOG = 'lab/operational-catalog-v1/catalog.json'
F1_CODE = 'scripts/ardrec_p14_r116_f1_root_deny_guard.py'
F1_LOCK = 'lab/operational-controller/r116-f1-root-bundle.json'
F3_CODE = 'scripts/ardrec_p14_r116_f3_root_pilot.py'
F3_LOCK = 'lab/operational-controller/r116-f3-root-source-lock-v1.json'
PIN_NEW_F1 = 'c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
PIN_NEW_F3 = '37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c'
PIN_OLD_F1 = '20acd520ac7ae93f8ba168c1f7cd36399193278ab0578f07a51cd6571964d254'
PIN_OLD_F3 = '24aac2a7b2b54743fb1114e788da1bbbeeb9b2ae5447b08dca6eacb1d7b67664'
PIN_R113 = '3a9c2d0e70d7b6b808ee2eaf7382b11715c2e2d8e0f777ff627a1ed084a8bb05'
PIN_R114 = '904083c970411a16d388e6f4dd73afc843267f58c4395e43c3469b7cad6db67b'
PIN_R114_RECEIPT = 'e80e6f33d7a82ac6e3c76bb70a262d0e65d2b4be0a7feb3558d0d2cd0711a742'
PIN_R114_MARKER = 'd403312ae9af24b99c2f0babb99491f30027a82e0a6f9c661699f9cebf4e6b0e'
PIN_CATALOG = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
SCHEMA = 'ARDREC-R117-F1-F12-ROOT-REDEPLOY-v1'

class Halt(RuntimeError):
    pass

def need(ok, code):
    if not ok:
        raise Halt(code)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def canon(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')

def emit(key, value):
    print('R117_F1_'+key+'='+str(value), flush=True)

def call(argv, *, timeout=30):
    need(type(argv) in (tuple, list) and argv and all(type(a) is str for a in argv), 'COMMAND_INVALID')
    result = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                            check=False, close_fds=True,
                            env={'PATH':'/usr/sbin:/usr/bin:/bin', 'LC_ALL':'C','LANG':'C',
                                 'PYTHONDONTWRITEBYTECODE':'1'})
    need(result.returncode == 0, 'COMMAND_FAILED_'+Path(argv[0]).name)
    need(len(result.stdout)<1048576 and len(result.stderr)<65536, 'COMMAND_OUTPUT_UNBOUNDED')
    return result.stdout

def git(*args):
    return call(['/usr/bin/git','-c','safe.directory='+str(REPO),'-C',str(REPO),*args], timeout=25)

def signed(path, rev='HEAD'):
    need(type(path) is str and re.fullmatch(r'(?:scripts|src|lab)/[A-Za-z0-9._/+-]+',path), 'UNSAFE_SIGNED_PATH')
    raw=git('show',rev+':'+path)
    need(0<len(raw)<524288, 'SOURCE_SIZE_INVALID')
    if rev=='HEAD':
        p=REPO/path
        need(p.is_file() and not p.is_symlink() and p.read_bytes()==raw,'SOURCE_WORKTREE_DRIFT_'+path)
    return raw

def directory(p, mode=None):
    s=p.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and not p.is_symlink(), 'ROOT_DIRECTORY_UNSAFE_'+str(p))
    if mode is not None: need(stat.S_IMODE(s.st_mode)==mode, 'ROOT_DIRECTORY_MODE_'+str(p))

def payload(p, limit=524288):
    fd=os.open(p, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and
             stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=limit, 'ROOT_FILE_UNSAFE_'+str(p))
        raw=os.read(fd,limit+1)
        need(len(raw)==s.st_size, 'ROOT_FILE_READ_CHANGED_'+str(p))
        return raw
    finally: os.close(fd)

def rootwrite(p, raw):
    need(type(raw) is bytes and 0<len(raw)<524288, 'WRITE_BYTES_INVALID')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def sync(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)

def preflight():
    need(os.geteuid()==0,'ROOT_REQUIRED')
    for p in (Path('/'),Path('/var'),Path('/var/lib'),ROOT): directory(p)
    need(REPO.is_dir() and not REPO.is_symlink(), 'REPOSITORY_INVALID')
    need(git('branch','--show-current').strip()==BRANCH.encode(), 'BRANCH_MISMATCH')
    need(git('status','--porcelain=v1','--untracked-files=all')==b'', 'DIRTY_REPOSITORY')
    need(git('log','-1','--format=%G?').strip()==b'G', 'GIT_SIGNATURE_NOT_G')
    need(git('merge-base','--is-ancestor',BASE,'HEAD')==b'', 'BASE_MERGE_MISSING')
    current=git('rev-parse','HEAD').decode('ascii').strip()
    need(re.fullmatch('[a-f0-9]{40}',current), 'CURRENT_HEAD_INVALID')
    own=Path(__file__)
    need(own.is_file() and not own.is_symlink() and
         own.resolve()==REPO/'scripts/ardrec_p14_r117_f1_redeploy_root.py' and
         signed('scripts/ardrec_p14_r117_f1_redeploy_root.py')==own.read_bytes(),
         'UPGRADE_SCRIPT_NOT_SIGNED')
    f1=signed(F1_CODE); f3=signed(F3_CODE)
    need(digest(f1)==PIN_NEW_F1 and digest(f3)==PIN_NEW_F3, 'F12_ROOT_SOURCE_DRIFT')
    l1=json.loads(signed(F1_LOCK));l3=json.loads(signed(F3_LOCK));cat=signed(CATALOG)
    need(l1.get('guard_sha256')==PIN_NEW_F1 and l1.get('p8')=='NO-GO' and
         l1.get('opens_ports') is False and l1.get('window_seconds')==60, 'F1_LOCK_BAD')
    need(l3.get('files',{}).get('root-pilot.py')==PIN_NEW_F3 and
         len(l3.get('files',{}))==33 and l3.get('p8')=='NO-GO' and
         l3.get('root_source_only') is True and l3.get('window_seconds')==60 and
         l3.get('catalog_sha256')==PIN_CATALOG and digest(cat)==PIN_CATALOG,
         'F3_LOCK_BAD')
    sources={}
    for name,sha in l3['files'].items():
        need(type(name) is str and re.fullmatch(r'(root-pilot\.py|runtime/ardrec/(?:coordination|evidence)/[a-z0-9_]+\.py)',name), 'PIN_ENTRY_PATH_INVALID')
        need(type(sha) is str and re.fullmatch('[a-f0-9]{64}',sha),'PIN_ENTRY_HASH_INVALID')
        src=F3_CODE if name=='root-pilot.py' else 'src/'+name.removeprefix('runtime/')
        raw=signed(src)
        need(digest(raw)==sha,'PIN_ENTRY_HASH_MISMATCH_'+name)
        sources[name]=raw
    # Source boundary must still prohibit general P8 and automatic traffic.
    need(signed('lab/closure/r116-source-merge-gate-v1.json').find(b'"p8": "NO-GO"')>=0,
         'MERGE_GATE_UNEXPECTED')
    emit('SOURCE','PASS_SIGNED_R117_HEAD_R116_F12_PINNED')
    emit('SOURCE_HEAD',current)
    emit('NEW_F3_SOURCES',len(sources))
    return current,f1,l1,f3,l3,sources,cat

def check_old():
    directory(F1,0o700);directory(F3,0o700)
    need({p.name for p in F1.iterdir()}=={'root-guard.py','manifest.json'},'F1_OLD_SCOPE_CHANGED')
    need(digest(payload(F1/'root-guard.py'))==PIN_OLD_F1 and
         payload(F1/'root-guard.py')==signed(F1_CODE,OLD) and
         payload(F1/'manifest.json')==signed(F1_LOCK,OLD),'F1_OLD_VERSION_MISMATCH')
    need({p.name for p in F3.iterdir()}=={'root-pilot.py','manifest.json','runtime','authority','catalog.json','lock'},'F3_OLD_SCOPE_CHANGED')
    need(digest(payload(F3/'root-pilot.py'))==PIN_OLD_F3 and
         payload(F3/'root-pilot.py')==signed(F3_CODE,OLD),'F3_OLD_CODE_MISMATCH')
    m=json.loads(payload(F3/'manifest.json',16384));l=json.loads(signed(F3_LOCK,OLD))
    need(m.get('head')==OLD and m.get('source_sha256')==l['files'] and
         len(l['files'])==31 and m.get('p8')=='NO-GO','F3_OLD_LOCK_MISMATCH')
    directory(F3/'authority',0o700)
    need(not any((F3/'authority').iterdir()),'EXTERNAL_AUTHORITY_PRESENT_STOP')
    for d in ('runtime','runtime/ardrec','runtime/ardrec/coordination','runtime/ardrec/evidence'):
        directory(F3/d,0o700)
    need(payload(F3/'lock')==b'R116_F3_ROOT_LOCK_V1\n' and
         digest(payload(F3/'catalog.json'))==PIN_CATALOG,'F3_OLD_CONTROL_CHANGED')
    names=set()
    for name,sha in l['files'].items():
        need(digest(payload(F3/name))==sha,'F3_OLD_FILE_CHANGED_'+name)
        names.add(name)
    actual={str(p.relative_to(F3)) for p in F3.rglob('*') if p.is_file()}
    need(actual==names|{'manifest.json','catalog.json','lock'},'F3_OLD_UNKNOWN_FILES')
    emit('OLD_ROOT','PASS_SIGNED_F8_F1_F3_INTACT_31_SOURCES')

def historical():
    for d in (R113,R114):directory(d,0o700)
    need(digest(payload(R113/'root-recover.py'))==PIN_R113,'R113_SOURCE_CHANGED')
    need(digest(payload(R114/'root-window.py'))==PIN_R114,'R114_SOURCE_CHANGED')
    # Preserve prior physical evidence and enforce irreversible one-shot semantics.
    marker=payload(R114/'window-attempted.once',2048)
    receipt=payload(R114/'window-46ebd6a6'/'receipt.json',300000)
    need(digest(marker)==PIN_R114_MARKER and digest(receipt)==PIN_R114_RECEIPT,
         'R114_HISTORICAL_RECEIPT_DRIFT')
    doc=json.loads(receipt)
    need(doc.get('status')=='CLOSED_DENY_FTP_220_A5_ATTEMPT' and
         doc.get('a6_admitted')==0 and doc.get('p8')=='NO-GO','R114_HISTORY_SEMANTICS')
    # Replays use previously SHA-pinned root sources and do not open network.
    a=call(['/usr/bin/python3','-I','-B',str(R113/'root-recover.py'),'--check-root-bundle'],timeout=35)
    b=call(['/usr/bin/python3','-I','-B',str(R114/'root-window.py'),'--check'],timeout=35)
    c=call(['/usr/bin/python3','-I','-B',str(R114/'root-window.py'),'--replay',str(R114/'window-46ebd6a6')],timeout=45)
    need(json.loads(a).get('result')=='ROOT_BUNDLE_VERIFIED' and
         b'R114_F5_ROOT_BUNDLE=VERIFIED' in b and
         b'R114_F5_REPLAY=PASS_ROOT_RECEIPT_BYTE_INTEGRITY' in c and
         b'R114_F5_REPLAY_A6=ND' in c,'R113_R114_DEEP_REPLAY_FAILED')
    emit('R114_HISTORY','PASS_CONSUMED_REPLAY_63_FILES_A6_ND')

def offline():
    for role in ('ssh','runner','ftp','smb'):
        status=call(['/usr/bin/virsh','-c','qemu:///system','domstate','ardrec-r33-dev-'+role]).decode('utf8').strip().lower()
        need(status in ('shut off','apagado'),'VM_NOT_OFF_'+role)
    for p in (F1/'arm-consumed.once',F3/'pilot-attempted.once'):
        need(not p.exists() and not p.is_symlink(),'F1_F3_ATTEMPT_ALREADY_CONSUMED')
    units=call(['/usr/bin/systemctl','list-units','--all','--no-legend','--plain',
                'ardrec-r116-f1-deny-*.timer','ardrec-r116-f1-deny-*.service',
                'ardrec-r117-*.timer','ardrec-r117-*.service'],timeout=15)
    for line in units.decode('utf8','replace').splitlines():
        parts=line.strip().split()
        if len(parts)>=4 and ('active' in parts[2:4] or 'activating' in parts[2:4]):
            raise Halt('EXISTING_ACTIVE_WATCHDOG')
    raw=call(['/usr/bin/python3','-I','-B',str(F1/'root-guard.py'),'--check'],timeout=30)
    doc=json.loads(raw)
    need(doc.get('deny')=='MATCH' and doc.get('host_writes')==0 and
         doc.get('p8')=='NO-GO' and doc.get('policy',{}).get('active_count')==0 and
         doc.get('policy',{}).get('absent_count')==6,'HOST_DENY_NOT_MATCH_0_6')
    emit('HOST_DENY','PASS_R34_0_ACTIVE_6_ABSENT_OFFLINE')
    emit('ACTIVE_TIMERS','NONE')

def new_tree(dirname, payloads, directories=()):
    need(not dirname.exists() and not dirname.is_symlink(), 'NEW_TREE_DESTINATION_EXISTS')
    tmp=Path(tempfile.mkdtemp(prefix='.r117-f1-new-',dir=ROOT))
    try:
        os.chmod(tmp,0o700)
        for path in directories:
            (tmp/path).mkdir(mode=0o700)
            os.chmod(tmp/path,0o700)
        for name,raw in payloads.items():rootwrite(tmp/name,raw)
        sync(tmp)
        need(not dirname.exists() and not dirname.is_symlink(), 'NEW_TREE_DESTINATION_APPEARED')
        os.rename(tmp,dirname)
        sync(ROOT)
    finally:
        # Never silently delete staging evidence if rename fails.
        if tmp.exists():
            raise Halt('PARTIAL_NEW_STAGING_PRESERVED_'+str(tmp))

def restore(old1,old3,dossier,moved):
    issues=[]
    for current,old,name in ((F3,old3,'f3'),(F1,old1,'f1')):
        if name not in moved:continue
        try:
            if current.exists():os.rename(current,dossier/('partial-new-'+name))
            if old.exists() and not current.exists():os.rename(old,current)
        except OSError as ex:issues.append(name+':'+str(ex))
    try:sync(ROOT);sync(dossier)
    except OSError as ex:issues.append('fsync:'+str(ex))
    emit('ROLLBACK','PASS_PRIOR_F8_RESTORED' if not issues else 'FAILED_MANUAL_REVIEW')
    emit('ROLLBACK_ISSUES',','.join(issues) if issues else 'NONE')

def apply(doc):
    head,f1,l1,f3,l3,sources,cat=doc
    # All irreversible writes are below this point after full read-only preflight.
    if not EVIDENCE.exists():os.mkdir(EVIDENCE,0o700)
    directory(EVIDENCE,0o700)
    fd=os.open(EVIDENCE/'migration.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Enforce a second preflight after acquiring the exclusive lock.
        check_old();offline()
        dossier=Path(tempfile.mkdtemp(prefix='capture-',dir=EVIDENCE))
        os.chmod(dossier,0o700)
        old1=dossier/'previous-f8-f1';old3=dossier/'previous-f8-f3'
        rootwrite(dossier/'preflight.json',canon({'schema':SCHEMA,'new_head':head,
            'previous_source':OLD,'new_f1_sha256':PIN_NEW_F1,'new_f3_sha256':PIN_NEW_F3,
            'old_f1_sha256':PIN_OLD_F1,'old_f3_sha256':PIN_OLD_F3,
            'r114_receipt_sha256':PIN_R114_RECEIPT,'authority':'NOT_PROVISIONED','p8':'NO-GO'}))
        moved=[]
        try:
            os.rename(F1,old1);moved.append('f1')
            os.rename(F3,old3);moved.append('f3')
            sync(ROOT);sync(dossier)
            new_tree(F1,{'root-guard.py':f1,'manifest.json':signed(F1_LOCK)})
            root_manifest={'schema':'ARDREC-R116-F3-ROOT-FTP-PILOT-v1-root-bundle','head':head,
                'base':l3['base'],'source_sha256':l3['files'], 'catalog_sha256':PIN_CATALOG,
                'p8':'NO-GO','window_seconds':60,'authority_paths':['contract.json',
                'scope-authorization.json','pilot-permit.json'],'network_automatic':False,'a6':'ND'}
            payloads={**sources,'catalog.json':cat,'lock':b'R116_F3_ROOT_LOCK_V1\n',
                      'manifest.json':canon(root_manifest)}
            dirs=('runtime','runtime/ardrec','runtime/ardrec/coordination',
                  'runtime/ardrec/evidence','authority')
            new_tree(F3,payloads,dirs)
            need(payload(F1/'root-guard.py')==f1 and
                 payload(F1/'manifest.json')==signed(F1_LOCK), 'NEW_F1_BYTES_MISMATCH')
            need(json.loads(payload(F3/'manifest.json',16384))==root_manifest,
                 'NEW_F3_MANIFEST_MISMATCH')
            for name,sha in l3['files'].items():
                need(digest(payload(F3/name))==sha,'NEW_F3_SOURCE_MISMATCH_'+name)
            directory(F3/'authority',0o700)
            need(not any((F3/'authority').iterdir()), 'AUTHORITY_UNEXPECTEDLY_PRESENT')
            # Re-attest physical deny using the newly deployed signed F1.
            raw=call(['/usr/bin/python3','-I','-B',str(F1/'root-guard.py'),'--check'],timeout=35)
            actual=json.loads(raw)
            need(actual.get('deny')=='MATCH' and actual.get('p8')=='NO-GO' and
                 actual.get('host_writes')==0 and
                 actual.get('policy',{}).get('active_count')==0 and
                 actual.get('policy',{}).get('absent_count')==6,
                 'POST_MIGRATION_DENY_NOT_ATTESTED')
            rootwrite(dossier/'result.json',canon({'schema':SCHEMA,'result':'PASS',
                'source_head':head,'f3_sources':len(sources),'old_preserved':True,
                'nft_changes':0,'guest_starts':0,'network_connections':0,'p8':'NO-GO'}))
            sync(dossier);sync(ROOT)
            emit('ARCHIVE',str(dossier))
            emit('NEW_F1_INTEGRITY','PASS_F12_SIGNED_SOURCE_BYTES')
            emit('NEW_F3_INTEGRITY','PASS_33_SIGNED_SOURCE_BYTES')
            emit('HOST_DENY','PASS_R34_MATCH_0_ACTIVE_6_ABSENT')
            emit('ROOT_MIGRATION','PASS_F8_HISTORY_ARCHIVED_F12_DEPLOYED')
        except Exception as exc:
            restore(old1,old3,dossier,moved)
            emit('ARCHIVE',str(dossier))
            raise Halt('MIGRATION_ABORTED_'+str(exc)[:175]) from exc
    finally:os.close(fd)

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--inspect',action='store_true')
    ap.add_argument('--apply',action='store_true')
    args=ap.parse_args(argv)
    need(args.inspect != args.apply,'EXPLICIT_INSPECT_OR_APPLY_REQUIRED')
    os.umask(0o077)
    doc=preflight()
    check_old();historical();offline()
    emit('AUTHORITY','NOT_PROVISIONED')
    emit('P7','DRAFT_NOT_CALIBRATED')
    emit('A6','ND')
    emit('P8','NO-GO')
    if args.inspect:
        emit('RESULT','PASS_READONLY_REVIEW_READY_FOR_SEPARATE_APPLY')
        emit('ROOT_WRITES',0)
        return 0
    apply(doc)
    emit('WATCHDOG_ARM','NOT_EXECUTED')
    emit('NETWORK_CONNECTIONS',0)
    emit('VM_STARTS',0)
    emit('RESULT','PASS_F12_ROOT_REDEPLOY_NO_GO')
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (Halt,ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as exc:
        emit('STOP',type(exc).__name__+':'+str(exc)[:220].replace('\n','_'))
        emit('P8','NO-GO')
        raise SystemExit(23)
