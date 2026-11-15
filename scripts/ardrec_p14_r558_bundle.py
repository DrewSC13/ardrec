#!/usr/bin/env python3
"""ARDREC R55.8: versioned, deny-only root recovery v2.

--verify-offline: current host private provenance only, no root or mutations.
--prepare-private: writes private bundle without privileges or system changes.
--install-root-bundle: separate user authorization, root-owned install/readback
    ONLY after merge. Never arms systemd or changes nft/libvirt/guests.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r558_recovery_contract as g
from ardrec.coordination import r553_transition_guard as r553

PRIVATE_PARENT=Path('/home/cicada/ardrec-lab/r58-root-recovery')
HELPER=ROOT/'scripts'/g.SOURCE_HELPER_NAME
ENV={**os.environ,'LC_ALL':'C','LANG':'C','PAGER':'cat','GIT_PAGER':'cat'}


def need(value, code):
    g.need(value, code)


def command(argv,*,timeout=60,input_bytes=None,check=True):
    p=subprocess.run(argv,cwd=ROOT,env=ENV,
            input=input_bytes,stdin=subprocess.DEVNULL if input_bytes is None else None,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,
            close_fds=True,check=False)
    need(len(p.stdout)<=512000 and len(p.stderr)<=16384, 'host_output_too_large')
    if check:
        need(p.returncode==0,'host_command_failed_'+str(p.returncode)+'_'+Path(argv[0]).name)
    return p


def private_dir(path):
    need(path.is_absolute(),'private_path_relative')
    for item in (path,*path.parents):
        need(not item.is_symlink(),'private_symlink')
    st=path.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and
         stat.S_IMODE(st.st_mode)==0o700,'private_directory_invalid')


def file_once(path,raw):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as fh:
        fh.write(raw);fh.flush();os.fsync(fh.fileno())


def verify_history():
    source=r553.verify_private_receipt(g.SOURCE_PLAN)
    r553.verify_plan(source)
    private_dir(g.R557_RECEIPT)
    result_path=g.R557_RECEIPT/'result.json'
    raw=result_path.read_bytes()
    need(g.sha(raw)==g.R557_RESULT_SHA256,'r557_result_digest_invalid')
    g.attest_r557(json.loads(raw))
    sums=(g.R557_RECEIPT/'SHA256SUMS').read_text('ascii').splitlines()
    checks={}
    for row in sums:
        need(len(row)>=67 and row[64:66]=='  ','r557_sums_format_invalid')
        name=row[66:]
        need(name in ('result.json','commands.json') and name not in checks,
             'r557_sums_names_invalid')
        checks[name]=row[:64]
    need(set(checks)=={'result.json','commands.json'} and
         all(g.sha((g.R557_RECEIPT/name).read_bytes())==digest
             for name,digest in checks.items()),'r557_sums_mismatch')
    helper=HELPER.read_bytes()
    need(not HELPER.is_symlink() and g.sha(helper)==g.HELPER_SHA,'new_helper_changed')
    return g.prepare(source,helper)


def prepare_private(payload):
    if not PRIVATE_PARENT.exists():
        PRIVATE_PARENT.mkdir(mode=0o700)
    private_dir(PRIVATE_PARENT)
    folder=PRIVATE_PARENT/('r558-prepared-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+str(os.getpid()))
    need(not folder.exists(),'duplicate_receipt')
    folder.mkdir(mode=0o700)
    files=dict(payload)
    files['contract.json']=g.canon(g.obligations())
    lines=''.join(g.sha(files[name])+'  '+name+'\n' for name in sorted(files))
    files['SHA256SUMS']=lines.encode('ascii')
    need(set(files)==g.PRIVATE_FILES,'private_receipt_set_invalid')
    for name,raw in sorted(files.items()):
        file_once(folder/name,raw)
    print('R558_PRIVATE_PREPARED='+str(folder),flush=True)
    print('R558_NEW_HELPER_SHA256='+g.HELPER_SHA)
    print('R558_ROOT_INSTALL=NOT_PERFORMED')
    print('R558_TIMER=NOT_ARMED')
    print('R558_TRAFFIC=0')
    print('R558_P8=NO-GO')
    return folder


def verify_prepared(folder,payload):
    need(folder.parent==PRIVATE_PARENT and g.RECEIPT_PATTERN.fullmatch(folder.name) is not None,
         'source_receipt_path_invalid')
    private_dir(PRIVATE_PARENT)
    private_dir(folder)
    need({p.name for p in folder.iterdir()}==g.PRIVATE_FILES,'receipt_file_inventory_invalid')
    data={}
    for name in g.PRIVATE_FILES:
        p=folder/name
        st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
             st.st_size<=262144,'receipt_file_unsafe_'+name)
        data[name]=p.read_bytes()
    g.check_bundle({name:data[name] for name in g.FILES},payload['root-recover.py'])
    need({name:data[name] for name in g.FILES}==payload,'source_payload_drift')
    need(json.loads(data['contract.json'])==g.obligations(),'contract_receipt_drift')
    rows=data['SHA256SUMS'].decode('ascii').splitlines()
    need(len(rows)==len(g.PRIVATE_FILES)-1,'receipt_checksum_count_invalid')
    expected={g.sha(data[name])+'  '+name for name in g.PRIVATE_FILES-{'SHA256SUMS'}}
    need(set(rows)==expected and len(rows)==len(set(rows)),'receipt_checksum_mismatch')
    return data


def git(*args):
    return command(['git',*args]).stdout.decode('utf-8').strip()


def git_gate():
    need(Path.cwd().resolve()==ROOT,'repository_directory_invalid')
    need(git('rev-parse','--show-toplevel')==str(ROOT),'git_root_invalid')
    need(git('branch','--show-current')=='main','main_required')
    need(git('status','--porcelain','--untracked-files=all')=='','worktree_dirty')
    need(command(['git','merge-base','--is-ancestor',g.BASE,'HEAD'],check=False).returncode==0,
         'r556_base_not_ancestor')
    head=git('rev-parse','HEAD')
    require_remote=command(['git','ls-remote','--heads','origin','main']).stdout.decode().split()[0]
    need(require_remote==head,'main_remote_not_exact')
    for path in ('scripts/ardrec_p14_r558_bundle.py',
                 'scripts/ardrec_p14_r558_root_recover.py',
                 'src/ardrec/coordination/r558_recovery_contract.py'):
        need(git('ls-files','--error-unmatch',path)==path,'r558_not_merged_'+path)
    need(command(['git','show','HEAD:scripts/ardrec_p14_r558_root_recover.py']).stdout==HELPER.read_bytes(),
         'helper_not_in_head')


def live_deny():
    source=r553.verify_private_receipt(g.SOURCE_PLAN)
    spec=importlib.util.spec_from_file_location('ardrec_r558_live_check',
               ROOT/'scripts/ardrec_p14_r553_transition.py')
    need(spec and spec.loader,'r553_module_not_loaded')
    obj=importlib.util.module_from_spec(spec); spec.loader.exec_module(obj)
    value=obj.live_readonly(source)
    need(value.get('status')=='LIVE_DENY_READONLY_VERIFIED' and
         value.get('p8_operational')=='NO-GO','host_not_verified_deny')


def sudo(*args,timeout=60,check=True):
    need(args and args[0] in ('/usr/bin/install','/usr/bin/stat',
         '/usr/bin/sha256sum','/usr/bin/python3'),'root_command_not_allowed')
    return command(['/usr/bin/sudo','-n','--',*args],timeout=timeout,check=check)


def root_stat(path):
    p=sudo('/usr/bin/stat','-c','%F|%u|%g|%a|%h',str(path),check=False)
    if p.returncode!=0:
        need(b'No such file or directory' in p.stderr,'root_stat_unknown_error')
        return None
    return p.stdout.decode('ascii').strip().split('|')


def tty_authorize(code):
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
    try:
        need(os.isatty(fd),'tty_not_interactive')
        os.write(fd,('Escribe '+code+': ').encode())
        text=os.read(fd,256).decode('utf-8','strict').strip()
        need(text==code,'operator_not_authorized')
    finally:
        os.close(fd)


def install_root(folder,payload):
    git_gate()
    live_deny()
    verify_prepared(folder,payload)
    # R55.5 stays immutable. v2 is installed at a DIFFERENT pinned path.
    need(root_stat(g.DEST) is None,'root_v2_target_already_exists')
    parent=root_stat(g.DEST.parent)
    if parent is not None:
        need(parent[:4]==['directory','0','0','700'],'root_parent_permission_invalid')
    need(root_stat(Path('/var/lib')) is not None,'var_lib_missing')
    old=sudo('/usr/bin/python3','-B','/var/lib/ardrec/r555-deny-guard/root-recover.py','--check-root-bundle')
    need(json.loads(old.stdout).get('result')=='ROOT_BUNDLE_VERIFIED_READONLY',
         'old_root_helper_unverified')
    print('R558_PHYSICAL_HOST=DENY_READONLY_VERIFIED',flush=True)
    print('R558_EXISTING_R555=UNCHANGED',flush=True)
    print('R558_ROOT_V2_TARGET=ABSENT',flush=True)
    print('R558_AUTHORIZATION_REQUIRED=AUTORIZO_R558_INSTALAR_ROOT_V2_SIN_TIMER',flush=True)
    tty_authorize('AUTORIZO_R558_INSTALAR_ROOT_V2_SIN_TIMER')
    # Recheck after operator interaction: no untrusted root code can run.
    fresh=verify_history()
    need(fresh==payload,'post_authorization_source_drift')
    verify_prepared(folder,payload)
    live_deny()
    need(root_stat(g.DEST) is None,'root_target_appeared')
    cmds=g.stage_commands(folder)
    writes=[]
    try:
        for argv in cmds:
            sudo(*argv)
            writes.append(argv[-1])
        for name in sorted(g.FILES):
            st=root_stat(g.DEST/name)
            need(st is not None and st==['regular file','0','0','600','1'],
                 'root_file_metadata_invalid_'+name)
            readback=sudo('/usr/bin/sha256sum','--',str(g.DEST/name)).stdout.decode().split()[0]
            need(readback==g.sha(payload[name]),'root_file_sha256_mismatch_'+name)
        cp=sudo('/usr/bin/python3','-B',str(g.DEST/'root-recover.py'),
                '--check-root-bundle')
        doc=json.loads(cp.stdout)
        need(doc.get('result')=='ROOT_BUNDLE_VERIFIED_READONLY' and
             doc.get('writes')==0 and doc.get('p8_operational')=='NO-GO',
             'root_v2_readonly_check_failed')
        live_deny()
        print('R558_ROOT_V2=INSTALLED_AND_VERIFIED',flush=True)
        print('R558_FIREWALL_MUTATIONS=0')
        print('R558_LIBVIRT_MUTATIONS=0')
        print('R558_TIMER=NOT_ARMED')
        print('R558_P8=NO-GO')
        return 0
    except Exception:
        print('R558_ROOT_V2=PARTIAL_INSTALL_REVIEW_REQUIRED',flush=True)
        print('R558_SUCCESSFUL_INSTALL_TARGETS='+json.dumps(writes),flush=True)
        print('R558_NO_AUTOMATIC_RETRY=TRUE',flush=True)
        raise



def probe_installed():
    """Explicit deny-only physical idempotence proof. No fault injection."""
    git_gate()
    payload=verify_history()
    live_deny()
    root_dir=g.DEST
    for name in sorted(g.FILES):
        p=root_stat(root_dir/name)
        need(p==['regular file','0','0','600','1'],'installed_v2_metadata_invalid_'+name)
        out=sudo('/usr/bin/sha256sum','--',str(root_dir/name)).stdout.decode().split()[0]
        need(out==g.sha(payload[name]),'installed_v2_sha256_invalid_'+name)
    helper=str(root_dir/'root-recover.py')
    pre=json.loads(sudo('/usr/bin/python3','-B',helper,'--check-root-bundle').stdout)
    need(pre.get('result')=='ROOT_BUNDLE_VERIFIED_READONLY' and pre.get('writes')==0,
         'installed_v2_helper_not_ready')
    print('R558_INSTALLED_V2=AUTHENTICATED',flush=True)
    print('R558_INITIAL_R34=DENY_VERIFIED',flush=True)
    print('R558_PHYSICAL_PROBE_AUTH=AUTORIZO_R558_PROBAR_ROOT_V2_DENY',flush=True)
    tty_authorize('AUTORIZO_R558_PROBAR_ROOT_V2_DENY')
    result=json.loads(sudo('/usr/bin/python3','-B',helper,'--restore-deny',timeout=120).stdout)
    need(result.get('result')=='DENY_RESTORATION_READBACK_PASS' and
         result.get('p8_operational')=='NO-GO' and
         result.get('bindings_restored_or_original') is True and
         result.get('packets_injected') is False and
         result.get('service_acceptance') is False,
         'v2_restore_result_invalid')
    live_deny()
    parent=Path('/home/cicada/ardrec-lab/r58-root-recovery')
    private_dir(parent)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder=parent/('r558-probe-'+stamp+'-'+str(os.getpid()))
    folder.mkdir(mode=0o700)
    report={
        'schema':'ardrec-r558-physical-deny-only-probe-v1',
        'source_main':git('rev-parse','HEAD'),
        'result':'PHYSICAL_DENY_IDEMPOTENCE_VERIFIED_NO_GO',
        'root_v2_sha256':g.HELPER_SHA,
        'recovery':result,
        'missing_binding_fault_injected':False,
        'timer_armed':False,'traffic_opened':False,
        'p8_operational':'NO-GO',
    }
    raw=g.canon(report)
    file_once(folder/'result.json',raw)
    file_once(folder/'SHA256SUMS',(g.sha(raw)+'  result.json\n').encode('ascii'))
    print('R558_PHYSICAL_DENY=PASS',flush=True)
    print('R558_PROBE_RECEIPT='+str(folder),flush=True)
    print('R558_PROBE_SHA256='+g.sha(raw),flush=True)
    print('R558_TIMER=NOT_ARMED',flush=True)
    print('R558_P8=NO-GO',flush=True)
    return 0


def main():
    ap=argparse.ArgumentParser()
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--verify-offline',action='store_true')
    modes.add_argument('--prepare-private',action='store_true')
    modes.add_argument('--install-root-bundle',type=Path)
    modes.add_argument('--probe-root-v2-deny-only',action='store_true')
    args=ap.parse_args()
    try:
        if args.probe_root_v2_deny_only:
            return probe_installed()
        payload=verify_history()
        print('R558_SOURCE_R552=AUTHENTICATED')
        print('R558_SOURCE_R557=AUTHENTICATED')
        print('R558_ROOT_PAYLOAD_FILES='+str(len(payload)))
        print('R558_RECOVERY=DENY_ONLY_MISSING_BINDING_RECONCILIATION')
        if args.verify_offline:
            print('R558_OFFLINE=PASS')
            print('R558_ROOT_OPERATIONS=0')
            print('R558_P8=NO-GO')
            return 0
        if args.prepare_private:
            prepare_private(payload)
            return 0
        return install_root(args.install_root_bundle,payload)
    except (OSError,ValueError,RuntimeError,EOFError,subprocess.TimeoutExpired) as exc:
        print('R558=BLOCKED:'+type(exc).__name__+':'+str(exc)[:200])
        print('R558_P8=NO-GO')
        return 2

if __name__=='__main__':
    sys.exit(main())
