#!/usr/bin/env python3
"""R55.6: root-owned installation of authenticated deny-only material; no timer.

Modes: offline preflight or separately authorized, deny-first root staging.
Runs as ordinary user. Never uses sudo to run scripts from writable checkout.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

from ardrec.coordination import r556_root_staging as g
from ardrec.coordination import r553_transition_guard as r553

SOURCE_HELPER=ROOT/'scripts/ardrec_p14_r555_root_recover.py'
PLAN=Path('/home/cicada/ardrec-lab/r55-transition/r552-f1-plan-20261115T152309Z-39487')
ENV={**os.environ,'LANG':'C','LC_ALL':'C','PAGER':'cat','GIT_PAGER':'cat'}


def cmd(argv: list[str], *, input_bytes: bytes | None=None, timeout=60):
    x=subprocess.run(argv,input=input_bytes,stdin=subprocess.DEVNULL if input_bytes is None else None,
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,
                     check=False,close_fds=True,env=ENV)
    return x

def require_success(argv, *, timeout=60):
    p=cmd(argv,timeout=timeout)
    g.require(p.returncode==0 and len(p.stdout)<262144 and len(p.stderr)<16384,
              'command_failed_'+str(p.returncode)+'_'+Path(argv[0]).name)
    return p.stdout

def git(*args):
    return require_success(['git',*args]).decode('utf-8').strip()

def read_manifest():
    g.require(Path.cwd().resolve()==ROOT,'wrong_repository')
    helper=SOURCE_HELPER.read_bytes()
    g.require(not SOURCE_HELPER.is_symlink(),'helper_symlink')
    return g.verify_private_material(g.PREPARED,helper_bytes=helper)

def verify_git():
    g.require(git('rev-parse','--show-toplevel')==str(ROOT),'wrong_git_root')
    g.require(git('branch','--show-current')=='main','main_required_for_root_stage')
    g.require(git('status','--porcelain','--untracked-files=all')=='','dirty_repository')
    g.require(cmd(['git','merge-base','--is-ancestor',g.BASE,'HEAD']).returncode==0,
              'r555_merge_missing')
    g.require(git('ls-files','--error-unmatch',
                  'src/ardrec/coordination/r556_root_staging.py')==
              'src/ardrec/coordination/r556_root_staging.py',
              'r556_not_yet_integrated_in_main')
    g.require(git('ls-files','--error-unmatch',
                  'scripts/ardrec_p14_r556_stage.py')==
              'scripts/ardrec_p14_r556_stage.py',
              'r556_script_not_tracked')

def sudo(*argv,timeout=60):
    g.require(len(argv)>=1 and argv[0] in ('/usr/bin/stat','/usr/bin/install',
              '/usr/bin/python3','/usr/bin/sha256sum'),
              'sudo_executable_not_allowed')
    return cmd(['/usr/bin/sudo','-n','--',*argv],timeout=timeout)

def _stat(path):
    p=sudo('/usr/bin/stat','-c','%F|%u|%g|%a|%h',str(path))
    if p.returncode==1 and b'No such file or directory' in p.stderr:
        return None
    g.require(p.returncode==0,'root_stat_failed_'+str(path))
    return p.stdout.decode('ascii').strip().split('|')

def check_host_target():
    # No installation over existing contents; a partial installation is REVIEW_REQUIRED.
    parent=_stat(g.PARENT)
    if parent is not None:
        g.require(parent==['directory','0','0','700','2'] or
                  (parent[:4]==['directory','0','0','700'] and int(parent[4])>=2),
                  'root_parent_insecure')
    g.require(_stat(g.DEST) is None,'root_target_exists_no_retry')
    hostvar=_stat(Path('/var/lib'))
    g.require(hostvar is not None and hostvar[0]=='directory' and
              hostvar[1]=='0' and not (int(hostvar[3],8) & 0o022),
              'root_ancestor_unsafe')

def verify_host_deny():
    # Import R55.3 as module in no-write mode, with tightly restricted command gate.
    import importlib.util
    source=ROOT/'scripts/ardrec_p14_r553_transition.py'
    spec=importlib.util.spec_from_file_location('ardrec_r553_live_readonly',source)
    g.require(spec is not None and spec.loader is not None,'r553_loader_unavailable')
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    files=r553.verify_private_receipt(PLAN)
    r553.verify_plan(files)
    result=m.live_readonly(files)
    g.require(result['status']=='LIVE_DENY_READONLY_VERIFIED' and
              result['p8_operational']=='NO-GO','host_readonly_deny_not_verified')
    return result

def store_receipt(results):
    root=g.RECEIPTS
    root.mkdir(mode=0o700,exist_ok=True)
    st=root.stat()
    g.require(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700 and
              not root.is_symlink(),'receipt_parent_invalid')
    folder=root/('r556-stage-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+
                 '-'+str(os.getpid()))
    folder.mkdir(mode=0o700,exist_ok=False)
    body=g.canonical(results)
    blobs={'result.json':body}
    checksum=''
    for name,raw in blobs.items():
        fd=os.open(folder/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            out.write(raw);out.flush();os.fsync(out.fileno())
        checksum+=g.sha(raw)+'  '+name+'\n'
    fd=os.open(folder/'SHA256SUMS',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(checksum.encode('ascii'));out.flush();os.fsync(out.fileno())
    print('R556_RECEIPT='+str(folder))
    print('R556_REPORT_SHA256='+g.sha(body))

def stage(bundle):
    # Only after separate, interactive authorization and main+CI integration.
    verify_git()
    print('R556_LOCAL_MAIN=INTEGRATED_CLEAN',flush=True)
    print('R556_SOURCE=AUTHENTICATED',flush=True)
    pre=verify_host_deny()
    print('R556_HOST=DENY_READONLY_VERIFIED',flush=True)
    cmds=g.root_install_commands(g.PREPARED)
    g.verify_install_commands(cmds,g.PREPARED)
    check_host_target()
    print('R556_ROOT_DESTINATION=EMPTY',flush=True)
    print('R556_OPERATOR_AUTH_REQUIRED='+g.AUTHORIZATION,flush=True)
    entered=input('Escribe '+g.AUTHORIZATION+' para instalar SOLO el bundle root: ').strip()
    g.require(entered==g.AUTHORIZATION,'installation_not_authorized')
    # Authentication again before any authorized root writes.
    fresh=read_manifest()
    g.require(fresh==bundle,'bundle_changed_after_preflight')
    verify_host_deny()
    check_host_target()
    require_success(['/usr/bin/sudo','-v'],timeout=30)
    attempt=False
    done=[]
    try:
        # root never executes the user-owned script. All writes are install with fixed paths.
        for row in cmds:
            attempt=True
            require_success(['/usr/bin/sudo','-n','--',*row])
            done.append(row[-1])
        # Verify staged owner/mode/links/bytes BEFORE invoking any root Python.
        for name in sorted(g.ROOT_FILES):
            row=_stat(g.DEST/name)
            g.require(row is not None and row[:4]==['regular file','0','0','600'] and
                      row[4]=='1','root_staged_file_metadata_invalid_'+name)
            # Authenticate root-owned copied bytes before executing even the
            # read-only root helper: closes user-source TOCTOU at trust boundary.
            p=sudo('/usr/bin/sha256sum','--',str(g.DEST/name))
            g.require(p.returncode==0 and p.stdout.decode('ascii').split()[0]==g.sha(bundle[name]),
                      'root_staged_sha256_invalid_'+name)
        p=sudo('/usr/bin/python3','-B',str(g.DEST/'root-recover.py'),'--check-root-bundle')
        g.require(p.returncode==0,'root_bundle_check_failed')
        report=json.loads(p.stdout)
        g.require(report.get('result')=='ROOT_BUNDLE_VERIFIED_READONLY' and
                  report.get('writes')==0 and report.get('p8_operational')=='NO-GO',
                  'root_check_response_invalid')
        # Network is still deny, no timer armed.
        verify_host_deny()
        output=g.stage_report(bundle,staged=True,checked=True)
        output['status']='ROOT_BUNDLE_STAGED_AND_READONLY_VERIFIED_NO_GO'
        output['installed_filenames']=done
        store_receipt(output)
        print('R556_ROOT_BUNDLE=VERIFIED')
        print('R556_FIREWALL_MUTATIONS=0')
        print('R556_LIBVIRT_MUTATIONS=0')
        print('R556_SYSTEM_TIMER=NOT_ARMED')
        print('R556_PHYSICAL_RESTORE_TESTED=NO')
        print('R556_P8=NO-GO')
        return 0
    except Exception as exc:
        output=g.stage_report(bundle,staged=attempt,checked=False)
        output['status']='REVIEW_REQUIRED_NO_AUTOMATIC_RETRY'
        output['successful_install_targets']=done
        output['failure']=type(exc).__name__+':'+str(exc)[:180]
        try:store_receipt(output)
        except Exception as e:print('R556_RECEIPT_BLOCKED='+str(e)[:120])
        print('R556_ROOT_INSTALL=REVIEW_REQUIRED_NO_AUTOMATIC_RETRY')
        raise

def main():
    p=argparse.ArgumentParser()
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--verify-offline',action='store_true')
    modes.add_argument('--install-root-bundle',action='store_true')
    a=p.parse_args()
    try:
        bundle=read_manifest()
        report=g.stage_report(bundle)
        print('R556_R555_MATERIAL=AUTHENTICATED')
        print('R556_ROOT_FILES='+str(len(bundle)))
        print('R556_ROOT_INSTALL_ARGV=EXACT_9_COMMANDS')
        g.verify_install_commands(g.root_install_commands(g.PREPARED),g.PREPARED)
        if a.verify_offline:
            print('R556_RESULT=OFFLINE_CONTRACT_PASS')
            print('R556_ROOT_WRITES=0')
            print('R556_SYSTEM_TIMER=NOT_ARMED')
            print('R556_TRAFFIC=0')
            print('R556_P8=NO-GO')
            return 0
        return stage(bundle)
    except (OSError,ValueError,RuntimeError,EOFError,subprocess.TimeoutExpired) as exc:
        print('R556_RESULT=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180])
        print('R556_P8=NO-GO')
        return 2

if __name__=='__main__':
    sys.exit(main())
