#!/usr/bin/env python3
"""R56.0 service closure: verifies existing sources and optionally inspects host read-only.

No nft -f, virsh define/start/delete, systemd-run, packet injection, SSH, FTP or SMB client.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r560_service_acceptance as c
from ardrec.coordination import r553_transition_guard as r553

E = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C','LANG':'C'}
PRIVATE = Path('/home/cicada/ardrec-lab/r560-service-closure')
R552 = Path('/home/cicada/ardrec-lab/r55-transition/r552-f1-plan-20261115T152309Z-39487')


def require(ok, why):
    c.require(ok, why)


def git(*args):
    cp = subprocess.run(['/usr/bin/git', *args], cwd=ROOT, env=E, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    require(cp.returncode == 0, 'git_failed')
    return cp.stdout.decode('utf-8').strip()


def provenance_gate(*, require_main:bool):
    require(Path.cwd().resolve()==ROOT,'working_directory')
    require(git('rev-parse','--show-toplevel') == str(ROOT), 'wrong_git_root')
    if require_main:
        require(git('branch','--show-current') == 'main', 'main_required')
        require(git('status','--porcelain','--untracked-files=all') == '', 'dirty_repo')
        require(git('rev-parse','HEAD') == git('ls-remote','origin','refs/heads/main').split()[0],
                'remote_main_drift')
        require(git('cat-file','-e',c.MAIN+'^{commit}') == '', 'source_main_missing')
        cp = subprocess.run(['/usr/bin/git','merge-base','--is-ancestor',c.MAIN,'HEAD'],
                            cwd=ROOT, env=E, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        require(cp.returncode==0,'r558_merge_not_ancestor')
    return {'head':git('rev-parse','HEAD'), 'branch':git('branch','--show-current')}


def check_offline():
    path=ROOT/'lab/verify_p14_r51_dev_contract.py'
    spec=importlib.util.spec_from_file_location('r560_r51',path)
    require(spec is not None and spec.loader is not None,'r51_loader')
    v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
    r51=v.verify(ROOT)
    c.require(r51.get('p8_operational')=='NO-GO' and
              r51.get('complete_family_acceptance')==0 and
              r51.get('confirmed_live_services')==0, 'r51_status_changed')
    m=c.parse((ROOT/'lab/p14-r51-dev-three-services-v1/manifest.json').read_bytes())
    configs={r:(ROOT/f'lab/services-v1/config/{r}.conf').read_bytes() for r in c.ROLES}
    evidence=c.parse((ROOT/'lab/services-v1/evidence.json').read_bytes())
    catalog=c.parse((ROOT/'lab/operational-catalog-v1/catalog.json').read_bytes())
    provenance=c.validate_sources(m,configs,evidence,catalog)
    return c.plan(provenance)


def fixed_readonly(args):
    require(type(args) is list and args and args[0] in ('/usr/bin/virsh',),
            'unapproved_host_program')
    cp=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE,check=False,timeout=25,env=E)
    require(len(cp.stdout)<=262144 and len(cp.stderr)<=8192,'host_output_limit')
    return {'returncode':cp.returncode,'stdout':cp.stdout.decode('utf-8','replace')[:30000],
            'stderr_sha256':c.sha(cp.stderr)}


def live_readonly():
    # Reuse independent R55.3 host deny attestation, including nft and both SSH bindings.
    files=r553.verify_private_receipt(R552)
    r553.verify_plan(files)
    src=ROOT/'scripts/ardrec_p14_r553_transition.py'
    spec=importlib.util.spec_from_file_location('r560_r553',src)
    require(spec is not None and spec.loader is not None,'r553_loader')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    host=mod.live_readonly(files)
    require(host.get('status')=='LIVE_DENY_READONLY_VERIFIED' and
            host.get('p8_operational')=='NO-GO','r34_not_deny')
    observed={}
    base=['/usr/bin/virsh','--readonly','-c','qemu:///system']
    for role in ('runner',*c.ROLES):
        domain='ardrec-r33-dev-'+role
        observed[domain]=fixed_readonly(base+['domstate',domain])
    for role in c.ROLES:
        network='ardrec-r33-dev-net-'+role
        observed[network]=fixed_readonly(base+['net-info',network])
    return {'r553_host_deny':host,'virsh_queries':observed,
            'no_protocol_smoke':True,'no_packets':True,
            'current_service_acceptance':'NOT_ATTESTED','p8_operational':'NO-GO'}


def store_private(doc):
    os.umask(0o077)
    require(not PRIVATE.is_symlink(),'private_root_symlink')
    PRIVATE.mkdir(mode=0o700,exist_ok=True)
    st=PRIVATE.stat()
    require(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,'private_parent_mode')
    folder=PRIVATE/('r560-readonly-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+str(os.getpid()))
    folder.mkdir(mode=0o700,exist_ok=False)
    raw=(json.dumps(doc,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
    fd=os.open(folder/'report.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as file:
        file.write(raw);file.flush();os.fsync(file.fileno())
    sums=(c.sha(raw)+'  report.json\n').encode('ascii')
    fd=os.open(folder/'SHA256SUMS',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as file:
        file.write(sums);file.flush();os.fsync(file.fileno())
    print('R560_PRIVATE_RECEIPT='+str(folder))
    print('R560_REPORT_SHA256='+c.sha(raw))


def main():
    p=argparse.ArgumentParser()
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--verify-offline',action='store_true')
    mode.add_argument('--host-readonly',action='store_true')
    a=p.parse_args()
    try:
        source=provenance_gate(require_main=a.host_readonly)
        report=check_offline()
        c.validate_plan(report)
        print('R560_SOURCE_R51=PASS')
        print('R560_SERVICE_CONFIGS=3_AUTHENTICATED')
        print('R560_HISTORICAL_SMOKE=17_OF_17_HISTORICAL_ONLY')
        print('R560_CATALOG=25_FAMILIES_0_ACCEPTED')
        print('R560_READINESS=SSH_FIRST_FTP_SECOND_SMB_THIRD')
        print('R560_P8=NO-GO')
        if a.host_readonly:
            snapshot=live_readonly()
            print('R560_R34=LIVE_DENY_VERIFIED')
            for name,val in snapshot['virsh_queries'].items():
                print('R560_HOST_QUERY='+name+' RC='+str(val['returncode'])+
                      ' OUTPUT='+repr(val['stdout'].strip()[:100]))
            store_private({'schema':'ardrec-r560-host-readonly-v1',
                           'source_main':c.MAIN,'current_git':source,
                           'closure_plan':report,'host':snapshot,
                           'host_mutations':0,'packets_injected':0,
                           'p8_operational':'NO-GO'})
        else:
            print('R560_OFFLINE=PASS_NO_HOST_QUERIES')
        return 0
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,IndexError,
            subprocess.TimeoutExpired) as exc:
        print('R560=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180])
        print('R560_P8=NO-GO')
        return 2

if __name__ == '__main__':
    sys.exit(main())
