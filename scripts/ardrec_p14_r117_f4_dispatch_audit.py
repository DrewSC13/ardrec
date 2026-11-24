#!/usr/bin/env python3
"""F4 audit of independently signed R117 SSH->runner->FTP DENY-only code.

--offline: source integrity and historical lock only, no git or host access.
--source: additionally require the current signed clean R117 git branch.
--root: inspect historical root F12 only; does not stage F4 or grant a boot.
No mode starts a VM, changes firewall, touches systemd or writes a receipt.
"""
from __future__ import annotations
import argparse,hashlib,json,os,sys
from pathlib import Path
sys.dont_write_bytecode=True
REPO=Path('/home/cicada/Development/GitHub/ardrec')
ROOT=Path(__file__).resolve().parents[1]
MANIFEST=Path('lab/operational-controller/r117-f4-dispatch-sources-v1.json')
LOCK=Path('lab/operational-controller/r116-f3-root-source-lock-v1.json')

# R168-F12: hashes exactos; el manifiesto historico no cambia.
R168_HISTORIC_LOCK_SHA = 'eb6e1dc56576fe59d973eb76b6b563d0baf44cdabcd06d5857f908ee345ca53d'
R168_DERIVED_LOCK_SHA = '2d15b24c9101d7615ca6f43dca3b050f1f6058ac3672592b621d3da042dd319a'
BASE='ecaa563735e8fc5a92c8d9e2a2d08c408658ff3c'
BRANCH='feat/p14-r117-piloto-real-a5-a10'
FIELDS={'schema','base','branch','r116_merge','root_release',
'root_f3_immutable_source_count','historical_f3_lock_sha256','source_sha256',
'git_signed_current_head_required','independent_scope_boot_revocation_required',
'one_attempt_per_role','deny_first_unchanged','network_traffic',
'vm_starts_during_install','pilot','a6','p8'}
FILES=('src/ardrec/coordination/r117_f4_controlled_boot.py',
       'src/ardrec/coordination/r117_f4_runner_ftp_boot.py',
       'src/ardrec/coordination/r117_f4_root_release.py')
class Stop(ValueError):pass
def need(cond,code):
    if not cond:raise Stop(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def audit_offline(repo=ROOT):
    """Pure byte-only authenticated review, usable in unsigned GitHub PR merge checkout."""
    mpath=repo/MANIFEST
    need(mpath.is_file() and not mpath.is_symlink(),'DISPATCH_MANIFEST_MISSING')
    obj=json.loads(mpath.read_bytes())
    need(type(obj) is dict and set(obj)==FIELDS,'DISPATCH_MANIFEST_FIELDS')
    need(obj['schema']=='ARDREC-R117-F4-VERSIONED-BOOT-DISPATCH-v1' and
         obj['base']==BASE and obj['branch']==BRANCH and
         obj['r116_merge']=='fdb6efa0c297ce18b28cddb9494514f51d88bdb4' and
         obj['root_release']=='NOT_INSTALLED' and
         obj['root_f3_immutable_source_count']==33 and
         type(obj['source_sha256']) is dict and
         set(obj['source_sha256'])==set(FILES) and
         all(obj[x] is True for x in ('git_signed_current_head_required',
               'independent_scope_boot_revocation_required','one_attempt_per_role',
               'deny_first_unchanged')) and
         obj['network_traffic'] is False and
         type(obj['vm_starts_during_install']) is int and obj['vm_starts_during_install']==0 and
         (obj['pilot'],obj['a6'],obj['p8'])==('DRAFT','ND','NO-GO'),
         'DISPATCH_MANIFEST_CHANGED')
    lock=repo/LOCK
    need(lock.is_file() and not lock.is_symlink(),
         'HISTORIC_33_LOCK_DRIFT')
    need(obj['historical_f3_lock_sha256'] == R168_HISTORIC_LOCK_SHA,
         'HISTORIC_33_MANIFEST_PIN_DRIFT')
    need(sha(lock.read_bytes()) in (
         R168_HISTORIC_LOCK_SHA, R168_DERIVED_LOCK_SHA),
         'HISTORIC_33_LOCK_DRIFT')
    for name in FILES:
        p=repo/name
        need(p.is_file() and not p.is_symlink() and
             sha(p.read_bytes())==obj['source_sha256'][name],
             'R117_DISPATCH_BYTES_CHANGED_'+name)
    return obj

def audit_current(repo=REPO):
    need(os.geteuid()!=0,'SOURCE_MODE_ROOT_FORBIDDEN')
    need(Path.cwd().resolve()==repo,'WRONG_WORKTREE')
    obj=audit_offline(repo)
    from ardrec.coordination import r117_f3_current_git_admission as gate
    from ardrec.coordination import r117_f4_controlled_boot as f7
    from ardrec.coordination import r117_f4_runner_ftp_boot as f8
    h=gate.git_guard()
    need(h==f7.git_guard(for_boot=True)==f8._check_sources(),
         'R117_BOOT_ENGINE_NOT_CURRENT_SIGNED_HEAD')
    need(f8.f7 is f7 and f7.BRANCH==BRANCH and f7.BASE==obj['r116_merge'],
         'R117_CHAIN_SPLIT_OR_BASE_DRIFT')
    return h,obj

def audit_root(repo=REPO):
    need(os.geteuid()==0,'ROOT_ONLY')
    from importlib.util import spec_from_file_location,module_from_spec
    path=repo/'scripts/ardrec_p14_r117_f3_boot_chain_gate.py'
    spec=spec_from_file_location('r117_f3_root_gate',path)
    mod=module_from_spec(spec)
    spec.loader.exec_module(mod)
    lock=json.loads((repo/LOCK).read_bytes())
    prev=mod.exact_lock(lock)
    relation,head=mod.root_audit(prev)
    need(relation=='F12_SIGNED_UNCHANGED_R117_DISPATCH_NOT_RELEASED',
         'R116_F12_STAGING_CHANGED')
    return head,relation

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    for flag in ('offline','source','root'):
        g.add_argument('--'+flag,action='store_true')
    x=p.parse_args(argv)
    try:
        if x.offline:
            m=audit_offline()
            print('R117_F4_OFFLINE=PASS_EXACT_THREE_VERSIONED_MODULES_AND_R116_33_PINNED')
        elif x.source:
            head,m=audit_current()
            print('R117_F4_SIGNED_HEAD='+head)
            print('R117_F4_SOURCE=PASS_SIGNED_CURRENT_R117_AND_THREE_VERSIONED_MODULES')
        else:
            head,relation=audit_root()
            print('R117_F4_ROOT_INSTALLED_HEAD='+head)
            print('R117_F4_ROOT_RELATION='+relation)
        print('R117_F4_ROOT_RELEASE=NOT_INSTALLED')
        print('R117_F4_BOOT=NOT_EXECUTED')
        print('R117_F4_INDEPENDENT_AUTHORITY=NOT_PROVISIONED')
        print('R117_F4_VM_STARTS=0')
        print('R117_F4_NETWORK_CONNECTIONS=0')
        print('R117_F4_P7=DRAFT')
        print('R117_F4_A6=ND')
        print('R117_F4_P8=NO-GO')
        return 0
    except (Stop,OSError,ValueError,TypeError,KeyError) as exc:
        print('R117_F4_STOP='+type(exc).__name__+':'+str(exc)[:140])
        print('R117_F4_P8=NO-GO')
        return 23
if __name__=='__main__':raise SystemExit(main())
