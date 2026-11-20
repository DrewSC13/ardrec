#!/usr/bin/env python3
"""Root-only one-time F10R stage; never touches nftables or nwfilter bindings.

Original F10 root bundle is verified and preserved. F10R is a distinct root bundle
containing signed semantic fix and exact authenticated F10 policy inputs.
"""
from __future__ import annotations
import hashlib, json, os, stat, subprocess, sys
from pathlib import Path

REPO=Path('/home/cicada/Development/GitHub/ardrec')
OLD=Path('/var/lib/ardrec/r113-f10-window-v1')
NEW=Path('/var/lib/ardrec/r113-f10r-window-v1')
OLD_HEAD='b1e1fccebed9830a9250b8908d123cca0a567a04'
BRANCH='feat/p14-r111-r114-real-lab'
ROLES=('runner-ssh','ssh','runner-ftp','ftp','runner-smb','smb')
NAMES=('r34-window-CANDIDATE.nft',)+tuple('ardrec-r113-'+r+'-tcp-v1.xml' for r in ROLES)
BASE={'contract.py','policy-manifest.json','f9r-report.json'}|set(NAMES)
SOURCE_MAP={
    'root-window.py':'scripts/ardrec_p14_r113_f10r_root_window.py',
    'semantic.py':'src/ardrec/coordination/r113_f10r_filter_semantics.py',
}
F9R_HASH='b336a40851a5723b507449042aed7010729327c57336e90bd1e95251c774870e'
F10D_REPORT=Path('/home/cicada/ardrec-lab/r113-f10d-nwfilter-drift-v1/inspect-b8510sei/report.json')
F10D_HASH='1eca4123643f1900e417912cf55c69ffceeec1308b58a3dd03904597a2fc2cc1'


def need(ok,msg):
    if not ok: raise ValueError(msg)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def run(args,timeout=30):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,check=False)
    need(p.returncode==0,'PREFLIGHT_COMMAND_FAILED_'+str(args[-1]))
    return p.stdout


def root_file(path, allow_empty=False):
    s=path.lstat()
    need(stat.S_ISREG(s.st_mode) and not path.is_symlink() and
         s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and
         ((0<=s.st_size) if allow_empty else (0<s.st_size)) and s.st_size<250000,
         'ROOT_FILE_INVALID_'+path.name)
    return path.read_bytes()


def write(name,raw):
    fd=os.open(NEW/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())


def main():
    os.umask(0o077)
    need(os.geteuid()==0,'ROOT_REQUIRED')
    need(len(sys.argv)==1,'NO_ARGUMENTS_ALLOWED')
    need(not NEW.exists() and not NEW.is_symlink(),'F10R_ROOT_ALREADY_EXISTS')
    need(run(['git','-C',str(REPO),'branch','--show-current']).decode().strip()==BRANCH,'GIT_BRANCH_CHANGED')
    head=run(['git','-C',str(REPO),'rev-parse','HEAD']).decode().strip()
    need(run(['git','-C',str(REPO),'rev-parse','HEAD^']).decode().strip()==OLD_HEAD,'PARENT_CHANGED')
    need(run(['git','-C',str(REPO),'log','-1','--format=%G?']).decode().strip()=='G','SIGNATURE_INVALID')
    need(run(['git','-C',str(REPO),'status','--porcelain=v1','-uall']).strip()==b'','GIT_DIRTY')
    # Only code committed in verified HEAD is privileged.
    for path in ('scripts/ardrec_p14_r113_f10r_root_stage.py',*SOURCE_MAP.values()):
        data=(REPO/path).read_bytes()
        need(data==run(['git','-C',str(REPO),'show',f'HEAD:{path}']),
             'UNSIGNED_SOURCE_'+path)
    old_dir=OLD.lstat()
    need(stat.S_ISDIR(old_dir.st_mode) and old_dir.st_uid==0 and
         stat.S_IMODE(old_dir.st_mode)==0o700,'ORIGINAL_ROOT_DIR_UNSAFE')
    # F10 original verified self: allowed to have its prior filters marker only.
    check=run(['/usr/bin/python3',str(OLD/'root-window.py'),'--check'])
    need(b'R113_F10_ROOT_BUNDLE=VERIFIED' in check,'ORIGINAL_ROOT_BUNDLE_UNVERIFIED')
    old_manifest=json.loads(root_file(OLD/'manifest.json'))
    need(old_manifest.get('schema')=='ARDREC-R113-F10-ROOT-BUNDLE-v1' and
         old_manifest.get('policy_host_pass_hash')==F9R_HASH and
         set(old_manifest['sha256'])==BASE|{'root-window.py'},'ORIGINAL_ROOT_MANIFEST_INVALID')
    need(root_file(OLD/'filters-installed.once')==b'R113_F10_FILTER_INSTALL_ATTEMPTED\n',
         'ORIGINAL_F10_DEFINITION_MARKER_MISSING')
    need(not (OLD/'window-attempted.once').exists() and
         not (OLD/'window-attempted.once').is_symlink(),'ORIGINAL_F10_WINDOW_ALREADY_ATTEMPTED')
    base_files={}
    for name in sorted(BASE):
        content=root_file(OLD/name)
        need(sha(content)==old_manifest['sha256'][name], 'ORIGINAL_POLICY_CHANGED_'+name)
        base_files[name]=content
    # Pin the original F10D forensic observation; do not merely infer that libvirt
    # default-chain insertion is the only difference from a schematic unit test.
    f10ds=F10D_REPORT.lstat()
    need(stat.S_ISREG(f10ds.st_mode) and not F10D_REPORT.is_symlink() and
         f10ds.st_nlink==1 and stat.S_IMODE(f10ds.st_mode)==0o600 and
         0<f10ds.st_size<200000,'F10D_PRIVATE_REPORT_UNSAFE')
    f10db=F10D_REPORT.read_bytes()
    need(sha(f10db)==F10D_HASH,'F10D_FORENSIC_HASH_CHANGED')
    f10dd=json.loads(f10db)
    need(f10dd.get('schema')=='ARDREC-R113-F10D-READONLY-DIAGNOSTIC-v1' and
         f10dd.get('source_commit')==OLD_HEAD and
         f10dd.get('observed_deny_after') is True and
         f10dd.get('error') is None and
         f10dd.get('host_mutations')==0 and
         f10dd.get('guest_exec')==0 and
         f10dd.get('tcp_probes')==0 and f10dd.get('p8')=='NO-GO',
         'F10D_FORENSIC_OUTCOME_INVALID')
    rows=f10dd.get('roles',[])
    need(isinstance(rows,list) and [row.get('role') for row in rows]==list(ROLES),
         'F10D_FORENSIC_ROLES_INVALID')
    for row in rows:
        role=row['role']
        name='ardrec-r113-'+role+'-tcp-v1'
        expected={'@tag':'filter','name':name}
        actual={**expected,'chain':'root'}
        need(row.get('equal_except_uuid') is False and
             row.get('diffs')==[{'path':'filter','expected':expected,'actual':actual}] and
             row.get('candidate_sha256')==sha(base_files[name+'.xml']),
             'F10D_DIFFERENCES_NOT_EXACT_'+role)
    source_files={name:(REPO/path).read_bytes() for name,path in SOURCE_MAP.items()}
    # Distinct signed root bundle, old directory is never overwritten.
    files={**base_files, **source_files}
    need(set(files)==BASE|set(SOURCE_MAP),'NEW_ROOT_SCOPE_INVALID')
    NEW.mkdir(mode=0o700)
    try:
        for name,blob in sorted(files.items()):write(name,blob)
        manifest={'schema':'ARDREC-R113-F10R-ROOT-BUNDLE-v1',
                  'policy_host_pass_hash':F9R_HASH,
                  'previous_f10_root_manifest_sha256':sha(root_file(OLD/'manifest.json')),
                  'source_git_head':head,
                  'sha256':{name:sha(blob) for name,blob in sorted(files.items())}}
        write('manifest.json',(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode())
        os.chmod(NEW,0o700)
        print('R113_F10R_ROOT_STAGE=PASS_'+str(len(files)+1)+'_FILES')
        print('R113_F10R_ORIGINAL_F10_ROOT=UNCHANGED')
        print('R113_F10R_DEFINITIONS=NOT_REPEATED')
        print('R113_F10R_NETWORK_MUTATIONS=0')
        print('R113_F10R_P8=NO-GO')
    except Exception:
        print('R113_F10R_STAGE_PARTIAL_CONSERVAR=TRUE')
        raise


if __name__=='__main__':
    try:main()
    except Exception as e:
        print('R113_F10R_ROOT_STAGE_STOP='+type(e).__name__+':'+str(e)[:180])
        raise SystemExit(23)
