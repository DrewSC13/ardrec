#!/usr/bin/env python3
"""F6 user-side bundle assembler and deterministic replay; no host mutations."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import sys

# Repository src-layout: keep the operator independent of PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from ardrec.coordination import r113_f6_six_binding_guard as g

ROOT=Path('/home/cicada/ardrec-lab/r113-f6-six-deny-v1')
RECOVER=Path(__file__).resolve().parent/'ardrec_p14_r113_f6_root_recover.py'

def private_file(path):
    st=path.lstat()
    # Successful F5 probes produce authentic zero-byte stderr files. Only
    # those F5 .stderr captures may be empty; all bytes are later authenticated
    # against the pinned F5 manifest, including SHA256(empty).
    f5_stderr = path.parent == g.F5 and path.name.endswith('.stderr')
    valid_size = ((0 <= st.st_size < 524288) if f5_stderr
                  else (0 < st.st_size < 524288))
    g.need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
           st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
           valid_size,'PRIVATE_FILE_INVALID_'+path.name)
    return path.read_bytes()

def source():
    m=g.load_json(private_file(g.F5/'manifest.json'))
    files={'manifest.json':private_file(g.F5/'manifest.json')}
    for name in m['files_sha256']:
        g.need('/' not in name and '..' not in name,'SOURCE_MEMBER_UNSAFE')
        files[name]=private_file(g.F5/name)
    g.check_f5(files)
    return files

def inspect_dir(directory):
    g.need(directory.is_absolute() and directory.parent==ROOT and
           directory.name.startswith('bundle-') and
           not directory.is_symlink(),'BUNDLE_PATH_INVALID')
    st=directory.lstat()
    g.need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
           stat.S_IMODE(st.st_mode)==0o700,'BUNDLE_MODE_INVALID')
    manifest=g.load_json(private_file(directory/'manifest.json'))
    expected=set(manifest['sha256'])|{'manifest.json'}
    g.need({p.name for p in directory.iterdir()}==expected,'BUNDLE_SCOPE_INVALID')
    raw={name:private_file(directory/name) for name in expected}
    g.need(manifest['schema']==g.SCHEMA and
           manifest['f5_sha256']==g.F5_DIGEST and
           manifest['traffic_allowed'] is False and manifest['p8']=='NO-GO',
           'BUNDLE_SCHEMA_INVALID')
    g.need(all(manifest['sha256'][n]==g.sha(raw[n]) for n in expected-{'manifest.json'}),
           'BUNDLE_HASH_INVALID')
    recomputed=g.prepare(source(),raw['root-recover.py'])
    g.need(raw==recomputed,'BUNDLE_BYTES_NOT_DETERMINISTIC')
    return raw

def build():
    import tempfile
    g.need(ROOT.is_dir() and ROOT.stat().st_uid==os.geteuid() and
           stat.S_IMODE(ROOT.stat().st_mode)==0o700,'BUNDLE_PARENT_INSECURE')
    files=g.prepare(source(),RECOVER.read_bytes())
    os.umask(0o077)
    directory=Path(tempfile.mkdtemp(prefix='bundle-',dir=ROOT))
    for name,raw in sorted(files.items()):
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
    g.need(inspect_dir(directory)==files,'BUNDLE_AFTER_WRITE_DRIFT')
    return directory

def main():
    ap=argparse.ArgumentParser()
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare',action='store_true')
    group.add_argument('--replay',type=Path)
    a=ap.parse_args()
    try:
        if a.prepare:
            p=build()
            print('R113_F6_BUNDLE_SESSION='+str(p))
        else:
            p=a.replay
            inspect_dir(p)
            print('R113_F6_BUNDLE_REPLAY=PASS')
        print('R113_F6_SIX_DENY_INPUT=PASS_F5_AUTHENTICATED')
        print('R113_F6_HOST_MUTATIONS=0')
        print('R113_F6_P8=NO-GO')
        return 0
    except Exception as exc:
        print('R113_F6_STOP='+type(exc).__name__+':'+str(exc)[:160])
        print('R113_F6_P8=NO-GO')
        return 23

if __name__=='__main__':sys.exit(main())
