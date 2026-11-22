#!/usr/bin/env python3
"""ARDREC R146 independently staged root installer candidate.

--capabilities is safe from the source checkout. --install ONLY operates when
this exact file is installed as /opt/ardrec/r146-installer-v1/installer.py by an
independent administrator, with root-owned runtime, manifest, trust, permit,
revocation and 12 authentic operational signers. Never launch root mode from
/home/cicada/Development/GitHub/ardrec.

NO VM starts, FTP sockets, nft changes, systemd or network opening. An
installation is NOT the physical FTP pilot, A6 proof or P8 authorization.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import sys

INSTALL_DIR = Path('/opt/ardrec/r146-installer-v1')
SCRIPT = INSTALL_DIR/'installer.py'
RUNTIME = INSTALL_DIR/'runtime'
BUNDLE = INSTALL_DIR/'manifest.json'
DROP = Path('/var/lib/ardrec/r146-source-drop-v1')
STATE = Path('/var/lib/ardrec/r146-install-state-v1')
PARENT = Path('/var/lib/ardrec')
TRUST = Path('/etc/ardrec/r146-install-trust-v1.json')
REVOCATION = Path('/etc/ardrec/r146-install-revocation-v1.json')
PERMIT = DROP/'install-permit.json'
F8_REFERENCE = Path('/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/ftp-boot-paths.json')
GUARD = Path('/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py')
F3 = Path('/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/root-pilot.py')
SCHEMA = 'ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1-root-bundle'
RUNTIME_MODULES = {
 'r146_independent_install.py':'r146_independent_install.py',
 'r135_root_transaction.py':'r135_root_transaction.py',
 'r136_operational_semantics.py':'r136_operational_semantics.py',
 'r139_independent_release_review.py':'r139_independent_release_review.py',
}
POLICY = {
 'root_trust':'/etc/ardrec/r126-root-session-trust-v1.json',
 'root_revocation':'/etc/ardrec/r126-root-session-revocation-v1.json',
 'scope_trust':'/etc/ardrec/r126-ftp-t01-scope-trust-v2.json',
 'scope_revocation':'/etc/ardrec/r126-ftp-t01-scope-revocation-v2.json',
 'pilot_trust':'/etc/ardrec/r115-p7-pilot-trust-v1.json',
 'pilot_revocation':'/etc/ardrec/r115-p7-pilot-revocation-v1.json',
 'window_trust':'/etc/ardrec/r115-p8-trust-v1.json',
 'window_revocation':'/etc/ardrec/r115-p8-revocation-v1.json',
 'traffic_trust':'/etc/ardrec/r128-root-traffic-trust-v1.json',
 'traffic_revocation':'/etc/ardrec/r128-root-traffic-revocation-v1.json',
 'release_trust':'/etc/ardrec/r128-root-release-trust-v1.json',
 'release_revocation':'/etc/ardrec/r128-root-release-revocation-v1.json',
}

class Stop(ValueError): pass

def require(ok,reason):
    if not ok: raise Stop(reason)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def secure_parent(path, mode=None):
    st=path.lstat()
    require(not path.is_symlink() and stat.S_ISDIR(st.st_mode) and
            st.st_uid==0 and not(st.st_mode&0o022),'UNSAFE_ROOT_DIRECTORY:'+str(path))
    if mode is not None:
        require(stat.S_IMODE(st.st_mode)==mode,'ROOT_DIRECTORY_NOT_PRIVATE:'+str(path))

def secure_file(path,limit=200000):
    require(isinstance(path,Path) and path.is_absolute() and not path.is_symlink(),
            'UNSAFE_ROOT_INPUT_PATH')
    for ancestor in reversed(path.parents):
        secure_parent(ancestor)
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and
            stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and
            0<before.st_size<=limit,'UNSAFE_ROOT_FILE_METADATA:'+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        require((a.st_dev,a.st_ino,a.st_size,a.st_uid,a.st_nlink)==
                (before.st_dev,before.st_ino,before.st_size,before.st_uid,before.st_nlink),
                'ROOT_INPUT_RACE')
        raw=bytearray()
        while len(raw)<a.st_size:
            chunk=os.read(fd,a.st_size-len(raw))
            require(chunk,'ROOT_INPUT_SHORT_READ')
            raw.extend(chunk)
        b=os.fstat(fd)
        require((a.st_ino,a.st_mtime_ns,a.st_ctime_ns,a.st_size)==
                (b.st_ino,b.st_mtime_ns,b.st_ctime_ns,b.st_size),
                'ROOT_INPUT_CHANGED_DURING_READ')
        return bytes(raw)
    finally:os.close(fd)

def root_entry():
    require(os.geteuid()==0,'ROOT_REQUIRED')
    require(sys.flags.isolated==1 and sys.dont_write_bytecode,
            'ROOT_PYTHON_ISOLATION_REQUIRED')
    require(Path(__file__).absolute()==SCRIPT and not Path(__file__).is_symlink(),
            'EXTERNAL_INSTALLED_AGENT_REQUIRED')
    for p in ('/','/opt','/opt/ardrec','/var','/var/lib','/var/lib/ardrec',
              '/etc','/etc/ardrec'):
        secure_parent(Path(p))
    secure_parent(INSTALL_DIR,0o700)
    secure_parent(RUNTIME,0o700)
    secure_parent(DROP,0o700)
    secure_parent(DROP/'B4',0o700)
    secure_parent(DROP/'B9',0o700)
    secure_parent(STATE,0o700)
    require(STATE.stat().st_dev==PARENT.stat().st_dev,'CROSS_DEVICE_INSTALL_REJECTED')
    return True

def approved_runtime():
    """No mutable-checkout imports; all runtime modules externally pinned."""
    root_entry()
    import json
    manifest_raw=secure_file(BUNDLE,12000)
    # Only the installed private runtime gets imported; no sys.path from cwd.
    manifest=json.loads(manifest_raw)
    require(set(manifest)=={'schema','approved_head','approved_tree','files',
            'source_only_until_independent_authority'} and
            manifest['schema']==SCHEMA and
            manifest['source_only_until_independent_authority'] is True,
            'AGENT_MANIFEST_INVALID')
    require(type(manifest['approved_head']) is str and len(manifest['approved_head'])==40 and
            type(manifest['approved_tree']) is str and len(manifest['approved_tree'])==40,
            'AGENT_GIT_IDENTITY_INVALID')
    expected={'installer.py'} | {'runtime/'+x for x in RUNTIME_MODULES}
    require(type(manifest['files']) is dict and set(manifest['files'])==expected,
            'AGENT_MODULE_SET_DRIFT')
    for relative,pin in manifest['files'].items():
        require(type(pin) is str and len(pin)==64,'AGENT_HASH_FORMAT')
        data=secure_file(INSTALL_DIR/relative,500000)
        require(sha(data)==pin,'AGENT_SOURCE_HASH_DRIFT:'+relative)
    # The independent root admin MUST bind this manifest to a real signed
    # installation permit; a root-owned file alone cannot attest reviewer identity.
    sys.path.insert(0,str(RUNTIME))
    from r146_independent_install import parse as parse_doc
    require(parse_doc(manifest_raw,12000)==manifest,'AGENT_MANIFEST_NONCANONICAL')
    import r146_independent_install as engine
    # Preserve compiled modules under root-owner-only runtime.
    import types, importlib.util
    pkg=types.ModuleType('ardrec')
    pkg.__path__=[str(RUNTIME)]
    sub=types.ModuleType('ardrec.coordination')
    sub.__path__=[str(RUNTIME)]
    sys.modules['ardrec']=pkg
    sys.modules['ardrec.coordination']=sub
    for name in ('r135_root_transaction','r136_operational_semantics',
                 'r139_independent_release_review'):
        file=RUNTIME/(name+'.py')
        spec=importlib.util.spec_from_file_location('ardrec.coordination.'+name,file)
        require(spec is not None and spec.loader is not None,'RUNTIME_MODULE_LOAD_INVALID')
        m=importlib.util.module_from_spec(spec)
        sys.modules[spec.name]=m
        spec.loader.exec_module(m)
    r139=sys.modules['ardrec.coordination.r139_independent_release_review']
    return manifest,manifest_raw,engine,r139

def key_pins(engine,policies):
    members=[]
    for name,field in (('root_trust','grant_signer'),
         ('scope_trust','scope_signer'),('pilot_trust','pilot_signer'),
         ('window_trust','window_signer'),('traffic_trust','traffic_signer'),
         ('release_trust','release_signer')):
        doc=engine.parse(policies[name])
        require(field in doc and 'revocation_signer' in doc,
                'OPERATIONAL_TRUST_SIGNER_MISSING')
        members.extend((doc[field],doc['revocation_signer']))
    return (tuple(sha(engine.signer(s)) for s in members),
            tuple(s['key_id'] for s in members))

def load_documents(engine):
    payload={}
    for role,items in (('B4',engine.B4),('B9',engine.B9)):
        folder=DROP/role
        require({x.name for x in folder.iterdir()}==set(items),
                'ROOT_PAYLOAD_FILE_SCOPE_CHANGED')
        for item in items:
            payload[role+'/'+item]=secure_file(folder/item)
    external={name:secure_file(Path(path)) for name,path in POLICY.items()}
    return payload,external

def installation_gate(manifest,manifest_raw,engine,r139,phase):
    """Re-read trust and all live revocations BEFORE every irreversible phase."""
    head=manifest['approved_head']
    tree=manifest['approved_tree']
    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    now=datetime.now(timezone.utc)
    payload,policies=load_documents(engine)
    reviewed=engine.validate_payload(payload,head)
    source_b4=payload['B4/root-controller.py']
    source_b9=payload['B9/root-executor.py']
    release=r139.review(payload=payload,
       external={k:v for k,v in policies.items()
                 if k not in ('release_trust','release_revocation')},
       release_trust=policies['release_trust'],
       release_revocation=policies['release_revocation'],
       f8_reference=secure_file(F8_REFERENCE),
       b4_source=source_b4,b9_source=source_b9,
       head=head,boot_id=boot_id,now=now)
    require(release['release_signed_semantics']=='PASS' and
            release['operational_signed_semantics']=='PASS',
            'SIGNED_RELEASE_NOT_ACREDITED')
    require(sha(secure_file(GUARD))==engine.GUARD_SHA and
            sha(secure_file(F3))==engine.F3_SHA,
            'R116_PIN_INVALID')
    pins,ids=key_pins(engine,policies)
    permit=engine.verified_install_permit(
       trust_raw=secure_file(TRUST),permit_raw=secure_file(PERMIT),
       revocation_raw=secure_file(REVOCATION),head=head,tree=tree,
       inventory_sha256=reviewed['inventory_sha256'],
       boot_id=boot_id,now=now,agent_bundle_sha256=sha(manifest_raw),
       other_signers=pins,other_signer_ids=ids)
    require(permit['p8']=='NO-GO' and
            permit['boot_id']==boot_id,'INSTALL_GATE_SCOPE_INVALID')
    return payload,permit,release

def run_root_install():
    manifest,manifest_raw,engine,r139=approved_runtime()
    payload,initial_permit,initial_release=installation_gate(
        manifest,manifest_raw,engine,r139,'read_only')
    original_sha=engine.sha(engine.canonical({k:engine.sha(v)
                          for k,v in sorted(payload.items())}))
    signed_evidence={
        'permit_sha256':initial_permit['permit_sha256'],
        'agent_bundle_sha256':initial_permit['agent_bundle_sha256'],
        'release_sha256':initial_release['release_sha256'],
        'initial_revocation_sha256':initial_permit['revocation_sha256'],
    }
    def authorize(phase,plan):
        latest,permit,release=installation_gate(manifest,manifest_raw,engine,r139,phase)
        digest=engine.sha(engine.canonical({k:engine.sha(v)
                           for k,v in sorted(latest.items())}))
        require(digest==original_sha and plan['inventory_sha256']==digest and
                permit['permit_sha256']==signed_evidence['permit_sha256'] and
                release['release_sha256']==signed_evidence['release_sha256'] and
                permit['agent_bundle_sha256']==signed_evidence['agent_bundle_sha256'],
                'SIGNED_EVIDENCE_CHANGED_BEFORE_PHASE')
        print('R146_PHASE_AUTHORIZED='+phase,flush=True)
        return True
    result=engine.transact(state_dir=STATE,root_parent=PARENT,
         payload=payload,head=manifest['approved_head'],
         tree=manifest['approved_tree'],
         boot_id=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip(),
         authorize=authorize,install_evidence=signed_evidence)
    require(result['status'] in ('INSTALLED_B4_B9_VERIFIED',
                                'ALREADY_INSTALLED_VERIFIED'), 'INSTALL_UNVERIFIED')
    print('R146_RESULT='+result['status'])
    print('R146_RECEIPT_SHA256='+result['receipt_sha256'])
    print('R146_ROOT_INSTALL=AUTHENTICATED_B4_B9_ONLY')
    print('R146_TRAFFIC=0 R146_VM_STARTS=0 A6=ND P8=NO-GO')

def main():
    ap=argparse.ArgumentParser()
    g=ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--capabilities',action='store_true')
    g.add_argument('--install',action='store_true')
    args=ap.parse_args()
    if args.capabilities:
        print('R146_AGENT=SOURCE_CANDIDATE')
        print('R146_EXTERNAL_BOOTSTRAP_REQUIRED=TRUE')
        print('R146_RUNNING_ROOT_INSTALL=NO')
        print('R146_A6=ND R146_P8=NO-GO')
        return 0
    try:
        run_root_install()
        return 0
    except (Stop,ValueError,TypeError,KeyError,OSError,RuntimeError,ImportError) as exc:
        print('R146_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R146_TRAFFIC=0 R146_VM_STARTS=0 P8=NO-GO')
        return 23

if __name__=='__main__':raise SystemExit(main())
