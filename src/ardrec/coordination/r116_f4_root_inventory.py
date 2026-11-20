"""R116-F4 conservative *read-only* inventory of the root pilot prerequisites.

An observed path is not an authorization, actual DENY measurement, or root attestation.
Never invoke stage-root, --arm-deny, nftables, virsh or sockets from this module.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA='ARDREC-R116-F4-ROOT-READONLY-INVENTORY-v1'
ROOT_FILES={
 'R113_GUARD':'/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py',
 'R114_FTP_DATA':'/var/lib/ardrec/r114-f5-ftp-t01-root-v1/root-window.py',
 'R116_F1_GUARD':'/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py',
 'R116_F1_MANIFEST':'/var/lib/ardrec/r116-f1-five-one-deny-v1/manifest.json',
 'R116_F3_CONTROLLER':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/root-pilot.py',
 'R116_F3_MANIFEST':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/manifest.json',
 'SCOPE_TRUST':'/etc/ardrec/r115-ftp-t01-trust-v1.json',
 'SCOPE_REVOCATION':'/etc/ardrec/r115-ftp-t01-revocation-v1.json',
 'PILOT_TRUST':'/etc/ardrec/r115-p7-pilot-trust-v1.json',
 'PILOT_REVOCATION':'/etc/ardrec/r115-p7-pilot-revocation-v1.json',
 'F3_SCOPE_DOCUMENT':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/scope-authorization.json',
 'F3_PILOT_DOCUMENT':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/pilot-permit.json',
 'F3_CONTRACT_DOCUMENT':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/contract.json',
 'F3_BOOT_REFERENCE':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/ftp-boot-paths.json',
}
ROOT_DIRS={
 'R113_STAGE':'/var/lib/ardrec/r113-six-deny-guard-v1',
 'R114_STAGE':'/var/lib/ardrec/r114-f5-ftp-t01-root-v1',
 'F1_STAGE':'/var/lib/ardrec/r116-f1-five-one-deny-v1',
 'F3_STAGE':'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1',
}
SHA_RE=re.compile('[0-9a-f]{64}\\Z')
class Stop(ValueError):pass

def canonical(obj):
    return (json.dumps(obj,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')

def sha(raw):return hashlib.sha256(raw).hexdigest()

def inspect_node(path,*,directory=False,stat_reader=os.lstat):
    """Metadata-only with lstat; never follows or opens privileged paths."""
    try:
        s=stat_reader(path)
    except FileNotFoundError:
        return 'ABSENT'
    except (PermissionError,OSError):
        return 'UNKNOWN_ACCESS'
    if stat.S_ISLNK(s.st_mode):return 'REJECT_SYMLINK'
    if directory:
        if not stat.S_ISDIR(s.st_mode):return 'REJECT_TYPE'
        if s.st_uid!=0 or bool(s.st_mode&0o022):return 'REJECT_OWNER_PERMISSIONS'
        return 'PRESENT_METADATA_ONLY'
    if not stat.S_ISREG(s.st_mode):return 'REJECT_TYPE'
    if s.st_uid!=0 or bool(s.st_mode&0o022) or s.st_nlink!=1:
        return 'REJECT_OWNER_PERMISSIONS'
    return 'PRESENT_METADATA_ONLY'

def inventory(*,stat_reader=os.lstat):
    paths={k:inspect_node(v,stat_reader=stat_reader) for k,v in ROOT_FILES.items()}
    dirs={k:inspect_node(v,directory=True,stat_reader=stat_reader) for k,v in ROOT_DIRS.items()}
    # Keep any missing, inaccessible or unsafe path as an explicit blocker.
    blockers=[f'ROOT_FILE_{k}_{v}' for k,v in paths.items() if v!='PRESENT_METADATA_ONLY']
    blockers += [f'ROOT_DIR_{k}_{v}' for k,v in dirs.items() if v!='PRESENT_METADATA_ONLY']
    # Even when all paths exist, metadata is not trusted content or authority.
    blockers += ['NO_INDEPENDENT_LIVE_SIGNATURE_OR_REVOCATION_VERIFICATION',
                 'NO_PHYSICAL_FIVE_ONE_DENY_OR_BOOT_CHAIN_ATTESTATION',
                 'NO_WATCHDOG_KILL_AND_TIMEOUT_PHYSICAL_PROOF',
                 'ROOT_STAGE_CONTENTS_NOT_VERIFIED_BY_METADATA',
                 'FTP_T01_PHYSICAL_PILOT_NOT_EXECUTED']
    return {'schema':SCHEMA,'files':paths,'directories':dirs,
            'blockers':sorted(blockers),'root_metadata_only':True,
            'root_commands_invoked':0,'network_connections':0,'vm_starts':0,
            'root_stage_performed':False,'watchdog_armed':False,
            'physical_authority_verified':False,'deny_physically_attested':False,
            'physical_pilot_performed':False,'a6':'ND','p7':'DRAFT_NOT_CALIBRATED',
            'p8':'NO-GO','result':'NO-GO'}

def check_source_lock(*,repo:Path,source_lock:dict):
    """Recheck signed F3 transitive file hashes against bytes on disk.

    Signature and HEAD binding are separate responsibilities of the installer.
    """
    if type(source_lock) is not dict or source_lock.get('p8')!='NO-GO' or not source_lock.get('root_source_only') is True or source_lock.get('window_seconds')!=60:
        raise Stop('ROOT_LOCK_SCHEMA_INVALID')
    files=source_lock.get('files')
    if type(files) is not dict or len(files)!=31:
        raise Stop('ROOT_LOCK_FILE_COUNT')
    if source_lock.get('catalog_sha256')!='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e':
        raise Stop('CATALOG_LOCK_INVALID')
    for key,value in files.items():
        if type(key) is not str or type(value) is not str or not SHA_RE.fullmatch(value):
            raise Stop('SOURCE_PIN_NOT_VALID')
        if key=='root-pilot.py':p=repo/'scripts/ardrec_p14_r116_f3_root_pilot.py'
        elif re.fullmatch(r'runtime/ardrec/(coordination|evidence)/[a-z0-9_]+\.py',key):
            p=repo/'src'/key.removeprefix('runtime/')
        else:raise Stop('SOURCE_LOCK_PATH_INVALID')
        if not p.is_file() or p.is_symlink() or sha(p.read_bytes())!=value:
            raise Stop('SOURCE_HASH_MISMATCH_'+key)
    return len(files)

def report(*,repo:Path,stat_reader=os.lstat):
    lockfile=repo/'lab/operational-controller/r116-f3-root-source-lock-v1.json'
    if lockfile.is_symlink() or not lockfile.is_file():raise Stop('ROOT_LOCK_MISSING')
    lock=json.loads(lockfile.read_bytes())
    count=check_source_lock(repo=repo,source_lock=lock)
    r=inventory(stat_reader=stat_reader)
    r['source_pins_verified']=count
    r['source_lock_sha256']=sha(lockfile.read_bytes())
    r['signature_verified_by_this_module']=False
    r['catalog_sha256']=lock['catalog_sha256']
    return r
