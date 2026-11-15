"""ARDREC P14 R55.6: validated root staging of R55.5 deny-only recovery.

Pure functions only. Root installation is separate, explicitly authorized, and
NEVER arms systemd or changes network/filter configuration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from ardrec.coordination import r555_recovery_contract as r555

SCHEMA = 'ardrec-p14-r556-root-stage-v1'
BASE = 'cb23f6a47d3d9f02ce720ec59fbdffc5c7421ece'
PREPARED = Path('/home/cicada/ardrec-lab/r55-recovery-preparation/r555-prepared-20261115T170340Z-5617')
DEST = Path(r555.ROOT_DIR)
PARENT = DEST.parent
RECEIPTS = Path('/home/cicada/ardrec-lab/r56-root-stage')
CONTENTS = frozenset((*r555.PAYLOADS, 'manifest.json', 'contract.json', 'SHA256SUMS'))
ROOT_FILES = frozenset((*r555.PAYLOADS, 'manifest.json'))
HASH = re.compile('[0-9a-f]{64}\\Z')
FILENAME = re.compile('[a-zA-Z0-9_.-]+\\Z')
AUTHORIZATION = 'AUTORIZO_R556_INSTALAR_ROOT_SIN_TIMER'

class StageError(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise StageError(code)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def canonical(doc: dict) -> bytes:
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                       allow_nan=False)+'\n').encode('ascii')

def _no_symlinks(path: Path) -> None:
    require(path.is_absolute(), 'path_not_absolute')
    for node in (path,*path.parents):
        require(not node.is_symlink(), 'path_contains_symlink')

def verify_private_material(folder: Path, *, helper_bytes: bytes) -> dict[str,bytes]:
    """Validate exact R55.5 evidence, contents and private file ownership/mode."""
    require(folder == PREPARED, 'unexpected_source_receipt')
    _no_symlinks(folder)
    s=folder.stat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
            stat.S_IMODE(s.st_mode) == 0o700, 'source_directory_not_private')
    require({p.name for p in folder.iterdir()} == CONTENTS, 'source_file_inventory_drift')
    data={}
    for name in CONTENTS:
        p=folder/name
        st=p.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
                st.st_size <= 262144, 'unsafe_source_file_'+name)
        data[name]=p.read_bytes()
    lines=data['SHA256SUMS'].decode('ascii').splitlines()
    entries={}
    for line in lines:
        require(len(line)>66 and line[64:66]=='  ' and HASH.fullmatch(line[:64]) is not None,
                'checksum_format_drift')
        name=line[66:]
        require(name in CONTENTS-{'SHA256SUMS'} and FILENAME.fullmatch(name) is not None
                and name not in entries,'checksum_filename_drift')
        entries[name]=line[:64]
    require(set(entries)==CONTENTS-{'SHA256SUMS'} and
            all(sha(data[n])==entries[n] for n in entries), 'sha256_receipt_mismatch')
    require(sha(helper_bytes)==r555.ROOT_HELPER_SHA256, 'checkout_helper_changed')
    require(data['root-recover.py']==helper_bytes, 'helper_not_exact_checkout')
    root_manifest = json.loads(data['manifest.json'])
    require(type(root_manifest) is dict and
            root_manifest.get('schema')==r555.SCHEMA and
            root_manifest.get('source_main')==r555.SOURCE_MAIN and
            root_manifest.get('r552_plan_sha256')==r555.PLAN_SHA and
            root_manifest.get('permission')=='DENY_ONLY_RESTORATION' and
            root_manifest.get('traffic_allowed') is False and
            root_manifest.get('p8_operational')=='NO-GO' and
            type(root_manifest.get('sha256')) is dict and
            set(root_manifest['sha256'])==set(r555.PAYLOADS),
            'manifest_authority_changed')
    require(all(root_manifest['sha256'][n]==sha(data[n]) for n in r555.PAYLOADS),
            'manifest_file_digest_drift')
    from ardrec.coordination import r553_transition_guard as r553
    require(data['r34-deny-restore.nft']==r553.expected_nft(allow=False),
            'restore_not_exact_r553_deny')
    for role in ('ssh','runner'):
        before=data[role+'-original.xml']
        after=data[role+'-candidate.xml']
        try:
            valid=(r553.binding_identity(before,role=role,candidate=False)==
                   r553.binding_identity(after,role=role,candidate=True))
        except (ValueError, TypeError) as exc:
            raise StageError('binding_rejected_'+role) from exc
        require(valid, 'binding_identity_drift_'+role)
    doc=json.loads(data['contract.json'])
    require(doc==r555.obligations(), 'r555_contract_drift')
    return {name:data[name] for name in sorted(ROOT_FILES)}

def root_install_commands(source: Path, *, dest: Path=DEST) -> list[list[str]]:
    require(source==PREPARED and dest==DEST, 'install_paths_not_pinned')
    _no_symlinks(source)
    require(dest.parent==PARENT, 'root_parent_changed')
    result=[['/usr/bin/install','-d','-m','0700','-o','0','-g','0',str(PARENT)],
            ['/usr/bin/install','-d','-m','0700','-o','0','-g','0',str(DEST)]]
    for name in sorted(ROOT_FILES):
        result.append(['/usr/bin/install','-m','0600','-o','0','-g','0','--',
                       str(source/name),str(dest/name)])
    return result

def verify_install_commands(cmds: list[list[str]], source: Path, dest: Path=DEST) -> None:
    require(type(cmds) is list and cmds==root_install_commands(source,dest=dest),
            'install_argv_changed')
    require(len(cmds)==9 and all(row[0]=='/usr/bin/install' for row in cmds),
            'unexpected_root_program')

def system_timer_preview(unit: str, seconds: int = 60) -> list[str]:
    """Reference only; R55.6 never calls this command."""
    return r555.watchdog_argv(unit, seconds)

def stage_report(bundle: dict[str,bytes], *, staged: bool=False, checked: bool=False) -> dict:
    require(type(staged) is bool and type(checked) is bool and
            (staged or not checked), 'stage_report_flags_invalid')
    return {'schema':SCHEMA,'source_main':BASE,'r555_source':str(PREPARED),
            'root_target':str(DEST),'file_sha256':{n:sha(bundle[n]) for n in sorted(bundle)},
            'root_stage_attempted':staged,'root_bundle_check_pass':checked,
            'system_timer_armed':False,'firewall_mutations':0,'libvirt_mutations':0,
            'packets_injected':0,'physical_restore_tested':False,
            'traffic_authorized':False,'p8_operational':'NO-GO'}
