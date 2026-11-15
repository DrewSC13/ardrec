"""P14 R47: define two *new, unused* R45 nwfilters only; never attach or send traffic.

Transition to traffic is NOT implemented here. Existing R33 shared filter and R34
nft guard remain unchanged. Partial failure is preserved; never auto-retry.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable
from xml.etree import ElementTree as ET

from ardrec.coordination import r45_ssh_positive_candidate as r45
from ardrec.coordination import r46_ssh_transition_audit as r46

BASE_MAIN = 'e659f0b76582236c0061960975027f3830cd59df'
R45_PIN = '3ddca2761bd4ca2d4244afa962bec305e68985466687824fa6ddd9db93bdceb3'
R46_PIN = '6cbe72db1b93f6ce33b63d6337d808f583a30944fa327b1a46c9b01f18284abb'
SCHEMA = 'ardrec-p14-r47-new-unused-ssh-nwfilter-staging-v1'
FILTER_FILES = (('ssh-nwfilter-candidate.xml', r45.FILTER_SSH),
                ('runner-ssh-nwfilter-candidate.xml', r45.FILTER_RUNNER))
RECEIPT_NAME = 'r47-stage-verified.json'
INTENT_NAME = 'r47-stage-intent.json'
SUMS = 'SHA256SUMS'
MAX_OUT = 131072

class R47Error(ValueError):
    pass

def need(cond: bool, code: str) -> None:
    if not cond: raise R47Error(code)

def canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('ascii')

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def _new_private_root(path: Path) -> None:
    need(isinstance(path, Path) and path.is_absolute() and
         re.fullmatch(r'r47-filter-stage-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}', path.name) is not None and
         not path.exists() and
         not any(x.is_symlink() for x in (path, *path.parents)), 'private_stage_path_invalid')
    parent=path.parent
    need(parent.is_dir() and parent.stat().st_uid==os.getuid() and
         stat.S_IMODE(parent.stat().st_mode)==0o700,'private_parent_required')

def _write(path: Path, raw: bytes) -> None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def _load_snapshot(r46_dir: Path) -> dict[str, bytes]:
    result = {}
    for name in r46.SNAPSHOTS:
        p=r46_dir/name
        need(not p.is_symlink() and p.is_file() and p.stat().st_mode&0o077==0,
             'source_snapshot_invalid_'+name)
        result[name]=p.read_bytes()
    return result

def _sources(r45_dir: Path, r46_dir: Path) -> dict[str,bytes]:
    need(r45.verify_directory(r45_dir)['sha256']==R45_PIN,'r45_receipt_drift')
    need(r46.verify_receipt(r46_dir,r45_dir)['sha256']==R46_PIN,'r46_receipt_drift')
    original=_load_snapshot(r46_dir)
    r46.verify_live_observation(original,r45_dir)
    return original

def _before_live(r45_dir: Path, original: dict[str,bytes], capture: Callable[[],dict[str,bytes]]) -> dict[str,bytes]:
    latest=capture()
    r46.verify_live_observation(latest,r45_dir)
    # Everything but counters must match the source snapshot (including inactive XMLs).
    for name in ('ssh-inactive.xml','runner-inactive.xml','r33-deny-nwfilter.xml',
                 'nwfilter-list.txt','bridge-ipv4.txt','vm-states.json'):
        need(latest[name]==original[name],'live_drift_'+name)
    r46.verify_nft_guard(latest['r34-bridge-deny.txt'])
    return latest

def _tree(raw: bytes) -> tuple:
    need(type(raw) is bytes and len(raw)<=16384, 'filter_xml_size')
    try: root=ET.fromstring(raw)
    except ET.ParseError as exc: raise R47Error('filter_xml_invalid') from exc
    def rec(el: ET.Element) -> tuple:
        return (el.tag,tuple(sorted(el.attrib.items())),(el.text or '').strip(),
                tuple(rec(x) for x in el))
    return rec(root)

def _check_definition(actual: bytes, expected: bytes) -> None:
    need(_tree(actual)==_tree(expected),'libvirt_filter_definition_drift')

def _host_call(argv: list[str], *, run: Callable[...,Any]) -> bytes:
    # Only fixed host operations; no shell, no service/network/guest operations.
    try:
        proc=run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE,timeout=18,check=False,close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise R47Error('host_call_unavailable') from exc
    need(type(proc.returncode) is int and proc.returncode==0 and
         type(proc.stdout) is bytes and type(proc.stderr) is bytes and
         len(proc.stdout)<=MAX_OUT and len(proc.stderr)<=4096,
         'host_call_failed_'+argv[-2][:40])
    return proc.stdout

def _virsh_cmd(*argv: str) -> list[str]:
    # Absolute paths make the permitted operation unambiguous.
    return ['/usr/bin/sudo','-n','--','/usr/bin/virsh','-c','qemu:///system',*argv]

def _live_ssh_filter(run:Callable[...,Any]) -> None:
    # R46 only audits inactive XML. A running SSH VM must keep the R33 filter
    # in *live* config as well; otherwise 'unused' would be an ungrounded claim.
    cmd=['/usr/bin/sudo','-n','--','/usr/bin/virsh','--readonly','-c',
         'qemu:///system','dumpxml',r46.SSH_DOMAIN]
    raw=_host_call(cmd,run=run)
    try: root=ET.fromstring(raw)
    except ET.ParseError as exc: raise R47Error('ssh_live_xml_invalid') from exc
    interfaces=root.findall('./devices/interface')
    need(root.findtext('name')==r46.SSH_DOMAIN and len(interfaces)==1 and
         interfaces[0].find('mac') is not None and
         interfaces[0].find('mac').get('address')==r45.SOURCE_MAC and
         interfaces[0].find('target') is not None and
         interfaces[0].find('target').get('dev')==r45.SSH_TAP and
         interfaces[0].find('filterref') is not None and
         interfaces[0].find('filterref').get('filter')==r46.OLD_FILTER,
         'ssh_live_filter_or_identity_drift')

def _inventory_without_new(data: bytes) -> bytes:
    lines=data.splitlines(keepends=True)
    for name in (r45.FILTER_SSH,r45.FILTER_RUNNER):
        lines=[x for x in lines if not x.rstrip().endswith(name.encode('ascii'))]
    return b''.join(lines)

def _after_live(original: dict[str,bytes], capture: Callable[[],dict[str,bytes]],
                r45_dir: Path, run: Callable[...,Any]) -> dict[str,bytes]:
    now=capture()
    _live_ssh_filter(run)
    need(set(now)==set(r46.SNAPSHOTS),'post_host_snapshot_set')
    for name in ('ssh-inactive.xml','runner-inactive.xml','r33-deny-nwfilter.xml',
                 'bridge-ipv4.txt','vm-states.json'):
        need(now[name]==original[name],'post_host_drift_'+name)
    r46.verify_original_filter(now['r33-deny-nwfilter.xml'])
    r46.verify_nft_guard(now['r34-bridge-deny.txt'])
    need(_inventory_without_new(now['nwfilter-list.txt'])==original['nwfilter-list.txt'],
         'post_filter_inventory_unexpected')
    for fname, name in FILTER_FILES:
        need(now['nwfilter-list.txt'].count(name.encode())==1,
             'post_filter_not_exclusive_'+name)
        actual=_host_call(_virsh_cmd('nwfilter-dumpxml',name),run=run)
        expected=(r45_dir/fname).read_bytes()
        _check_definition(actual,expected)
    return now

def plan(r45_dir:Path,r46_dir:Path)->dict:
    original=_sources(r45_dir,r46_dir)
    out={
      'schema':SCHEMA, 'source_main':BASE_MAIN,'source_r45_sha256':R45_PIN,
      'source_r46_sha256':R46_PIN,
      'status':'READY_FOR_EXPLICIT_UNUSED_NWFILTER_STAGE',
      'only_new_filter_names':[x[1] for x in FILTER_FILES],
      'original_state':json.loads(original['vm-states.json']),
      'original_snapshot_sha256':{n:sha(raw) for n,raw in sorted(original.items())},
      'definitions_sha256':{f:sha((r45_dir/f).read_bytes()) for f,_ in FILTER_FILES},
      'host_filter_additions_applied':False,
      'shared_r33_filter_modified':False,'r34_guard_modified':False,
      'vm_defined_or_started':False,'packets_sent':False,
      'operational_dispatch':False,'isolation_proven':False,
      'restoration_tested':False,'p8_operational':'NO-GO',
    }
    out['sha256']=sha(canon(out))
    return out

def stage(r45_dir: Path,r46_dir:Path,root:Path,
          *, capture:Callable[[],dict[str,bytes]]|None=None,
          run:Callable[...,Any]=subprocess.run)->dict:
    _new_private_root(root)
    original=_sources(r45_dir,r46_dir)
    if capture is None: capture=r46.capture_host
    _before_live(r45_dir,original,capture)
    _live_ssh_filter(run)
    stamp=plan(r45_dir,r46_dir)
    root.mkdir(mode=0o700)
    # The intent is durable BEFORE the first libvirt mutation.
    _write(root/INTENT_NAME,canon(stamp)+b'\n')
    for index,(fname,name) in enumerate(FILTER_FILES):
        _host_call(_virsh_cmd('nwfilter-define',str(r45_dir/fname)),run=run)
        # Must be able to read back exact semantic rules before second define.
        actual=_host_call(_virsh_cmd('nwfilter-dumpxml',name),run=run)
        _check_definition(actual,(r45_dir/fname).read_bytes())
        _write(root/f'r47-defined-{index+1}.json',canon({'filter':name,'sha256':sha(actual)})+b'\n')
    after=_after_live(original,capture,r45_dir,run)
    document={**stamp,
              'status':'STAGED_NEW_UNUSED_FILTERS_ONLY_NO_GO',
              'host_filter_additions_applied':True,
              'filter_readback':{'inventory':sha(after['nwfilter-list.txt'])},
              'isolation_proven':False,
              'shared_r33_filter_modified':False,'r34_guard_modified':False,
              'vm_defined_or_started':False,'packets_sent':False,
              'operational_dispatch':False,'p8_operational':'NO-GO'}
    document.pop('sha256')
    document['sha256']=sha(canon(document))
    _write(root/RECEIPT_NAME,canon(document)+b'\n')
    files=[INTENT_NAME,'r47-defined-1.json','r47-defined-2.json',RECEIPT_NAME]
    _write(root/SUMS,(''.join(f'{sha((root/n).read_bytes())}  {n}\n' for n in sorted(files))).encode('ascii'))
    return document

def verify_receipt(r45_dir:Path,r46_dir:Path,root:Path,
                   *, capture:Callable[[],dict[str,bytes]]|None=None,
                   run:Callable[...,Any]=subprocess.run)->dict:
    _new_private_root_for_verify(root)
    original=_sources(r45_dir,r46_dir)
    if capture is None:capture=r46.capture_host
    after=_after_live(original,capture,r45_dir,run)
    expected={INTENT_NAME,'r47-defined-1.json','r47-defined-2.json',RECEIPT_NAME,SUMS}
    need({x.name for x in root.iterdir()}==expected,'receipt_file_set_invalid')
    data={}
    for name in expected:
        p=root/name; st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==os.getuid(),
             'receipt_file_insecure_'+name)
        data[name]=p.read_bytes()
    need(data[SUMS]==(''.join(f'{sha(data[n])}  {n}\n' for n in sorted(expected-{SUMS}))).encode('ascii'),
         'receipt_sums_invalid')
    source=plan(r45_dir,r46_dir)
    need(data[INTENT_NAME]==canon(source)+b'\n','intent_source_invalid')
    for i,(fname,name) in enumerate(FILTER_FILES,1):
        doc=json.loads(data[f'r47-defined-{i}.json'])
        actual=_host_call(_virsh_cmd('nwfilter-dumpxml',name),run=run)
        _check_definition(actual,(r45_dir/fname).read_bytes())
        need(doc['filter']==name and type(doc['sha256']) is str and
             doc['sha256']==sha(actual), 'filter_operation_receipt_invalid')
    report=json.loads(data[RECEIPT_NAME])
    need(report.get('status')=='STAGED_NEW_UNUSED_FILTERS_ONLY_NO_GO' and
         report.get('host_filter_additions_applied') is True and
         report.get('filter_readback')=={'inventory':sha(after['nwfilter-list.txt'])} and
         all(report.get(k) is False for k in ('shared_r33_filter_modified','r34_guard_modified',
                 'vm_defined_or_started','packets_sent','operational_dispatch','isolation_proven')) and
         report.get('p8_operational')=='NO-GO' and
         report.get('sha256')==sha(canon({k:v for k,v in report.items() if k!='sha256'})),
         'staged_receipt_invalid')
    need(report['source_r46_sha256']==R46_PIN and report['source_r45_sha256']==R45_PIN,
         'receipt_source_mismatch')
    return report

def _new_private_root_for_verify(root:Path)->None:
    need(root.is_absolute() and root.is_dir() and
         re.fullmatch(r'r47-filter-stage-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}',root.name) is not None and
         not any(x.is_symlink() for x in (root,*root.parents)) and
         root.stat().st_uid==os.getuid() and stat.S_IMODE(root.stat().st_mode)==0o700 and
         stat.S_IMODE(root.parent.stat().st_mode)==0o700,'receipt_root_insecure')
