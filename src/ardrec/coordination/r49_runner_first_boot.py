"""P14 R49: guarded runner SSH-only domain definition and isolated first boot.

Only two separately authorized host mutations exist: libvirt domain `define`
and libvirt domain `start`. No guest commands, packet probes, nft edits or
operational dispatch. Original R33 and R34 must remain in full denial.
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

from ardrec.coordination import r33_offline_topology as r33
from ardrec.coordination import r45_ssh_positive_candidate as r45
from ardrec.coordination import r46_ssh_transition_audit as r46
from ardrec.coordination import r47_filter_stage as r47
from ardrec.coordination import r48_runner_cow_stage as r48

BASE_MAIN = 'f321970709a36e1414e700af0d52e8e5e60ebb3f'
R45_PIN = r48.R45_PIN
R46_PIN = r48.R46_PIN
R47_PIN = r48.R47_PIN
R48_PIN = 'c2a1c76239554eee224f8c188c0a517ae738bb469bbd2bfa27a79004ad22fba8'
SCHEMA = 'ardrec-p14-r49-runner-ssh-only-first-boot-v1'
SSH = r46.SSH_DOMAIN
RUNNER = r46.RUNNER_DOMAIN
FTP = 'ardrec-r33-dev-ftp'
SMB = 'ardrec-r33-dev-smb'
NETWORK_SSH = 'ardrec-r33-dev-net-ssh'
NETWORK_FTP = 'ardrec-r33-dev-net-ftp'
NETWORK_SMB = 'ardrec-r33-dev-net-smb'
DEFINITION_FILES = ('r49-define-intent.json', 'runner-original-inactive.xml',
                    'runner-defined-inactive.xml', 'r49-define-verified.json')
BOOT_FILES = ('r49-boot-intent.json', 'r49-boot-verified.json')
RESTORE_FILES = ('r49-restore-intent.json', 'runner-restored-inactive.xml',
                 'r49-restore-verified.json')
MAX_OUT = 131072

class R49Error(ValueError):
    pass

def need(condition: bool, reason: str) -> None:
    if not condition:
        raise R49Error(reason)

def canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _host(argv: list[str], *, run: Callable[..., Any] = subprocess.run) -> bytes:
    need(len(argv) >= 5 and argv[:3] == ['/usr/bin/sudo', '-n', '--'], 'host_command_invalid')
    try:
        p = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=45, close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise R49Error('host_command_unavailable') from ex
    need(type(p.returncode) is int and p.returncode == 0 and
         type(p.stdout) is bytes and len(p.stdout) <= MAX_OUT and
         type(p.stderr) is bytes and len(p.stderr) <= 4096,
         'host_command_failed_' + argv[-1][-48:])
    return p.stdout

def _virsh(*args: str, readonly: bool = True) -> list[str]:
    prefix = ['/usr/bin/sudo', '-n', '--', '/usr/bin/virsh']
    if readonly:
        prefix.append('--readonly')
    return prefix + ['-c', 'qemu:///system', *args]

def _nft() -> list[str]:
    return ['/usr/bin/sudo', '-n', '--', r46._which('nft', ('/usr/sbin/nft','/usr/bin/nft')), '-a', 'list',
            'table', 'bridge', r34_table()]

def r34_table() -> str:
    return 'ardrec_r34_guard'

def _state(raw: bytes) -> str:
    need(len(raw) < 128, 'vm_state_size')
    text = raw.decode('utf-8').strip().casefold()
    if text in ('running', 'ejecutando'):
        return 'RUNNING'
    if text in ('shut off', 'apagado'):
        return 'SHUTOFF'
    raise R49Error('unexpected_domain_state')

def _capture(*, run: Callable[..., Any] = subprocess.run,
             include_runner_live: bool = False) -> dict[str, bytes]:
    """Read only the pinned VMs, policies, active-net list and SSH bridge."""
    commands = {
        'ssh-inactive.xml': _virsh('dumpxml', '--inactive', SSH),
        'runner-inactive.xml': _virsh('dumpxml', '--inactive', RUNNER),
        'ssh-live.xml': _virsh('dumpxml', SSH),
        'r33-deny-nwfilter.xml': _virsh('nwfilter-dumpxml', r33.DENY_FILTER),
        'nwfilter-list.txt': _virsh('nwfilter-list'),
        'r34-bridge-deny.txt': _nft(),
        'bridge-ipv4.txt': ['/usr/bin/sudo','-n','--',r46._which('ip', ('/usr/sbin/ip','/usr/bin/ip')), '-o','-4','addr', 'show','dev','br33d30'],
        'active-networks.txt': _virsh('net-list', '--name'),
    }
    if include_runner_live:
        commands['runner-live.xml'] = _virsh('dumpxml', RUNNER)
    result = {name: _host(args, run=run) for name, args in commands.items()}
    states = {name: _state(_host(_virsh('domstate', name), run=run))
              for name in (SSH, RUNNER, FTP, SMB)}
    result['vm-states.json'] = canon(states) + b'\n'
    return result

def _xml(raw: bytes) -> ET.Element:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_OUT, 'domain_xml_length')
    try:
        return ET.fromstring(raw)
    except ET.ParseError as ex:
        raise R49Error('domain_xml_invalid') from ex

def _check_runner_domain(raw: bytes) -> None:
    """Accept libvirt XML normalization, but not identity/device/filter drift."""
    root = _xml(raw)
    baseline = _xml(r48.runner_domain_candidate())
    def memory_bytes(domain: ET.Element) -> int:
        memory = domain.find('memory')
        need(memory is not None and memory.text is not None, 'memory_missing')
        value = int(memory.text.strip())
        multiplier = {'KiB':1024, 'MiB':1024**2, 'GiB':1024**3, 'B':1}
        unit = memory.get('unit', 'KiB')
        need(unit in multiplier, 'unknown_memory_unit')
        return value * multiplier[unit]
    need(root.tag == 'domain' and root.get('type') == 'kvm' and
         root.findtext('name') == baseline.findtext('name') and
         root.findtext('uuid') == baseline.findtext('uuid') and
         root.findtext('vcpu') == baseline.findtext('vcpu') and
         memory_bytes(root) == memory_bytes(baseline) and
         root.find('currentMemory') is not None and
         baseline.find('currentMemory') is not None and
         int(root.findtext('currentMemory')) * {'KiB':1024,'MiB':1024**2,'GiB':1024**3,'B':1}.get(root.find('currentMemory').get('unit','KiB'),0) ==
         int(baseline.findtext('currentMemory')) * {'KiB':1024,'MiB':1024**2,'GiB':1024**3,'B':1}.get(baseline.find('currentMemory').get('unit','KiB'),0) and
         root.findtext('on_reboot') == 'destroy', 'runner_domain_identity_drift')
    disks = root.findall('./devices/disk')
    need(len(disks) == 1 and disks[0].get('type') == 'file' and
         disks[0].get('device') == 'disk' and
         disks[0].find('driver') is not None and
         disks[0].find('driver').get('type') == 'qcow2' and
         disks[0].find('driver').get('cache') == 'none' and
         disks[0].find('driver').get('io') == 'native' and
         disks[0].find('source') is not None and
         disks[0].find('source').get('file') == r48.NEW_DISK and
         disks[0].find('target') is not None and
         disks[0].find('target').get('dev') == 'vda', 'runner_disk_drift')
    nic = root.findall('./devices/interface')
    need(len(nic) == 1 and nic[0].get('type') == 'network', 'runner_nic_count_drift')
    iface = nic[0]
    expected = (('mac', 'address', r45.DEST_MAC),
                ('source', 'network', NETWORK_SSH),
                ('target', 'dev', r45.RUNNER_TAP),
                ('filterref', 'filter', r33.DENY_FILTER))
    need(all(iface.find(tag) is not None and iface.find(tag).get(attr) == value
             for tag, attr, value in expected) and
         iface.find('model') is not None and
         iface.find('model').get('type') == 'virtio', 'runner_interface_drift')
    for device in ('hostdev','filesystem','redirdev','vsock','graphics','interface'):
        if device == 'interface':
            continue
        need(not root.findall('./devices/' + device), 'unexpected_device_' + device)
    need(root.find('./os/boot') is not None and
         root.find('./os/boot').get('dev') == 'hd', 'boot_order_drift')

def _check_ssh_live(raw: bytes) -> None:
    root = _xml(raw)
    iface = root.findall('./devices/interface')
    need(root.findtext('name') == SSH and len(iface) == 1, 'ssh_live_nic_drift')
    row = iface[0]
    need(all(row.find(tag) is not None and row.find(tag).get(attr) == value
             for tag,attr,value in (
                 ('mac','address',r45.SOURCE_MAC),
                 ('source','network',NETWORK_SSH),
                 ('target','dev',r45.SSH_TAP),
                 ('filterref','filter',r33.DENY_FILTER))), 'ssh_live_filter_drift')

def _validate_common(current: dict[str, bytes], r46dir: Path, r45dir: Path,
                     *, state: str, candidate: bool,
                     run: Callable[..., Any] = subprocess.run) -> dict[str, str]:
    expected = {SSH:'RUNNING',RUNNER:state,FTP:'SHUTOFF',SMB:'SHUTOFF'}
    try:
        states = json.loads(current['vm-states.json'])
    except (KeyError, TypeError, ValueError) as ex:
        raise R49Error('state_snapshot_invalid') from ex
    need(states == expected, 'vm_state_drift')
    r46.verify_domain(current['ssh-inactive.xml'], 'ssh')
    _check_ssh_live(current['ssh-live.xml'])
    if candidate:
        _check_runner_domain(current['runner-inactive.xml'])
        if state == 'RUNNING':
            need('runner-live.xml' in current, 'runner_live_snapshot_missing')
            _check_runner_domain(current['runner-live.xml'])
    else:
        r46.verify_domain(current['runner-inactive.xml'], 'runner')
    r46.verify_original_filter(current['r33-deny-nwfilter.xml'])
    r46.verify_nft_guard(current['r34-bridge-deny.txt'])
    need(current['bridge-ipv4.txt'].strip() == b'', 'bridge_ipv4_drift')
    live_nets = {x.strip() for x in current['active-networks.txt'].decode('utf-8').splitlines() if x.strip()}
    need(NETWORK_SSH in live_nets and NETWORK_FTP not in live_nets and
         NETWORK_SMB not in live_nets, 'network_state_drift')
    old = (r46dir / 'nwfilter-list.txt').read_bytes()
    now = current['nwfilter-list.txt']
    need(r47._inventory_without_new(now) == old, 'nwfilter_inventory_drift')
    for fname, name in r47.FILTER_FILES:
        need(now.count(name.encode('ascii')) == 1, 'nwfilter_exclusivity_drift')
        actual = _host(_virsh('nwfilter-dumpxml', name), run=run)
        r47._check_definition(actual, (r45dir / fname).read_bytes())
    return states

def _sources_before(r45dir: Path,r46dir: Path,r47dir: Path,r48dir: Path,
                    *,run: Callable[..., Any]) -> dict[str, Any]:
    need(r48.verify(r45dir,r46dir,r47dir,r48dir,run=run)['sha256'] == R48_PIN,
         'r48_receipt_or_disk_drift')
    receipt = json.loads((r48dir/'r48-stage-verified.json').read_bytes())
    return receipt

def _r48_local(r48dir: Path, *, run: Callable[..., Any], check_chain: bool = True,
               require_pristine: bool = True) -> dict[str, Any]:
    """R48's historical receipt remains valid after domain redefinition.

    R48.verify() cannot be reused after the domain transition because its R47
    predecessor intentionally requires the original three-NIC runner.
    """
    r48._private_receipt_root(r48dir, exists=True)
    names = set(r48.REC_FILES) | {'SHA256SUMS'}
    need({p.name for p in r48dir.iterdir()} == names, 'r48_receipt_file_set')
    bodies = {}
    for name in names:
        p=r48dir/name; st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.getuid() and
             stat.S_IMODE(st.st_mode) == 0o600, 'r48_receipt_file_permission')
        bodies[name] = p.read_bytes()
    sums=''.join(f'{sha(bodies[n])}  {n}\n' for n in sorted(names-{'SHA256SUMS'})).encode('ascii')
    need(bodies['SHA256SUMS'] == sums and
         bodies['runner-ssh-only-deny-r48.xml'] == r48.runner_domain_candidate(),
         'r48_receipt_hash_drift')
    intent=json.loads(bodies['r48-stage-intent.json'])
    report=json.loads(bodies['r48-stage-verified.json'])
    need(report['sha256'] == R48_PIN and report['mode'] == 'RUNNER_DISPOSABLE_COW_STAGED_NO_GO' and
         sha(canon({k:v for k,v in report.items() if k!='sha256'})) == R48_PIN and
         report['original_r32_sha256_verified_unchanged'] is True and
         report['new_disk'] == r48.NEW_DISK and
         intent['base_top_sha256'] == r48._top_hash(run) and
         intent['base_top_stat'] == r48._stat_disk(r48.TOP, run), 'r48_receipt_or_r32_drift')
    if check_chain:
        r48._chain(r48._info(r48.NEW_DISK, run),
                   (r48.NEW_DISK,r48.TOP,r48.PARENT,r48.BASE))
        if require_pristine:
            need(r48._stat_disk(r48.NEW_DISK,run) == report['new_overlay_stat'],
                 'runner_overlay_modified_before_first_boot')
        else:
            need(r48._stat_disk(r48.NEW_DISK,run)['mode'] == '600',
                 'runner_overlay_mode_drift')
    else:
        need(r48._stat_disk(r48.NEW_DISK,run)['mode'] == '600', 'runner_overlay_mode_drift')
    return report

def _private_root(path: Path, prefix: str, *, exists: bool) -> None:
    need(path.is_absolute() and re.fullmatch(prefix + r'-\d{8}T\d{6}Z-\d{1,10}', path.name) is not None and
         not any(x.is_symlink() for x in (path,*path.parents)), 'receipt_path_invalid')
    parent=path.parent
    need(parent.is_dir() and parent.stat().st_uid == os.getuid() and
         stat.S_IMODE(parent.stat().st_mode) == 0o700, 'private_receipt_parent_invalid')
    need(path.is_dir() if exists else not path.exists(), 'receipt_collision_or_absent')
    if exists:
        st=path.stat()
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700,
             'receipt_directory_permission')

def _write(path: Path, contents: bytes) -> None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(contents); f.flush(); os.fsync(f.fileno())

def _seal(root: Path, names: tuple[str, ...]) -> None:
    sums=''.join(f'{sha((root/n).read_bytes())}  {n}\n' for n in sorted(names))
    _write(root/'SHA256SUMS',sums.encode('ascii'))

def _load_private(root: Path, prefix: str, names: tuple[str, ...]) -> dict[str, bytes]:
    _private_root(root,prefix,exists=True)
    need({p.name for p in root.iterdir()} == set(names)|{'SHA256SUMS'}, 'receipt_file_set_drift')
    result={}
    for n in (*names,'SHA256SUMS'):
        p=root/n; st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==os.getuid() and
             stat.S_IMODE(st.st_mode)==0o600,'receipt_file_permission')
        result[n]=p.read_bytes()
    sums=''.join(f'{sha(result[n])}  {n}\n' for n in sorted(names)).encode('ascii')
    need(result['SHA256SUMS']==sums,'receipt_hash_invalid')
    return result

def _assert_sources(r45dir: Path,r46dir: Path,r47dir: Path) -> None:
    need(r45.verify_directory(r45dir)['sha256']==R45_PIN and
         r46.verify_receipt(r46dir,r45dir)['sha256']==R46_PIN,
         'historical_receipts_invalid')
    # Can't call R47.verify after runner redefinition: R47 explicitly guards 3 NIC.
    r47._new_private_root_for_verify(r47dir)
    files={r47.INTENT_NAME, 'r47-defined-1.json', 'r47-defined-2.json',
           r47.RECEIPT_NAME, r47.SUMS}
    need({p.name for p in r47dir.iterdir()} == files, 'r47_receipt_file_set')
    blobs={}
    for n in files:
        p=r47dir/n; st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,
             'r47_receipt_permissions')
        blobs[n]=p.read_bytes()
    need(blobs[r47.SUMS] == ''.join(f'{sha(blobs[n])}  {n}\n' for n in sorted(files-{r47.SUMS})).encode('ascii'),
         'r47_receipt_hashes')
    original=json.loads(blobs[r47.RECEIPT_NAME])
    need(original['sha256']==R47_PIN and
         original['status']=='STAGED_NEW_UNUSED_FILTERS_ONLY_NO_GO' and
         sha(canon({k:v for k,v in original.items() if k!='sha256'}))==R47_PIN,
         'r47_stage_receipt_drift')

def _preflight(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,
               *,run:Callable[...,Any]=subprocess.run,
               capture:Callable[...,dict[str,bytes]]=_capture) -> dict[str,Any]:
    _sources_before(r45dir,r46dir,r47dir,r48dir,run=run)
    current=capture(run=run)
    _validate_common(current,r46dir,r45dir,state='SHUTOFF',candidate=False,run=run)
    need(current['runner-inactive.xml']==(r46dir/'runner-inactive.xml').read_bytes(),
         'runner_original_snapshot_drift')
    return {'schema':SCHEMA,'source_main':BASE_MAIN,'mode':'PREDEFINE_READONLY',
            'r45_sha256':R45_PIN,'r46_sha256':R46_PIN,'r47_sha256':R47_PIN,
            'r48_sha256':R48_PIN,'original_runner_sha256':sha(current['runner-inactive.xml']),
            'candidate_sha256':sha((r48dir/'runner-ssh-only-deny-r48.xml').read_bytes()),
            'runner_original_state':'SHUTOFF','ssh_state':'RUNNING',
            'runner_ssh_only':False,'domain_defined':False,'runner_started':False,
            'policy_modified':False,'guest_commands_executed':False,
            'packets_injected':False,'restoration_tested':False,
            'operational_dispatch':False,'p8_operational':'NO-GO'}

def plan(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path)->dict[str,Any]:
    out=_preflight(r45dir,r46dir,r47dir,r48dir)
    out['sha256']=sha(canon(out))
    return out

def define(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,root:Path,
           *,run:Callable[...,Any]=subprocess.run,
           capture:Callable[...,dict[str,bytes]]=_capture) -> dict[str,Any]:
    _private_root(root,'r49-runner-define',exists=False)
    original=_preflight(r45dir,r46dir,r47dir,r48dir,run=run,capture=capture)
    snapshot=capture(run=run)
    need(snapshot['runner-inactive.xml']==(r46dir/'runner-inactive.xml').read_bytes(),
         'snapshot_changed_before_define')
    root.mkdir(mode=0o700)
    _write(root/DEFINITION_FILES[0],canon(original)+b'\n')
    _write(root/DEFINITION_FILES[1],snapshot['runner-inactive.xml'])
    # Exactly one inactive domain definition mutation, runner OFF, R33/R34 deny.
    _host(_virsh('define',str(r48dir/'runner-ssh-only-deny-r48.xml'),readonly=False),run=run)
    current=capture(run=run)
    _validate_common(current,r46dir,r45dir,state='SHUTOFF',candidate=True,run=run)
    _r48_local(r48dir,run=run)
    _write(root/DEFINITION_FILES[2],current['runner-inactive.xml'])
    report={**original,'mode':'RUNNER_SSH_ONLY_DEFINED_SHUTOFF_NO_GO',
            'runner_ssh_only':True,'domain_defined':True,
            'runner_defined_sha256':sha(current['runner-inactive.xml']),
            'runner_started':False,'restoration_tested':False}
    report.pop('sha256',None)
    report['sha256']=sha(canon(report))
    _write(root/DEFINITION_FILES[3],canon(report)+b'\n')
    _seal(root,DEFINITION_FILES)
    return report

def verify_defined(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,root:Path,
                   *,run:Callable[...,Any]=subprocess.run,
                   capture:Callable[...,dict[str,bytes]]=_capture,
                   state: str='SHUTOFF',
                   require_pristine: bool=True)->dict[str,Any]:
    need(state in ('SHUTOFF','RUNNING'),'state_expected_invalid')
    docs=_load_private(root,'r49-runner-define',DEFINITION_FILES)
    intent=json.loads(docs[DEFINITION_FILES[0]])
    report=json.loads(docs[DEFINITION_FILES[3]])
    expected={**intent,'mode':'RUNNER_SSH_ONLY_DEFINED_SHUTOFF_NO_GO',
              'runner_ssh_only':True,'domain_defined':True,
              'runner_defined_sha256':sha(docs[DEFINITION_FILES[2]]),
              'runner_started':False,'restoration_tested':False}
    expected['sha256']=sha(canon(expected))
    need(report==expected and
         intent.get('mode')=='PREDEFINE_READONLY' and
         intent.get('schema')==SCHEMA and
         intent.get('source_main')==BASE_MAIN and
         intent.get('r45_sha256')==R45_PIN and
         intent.get('r46_sha256')==R46_PIN and
         intent.get('r47_sha256')==R47_PIN and
         intent.get('r48_sha256')==R48_PIN and
         intent.get('operational_dispatch') is False and
         intent.get('p8_operational')=='NO-GO' and
         intent.get('domain_defined') is False and
         intent.get('runner_started') is False and
         intent.get('original_runner_sha256')==sha(docs[DEFINITION_FILES[1]]) and
         docs[DEFINITION_FILES[1]]==(r46dir/'runner-inactive.xml').read_bytes(),
         'definition_receipt_invalid')
    _assert_sources(r45dir,r46dir,r47dir)
    _r48_local(r48dir,run=run,check_chain=(state=='SHUTOFF'),
               require_pristine=require_pristine)
    current=capture(run=run,include_runner_live=(state=='RUNNING'))
    _validate_common(current,r46dir,r45dir,state=state,candidate=True,run=run)
    # Inactive XML must not drift after the approved definition.
    need(current['runner-inactive.xml']==docs[DEFINITION_FILES[2]],
         'runner_inactive_xml_drift')
    return report

def boot(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,
         defined_root:Path,root:Path,*,run:Callable[...,Any]=subprocess.run,
         capture:Callable[...,dict[str,bytes]]=_capture)->dict[str,Any]:
    _private_root(root,'r49-runner-boot',exists=False)
    definition=verify_defined(r45dir,r46dir,r47dir,r48dir,defined_root,
                               run=run,capture=capture)
    intent={'schema':SCHEMA,'mode':'RUNNER_FIRST_BOOT_INTENT',
            'source_main':BASE_MAIN,'defined_receipt_sha256':definition['sha256'],
            'r48_receipt_sha256':R48_PIN,'previous_state':'SHUTOFF',
            'one_nic_ssh_only':True,'r33_r34_deny_checked':True,
            'runner_started':False,'operational_dispatch':False,'p8_operational':'NO-GO'}
    root.mkdir(mode=0o700)
    _write(root/BOOT_FILES[0],canon(intent)+b'\n')
    # Separate operator authorization is enforced by the CLI. No guest command.
    _host(_virsh('start',RUNNER,readonly=False),run=run)
    current=capture(run=run,include_runner_live=True)
    _validate_common(current,r46dir,r45dir,state='RUNNING',candidate=True,run=run)
    # Disk metadata can legitimately change during a guest boot; don't hash it.
    report={**intent,'mode':'RUNNER_FIRST_BOOT_WITH_DENY_CONFIG_NO_GO',
            'runner_started':True,'runner_state':'RUNNING',
            'ssh_state':'RUNNING','ftp_smb_domains':'SHUTOFF',
            'ftp_smb_networks':'INACTIVE',
            'traffic_control_positive':False,
            'isolation_packet_witness':False,'guest_ip_verified':False,
            'restoration_tested':False,'packets_injected':False}
    report['sha256']=sha(canon(report))
    _write(root/BOOT_FILES[1],canon(report)+b'\n')
    _seal(root,BOOT_FILES)
    return report

def verify_boot(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,
                defined_root:Path,root:Path,*,run:Callable[...,Any]=subprocess.run,
                capture:Callable[...,dict[str,bytes]]=_capture)->dict[str,Any]:
    docs=_load_private(root,'r49-runner-boot',BOOT_FILES)
    intent=json.loads(docs[BOOT_FILES[0]])
    report=json.loads(docs[BOOT_FILES[1]])
    expected={**intent,'mode':'RUNNER_FIRST_BOOT_WITH_DENY_CONFIG_NO_GO',
              'runner_started':True,'runner_state':'RUNNING',
              'ssh_state':'RUNNING','ftp_smb_domains':'SHUTOFF',
              'ftp_smb_networks':'INACTIVE',
              'traffic_control_positive':False,'isolation_packet_witness':False,
              'guest_ip_verified':False,'restoration_tested':False,
              'packets_injected':False}
    expected['sha256']=sha(canon(expected))
    need(report==expected and
         intent.get('mode')=='RUNNER_FIRST_BOOT_INTENT' and
         intent.get('schema')==SCHEMA and intent.get('source_main')==BASE_MAIN and
         intent.get('runner_started') is False and
         intent.get('operational_dispatch') is False and
         intent.get('r48_receipt_sha256')==R48_PIN and
         intent.get('r33_r34_deny_checked') is True and
         intent.get('p8_operational')=='NO-GO', 'boot_receipt_invalid')
    defined=verify_defined(r45dir,r46dir,r47dir,r48dir,defined_root,
                          run=run,capture=capture,state='RUNNING')
    need(report['defined_receipt_sha256']==defined['sha256'], 'boot_source_drift')
    return report


def restore_original(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,
                     defined_root:Path,root:Path,*,run:Callable[...,Any]=subprocess.run,
                     capture:Callable[...,dict[str,bytes]]=_capture)->dict[str,Any]:
    """Revert only inactive runner definition while SHUTOFF; no guest stop.

    Original R32 disk was never modified by the R49 definition/start operation.
    This does not restore a running guest or claim that arbitrary guest writes
    to the disposable R48 overlay were removed.
    """
    _private_root(root,'r49-runner-restore',exists=False)
    defined=verify_defined(r45dir,r46dir,r47dir,r48dir,defined_root,
                           run=run,capture=capture,require_pristine=False)
    docs=_load_private(defined_root,'r49-runner-define',DEFINITION_FILES)
    original=docs['runner-original-inactive.xml']
    r46.verify_domain(original,'runner')
    need(original==(r46dir/'runner-inactive.xml').read_bytes(),
         'restoration_original_snapshot_drift')
    intent={'schema':SCHEMA,'mode':'RESTORE_ORIGINAL_RUNNER_INTENT',
            'source_main':BASE_MAIN,'defined_receipt_sha256':defined['sha256'],
            'runner_original_sha256':sha(original),
            'from_state':'SHUTOFF','original_disk':r48.TOP,
            'restore_attempted':False,'runner_started':False,
            'firewall_modified':False,'p8_operational':'NO-GO'}
    root.mkdir(mode=0o700)
    _write(root/RESTORE_FILES[0],canon(intent)+b'\n')
    # Only change the inactive definition. Already-running VM is rejected.
    _host(_virsh('define',str(defined_root/'runner-original-inactive.xml'),
                 readonly=False),run=run)
    current=capture(run=run)
    _validate_common(current,r46dir,r45dir,state='SHUTOFF',candidate=False,run=run)
    need(current['runner-inactive.xml']==original,'restoration_readback_drift')
    # Now the exact original R47/R48 historical guard is usable once again.
    _assert_sources(r45dir,r46dir,r47dir)
    _r48_local(r48dir,run=run,require_pristine=False)
    _write(root/RESTORE_FILES[1],current['runner-inactive.xml'])
    report={**intent,'mode':'ORIGINAL_RUNNER_DEFINITION_RESTORED_SHUTOFF_NO_GO',
            'restore_attempted':True,'restoration_readback_verified':True,
            'restored_disk':r48.TOP,'runner_started':False,
            'network_or_firewall_modified':False}
    report['sha256']=sha(canon(report))
    _write(root/RESTORE_FILES[2],canon(report)+b'\n')
    _seal(root,RESTORE_FILES)
    return report

def verify_restored(r45dir:Path,r46dir:Path,r47dir:Path,r48dir:Path,
                    defined_root:Path,root:Path,*,run:Callable[...,Any]=subprocess.run,
                    capture:Callable[...,dict[str,bytes]]=_capture)->dict[str,Any]:
    docs=_load_private(root,'r49-runner-restore',RESTORE_FILES)
    intent=json.loads(docs[RESTORE_FILES[0]])
    report=json.loads(docs[RESTORE_FILES[2]])
    expected={**intent,'mode':'ORIGINAL_RUNNER_DEFINITION_RESTORED_SHUTOFF_NO_GO',
              'restore_attempted':True,'restoration_readback_verified':True,
              'restored_disk':r48.TOP,'runner_started':False,
              'network_or_firewall_modified':False}
    expected['sha256']=sha(canon(expected))
    need(report==expected and
         intent.get('mode')=='RESTORE_ORIGINAL_RUNNER_INTENT' and
         intent.get('schema')==SCHEMA and
         intent.get('source_main')==BASE_MAIN and
         intent.get('runner_started') is False and
         intent.get('restore_attempted') is False and
         intent.get('firewall_modified') is False and
         intent.get('p8_operational')=='NO-GO', 'restore_receipt_invalid')
    original=_load_private(defined_root,'r49-runner-define',DEFINITION_FILES)['runner-original-inactive.xml']
    need(docs[RESTORE_FILES[1]]==original and
         intent.get('runner_original_sha256')==sha(original), 'restored_original_hash_drift')
    current=capture(run=run)
    _validate_common(current,r46dir,r45dir,state='SHUTOFF',candidate=False,run=run)
    need(current['runner-inactive.xml']==original,'restored_host_drift')
    _assert_sources(r45dir,r46dir,r47dir)
    _r48_local(r48dir,run=run,require_pristine=False)
    return report
