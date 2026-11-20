#!/usr/bin/env python3
"""R113-F1: audit real de la topología, sin transmitir paquetes de prueba."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ROOT = Path('/home/cicada/ardrec-lab/r113-f1-network-readonly-v1')
PARENT = 'de191525e5975ea485c750d07e755a7d7b71435d'
BRANCH = 'feat/p14-r111-r114-real-lab'
F10_SCRIPT_SHA = 'f84bfdc626ded7bcd14b62beda26118688cb6154c69eaac2ad0c6fc602c0bf69'
F10_ROOT = Path('/home/cicada/ardrec-lab/r112-f10-real-ftp-smb-boot-v1')
PREDECESSORS = {
    'ftp': ('plan-x1ju10qs', 'boot-ci1rrrj0', '98d894b6cd8a696c65142c0fb8b7f7a07f3e1e24013d2db8400390598b74890a'),
    'smb': ('plan-iu0pvs0p', 'boot-12fvvb2s', 'c9afbc9303e74c32dca52cad04701315d5c3e54aee692dc2a79757d5a0a838d7'),
}
sys.path[:0] = [str(REPO/'src'), str(REPO/'scripts')]
from ardrec.coordination import r113_f1_network_audit as core
from ardrec.coordination import r112_f10_targets_boot as f10core
from ardrec.coordination import r112_runner_nic_definition as nic
from ardrec.coordination import r112_f9_runner_boot as f9
import ardrec_p14_r112_f10_targets_boot as f10cli
import ardrec_p14_r112_f6_hook_lifecycle as f6
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4

SCHEMA = core.SCHEMA
FILES = ('snapshot.json', 'live.json', 'bridges.json', 'classification.json', 'manifest.json')

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(',', ':')).encode('ascii') + b'\n'

def need(ok, why):
    core.need(ok, why)

def cmd(*argv, timeout=20):
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                           check=False, timeout=timeout)
        out, err = p.stdout[:256000], p.stderr[:2048]
        return {'rc': p.returncode, 'stdout': out.decode('utf8', 'replace'),
                'stderr': err.decode('utf8', 'replace'), 'timeout': False,
                'truncated': len(out) < len(p.stdout) or len(err) < len(p.stderr)}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'rc': None, 'stdout': '', 'stderr': type(exc).__name__,
                'timeout': isinstance(exc, subprocess.TimeoutExpired),
                'truncated': False}

def ok(*argv):
    x = cmd(*argv)
    need(core.valid_capture(x), 'COMMAND_UNAVAILABLE_'+argv[0])
    return x['stdout'].strip()

def source():
    need(Path.cwd().resolve() == REPO, 'REPO_CHANGED')
    need(ok('git', 'branch', '--show-current') == BRANCH, 'WRONG_BRANCH')
    need(cmd('git', 'merge-base', '--is-ancestor', PARENT, 'HEAD')['rc'] == 0,
         'F10R_COMMIT_NOT_ANCESTOR')
    need(not ok('git', 'status', '--porcelain=v1', '-uall'), 'WORKTREE_NOT_CLEAN')
    need(ok('git', 'log', '-1', '--format=%G?') == 'G', 'SIGNATURE_NOT_VERIFIED')
    candidate = REPO/'scripts/ardrec_p14_r112_f10_targets_boot.py'
    need(candidate.is_file() and not candidate.is_symlink() and
         digest(candidate.read_bytes()) == F10_SCRIPT_SHA, 'F10R_SCRIPT_DRIFT')

def old_receipts():
    for role, (plan, boot, expected) in PREDECESSORS.items():
        plan_dir, boot_dir = F10_ROOT/plan, F10_ROOT/boot
        receipt = boot_dir/'receipt.json'
        need(plan_dir.is_dir() and boot_dir.is_dir() and
             not plan_dir.is_symlink() and not boot_dir.is_symlink() and
             receipt.is_file() and not receipt.is_symlink() and
             digest(receipt.read_bytes()) == expected, 'F10_PREDECESSOR_DRIFT_'+role)
        outcome = f10cli.replay(plan_dir, boot_dir, expected_role=role)
        need(outcome['target'] == role and outcome['protocol_tested'] is False and
             outcome['traffic_authorized'] is False and
             outcome['p8_operational'] == 'NO-GO', 'F10_REPLAY_INVALID_'+role)
    return {role: expected for role, (_, _, expected) in PREDECESSORS.items()}

def private(path: Path) -> None:
    need(path.is_dir() and not path.is_symlink(), 'PRIVATE_DIR_UNSAFE')
    st = path.stat()
    need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
         'PRIVATE_OWNER_OR_MODE')

def write(path: Path, value):
    raw = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())

def read(path: Path):
    need(path.is_file() and not path.is_symlink() and
         stat.S_IMODE(path.stat().st_mode) == 0o600,
         'PRIVATE_FILE_SCOPE')
    return json.loads(path.read_bytes())

def gather():
    source()
    old = old_receipts()
    record = f6.capture()
    # Exige el mismo clasificador del cierre físico de F10 (4 VM + 3 redes + DENY).
    f10core.audited(record, 'smb', after=True, legacy=legacy, f4=f4)
    common = ('virsh', '--readonly', '-c', 'qemu:///system')
    guest = {}
    for role in core.ROLES:
        name = 'ardrec-r33-dev-' + role
        guest[role] = {
            'live_xml': cmd(*common, 'dumpxml', name),
            'agent': cmd('virsh', '-c', 'qemu:///system', 'domifaddr', name, '--source', 'agent', timeout=12),
            'domiflist': cmd(*common, 'domiflist', name),
        }
    bridges = {}
    for role, bridge in core.BRIDGES.items():
        bridges[role] = {
            'link': cmd('ip', '-j', '-d', 'link', 'show', 'dev', bridge),
            'addresses': cmd('ip', '-j', 'addr', 'show', 'dev', bridge),
        }
    classified = core.classify_live(record, guest, bridges, f10=f10core,
                                     legacy=legacy, f4=f4, nic=nic, f9=f9)
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    private(ROOT)
    folder = Path(tempfile.mkdtemp(prefix='audit-', dir=ROOT))
    private(folder)
    for name, data in (('snapshot.json', record), ('live.json', guest),
                       ('bridges.json', bridges), ('classification.json', classified)):
        write(folder/name, data)
    manifest = {
        'schema': SCHEMA + '-manifest', 'source_commit': ok('git','rev-parse','HEAD'),
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'predecessor_receipts_sha256': old,
        'files': {name: digest((folder/name).read_bytes()) for name in FILES[:-1]},
        'traffic_authorized': False, 'p8_operational': 'NO-GO',
    }
    write(folder/'manifest.json', manifest)
    verify(folder)
    print('R113_F1_AUDIT=PASS_FOUR_GUESTS_THREE_NETWORKS_DENY')
    print('R113_F1_AGENT_IP_DISCOVERY=' + classified['agent_ip_discovery'])
    for role in core.ROLES:
        entry = classified['guest_network_inventory'][role]
        print('R113_F1_'+role.upper()+'_AGENT_RC='+str(entry['agent_rc']))
        print('R113_F1_'+role.upper()+'_IP_CANDIDATES='+json.dumps(
            entry['agent_ipv4_ipv6_candidates'],sort_keys=True))
        print('R113_F1_'+role.upper()+'_NIC_COUNT='+str(len(entry['interfaces'])))
    print('R113_F1_RECEIPT='+str(folder))
    print('R113_F1_MANIFEST_SHA256='+digest((folder/'manifest.json').read_bytes()))
    print('R113_F1_HOST_MUTATIONS=0')
    print('R113_F1_NETWORK_TRAFFIC=0')
    print('R113_F1_PROTOCOL=NOT_TESTED')
    print('R113_F1_P8=NO-GO')
    return 0

def verify(folder: Path):
    need(folder.is_absolute() and folder.parent == ROOT and
         folder.name.startswith('audit-'), 'AUDIT_SCOPE_INVALID')
    private(folder)
    need({p.name for p in folder.iterdir()} == set(FILES), 'AUDIT_FILES_CHANGED')
    docs = {name: read(folder/name) for name in FILES}
    man = docs['manifest.json']
    need(man['schema'] == SCHEMA+'-manifest' and
         man['traffic_authorized'] is False and man['p8_operational'] == 'NO-GO' and
         man['predecessor_receipts_sha256'] ==
         {role: data[2] for role,data in PREDECESSORS.items()}, 'MANIFEST_DRIFT')
    need(man['files'] == {name: digest((folder/name).read_bytes())
                          for name in FILES[:-1]}, 'AUDIT_HASH_DRIFT')
    again = core.classify_live(docs['snapshot.json'], docs['live.json'],
               docs['bridges.json'], f10=f10core, legacy=legacy, f4=f4,
               nic=nic, f9=f9)
    need(again == docs['classification.json'], 'AUDIT_REPLAY_MISMATCH')
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--audit', action='store_true')
    group.add_argument('--replay', type=Path)
    args = parser.parse_args()
    try:
        source()
        if args.audit:
            return gather()
        old_receipts()
        verify(args.replay)
        print('R113_F1_REPLAY=PASS')
        print('R113_F1_P8=NO-GO')
        return 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print('R113_F1_STOP='+type(exc).__name__+':'+str(exc)[:160])
        print('R113_F1_NO_RETRY_OR_MUTATION=TRUE')
        print('R113_F1_P8=NO-GO')
        return 23

if __name__ == '__main__':
    raise SystemExit(main())
