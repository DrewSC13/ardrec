#!/usr/bin/env python3
"""R51: capturar solo lectura estado actual R34/libvirt en un recibo PRIVADO.

No inicia VM, red, servicio, firewall ni QGA. NO establece autorización P8.
Requires sudo -n for read-only nft/virsh; no password prompt is permitted.
"""
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

FIXED = {
    'nft_tables': ['/usr/bin/sudo', '-n', '--', '/usr/sbin/nft', 'list', 'tables'],
    'r34_table': ['/usr/bin/sudo', '-n', '--', '/usr/sbin/nft', '-a', 'list', 'table', 'bridge', 'ardrec_r34_guard'],
    'domains': ['/usr/bin/sudo', '-n', '--', '/usr/bin/virsh', '-c', 'qemu:///system', 'list', '--all'],
    'networks': ['/usr/bin/sudo', '-n', '--', '/usr/bin/virsh', '-c', 'qemu:///system', 'net-list', '--all'],
}
MAX_OUTPUT = 512_000

class AuditError(ValueError):
    pass

def must(ok, message):
    if not ok: raise AuditError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def canon(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')

def private_parent(parent: Path):
    must(parent.is_absolute() and parent.is_dir() and not parent.is_symlink(), 'private_parent_invalid')
    for part in (parent, *parent.parents):
        must(not part.is_symlink(), 'private_parent_symlink')
    st = parent.stat()
    must(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, 'private_parent_owner_mode')

def run_readonly(name, runner=subprocess.run):
    must(name in FIXED, 'command_not_allowlisted')
    cmd = FIXED[name]
    try:
        cp = runner(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False, timeout=15, close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'command': name, 'argv': cmd, 'rc': None,
                'stdout': b'', 'stderr': str(type(exc).__name__).encode('ascii'), 'error': 'UNAVAILABLE'}
    must(type(cp.returncode) is int and type(cp.stdout) is bytes and
         type(cp.stderr) is bytes, 'subprocess_contract')
    must(len(cp.stdout) <= MAX_OUTPUT and len(cp.stderr) <= MAX_OUTPUT,
         'subprocess_output_limit')
    return {'command': name, 'argv': cmd, 'rc': cp.returncode,
            'stdout': cp.stdout, 'stderr': cp.stderr, 'error': None}

def analyze(observations):
    must(type(observations) is dict and set(observations) == set(FIXED), 'observation_set')
    r34 = observations['r34_table']
    must(type(r34) is dict and r34['command'] == 'r34_table', 'r34_response_invalid')
    if r34['rc'] != 0:
        status = 'R34_NOT_VERIFIED_OR_UNAVAILABLE_NO_GO'
    elif b'table bridge ardrec_r34_guard' not in r34['stdout']:
        status = 'R34_RESPONSE_INCONSISTENT_NO_GO'
    else:
        # Table existence alone does NOT demonstrate all effective cross-host isolation.
        status = 'R34_TABLE_OBSERVED_UNREVIEWED_NO_GO'
    return {'classification': status, 'p8_operational': 'NO-GO',
            'isolation_proven': False, 'activation_allowed': False,
            'host_change_performed': False, 'guest_qga_called': False,
            'historical_receipts_replaced': False}

def secure_write(target: Path, content: bytes):
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())

def capture(parent: Path, runner=subprocess.run):
    private_parent(parent)
    now = datetime.now(timezone.utc)
    stamp = now.strftime('%Y%m%dT%H%M%SZ')
    root = parent / f'r51-host-inspection-{stamp}-{os.getpid()}'
    root.mkdir(mode=0o700, exist_ok=False)
    obs = {}
    for name in FIXED:
        obs[name] = run_readonly(name, runner)
    conclusion = analyze(obs)
    files = {}
    public = {}
    for name, value in obs.items():
        for stream in ('stdout', 'stderr'):
            filename = f'{name}.{stream}.bin'
            secure_write(root / filename, value[stream])
            files[filename] = digest(value[stream])
        public[name] = {'rc': value['rc'], 'argv': value['argv'],
                        'stdout_sha256': digest(value['stdout']),
                        'stderr_sha256': digest(value['stderr']),
                        'error': value['error']}
    receipt = {'schema': 'ardrec-p14-r51-host-inspection-v1',
               'captured_utc': now.isoformat(timespec='seconds'),
               'source': 'FIXED_READONLY_NFT_VIRSH_COMMANDS',
               'observations': public, 'assessment': conclusion,
               'raw_files_sha256': files}
    raw = canon(receipt)
    secure_write(root / 'receipt.json', raw)
    files['receipt.json'] = digest(raw)
    secure_write(root / 'SHA256SUMS',
                 ''.join(f'{h}  {f}\n' for f, h in sorted(files.items())).encode('ascii'))
    return root, conclusion, digest(raw)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--private-parent', type=Path, required=True)
    args = p.parse_args()
    try:
        root, conclusion, receipt_sha = capture(args.private_parent)
    except (AuditError, OSError, ValueError) as err:
        print('R51_HOST_AUDIT=FAIL_CLOSED:' + str(err), file=sys.stderr)
        return 2
    print('R51_HOST_AUDIT=' + conclusion['classification'])
    print('R51_HOST_RECEIPT=' + str(root / 'receipt.json'))
    print('R51_HOST_RECEIPT_SHA256=' + receipt_sha)
    print('R51_P8=NO-GO')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
