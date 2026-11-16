#!/usr/bin/env python3
"""R58-B F11: verify source-only launch barrier candidates. NO host calls."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path('/home/cicada/Development/GitHub/ardrec')
BASE = 'a827a3935ec0bdeeff8a0fa0aabfca5f041d43a2'
SCOPE = 'lab/f11-runtime-v1/'
FILES = (
    '00-ardrec-r33-deny',
    'libvirtd-f11-guard.conf',
    'ardrec-r34-deny-watchdog.service',
    'ardrec-r34-deny-watchdog.timer',
)
EXPECTED_UNIT = '/usr/bin/python3 -I -B /var/lib/ardrec/r58a-r34-boot/boot-guard.py'

class AuditError(ValueError):
    pass


def need(ok: bool, why: str) -> None:
    if not ok:
        raise AuditError(why)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit(root: Path = ROOT) -> dict:
    """Deterministic offline audit of the entire candidate set."""
    folder = root / SCOPE
    source = {}
    for name in FILES:
        path = folder / name
        need(path.is_file() and not path.is_symlink(), 'MISSING_OR_SYMLINK_'+name)
        raw = path.read_bytes()
        need(0 < len(raw) < 16_384 and b'\x00' not in raw, 'SOURCE_SIZE_'+name)
        source[name] = raw.decode('utf-8', 'strict')
    hook = source['00-ardrec-r33-deny']
    need(hook.startswith('#!/usr/bin/python3 -I\n'), 'HOOK_INTERPRETER')
    need('PREFIX = "ardrec-r33-dev-"' in hook and
         'STOP_EVENTS = frozenset(("stopped", "release"))' in hook,
         'HOOK_SCOPE_DRIFT')
    for forbidden in ('subprocess', 'os.system', 'socket', 'libvirt.', 'virsh ',
                      'nft ', 'systemctl ', 'open(', 'eval(', 'exec('):
        need(forbidden not in hook, 'HOOK_PRIVILEGED_BEHAVIOR')
    units = source['libvirtd-f11-guard.conf']
    need(units.count('[Unit]') == 1 and
         re.findall(r'^Requires=(.*)$',units,re.M) == ['ardrec-r34-boot-deny.service'] and
         re.findall(r'^After=(.*)$',units,re.M) == ['ardrec-r34-boot-deny.service'] and
         '[Service]' not in units, 'DEPENDENCY_DRIFT')
    service=source['ardrec-r34-deny-watchdog.service']
    timer=source['ardrec-r34-deny-watchdog.timer']
    need(service.count('ExecStart=')==1 and ('ExecStart='+EXPECTED_UNIT) in service,
         'WATCHDOG_EXECSTART_DRIFT')
    for name in ('User=root','Group=root','Type=oneshot','NoNewPrivileges=yes',
                 'ProtectSystem=strict','TimeoutStartSec=60'):
        need(name in service,'WATCHDOG_SANDBOX_DRIFT_'+name)
    need('OnBootSec=20s' in timer and 'OnUnitInactiveSec=10s' in timer and
         'Unit=ardrec-r34-deny-watchdog.service' in timer and
         'WantedBy=timers.target' in timer and
         'OnCalendar=' not in timer, 'WATCHDOG_TIMER_DRIFT')
    return {
        'schema':'ardrec-r58b-f11-runtime-source-only-v1',
        'status':'F11_RUNTIME_CANDIDATES_VERIFIED_SOURCE_ONLY',
        'sources_sha256': {n:sha((folder/n).read_bytes()) for n in FILES},
        'hook':'DENY_ALL_R33_DEV_STARTS_AND_NONSTOP_EVENTS',
        'libvirt_dependency':'REQUIRES_AND_AFTER_BOOT_GUARD_CANDIDATE',
        'watchdog':'SYSTEM_TIMER_CANDIDATE_UNPROVEN',
        'effective_hook_installed':False,
        'libvirt_restarted':False,
        'watchdog_installed':False,
        'boot_attested':False,
        'physical_mutations':0,
        'guest_traffic_generated':False,
        'p8':'NO-GO',
        'next_gate':'SEPARATE_HOST_AUDIT_AUTHORIZATION_AND_NEGATIVE_TEST',
    }


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--verify-offline',action='store_true',required=True)
    ap.parse_args()
    try:
        need(Path.cwd().resolve()==ROOT,'MUST_RUN_FROM_REPO')
        report=audit(ROOT)
    except (AuditError,OSError,UnicodeError) as exc:
        print('R58B_F11=BLOCKED:'+str(exc)[:160])
        print('R58B_P8=NO-GO')
        return 23
    print(json.dumps(report,indent=2,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
