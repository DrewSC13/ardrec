#!/usr/bin/env python3
"""R58-C: source provenance + strictly read-only F11 installation preflight.

Never installs hooks/drop-ins, executes boot-guard, restarts libvirtd,
starts a VM, changes nftables, enables a timer, or authorizes P8.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
# Absolute host identity is deliberately required ONLY for host inspection.
HOST_REPO = Path('/home/cicada/Development/GitHub/ardrec')
BASE = '0153c8513efe10192ff0704a2132756a4517ed54'
SOURCE = {
    '00-ardrec-r33-deny': '8bad829fa029d78375f28f6978669721dc934481a97ee867449f45a1662dbc38',
    'libvirtd-f11-guard.conf': '5368b91b633b271da037633e374e4b04df801a3fe1d76dafa72e5876b79b6009',
    'ardrec-r34-deny-watchdog.service': '4a70c34311cf8980f05bdb14d82ef87d2b9fb4b377f6d26201c4d5f41532e079',
    'ardrec-r34-deny-watchdog.timer': '5e50b1ddf916c2389d015cf4e627a70f6e17765f4cc40104345a933ce9654a14',
}
DOMAIN_SET = frozenset(('ardrec-r33-dev-runner', 'ardrec-r33-dev-ssh',
                        'ardrec-r33-dev-ftp', 'ardrec-r33-dev-smb'))
PLANNED_PATHS = {
    '00-ardrec-r33-deny': '/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny',
    'libvirtd-f11-guard.conf': '/etc/systemd/system/libvirtd.service.d/90-ardrec-r34-boot.conf',
    'ardrec-r34-deny-watchdog.service': '/etc/systemd/system/ardrec-r34-deny-watchdog.service',
    'ardrec-r34-deny-watchdog.timer': '/etc/systemd/system/ardrec-r34-deny-watchdog.timer',
}

class PlanError(ValueError):
    pass


def require(ok: bool, code: str):
    if not ok:
        raise PlanError(code)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def check_source(root: Path = REPO) -> dict:
    require(root.resolve() == REPO and Path.cwd().resolve() == REPO,
            'MUST_RUN_FROM_CANONICAL_REPOSITORY')
    actual = {}
    for name, expected in SOURCE.items():
        p = root / 'lab/f11-runtime-v1' / name
        require(p.is_file() and not p.is_symlink(), 'SOURCE_MISSING_OR_SYMLINK_' + name)
        blob = p.read_bytes()
        require(0 < len(blob) < 16384 and digest(blob) == expected,
                'SOURCE_SHA_DRIFT_' + name)
        actual[name] = expected
    return actual


def git_check(run=None):
    cmd = ['/usr/bin/git', '-C', str(REPO), 'merge-base', '--is-ancestor', BASE, 'HEAD']
    raw = run if run is not None else read_command
    raw(cmd)


def read_command(cmd: list[str]) -> bytes:
    root = ['/usr/bin/virsh', '--readonly', '-c', 'qemu:///system']
    allowed = [root + ['list', '--all', '--name'], root + ['list', '--name'],
               ['/usr/bin/git', '-C', str(REPO), 'merge-base', '--is-ancestor', BASE, 'HEAD']]
    require(cmd in allowed, 'READONLY_COMMAND_NOT_ALLOWED')
    try:
        cp = subprocess.run(cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=25, check=False, close_fds=True,
            env={**os.environ, 'LC_ALL':'C','LANG':'C'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanError('HOST_READ_UNAVAILABLE') from exc
    require(cp.returncode == 0 and len(cp.stdout) <= 32768 and len(cp.stderr) <= 8192,
            'HOST_READ_FAILED')
    return cp.stdout


def path_inventory(root: Path = Path('/')) -> dict[str, str]:
    """Only inspect path metadata; no reads of existing hook contents."""
    results = {}
    for name, target in PLANNED_PATHS.items():
        p = root / target.lstrip('/')
        try:
            st = p.lstat()
        except FileNotFoundError:
            results[name] = 'NOT_INSTALLED'
        except PermissionError:
            results[name] = 'UNREADABLE_BLOCKED'
        else:
            if stat.S_ISLNK(st.st_mode):
                results[name] = 'SYMLINK_BLOCKED'
            else:
                # Existing content must be independently inspected; never overwrite it.
                results[name] = 'EXISTS_REQUIRES_INDEPENDENT_REVIEW'
    return results


def package_plan(sources: dict[str, str], *, inventory: dict[str,str] | None = None,
                 f11: dict | None = None, domains: set[str] | None = None,
                 active: set[str] | None = None) -> dict:
    require(sources == SOURCE, 'PINNED_SOURCE_DRIFT')
    if inventory is not None:
        require(set(inventory) == set(PLANNED_PATHS), 'HOST_INVENTORY_INCOMPLETE')
        require(type(domains) is set and type(active) is set and
                DOMAIN_SET <= domains and active <= domains, 'VM_INVENTORY_INVALID')
        require(type(f11) is dict and f11.get('nft_r34') == 'DENY_STRUCTURALLY_VERIFIED_TWICE'
                and f11.get('nwfilter_r34') == 'DROP_ALL_DEFINITION_VERIFIED'
                and f11.get('dev_vms_off') is True and
                f11.get('ftp_network_inactive') is True and
                f11.get('root_bundle') == 'THREE_ROOT_BUNDLE_HASHES_MATCH_PIN',
                'F11_CURRENT_DENY_NOT_VERIFIED')
    non_ardrec_active = sorted(active - DOMAIN_SET) if active is not None else []
    conflict = ([k for k,v in (inventory or {}).items() if v != 'NOT_INSTALLED'])
    return {
        'schema': 'ardrec-r58c-f11-install-plan-readonly-v1',
        'source_main': BASE,
        'sources_sha256': dict(sorted(sources.items())),
        'install_targets': dict(sorted(PLANNED_PATHS.items())),
        'host_audited': inventory is not None,
        'target_paths': inventory,
        'foreign_active_vms': non_ardrec_active,
        'existing_path_conflicts': sorted(conflict),
        'safe_to_restart_libvirtd': False,
        'boot_first_execution_attested': False,
        'manual_boot_block_attested': False,
        'watchdog_operationally_attested': False,
        'runtime_hook_loaded': False,
        'installer_executed': False,
        'host_mutations': 0,
        'p8': 'NO-GO',
        'decision': 'BLOCKED_SEPARATE_PHYSICAL_AUTHORIZATION_REQUIRED',
        'next_gate': 'REVIEW_OTHER_HOOKS_AND_LIBVIRT_IMPACT_THEN_SEPARATE_INSTALL_AUTHORIZATION',
    }


def host_audit() -> dict:
    # Never inspect Prometheus host state from CI, clones or alternate checkouts.
    require(REPO == HOST_REPO and Path.cwd().resolve() == HOST_REPO,
            'HOST_CANONICAL_REPOSITORY_REQUIRED')
    source = check_source()
    git_check()
    from importlib.machinery import SourceFileLoader
    p = REPO/'scripts/ardrec_p14_r58a_f11p_boot_readiness.py'
    require(p.is_file() and not p.is_symlink(), 'F11P_AUDITOR_NOT_PRESENT')
    spec = importlib.util.spec_from_loader('ardrec_r58c_pinned_f11p', SourceFileLoader('ardrec_r58c_pinned_f11p', str(p)))
    require(spec is not None and spec.loader is not None, 'F11P_IMPORT_FAILED')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    f11 = mod.host_readonly()
    virsh = ['/usr/bin/virsh', '--readonly', '-c', 'qemu:///system']
    defined = set(x for x in read_command(virsh + ['list','--all','--name']).decode('utf-8').splitlines() if x)
    active = set(x for x in read_command(virsh + ['list','--name']).decode('utf-8').splitlines() if x)
    return package_plan(source, inventory=path_inventory(), f11=f11, domains=defined, active=active)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument('--verify-offline', action='store_true')
    options.add_argument('--host-readonly', action='store_true')
    args = parser.parse_args()
    try:
        result = host_audit() if args.host_readonly else package_plan(check_source())
    except (PlanError, ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        print('R58C_F11=BLOCKED:'+type(exc).__name__+':'+str(exc)[:140])
        print('R58C_F11_HOST_MUTATIONS=0')
        print('R58C_F11_P8=NO-GO')
        return 23
    print(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=True))
    return 21 if args.host_readonly else 0


if __name__ == '__main__':
    raise SystemExit(main())
