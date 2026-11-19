"""R112-F5: non-network, DENY-first root hook upgrade contract.

The upgrade itself issues zero leases and boots zero guests. Future leases
are separate, short-lived, root-owned and single-use; absent lease => DENY.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any

SCHEMA = 'ardrec-r112-f5-f11-scoped-hook-upgrade-v1'
PARENT = '493305394fb8e5a9c2f55f750a5515c62938bc9c'
ORIGINAL = '8bad829fa029d78375f28f6978669721dc934481a97ee867449f45a1662dbc38'
CANDIDATE = '0a9d84a45649e8a81d09298be0fd828b13c155bc372ed2c678c169d2e566a1c7'
HOST_HOOK = '/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny'
STAGING = '/etc/libvirt/.ardrec-r112-f5-hook-stage'
LEASE_DIR = '/run/ardrec-f11-boot-v1'
GUESTS = ('runner','ssh','ftp','smb')
NETWORKS = ('ssh','ftp','smb')
MAX_REPORT = 3_500_000

class HookUpgradeError(ValueError):
    pass


def need(cond: bool, code: str):
    if not cond:
        raise HookUpgradeError(code)


def canonical(item: Any) -> bytes:
    data = json.dumps(item,sort_keys=True,ensure_ascii=True,allow_nan=False,
                      separators=(',',':')).encode('ascii') + b'\n'
    need(len(data) <= MAX_REPORT,'REPORT_TOO_LARGE')
    return data


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(item: Any) -> str:
    return sha(canonical(item))


def plan_for(before: dict, candidate_hash: str, legacy, f4):
    status = f4.core.inspect(before,legacy)
    need(status == dict.fromkeys(NETWORKS,'ACTIVE'), 'NETWORKS_NOT_ACTIVE')
    need(candidate_hash == CANDIDATE, 'CANDIDATE_SOURCE_DRIFT')
    need(before['snapshot']['summary']['hook_sha256'] == ORIGINAL,
         'ORIGINAL_HOOK_NOT_PINNED')
    return {'schema':SCHEMA+'-plan', 'mode':'ROOT_HOOK_DENY_DEFAULT_UPGRADE_ONLY',
            'source_parent':PARENT,'original_hook_sha256':ORIGINAL,
            'candidate_hook_sha256':CANDIDATE,'before_sha256':digest(before),
            'installation_path':HOST_HOOK,'staging_path':STAGING,
            'root_lease_directory_must_not_exist':LEASE_DIR,
            'networks_active':list(NETWORKS),'guests_shutoff':list(GUESTS),
            'candidate_lease_installed':False,'hook_changes_allowed':1,
            'vm_starts':0,'guest_traffic_allowed':False,
            'operational_dispatch':False,'p8_operational':'NO-GO'}


def check_post(before: dict, after: dict, legacy, f4, r112):
    """Validate changed hook SHA as the *only* meaningful host mutation."""
    old = f4.core.inspect(before,legacy)
    need(old == dict.fromkeys(NETWORKS,'ACTIVE'), 'SOURCE_NOT_READY')
    need(type(after) is dict and set(after)==set(before), 'POST_SCHEMA')
    snap = after['snapshot']
    need(snap['commands'] == before['snapshot']['commands']
         and snap['summary'] == legacy.summarize(snap['probes'])
         and set(snap['probes']) == set(before['snapshot']['probes'])
         and len(snap['probes']) == 29, 'POST_SNAPSHOT_NOT_REPLAYABLE')
    for item in snap['probes'].values():
        need(item['rc'] == 0 and item['timeout'] is False
             and item['truncated'] is False,'POST_PROBE_FAILED')
    need(snap['summary']['hook_sha256'] == CANDIDATE, 'NEW_HOOK_HASH_DRIFT')
    need(snap['summary']['nft_rule_count']==4,'R34_RULE_COUNT')
    for role in GUESTS:
        need(snap['summary']['domains'][role] in ('SHUT OFF','SHUTOFF','APAGADO'),
             'POST_VM_NOT_SHUTOFF')
        r112.validate_domain(snap['probes']['vm-'+role+'-inactive-xml']['stdout'],
                             role,configured=role=='runner')
    for role in NETWORKS:
        r112._safe_net(snap['probes']['net-'+role+'-xml']['stdout'],role)
        need(f4.core.parse_net_info(after['english_info'][role]['stdout'],role)
             == 'ACTIVE','POST_NET_NOT_ACTIVE')
    need(after['other_domains']==before['other_domains'], 'UNRELATED_GUEST_DRIFT')
    need(r112.sha(r112.canonical(r112._nft_structure(
        before['snapshot']['probes']['r34-nft']['stdout']))) ==
         r112.sha(r112.canonical(r112._nft_structure(
        snap['probes']['r34-nft']['stdout']))), 'R34_STRUCTURE_CHANGED')
    # Unchanged domain XML, nwfilter, network identity and block backing files.
    stable = ([f'vm-{role}-{part}' for role in GUESTS
               for part in ('state','inactive-xml','block')]
              + [f'net-{role}-xml' for role in NETWORKS]
              + ['deny-nwfilter-xml'])
    for key in stable:
        need(before['snapshot']['probes'][key]['stdout'] == snap['probes'][key]['stdout'],
             'UNEXPECTED_HOST_CHANGE_'+key)
    for key in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        need(snap['summary']['systemd'][key]['ActiveState']=='active',
             'F11_RUNTIME_NOT_ACTIVE_'+key)
    return {'schema':SCHEMA+'-verified-state',
            'old_snapshot_sha256':digest(before),'new_snapshot_sha256':digest(after),
            'old_hook_sha256':ORIGINAL,'new_hook_sha256':CANDIDATE,
            'vm_starts':0,'root_leases_issued':0,'network_policy_changed':False,
            'p8_operational':'NO-GO'}
