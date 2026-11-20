"""R112-F6: exact physical lifecycle-hook repair; no guest start or lease issuance.

Fail closed on host drift, missing proof, or unknown libvirt hook return values.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any

SCHEMA = 'ardrec-p14-r112-f6-lifecycle-hook-repair-v1'
PARENT = 'fa965b28dcfc19172ab0fdf7fd3180bc7873efa1'
OLD_HOOK_SHA256 = '0a9d84a45649e8a81d09298be0fd828b13c155bc372ed2c678c169d2e566a1c7'
NEW_HOOK_SHA256 = '1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b'
HOST_HOOK = '/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny'
STAGE = '/etc/libvirt/.ardrec-r112-f6-hook-stage'
GUESTS = ('runner','ssh','ftp','smb')
NETWORKS = ('ssh','ftp','smb')
MAX_DOC = 3_600_000

class LifecycleError(ValueError):
    pass


def need(ok: bool, code: str):
    if not ok:
        raise LifecycleError(code)


def canonical(obj: Any) -> bytes:
    data=json.dumps(obj, sort_keys=True, separators=(',', ':'),
                    ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'
    need(len(data)<=MAX_DOC,'RECEIPT_BOUNDS')
    return data


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def snapshot_ok(item, expected_hash, legacy, f4):
    need(type(item) is dict and set(item)=={'snapshot','english_info','other_domains'},
         'MEASUREMENT_SCHEMA')
    s=item['snapshot']
    need(type(s) is dict and set(s['probes'])==set(s['commands']) and
         len(s['probes'])==29 and s['summary']==legacy.summarize(s['probes']),
         'SNAPSHOT_INTEGRITY')
    need(s['summary']['hook_sha256']==expected_hash,'HOOK_SHA_NOT_EXPECTED')
    for k,v in s['probes'].items():
        need(v['rc']==0 and v['timeout'] is False and v['truncated'] is False,
             'READONLY_FAILURE_'+k)
    for role in GUESTS:
        need(s['summary']['domains'][role] in ('SHUT OFF','SHUTOFF','APAGADO'),
             'VM_RUNNING_'+role)
    for role in NETWORKS:
        result=item['english_info'][role]
        need(result['rc']==0 and result['timeout'] is False and
             result['truncated'] is False and
             f4.core.parse_net_info(result['stdout'],role)=='ACTIVE',
             'NETWORK_NOT_ACTIVE_'+role)
    need(item['other_domains']['status']=='NO_UNRELATED_R33_NET_ATTACHMENTS' and
         item['other_domains']['inspected'] is True,'UNRELATED_DOMAIN_SCOPE')
    for role in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        need(s['summary']['systemd'][role]['ActiveState']=='active',
             'REQUIRED_SYSTEMD_INACTIVE_'+role)
    return True


def same_boundary(before,after,legacy,f4,r112,*,new_hook: bool):
    snapshot_ok(before,OLD_HOOK_SHA256,legacy,f4)
    snapshot_ok(after,NEW_HOOK_SHA256 if new_hook else OLD_HOOK_SHA256,legacy,f4)
    need(before['snapshot']['commands']==after['snapshot']['commands'],
         'READONLY_COMMAND_SCOPE_CHANGED')
    need(before['other_domains']==after['other_domains'],
         'UNRELATED_DOMAIN_CHANGED')
    need(before['english_info']==after['english_info'],
         'NETWORK_STATE_CHANGED')
    stable = ([f'vm-{role}-{kind}' for role in GUESTS
               for kind in ('state','inactive-xml','block')]
              + [f'net-{role}-xml' for role in NETWORKS]
              + ['deny-nwfilter-xml'])
    for key in stable:
        need(before['snapshot']['probes'][key]['stdout']==
             after['snapshot']['probes'][key]['stdout'],
             'HOST_SCOPE_DRIFT_'+key)
    # Only the pinned script bytes and consequent stat-size may change.
    old_size = 5236
    new_size = 6641
    old_stat = f'0:0 755 {old_size} {HOST_HOOK}'
    new_stat = f'0:0 755 {new_size if new_hook else old_size} {HOST_HOOK}'
    need(before['snapshot']['probes']['f11-hook-stat']['stdout'].strip()==old_stat and
         after['snapshot']['probes']['f11-hook-stat']['stdout'].strip()==new_stat,
         'ROOT_HOOK_MODE_OWNER_OR_SIZE_DRIFT')
    structure=lambda item: r112._nft_structure(
        item['snapshot']['probes']['r34-nft']['stdout'])
    need(digest(structure(before))==digest(structure(after)),
         'R34_NFT_STRUCTURE_CHANGED')
    return True


def proposal(before, f5_receipt_sha: str, legacy, f4):
    snapshot_ok(before,OLD_HOOK_SHA256,legacy,f4)
    need(isinstance(f5_receipt_sha,str) and len(f5_receipt_sha)==64 and
         all(c in '0123456789abcdef' for c in f5_receipt_sha),
         'SOURCE_F5_RECEIPT_SHA')
    return {'schema':SCHEMA+'-plan','source_parent':PARENT,
            'mode':'REPLACE_F11_HOOK_LIFECYCLE_DENY_DEFAULT',
            'source_f5_receipt_sha256':f5_receipt_sha,
            'before_sha256':digest(before),
            'old_hook_sha256':OLD_HOOK_SHA256,
            'new_hook_sha256':NEW_HOOK_SHA256,
            'guest_starts':0,'lease_issues':0,'network_policy_changes':0,
            'libvirt_restarts':0,'p8_operational':'NO-GO'}


def result(before, after, legacy, f4, r112):
    same_boundary(before,after,legacy,f4,r112,new_hook=True)
    return {'schema':SCHEMA+'-host-verified','before_sha256':digest(before),
            'after_sha256':digest(after),'old_hook_sha256':OLD_HOOK_SHA256,
            'new_hook_sha256':NEW_HOOK_SHA256,'shutdown_reason_supported':True,
            'reconnect_requires_completed_boot_markers':True,
            'guest_starts':0,'lease_issues':0,'network_policy_changes':0,
            'libvirt_restarts':0,'p8_operational':'NO-GO'}
