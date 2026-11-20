"""R112-F7: genuine libvirt DENY test; never infer hook enforcement from CLI failure.

This core contains no host operations. A success requires hook-specific error,
all guests still SHUTOFF, unchanged scoped network/firewall/hook inventory.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ardrec.coordination import r112_f6_hook_lifecycle as f6_core
from ardrec.coordination import r112_runner_nic_definition as r112_core

SCHEMA = 'ardrec-p14-r112-f7-real-libvirt-negative-v1'
PARENT = '1a22f13ff585e9b3724a42680607c1d45f98469e'
HOOK_SHA = f6_core.NEW_HOOK_SHA256
DOMAIN = 'ardrec-r33-dev-ssh'
START = ('sudo','-n','virsh','-c','qemu:///system','start',DOMAIN)
DENIAL = 'ARDREC_F11_QEMU_HOOK=DENY_UNATTESTED_OR_ALREADY_USED_LEASE'
ROLES = ('runner','ssh','ftp','smb')
NETWORKS = ('ssh','ftp','smb')
STABLE_KEYS = tuple([f'vm-{r}-{k}' for r in ROLES
                     for k in ('state','inactive-xml','block')]
                    +[f'net-{r}-xml' for r in NETWORKS]
                    +['deny-nwfilter-xml','f11-hook-stat','f11-hook-hash'])

class NegativeProbeError(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise NegativeProbeError(code)

def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')+b'\n'

def sha(obj: Any) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()

def boundary(value, legacy, f4, f6):
    f6.snapshot_ok(value, HOOK_SHA, legacy, f4)
    s = value['snapshot']['summary']
    links=s['domain_inventory']
    need(tuple(row['network'] for row in links['runner']['interfaces']) ==
         tuple('ardrec-r33-dev-net-'+r for r in NETWORKS),
         'RUNNER_THREE_NICS_NOT_EXACT')
    need(all(row['filter']=='ardrec-r33-block-until-containment'
             for row in links['runner']['interfaces']),
         'RUNNER_DENY_FILTER_NOT_PRESENT')
    need(s['nft_rule_count']==4,'NFT_RULE_COUNT_NOT_EXACT')
    return True

def same(before, after, legacy, f4, f6):
    boundary(before,legacy,f4,f6)
    boundary(after,legacy,f4,f6)
    a=before['snapshot']['probes']
    b=after['snapshot']['probes']
    need(before['snapshot']['commands']==after['snapshot']['commands'],
         'READONLY_COMMAND_DRIFT')
    for name in STABLE_KEYS:
        need(a[name]['stdout']==b[name]['stdout'],
             'HOST_STABLE_SCOPE_DRIFT_'+name)
    need(before['other_domains']==after['other_domains'],
         'UNRELATED_DOMAIN_SCOPE_CHANGED')
    for role in NETWORKS:
        need(f4.core.parse_net_info(before['english_info'][role]['stdout'],role)=='ACTIVE'
             and f4.core.parse_net_info(after['english_info'][role]['stdout'],role)=='ACTIVE',
             'NETWORK_NOT_ACTIVE_'+role)
    need(r112_core._nft_structure(a['r34-nft']['stdout'])==
         r112_core._nft_structure(b['r34-nft']['stdout']),
         'NFT_STRUCTURE_CHANGED')
    return True

def classify(before, after, command, legacy, f4, f6):
    """Only an error attributable to the installed hook counts as enforcement."""
    need(type(command) is dict and set(command)==
         {'rc','timeout','stdout','stderr','truncated'}, 'COMMAND_SHAPE')
    if (command['timeout'] is not False or command['truncated'] is not False or
            type(command['rc']) is not int or command['rc']==0 or
            type(command['stderr']) is not str or
            DENIAL not in command['stderr'] or
            'prepare' not in command['stderr'].lower()):
        raise NegativeProbeError('LIBVIRT_HOOK_DENIAL_NOT_ATTESTED')
    same(before,after,legacy,f4,f6)
    return {'schema':SCHEMA+'-result',
            'libvirt_denied_with_exact_hook_marker':True,
            'guest_remained_shutoff':True,
            'four_guest_states_verified':True,
            'three_networks_active_and_stable':True,
            'nft_deny_structure_preserved':True,
            'hook_sha256':HOOK_SHA,
            'physical_start_commands_attempted':1,
            'physical_guest_starts':0,
            'hook_lease_granted':False,
            'service_traffic_granted':False,
            'next_action':'SEPARATE_EXPLICIT_POSITIVE_BOOT_AUTHORIZATION_REQUIRED',
            'p8_operational':'NO-GO'}
