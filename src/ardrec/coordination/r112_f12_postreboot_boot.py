"""R112-F12: pure validators for post-reboot SSH then runner admissions.

No host operations. The existing F8/F9 strict physical classifiers are reused.
Every receipt describes a *new* boot, and never grants network traffic or P8.
"""
from __future__ import annotations
import hashlib
import json
import xml.etree.ElementTree as ET

from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_f9_runner_boot as f9
from ardrec.coordination import r112_runner_nic_definition as nic

SCHEMA = 'ardrec-r112-f12-postreboot-ssh-runner-boot-v1'
PARENT = 'f92e42c100497b09a961ca70d09b3454beb49ac8'
ROLES = ('ssh', 'runner')
NETWORKS = ('ssh', 'ftp', 'smb')
ROOT_LEASE = '/run/ardrec-f11-boot-v1'
TTL = 180

class Stop(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise Stop(why)

def canon(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      allow_nan=False, separators=(',', ':')).encode('ascii') + b'\n'

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def sha(obj):
    return digest(canon(obj))

def allowed(role):
    need(type(role) is str and role in ROLES, 'ROLE_NOT_ALLOWED')
    return role

def guest(role):
    return 'ardrec-r33-dev-' + allowed(role)

def command(role):
    return ('sudo', '-n', 'virsh', '-c', 'qemu:///system', 'start', guest(role))

def ticket(role, now, nonce):
    return f8.ticket(now, nonce) if allowed(role) == 'ssh' else f9.ticket(now, nonce)

def lease(role):
    return ROOT_LEASE + '/allow-' + guest(role) + '.json'

def markers(role):
    return {kind: ROOT_LEASE + '/' + kind + '-' + guest(role) + '.sha256'
            for kind in ('used', 'stage', 'active')}

def expected(role, after=False):
    allowed(role)
    return {'ssh': 'RUNNING' if (role == 'runner' or after) else 'SHUTOFF',
            'runner': 'RUNNING' if role == 'runner' and after else 'SHUTOFF',
            'ftp': 'SHUTOFF', 'smb': 'SHUTOFF'}

def audited(record, role, after, legacy, f4, f6):
    allowed(role)
    if role == 'ssh':
        f8.audited(record, ssh_running=after, legacy=legacy, f4=f4, f6=f6)
    else:
        f9.audited(record, runner_running=after, legacy=legacy, f4=f4)
    s = record['snapshot']['probes']
    for service in NETWORKS:
        nic._safe_net(s['net-' + service + '-xml']['stdout'], service)
    filt = ET.fromstring(s['deny-nwfilter-xml']['stdout'])
    rules = filt.findall('rule')
    need(filt.tag == 'filter' and filt.get('name') == nic.FILTER and
         len(rules) == 1 and rules[0].get('action') == 'drop' and
         rules[0].get('direction') == 'inout' and
         rules[0].find('all') is not None, 'DENY_FILTER_CHANGED')
    need(record['snapshot']['summary']['p8_operational'] == 'NO-GO',
         'P8_STATE_CHANGED')
    return True

def boundary(before, current, role, legacy, f4, f6):
    audited(before, role, False, legacy, f4, f6)
    audited(current, role, False, legacy, f4, f6)
    a, b = before['snapshot']['probes'], current['snapshot']['probes']
    need(before['snapshot']['commands'] == current['snapshot']['commands'],
         'COMMAND_INVENTORY_CHANGED')
    for r in ('ssh', 'runner', 'ftp', 'smb'):
        for suffix in ('state', 'inactive-xml', 'block'):
            key = 'vm-' + r + '-' + suffix
            need(a[key]['stdout'] == b[key]['stdout'], 'STATIC_VM_DRIFT_' + key)
    for key in ('f11-hook-hash', 'f11-hook-stat', 'deny-nwfilter-xml'):
        need(a[key]['stdout'] == b[key]['stdout'], 'STATIC_PROTECTION_DRIFT_' + key)
    for service in NETWORKS:
        key = 'net-' + service + '-xml'
        need(f8._r112_f8_static_network_xml(a[key]['stdout']) ==
             f8._r112_f8_static_network_xml(b[key]['stdout']),
             'STATIC_NETWORK_DRIFT_' + service)
    need(before['english_info'] == current['english_info'] and
         before['other_domains'] == current['other_domains'],
         'NETWORK_OR_UNRELATED_SCOPE_CHANGED')
    need(nic._nft_structure(a['r34-nft']['stdout']) ==
         nic._nft_structure(b['r34-nft']['stdout']), 'R34_DENY_DRIFT')
    return True

def classify(before, after, start_result, live_xml, doc, grant, claims,
             role, predecessor, legacy, f4, f6):
    audited(before, role, False, legacy, f4, f6)
    audited(after, role, True, legacy, f4, f6)
    if role == 'ssh':
        proof = f8.classify(before, after, start_result, live_xml, doc,
                            grant, claims, legacy, f4, f6)
    else:
        proof = f9.classify(before, after, start_result, live_xml, doc,
                            grant, claims, legacy=legacy, f4=f4)
    need(type(predecessor) is dict and
         set(predecessor) == {'type', 'plan', 'receipt', 'sha256'},
         'PREDECESSOR_FIELDS_INVALID')
    need(predecessor['type'] == ('F11N_NETWORKS' if role == 'ssh' else 'F12_SSH'),
         'PREDECESSOR_TYPE_CHANGED')
    return {'schema': SCHEMA + '-receipt', 'parent_commit': PARENT,
            'role': role, 'guest': guest(role),
            'before_sha256': sha(before), 'after_sha256': sha(after),
            'predecessor_sha256': predecessor['sha256'],
            'evidence_proof_sha256': sha(proof),
            'lease_sha256': digest(canon(doc)),
            'hook_sha256': f8.HOOK_SHA,
            'guest_states': expected(role, after=True),
            'networks': 'ACTIVE_3_R34_DENY',
            'f11_phases': ['prepare', 'start', 'started'],
            'vm_starts_in_this_attempt': 1,
            'traffic_authorized': False, 'protocol_tested': False,
            'a5_dispatched': False, 'a6': 'ND',
            'a7': 'NOT_ATTESTED', 'a9': False,
            'p8_operational': 'NO-GO'}
