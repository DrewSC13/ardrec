"""R112-F8: one authorized real SSH VM boot, R33/R34 DENY intact.

Pure and deterministic checks. No host operations in this module. A QEMU
start is NOT evidence of a reachable SSH service or P8 authorization.
"""
from __future__ import annotations
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from ardrec.coordination import r112_f7_libvirt_negative as f7
from ardrec.coordination import r112_runner_nic_definition as nic

SCHEMA='ardrec-p14-r112-f8-one-real-ssh-boot-v1'
PARENT='0b00f79afd8e7b62fb81c54807e099873ed726d5'
GUEST='ardrec-r33-dev-ssh'
ROLES=('runner','ssh','ftp','smb')
NETWORKS=('ssh','ftp','smb')
LEASE_ROOT='/run/ardrec-f11-boot-v1'
LEASE_PATH=LEASE_ROOT+'/allow-'+GUEST+'.json'
MARKERS={k:LEASE_ROOT+'/'+k+'-'+GUEST+'.sha256' for k in ('used','stage','active')}
HOOK_SHA=f7.HOOK_SHA
LEASE_SCHEMA='ardrec-r112-f11-one-start-root-lease-v1'
START=('sudo','-n','virsh','-c','qemu:///system','start',GUEST)
TTL=180

class BootError(ValueError):
    pass


def _r112_f8_static_network_xml(raw: str) -> str:
    """Excluye exclusivamente el contador runtime de conexiones de libvirt."""
    from xml.etree import ElementTree as _ET

    if not isinstance(raw, str):
        raise ValueError("INVALID_STATIC_NETWORK_XML_TYPE")

    try:
        root = _ET.fromstring(raw)
    except _ET.ParseError as exc:
        raise ValueError("INVALID_STATIC_NETWORK_XML") from exc

    if root.tag != "network":
        raise ValueError("EXPECTED_NETWORK_XML")

    count = root.attrib.get("connections")
    if count is not None:
        if not count.isascii() or not count.isdecimal():
            raise ValueError("INVALID_RUNTIME_CONNECTIONS")

    root.attrib.pop("connections", None)

    return _ET.canonicalize(
        _ET.tostring(root, encoding="unicode")
    )

def need(value: bool, why: str) -> None:
    if not value:
        raise BootError(why)

def canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, allow_nan=False,
                      separators=(',',':')).encode('ascii')+b'\n'

def sha(obj: Any) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()

def raw_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def ticket(now: int, nonce: str) -> dict:
    need(type(now) is int and now > 0 and type(nonce) is str and
         re.fullmatch('[0-9a-f]{64}', nonce) is not None,'TICKET_TIME_OR_NONCE')
    return {'schema':LEASE_SCHEMA,'guest':GUEST,'issued_at':now,
            'expires_at':now+TTL,'nonce':nonce,
            'mode':'ONE_START_ONLY_NO_TRAFFIC_AUTHORITY','p8_operational':'NO-GO',
            'r34_policy':'DENY_PRESERVED',
            'scope':'R112_LAB_BOOT_PREAUTHORIZATION_ONLY',
            'phases':['prepare','start','started']}

def _vm_state(snapshot:dict,role:str) -> str:
    raw=snapshot['snapshot']['summary']['domains'][role].upper().replace(' ','')
    if raw in ('SHUTOFF','APAGADO'):
        return 'SHUTOFF'
    if raw in ('RUNNING','EJECUTANDO','ENMARCHA'):
        return 'RUNNING'
    return 'UNKNOWN'

def audited(data:dict, *, ssh_running:bool, legacy, f4, f6) -> bool:
    """Revalidate *real* 29 host reads; explicitly allow only SSH state drift."""
    need(type(data) is dict and set(data)=={'snapshot','english_info','other_domains'},
         'PHYSICAL_SNAPSHOT_SCHEMA')
    s=data['snapshot']
    need(set(s)=={'schema','commands','probes','summary'} and
         s['schema']==legacy.SCHEMA and
         s['commands']=={k:list(v) for k,v in legacy.command_list().items()} and
         set(s['probes'])==set(s['commands']) and len(s['probes'])==29 and
         s['summary']==legacy.summarize(s['probes']),'PHYSICAL_SNAPSHOT_NOT_REPRODUCIBLE')
    need(all(p['rc']==0 and p['timeout'] is False and p['truncated'] is False
             for p in s['probes'].values()),'PHYSICAL_READ_FAILURE')
    need(s['summary']['hook_sha256']==HOOK_SHA and
         s['summary']['nft_rule_count']==4,'F11_R34_DRIFT')
    for role in ROLES:
        desired='RUNNING' if role=='ssh' and ssh_running else 'SHUTOFF'
        need(_vm_state(data,role)==desired,'VM_STATE_'+role)
        nic.validate_domain(s['probes']['vm-'+role+'-inactive-xml']['stdout'],role,
                            configured=(role=='runner'))
    need(tuple(x['network'] for x in
               s['summary']['domain_inventory']['runner']['interfaces'])==
         tuple('ardrec-r33-dev-net-'+r for r in NETWORKS),'RUNNER_NIC_DRIFT')
    need(data['other_domains']['status']=='NO_UNRELATED_R33_NET_ATTACHMENTS' and
         data['other_domains']['inspected'] is True,'UNRELATED_VM_SCOPE')
    for role in NETWORKS:
        r=data['english_info'][role]
        need(r['rc']==0 and r['timeout'] is False and r['truncated'] is False and
             f4.core.parse_net_info(r['stdout'],role)=='ACTIVE','NETWORK_NOT_ACTIVE_'+role)
    need(set(data['english_info'])==set(NETWORKS),'NETWORK_SET')
    for k in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        need(s['summary']['systemd'][k]['ActiveState']=='active','F11_SYSTEMD_'+k)
    nic._nft_structure(s['probes']['r34-nft']['stdout'])
    return True

def compare(before:dict,after:dict,legacy,f4,f6) -> bool:
    audited(before,ssh_running=False,legacy=legacy,f4=f4,f6=f6)
    audited(after,ssh_running=True,legacy=legacy,f4=f4,f6=f6)
    a,b=before['snapshot']['probes'],after['snapshot']['probes']
    need(before['snapshot']['commands']==after['snapshot']['commands'],
         'COMMAND_INVENTORY_CHANGED')
    for k in ([f'vm-{r}-{field}' for r in ROLES for field in
               ('inactive-xml','block')]+[f'net-{r}-xml' for r in NETWORKS]+[
               'f11-hook-stat','f11-hook-hash','deny-nwfilter-xml']):
        if k in ('net-ssh-xml', 'net-ftp-xml', 'net-smb-xml'):
            try:
                before_xml = _r112_f8_static_network_xml(a[k]['stdout'])
                after_xml = _r112_f8_static_network_xml(b[k]['stdout'])
            except ValueError:
                need(False, 'INVALID_STATIC_NETWORK_XML_'+k)
                raise
            need(before_xml == after_xml,
                 'STATIC_RESOURCE_CHANGED_'+k)
        else:
            need(a[k]['stdout']==b[k]['stdout'],
                 'STATIC_RESOURCE_CHANGED_'+k)
    need(before['english_info']==after['english_info'] and
         before['other_domains']==after['other_domains'],
         'NETWORK_OR_UNRELATED_SCOPE_CHANGED')
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']),'R34_DENY_CHANGED')
    return True

def check_guest_live_xml(raw:str) -> bool:
    nic.validate_domain(raw,'ssh')
    root=ET.fromstring(raw)
    need(root.findtext('name')==GUEST and
         len(root.findall('devices/interface'))==1 and
         len(root.findall('devices/disk[@device="disk"]'))==1 and
         not root.findall('devices/hostdev') and
         not root.findall('devices/interface[@type="bridge"]'),
         'LIVE_SSH_XML_UNAUTHORIZED_DEVICES')
    return True

def check_grant(ticket_doc:dict, grant:dict, claims:dict) -> str:
    """Check root readback metadata and hook's 3 durable stage claims."""
    need(type(grant) is dict and set(grant)=={'directory_stat','lease_stat',
         'lease_sha256'},'GRANT_READBACK_SCHEMA')
    raw=canon(ticket_doc)
    digest=raw_sha(raw)
    need(grant['directory_stat'].strip()==
         '0:0 700 '+LEASE_ROOT and
         grant['lease_stat'].strip()==
         '0:0 600 1 '+str(len(raw))+' '+LEASE_PATH and
         grant['lease_sha256']==digest,'ROOT_LEASE_PROVENANCE')
    need(type(claims) is dict and set(claims)=={'used','stage','active'},
         'STAGE_CLAIM_KEYS')
    for kind in ('used','stage','active'):
        claim=claims[kind]
        need(type(claim) is dict and set(claim)=={'stat','content'},
             'STAGE_CLAIM_SCHEMA')
        need(claim['stat'].strip()==
             '0:0 600 1 65 '+MARKERS[kind] and
             claim['content']==digest+'\n','STAGE_CLAIM_NOT_COMPLETED_'+kind)
    return digest

def classify(before,after,command,live_xml,ticket_doc,grant,claims,legacy,f4,f6):
    need(type(command) is dict and set(command)==
         {'rc','stdout','stderr','timeout','truncated'} and
         command['rc']==0 and command['timeout'] is False and
         command['truncated'] is False,'SSH_QEMU_START_NOT_ACKNOWLEDGED')
    compare(before,after,legacy,f4,f6)
    check_guest_live_xml(live_xml)
    grant_sha=check_grant(ticket_doc,grant,claims)
    return {'schema':SCHEMA+'-physical-receipt',
            'mode':'ONE_REAL_SSH_QEMU_BOOT_UNDER_FULL_R34_DENY',
            'source_parent':PARENT,
            'source_before_sha256':sha(before),
            'observed_after_sha256':sha(after),
            'ticket_sha256':grant_sha,
            'hook_sha256':HOOK_SHA,
            'guest':GUEST,
            'guest_running':True,
            'other_three_guests_shutoff':True,
            'networks_active':3,
            'f11_boot_phases_attested':list(('prepare','start','started')),
            'service_protocol_verified':False,
            'traffic_granted':False,
            'a5_executed':False,
            'a6':'ND',
            'a7_rf':'NOT_CONFIRMED',
            'a9_publications':0,
            'p8_operational':'NO-GO'}
