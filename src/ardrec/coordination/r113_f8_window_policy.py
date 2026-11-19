"""ARDREC R113-F8: offline fail-closed TCP/ARP policy for 3 isolated networks.

Does not run nft, libvirt, systemd, QGA or any network connection.
F6's six exact candidate binding names are intentionally reused.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from ardrec.coordination import r113_f6_six_binding_guard as f6

SCHEMA='ARDREC-R113-F8-OFFLINE-ADMISSION-POLICY-v1'
F7E_MANIFEST_SHA256='e7bd6fd12d3188ec821d16751cda18d21f88d2da6043acb1db8a3dafe369729c'
F7E_RECEIPT=Path('/home/cicada/ardrec-lab/r113-f7e-forensic-closure-v1/closure-4pz1gq_c/manifest.json')
PARENT='45c5018660b645d914ad8d756f64c0b5239836ce'
DEST=Path('/home/cicada/ardrec-lab/r113-f8-admission-policy-v1')
PAIRS={
 'ssh':('a33d30r','a33d30t','52:54:00:ad:30:01','52:54:00:ad:30:02','10.203.30.1','10.203.30.2',22),
 'ftp':('a33d31r','a33d31t','52:54:00:ad:31:01','52:54:00:ad:31:02','10.203.31.1','10.203.31.2',21),
 'smb':('a33d32r','a33d32t','52:54:00:ad:32:01','52:54:00:ad:32:02','10.203.32.1','10.203.32.2',445),
}

class PolicyError(ValueError):pass

def need(ok,msg):
    if not ok: raise PolicyError(msg)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(obj):
    return (json.dumps(obj,ensure_ascii=True,allow_nan=False,sort_keys=True,
                       separators=(',',':'))+'\n').encode('ascii')

def filter_name(key):
    need(key in f6.ROLES,'BAD_ROLE')
    return 'ardrec-r113-'+key.replace('_','-')+'-tcp-v1'

def filter_xml(role):
    need(role in f6.ROLES,'BAD_ROLE')
    which, network, tap, local_mac=f6.ROLES[role]
    r,t,rm,tm,rip,tip,port=PAIRS[network]
    is_runner=role.startswith('runner_')
    lip, pip=(rip,tip) if is_runner else (tip,rip)
    peer_mac=tm if is_runner else rm
    want_tap=r if is_runner else t
    need(tap==want_tap and local_mac==(rm if is_runner else tm), 'ROLE_TOPOLOGY_MISMATCH')
    root=ET.Element('filter',{'name':filter_name(role)})
    # Only ARP between the pinned two IPv4 peers. Stateless matching is
    # explicit; no IP6, DHCP, multicast, ICMP or FTP data-channel exception.
    for direction,mac,src,dst in (
        ('out',local_mac,lip,pip),('in',peer_mac,pip,lip)):
        rule=ET.SubElement(root,'rule',{'action':'accept','direction':direction,
                                       'priority':'100','statematch':'false'})
        ET.SubElement(rule,'arp',{'srcmacaddr':mac,'srcipaddr':src,'dstipaddr':dst})
    # Runner can initiate one target/port only; server replies only when
    # conntrack reports established. No generic RELATED or broad TCP accept.
    for direction,mac,src,dst,port_key,state in (
        ('out',local_mac,lip,pip,'dstportstart','NEW,ESTABLISHED') if is_runner else
        ('in',peer_mac,pip,lip,'dstportstart','NEW,ESTABLISHED'),
        ('in',peer_mac,pip,lip,'srcportstart','ESTABLISHED') if is_runner else
        ('out',local_mac,lip,pip,'srcportstart','ESTABLISHED'),
    ):
        rule=ET.SubElement(root,'rule',{'action':'accept','direction':direction,
                                       'priority':'200'})
        ET.SubElement(rule,'tcp',{'srcmacaddr':mac,'srcipaddr':src,'dstipaddr':dst,
                                  port_key:str(port),'state':state})
    rule=ET.SubElement(root,'rule',{'action':'drop','direction':'inout','priority':'1000'})
    ET.SubElement(rule,'all')
    raw=ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'
    return raw

def validate_filter(raw,role):
    need(type(raw) is bytes and 0<len(raw)<12000 and b'<!' not in raw,'FILTER_BYTES_INVALID')
    root=ET.fromstring(raw)
    need(root.tag=='filter' and root.attrib=={'name':filter_name(role)} and
         len(root)==5,'FILTER_SCOPE_INVALID')
    for i,rule in enumerate(root):
        need(rule.tag=='rule' and len(rule)==1 and set(rule.attrib) <=
             {'action','direction','priority','statematch'},'RULE_SHAPE_INVALID')
        if i<2:
            need(rule.attrib['action']=='accept' and rule.attrib['priority']=='100'
                 and rule.attrib['statematch']=='false' and rule[0].tag=='arp','ARP_RULE_INVALID')
        elif i<4:
            need(rule.attrib['action']=='accept' and rule.attrib['priority']=='200'
                 and 'statematch' not in rule.attrib and rule[0].tag=='tcp','TCP_RULE_INVALID')
        else:
            need(rule.attrib=={'action':'drop','direction':'inout','priority':'1000'}
                 and rule[0].tag=='all' and not rule[0].attrib,'FINAL_DROP_INVALID')
    # Byte-for-byte canonical policy prevents hidden extra permissions.
    need(raw==filter_xml(role),'FILTER_CANONICAL_BYTES_CHANGED')
    return True

def nft_script():
    # Only one already existing isolated table is flushed; no global ruleset
    # flush and no allow in bridge input or output. Atomic nft -f later.
    table='ardrec_r34_guard'
    out=[f'flush table bridge {table}']
    for role in ('ssh','ftp','smb'):
        r,t,rm,tm,rip,tip,port=PAIRS[role]
        for ingress,egress,smac,src,dst in (
            (r,t,rm,rip,tip),(t,r,tm,tip,rip)):
            out.append(f'add rule bridge {table} forward iifname "{ingress}" '
                       f'oifname "{egress}" ether saddr {smac} '
                       f'ether type arp arp saddr ip {src} arp daddr ip {dst} counter accept')
        out.append(f'add rule bridge {table} forward iifname "{r}" oifname "{t}" '
                   f'ether saddr {rm} ether type ip ip saddr {rip} ip daddr {tip} '
                   f'ip protocol tcp tcp dport {port} counter accept')
        out.append(f'add rule bridge {table} forward iifname "{t}" oifname "{r}" '
                   f'ether saddr {tm} ether type ip ip saddr {tip} ip daddr {rip} '
                   f'ip protocol tcp tcp sport {port} counter accept')
    taps=', '.join('"'+x+'"' for x in sorted({x[2] for x in f6.ROLES.values()}))
    out.extend([
        f'add rule bridge {table} input iifname {{ {taps} }} counter drop',
        f'add rule bridge {table} output oifname {{ {taps} }} counter drop',
        f'add rule bridge {table} forward iifname {{ {taps} }} counter drop',
        f'add rule bridge {table} forward oifname {{ {taps} }} counter drop',
    ])
    raw=('\n'.join(out)+'\n').encode('ascii')
    need(len(out)==17 and raw.count(b'counter accept')==12 and
         raw.count(b'counter drop')==4 and
         b'flush ruleset' not in raw and b'flush table bridge '+table.encode() in raw,
         'NFT_SCOPE_INVALID')
    return raw

def prepare(f5_files,closure_bytes):
    f6.check_f5(f5_files)
    need(type(closure_bytes) is bytes and sha(closure_bytes)==F7E_MANIFEST_SHA256,
         'F7E_CLOSURE_CHANGED')
    closure=f6.load_json(closure_bytes)
    need(closure.get('schema')=='ARDREC-R113-F7E-HISTORICAL-FORENSIC-CLOSURE-v1'
         and closure.get('f7_physical_recovery_reconciled') is True
         and closure.get('f7_original_replay_completed') is False
         and closure.get('six_binding_deny_after')=='SIX_BINDING_DENY_ATTESTED'
         and closure.get('network_traffic_authorized') is False,
         'F7E_PROVENANCE_INVALID')
    result={'r34-window-CANDIDATE.nft':nft_script()}
    for role in f6.ROLES:
        rendered=filter_xml(role)
        validate_filter(rendered,role)
        result[filter_name(role)+'.xml']=rendered
    meta={
        'schema':SCHEMA,'f5_manifest_sha256':f6.F5_DIGEST,
        'f7e_manifest_sha256':F7E_MANIFEST_SHA256,
        'verified_pairs':[{ 'role':role,'runner_ipv4':PAIRS[role][4],
                            'target_ipv4':PAIRS[role][5],'target_tcp':PAIRS[role][6]}
                          for role in ('ssh','ftp','smb')],
        'allow_filter_candidates':6,'bridge_allow_rules_prepared':12,
        'bridge_deny_rules_preserved':4,
        'next_step':'PRIVILEGED_ADMISSION_REQUIRES_SEPARATE_AUTHORIZATION',
        'root_recovery':'F6_ROOT_SIX_BINDINGS',
        'policy_not_deployed':True,'window_not_opened':True,
        'protocol_connections':0,'p8':'NO-GO',
        'sha256':{k:sha(v) for k,v in sorted(result.items())},
    }
    result['manifest.json']=canonical(meta)
    return result
