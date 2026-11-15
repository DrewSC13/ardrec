"""R45: candidate SSH/runner positive control OFFLINE; never deployed or run.

All network policy is deny-first. These bytes are candidates for review, not
permission to attach/modify nwfilters, nftables, or VM configuration.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET

from ardrec.coordination import r33_offline_topology as r33
from ardrec.coordination import r34_containment as r34

SCHEMA = 'ardrec-p14-r45-ssh-pair-offline-candidate-v1'
BASE = '1a8483910b030a49454a924bbddbd1668289d623'
SOURCE_IP = '10.203.30.2'
DEST_IP = '10.203.30.1'
SOURCE_MAC = '52:54:00:ad:30:02'
DEST_MAC = '52:54:00:ad:30:01'
SSH_TAP = 'a33d30t'
RUNNER_TAP = 'a33d30r'
FILTER_SSH = 'ardrec-r45-ssh-icmp-candidate'
FILTER_RUNNER = 'ardrec-r45-runner-icmp-candidate'
NFT_CANDIDATE_TABLE = 'ardrec_r45_syntax_only'
FILES = ('ssh-nwfilter-candidate.xml', 'runner-ssh-nwfilter-candidate.xml',
         'ssh-domain-candidate.xml', 'runner-ssh-only-domain-candidate.xml',
         'bridge-ssh-syntax-only.nft', 'r45_candidate.json')

class CandidateError(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok: raise CandidateError(code)

def canon(v: object) -> bytes:
    return json.dumps(v, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')

def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def source_guard() -> None:
    """A changed R33/R34 topology MUST block candidate generation."""
    need(r33.DENY_FILTER == 'ardrec-r33-block-until-containment' and
         r34.NFT_TABLE == 'ardrec_r34_guard' and
         r33.NET_BRIDGE == {'ssh':'br33d30','ftp':'br33d31','smb':'br33d32'},
         'source_policy_identity_drift')
    ssh = r33.RESOURCE['ssh']['nics']; runner = r33.RESOURCE['runner']['nics']
    need(ssh == [('ssh', SOURCE_IP, SOURCE_MAC, SSH_TAP)] and
         runner == [('ssh', DEST_IP, DEST_MAC, RUNNER_TAP),
                    ('ftp', '10.203.31.1','52:54:00:ad:31:01','a33d31r'),
                    ('smb', '10.203.32.1','52:54:00:ad:32:01','a33d32r')] and
         tuple(sorted(r34.TAPS)) == ('a33d30r','a33d30t','a33d31r','a33d31t','a33d32r','a33d32t'),
         'source_topology_identity_drift')

def xml_bytes(root: ET.Element) -> bytes:
    ET.indent(root, space='  ')
    return ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'

def filter_candidate(*, runner: bool) -> bytes:
    source_guard()
    name = FILTER_RUNNER if runner else FILTER_SSH
    ownip, peerip = (DEST_IP, SOURCE_IP) if runner else (SOURCE_IP, DEST_IP)
    ownmac, peermac = (DEST_MAC, SOURCE_MAC) if runner else (SOURCE_MAC, DEST_MAC)
    root = ET.Element('filter', {'name':name, 'chain':'root'})
    ET.SubElement(root, 'uuid').text = str(uuid.uuid5(uuid.NAMESPACE_URL, 'urn:ardrec:r45:offline:'+name))
    rules = [
        ('out','arp', {'opcode': 'Reply' if runner else 'Request',
                       'arpsrcmacaddr':ownmac, 'arpsrcipaddr':ownip,
                       'arpdstipaddr':peerip}),
        ('in','arp', {'opcode': 'Request' if runner else 'Reply',
                      'arpsrcmacaddr':peermac, 'arpsrcipaddr':peerip,
                      'arpdstipaddr':ownip}),
        ('out','icmp', {'type':'0' if runner else '8', 'code':'0',
                        'srcmacaddr':ownmac,
                        'srcipaddr':ownip, 'dstipaddr':peerip}),
        ('in','icmp', {'type':'8' if runner else '0','code':'0',
                       'srcmacaddr':peermac,
                       'srcipaddr':peerip, 'dstipaddr':ownip}),
    ]
    for i, (direction, protocol, attrs) in enumerate(rules):
        rule = ET.SubElement(root, 'rule', {'action':'accept',
                            'direction':direction, 'priority':str(100+i*20)})
        ET.SubElement(rule, protocol, attrs)
    ET.SubElement(ET.SubElement(root,'rule', {'action':'drop',
                  'direction':'inout','priority':'1000'}), 'all')
    raw = xml_bytes(root)
    check_filter(raw, runner=runner)
    return raw

def check_filter(raw: bytes, *, runner: bool) -> None:
    root=ET.fromstring(raw)
    target=FILTER_RUNNER if runner else FILTER_SSH
    need(root.tag=='filter' and root.attrib=={'name':target,'chain':'root'} and
         len(root.findall('uuid')) == 1, 'filter_identity_invalid')
    rules=root.findall('rule')
    need(len(rules)==5 and [(r.attrib['action'],r.attrib['direction']) for r in rules] ==
         [('accept','out'),('accept','in'),('accept','out'),('accept','in'),('drop','inout')],
         'filter_rule_order_invalid')
    need([r[0].tag for r in rules] == ['arp','arp','icmp','icmp','all'] and
         rules[-1].attrib['priority']=='1000', 'filter_proto_or_drop_invalid')
    # libvirt's actual nwfilter Relax-NG grammar allows srcmacaddr, but NOT
    # dstmacaddr, in an <icmp/> child. Keep destination-IP restrictions here;
    # candidate nftables also pins the destination Ethernet MAC independently.
    ownip, peerip = (DEST_IP, SOURCE_IP) if runner else (SOURCE_IP, DEST_IP)
    ownmac, peermac = (DEST_MAC, SOURCE_MAC) if runner else (SOURCE_MAC, DEST_MAC)
    expected = [
        {'opcode':'Reply' if runner else 'Request',
         'arpsrcmacaddr':ownmac, 'arpsrcipaddr':ownip, 'arpdstipaddr':peerip},
        {'opcode':'Request' if runner else 'Reply',
         'arpsrcmacaddr':peermac, 'arpsrcipaddr':peerip, 'arpdstipaddr':ownip},
        {'type':'0' if runner else '8', 'code':'0',
         'srcmacaddr':ownmac, 'srcipaddr':ownip, 'dstipaddr':peerip},
        {'type':'8' if runner else '0', 'code':'0',
         'srcmacaddr':peermac, 'srcipaddr':peerip, 'dstipaddr':ownip},
    ]
    for i, (rule, attrs) in enumerate(zip(rules[:4], expected)):
        need(rule.attrib['priority']==str(100+i*20) and len(rule)==1 and
             rule[0].attrib==attrs and not list(rule[0]),
             'filter_protocol_attributes_invalid')
    need(rules[-1].attrib=={'action':'drop','direction':'inout','priority':'1000'} and
         len(rules[-1])==1 and not rules[-1][0].attrib and
         not list(rules[-1][0]), 'filter_terminal_drop_invalid')

def domain_candidate(*, runner: bool) -> bytes:
    source_guard()
    name='runner' if runner else 'ssh'
    root=ET.fromstring(r33.render_xml(r33.R32_RECEIPT_FILE_SHA256)['domain-'+name+'.xml'])
    interfaces=root.findall('./devices/interface')
    need(len(interfaces)==(3 if runner else 1), 'source_interface_cardinality')
    if runner:
        for nic in interfaces[1:]: root.find('devices').remove(nic)
    nic=root.find('./devices/interface')
    need(nic is not None and nic.find('mac').attrib['address']==
         (DEST_MAC if runner else SOURCE_MAC), 'domain_ssh_mac_mismatch')
    ref=nic.find('filterref')
    need(ref is not None and ref.attrib.get('filter')==r33.DENY_FILTER, 'source_filterref_changed')
    ref.attrib['filter'] = FILTER_RUNNER if runner else FILTER_SSH
    raw=xml_bytes(root)
    check_domain(raw,runner=runner)
    return raw

def check_domain(raw: bytes, *, runner: bool) -> None:
    root=ET.fromstring(raw)
    need(root.tag=='domain' and root.findtext('name')==r33.DOMAIN_PREFIX+('runner' if runner else 'ssh'),
         'domain_identity_mismatch')
    interfaces=root.findall('./devices/interface')
    need(len(interfaces)==1, 'extra_runner_nics_not_removed')
    nic=interfaces[0]
    need(nic.find('source').attrib['network']==r33.NETWORK_PREFIX+'ssh' and
         nic.find('filterref').attrib['filter']==(FILTER_RUNNER if runner else FILTER_SSH) and
         nic.find('target').attrib['dev']==(RUNNER_TAP if runner else SSH_TAP) and
         nic.find('mac').attrib['address']==(DEST_MAC if runner else SOURCE_MAC),
         'interface_candidate_mismatch')
    need(root.find('./devices/disk/source') is not None and
         root.find('./devices/disk/source').attrib['file']==
         '/var/lib/libvirt/images/ardrec-dev-point4-r32/'+('runner' if runner else 'ssh')+'-runtime.qcow2',
         'disk_changed')
    need(not root.findall('./devices/hostdev') and not root.findall('./devices/graphics') and
         not root.findall('./devices/filesystem'), 'unsafe_domain_device')

def nft_candidate() -> bytes:
    """Syntax-check-only table. Existing R34 deny table is NOT replaced.

    This table is deliberately named differently: even installing it would not
    defeat R34 DROP and is not a functional positive-control authorization.
    """
    source_guard()
    names=', '.join('"'+x+'"' for x in sorted(r34.TAPS))
    lines=[
        '# R45 SYNTAX-ONLY candidate. NOT AN APPLY SCRIPT. R34 remains DROP ALL.',
        '# Do not load this as a functioning allowlist. Requires coordinated review.',
        f'table bridge {NFT_CANDIDATE_TABLE} {{',
        '  chain input {',
        '    type filter hook input priority -200; policy accept;',
        f'    iifname {{ {names} }} counter drop',
        '  }',
        '  chain output {',
        '    type filter hook output priority -200; policy accept;',
        f'    oifname {{ {names} }} counter drop',
        '  }',
        '  chain forward {',
        '    type filter hook forward priority -200; policy accept;',
        f'    iifname "{SSH_TAP}" oifname "{RUNNER_TAP}" ether saddr {SOURCE_MAC} ether type arp arp operation request arp saddr ip {SOURCE_IP} arp daddr ip {DEST_IP} counter accept',
        f'    iifname "{RUNNER_TAP}" oifname "{SSH_TAP}" ether saddr {DEST_MAC} ether type arp arp operation reply arp saddr ip {DEST_IP} arp daddr ip {SOURCE_IP} counter accept',
        f'    iifname "{SSH_TAP}" oifname "{RUNNER_TAP}" ether saddr {SOURCE_MAC} ether daddr {DEST_MAC} ip saddr {SOURCE_IP} ip daddr {DEST_IP} icmp type echo-request counter accept',
        f'    iifname "{RUNNER_TAP}" oifname "{SSH_TAP}" ether saddr {DEST_MAC} ether daddr {SOURCE_MAC} ip saddr {DEST_IP} ip daddr {SOURCE_IP} icmp type echo-reply counter accept',
        f'    iifname {{ {names} }} counter drop',
        f'    oifname {{ {names} }} counter drop',
        '  }','}',
    ]
    raw=('\n'.join(lines)+'\n').encode('ascii')
    need(b'flush ruleset' not in raw and b'10.203.31.' not in raw and b'10.203.32.' not in raw and
         raw.count(b'counter accept')==4 and raw.count(b'counter drop')==4 and
         b'table bridge ardrec_r34_guard' not in raw, 'nft_candidate_scope_invalid')
    return raw

def build_files() -> dict[str,bytes]:
    source_guard()
    outputs={
      'ssh-nwfilter-candidate.xml':filter_candidate(runner=False),
      'runner-ssh-nwfilter-candidate.xml':filter_candidate(runner=True),
      'ssh-domain-candidate.xml':domain_candidate(runner=False),
      'runner-ssh-only-domain-candidate.xml':domain_candidate(runner=True),
      'bridge-ssh-syntax-only.nft':nft_candidate(),
    }
    report={
        'schema':SCHEMA,'status':'OFFLINE_CANDIDATES_ONLY_NO_GO',
        'source_main':BASE,
        'source_r33_r34':'PINNED_ORIGINAL_DENY_FIRST_UNCHANGED',
        'positive_destination_available':False,
        'runner_current_state':'OFF_ORIGINALLY_THREE_NICS',
        'runner_candidate_nics':['ssh'],
        'existing_filter_modified':False,'existing_nft_guard_modified':False,
        'active_libvirt_domain_modified':False,
        'host_commands_executed':False,'guest_commands_executed':False,
        'vm_started':False,'packets_injected':False,
        'ssh_positive_control_verified':False,
        'isolation_proven':False,'p8_operational':'NO-GO',
        'operational_dispatch':False,'real_pentesting':'NOT_EXECUTED',
        'candidate_files':[{'filename':name,'sha256':sha(content)} for name,content in sorted(outputs.items())],
        'required_next_gates':[
            'OFFLINE_SYNTAX_VALIDATE_NWFILTER_AND_NFT',
            'INDEPENDENT_CHANGE_REVIEW_AND_ROLLBACK_PLAN',
            'VERIFY_LIVE_LIBVIRT_AND_RUNNER_DISK_EXACT_MATCH',
            'SEPARATE_OPERATOR_APPROVAL_FOR_ANY_FILTER_OR_VM_MODIFICATION',
            'POSITIVE_AND_NEGATIVE_PACKET_WITNESS_WITH_DESTINATION_RECEIPT',
            'RE_EVALUATE_P8_ONLY_AFTER_EVIDENCE',
        ],
    }
    report['sha256']=sha(canon(report))
    outputs['r45_candidate.json']=canon(report)+b'\n'
    need(tuple(sorted(outputs))==tuple(sorted(FILES)), 'candidate_file_count_invalid')
    return outputs

def verify_directory(path:Path) -> dict:
    need(isinstance(path,Path) and path.is_absolute() and not path.is_symlink() and
         path.is_dir(), 'receipt_dir_invalid')
    outputs=build_files()
    need(set(p.name for p in path.iterdir())==set(outputs)|{'SHA256SUMS'}, 'unexpected_file_in_receipt')
    for name,expected in outputs.items():
        file=path/name
        need(file.is_file() and not file.is_symlink() and file.stat().st_nlink==1 and
             file.stat().st_mode&0o077==0 and file.read_bytes()==expected,'receipt_file_invalid_'+name)
    sums=(''.join(f'{sha(outputs[name])}  {name}\n' for name in sorted(outputs))).encode('ascii')
    need((path/'SHA256SUMS').read_bytes()==sums, 'receipt_sums_invalid')
    doc=json.loads(outputs['r45_candidate.json'])
    need(doc['sha256']==sha(canon({k:v for k,v in doc.items() if k!='sha256'})), 'internal_digest_invalid')
    return doc

def prepare(path:Path)->dict:
    need(isinstance(path,Path) and path.is_absolute() and not path.exists() and
         not any(p.is_symlink() for p in (path,*path.parents)), 'new_absolute_non_symlink_path_required')
    parent=path.parent
    need(parent.is_dir() and parent.stat().st_uid==os.getuid() and
         stat.S_IMODE(parent.stat().st_mode)==0o700, 'private_parent_required')
    outputs=build_files()
    path.mkdir(mode=0o700)
    try:
        for name,data in sorted(outputs.items()):
            fd=os.open(path/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
        sums=''.join(f'{sha(outputs[name])}  {name}\n' for name in sorted(outputs)).encode('ascii')
        fd=os.open(path/'SHA256SUMS',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(sums); stream.flush(); os.fsync(stream.fileno())
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except BaseException:
        # Keep partial evidence for operator review; no automatic cleanup.
        raise
    return verify_directory(path)
