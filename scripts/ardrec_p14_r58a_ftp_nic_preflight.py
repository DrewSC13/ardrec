#!/usr/bin/env python3
"""R58-A / FTP: host-only READONLY reconciliation of the runner NIC and R34.

No write commands, VM starts, network creation, changes to systemd, or packets.
The audit deliberately never attests the first-boot guard or P8.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree as ET

SOURCE_COMMIT = 'be7bc497bbbb45b585ac308066d6ff08b07775bd'
REPO = Path('/home/cicada/Development/GitHub/ardrec')
DOMAIN_PREFIX = 'ardrec-r33-dev-'
NET_PREFIX = 'ardrec-r33-dev-net-'
FILTER = 'ardrec-r33-block-until-containment'
TABLE = 'ardrec_r34_guard'
TAPS = frozenset(('a33d30r','a33d30t','a33d31r','a33d31t','a33d32r','a33d32t'))
NIC = {
    'runner_ssh': ('ardrec-r33-dev-net-ssh', '52:54:00:ad:30:01', 'a33d30r'),
    'runner_ftp': ('ardrec-r33-dev-net-ftp', '52:54:00:ad:31:01', 'a33d31r'),
    'runner_smb': ('ardrec-r33-dev-net-smb', '52:54:00:ad:32:01', 'a33d32r'),
    'ftp_target': ('ardrec-r33-dev-net-ftp', '52:54:00:ad:31:02', 'a33d31t'),
}
NET = 'ardrec-r33-dev-net-ftp'
BRIDGE = 'br33d31'

class Blocked(ValueError):
    """Fail closed on host mismatch or missing read permission."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise Blocked(code)


def _root(raw: bytes) -> ET.Element:
    need(type(raw) is bytes and 0 < len(raw) < 300_000 and
         b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,
         'XML_SIZE_OR_ENTITIES')
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise Blocked('XML_PARSE') from exc


def nic_details(interface: ET.Element) -> tuple[str, str, str, str]:
    need(interface.tag == 'interface' and interface.get('type') == 'network',
         'UNSUPPORTED_NIC_TYPE')
    src = interface.find('source')
    mac = interface.find('mac')
    target = interface.find('target')
    guard = interface.find('filterref')
    need(src is not None and mac is not None and target is not None and guard is not None,
         'NIC_MISSING_ATTRIBUTE')
    need(len(interface.findall('filterref')) == 1,
         'NIC_FILTER_DUPLICATED')
    values = (src.get('network'),mac.get('address'),target.get('dev'),guard.get('filter'))
    need(all(isinstance(x, str) and x for x in values), 'NIC_VALUE_EMPTY')
    return values


def read_nics(raw: bytes, domain: str) -> dict[str, tuple[str,str,str,str]]:
    root = _root(raw)
    need(root.tag == 'domain' and root.findtext('name') == domain,
         'DOMAIN_NAME_OR_TYPE_MISMATCH')
    rows = root.findall('devices/interface')
    result: dict[str, tuple[str,str,str,str]] = {}
    for iface in rows:
        fields = nic_details(iface)
        tap = fields[2]
        need(tap not in result, 'DUPLICATE_TAP')
        result[tap] = fields
    return result


def audit_domain_nics(runner_raw: bytes, ftp_raw: bytes) -> dict:
    runner = read_nics(runner_raw, DOMAIN_PREFIX + 'runner')
    target = read_nics(ftp_raw, DOMAIN_PREFIX + 'ftp')
    expected_runner = {
        NIC[key][2]: (*NIC[key], FILTER)
        for key in ('runner_ssh', 'runner_ftp', 'runner_smb')
    }
    need(set(runner).issubset(set(expected_runner)), 'RUNNER_UNAUTHORIZED_TAP')
    for tap, value in runner.items():
        need(value == expected_runner[tap], 'RUNNER_NIC_IDENTITY_OR_FILTER_DRIFT_' + tap)
    need('a33d30r' in runner, 'RUNNER_SSH_NIC_MISSING')
    need(target == {'a33d31t': (*NIC['ftp_target'], FILTER)},
         'FTP_TARGET_NIC_IDENTITY_OR_FILTER_DRIFT')
    return {
        'runner_ssh': 'MATCHED',
        'runner_ftp': 'MATCHED' if 'a33d31r' in runner else 'MISSING_IN_INACTIVE_XML',
        'runner_smb': 'MATCHED' if 'a33d32r' in runner else 'MISSING_IN_INACTIVE_XML',
        'ftp_target': 'MATCHED',
        'observed_runner_taps': sorted(runner),
        'expected_ftp_runner': {
            'network': NIC['runner_ftp'][0], 'mac': NIC['runner_ftp'][1],
            'tap': NIC['runner_ftp'][2], 'filter': FILTER,
        },
    }


def audit_network(raw: bytes) -> dict:
    root = _root(raw)
    need(root.tag == 'network' and root.findtext('name') == NET,
         'FTP_NET_NAME_DRIFT')
    b = root.find('bridge')
    dns = root.find('dns')
    need(b is not None and b.get('name') == BRIDGE and b.get('stp') == 'off'
         and b.get('delay') == '0', 'FTP_NET_BRIDGE_DRIFT')
    need(dns is not None and dns.get('enable') == 'no', 'FTP_NET_DNS_DRIFT')
    need(all(root.find(n) is None for n in ('forward','ip','route','dhcp','portgroup')),
         'FTP_NET_ROUTING_OR_IP_PRESENT')
    need(root.find('virtualport') is None, 'FTP_NET_VIRTUALPORT_PRESENT')
    # libvirt may add a generated <mac> during define; no global subnet inference.
    return {'definition':'ISOLATED_XML_CONSISTENT',
            'bridge': BRIDGE, 'ip_or_forward_in_xml':False,
            'ipv6_explicitly_attested':root.get('ipv6') == 'no'}


def audit_filter(raw: bytes) -> str:
    root = _root(raw)
    need(root.tag == 'filter' and root.get('name') == FILTER and
         root.get('chain') == 'root', 'DENY_FILTER_IDENTITY')
    rules = root.findall('rule')
    need(len(rules) == 1 and rules[0].attrib == {
         'action':'drop','direction':'inout','priority':'1000'} and
         len(rules[0]) == 1 and rules[0][0].tag == 'all' and
         not rules[0][0].attrib, 'DENY_FILTER_NOT_DROP_ALL')
    return 'DROP_ALL_DEFINITION_MATCHED'


def audit_nft(raw: bytes) -> str:
    need(type(raw) is bytes and 0 < len(raw) < 400_000, 'NFT_JSON_SIZE')
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Blocked('NFT_JSON_PARSE') from exc
    need(type(doc) is dict and type(doc.get('nftables')) is list,
         'NFT_JSON_SCHEMA')
    rows = doc['nftables']
    tables = [x['table'] for x in rows if isinstance(x,dict) and isinstance(x.get('table'),dict)]
    need(len(tables) == 1 and tables[0].get('family') == 'bridge'
         and tables[0].get('name') == TABLE, 'NFT_TABLE_DRIFT')
    chains = {x['chain'].get('name'):x['chain'] for x in rows
              if isinstance(x,dict) and isinstance(x.get('chain'),dict)}
    need(set(chains)=={'input','output','forward'},'NFT_CHAIN_INVENTORY_DRIFT')
    for name in ('input','output','forward'):
        x = chains[name]
        need(x.get('family')=='bridge' and x.get('table')==TABLE and
             x.get('hook')==name and x.get('type')=='filter' and
             x.get('prio')==-200 and x.get('policy')=='accept',
             'NFT_CHAIN_DRIFT_' + name)
    expected = {('input','iifname'), ('output','oifname'),
                ('forward','iifname'),('forward','oifname')}
    seen: set[tuple[str,str]] = set()
    rules = [x['rule'] for x in rows if isinstance(x,dict) and isinstance(x.get('rule'),dict)]
    need(len(rules)==4, 'NFT_RULE_COUNT')
    for row in rules:
        need(row.get('family')=='bridge' and row.get('table')==TABLE,
             'NFT_RULE_SCOPE')
        expr = row.get('expr')
        need(type(expr) is list and len(expr)==3, 'NFT_RULE_EXPR_COUNT')
        m = expr[0].get('match') if isinstance(expr[0],dict) else None
        need(isinstance(m,dict) and m.get('op')=='==' and
             isinstance(m.get('left'),dict) and
             isinstance(m['left'].get('meta'),dict), 'NFT_MATCH_SHAPE')
        side = m['left']['meta'].get('key')
        need((row.get('chain'),side) in expected and (row.get('chain'),side) not in seen,
             'NFT_RULE_DUPLICATE_OR_UNEXPECTED')
        right = m.get('right')
        need(isinstance(right,dict) and type(right.get('set')) is list and
             set(right['set'])==TAPS and len(right['set'])==len(TAPS),
             'NFT_TAP_SET')
        need(isinstance(expr[1],dict) and 'counter' in expr[1] and
             isinstance(expr[2],dict) and 'drop' in expr[2], 'NFT_DROP_MISSING')
        seen.add((row['chain'],side))
    need(seen == expected,'NFT_RULES_INCOMPLETE')
    return 'DENY_STRUCTURE_MATCHED_FOUR_SCOPED_DROPS'


def decide(nics: dict, *, network: dict, nft_status: str, filter_status: str,
           four_off: bool, ftp_network_inactive: bool) -> dict:
    need(nics['ftp_target'] == 'MATCHED' and nics['runner_ssh'] == 'MATCHED',
         'NIC_REQUIRED_ASSERTION')
    need(network['definition']=='ISOLATED_XML_CONSISTENT' and
         nft_status.startswith('DENY_STRUCTURE_MATCHED') and
         filter_status=='DROP_ALL_DEFINITION_MATCHED', 'DENY_GUARD_NOT_VERIFIED')
    need(four_off and ftp_network_inactive, 'LIVE_GUEST_OR_FTP_NET_UNEXPECTED')
    missing = nics['runner_ftp'] != 'MATCHED'
    return {
        'schema':'ardrec-r58a-ftp-nic-readonly-v1',
        'source_git_head':SOURCE_COMMIT,
        'ftp_nic':nics,
        'ftp_network':network,
        'nft_r34':nft_status,
        'nwfilter_r34':filter_status,
        'four_dev_domains_off':True,
        'ftp_network_inactive':True,
        'result':('BLOCKED_FTP_RUNNER_NIC_MISSING'
                  if missing else 'FTP_NIC_PRESENT_NOT_AUTHORIZED_TO_START'),
        'next_step':('PREPARE_SEPARATE_FTP_RUNNER_NIC_RECONCILIATION'
                     if missing else 'COMPLETE_F11_BOOT_GUARD_AND_BINDING_ATTESTATION'),
        'physical_mutations':0,
        'traffic_generated':False,
        'boot_guard_first_start_attested':False,
        'effective_binding_attested':False,
        'p8':'NO-GO',
        'experimental_validation':'NOT_RUN',
    }


def run_readonly(cmd: list[str], timeout: int=30) -> bytes:
    allowed = (
        ['/usr/bin/git', '-C', str(REPO), 'rev-parse', 'HEAD'],
        ['/usr/bin/git', '-C', str(REPO), 'merge-base', '--is-ancestor',
         SOURCE_COMMIT, 'HEAD'],
    )
    is_virsh = cmd[:4] == ['/usr/bin/virsh','--readonly','-c','qemu:///system']
    is_nft = cmd[:5] == ['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j']
    need(is_virsh or is_nft or cmd in allowed, 'HOST_COMMAND_NOT_ALLOWLISTED')
    if is_virsh:
        need(cmd[4:] in [
            ['dumpxml',DOMAIN_PREFIX+'runner','--inactive'],
            ['dumpxml',DOMAIN_PREFIX+'ftp','--inactive'],
            ['net-dumpxml',NET],
            ['nwfilter-dumpxml',FILTER],
            ['net-list','--name'],
        ] + [['domstate',DOMAIN_PREFIX+r] for r in ('runner','ssh','ftp','smb')],
        'HOST_VIRSH_VERB_NOT_ALLOWED')
    if is_nft:
        need(cmd == ['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j','-a','list','table','bridge',TABLE],
             'HOST_NFT_VERB_NOT_ALLOWED')
    try:
        p = subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=timeout,check=False,
            env={**os.environ,'LC_ALL':'C','LANG':'C'},close_fds=True)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Blocked('HOST_READ_UNAVAILABLE') from exc
    need(p.returncode==0 and len(p.stdout)<=400_000 and len(p.stderr)<=16_000,
         'HOST_READ_FAILED_' + cmd[-1][:60])
    return p.stdout


def read_host() -> dict:
    need(Path.cwd().resolve() == REPO,'CWD_MUST_BE_REPOSITORY')
    head = run_readonly(['/usr/bin/git','-C',str(REPO),'rev-parse','HEAD']).decode().strip()
    # The original commit is an immutable provenance anchor, not the only
    # permitted HEAD: signed integration commits must remain executable.
    need(len(head) == 40 and all(c in '0123456789abcdef' for c in head),
         'GIT_HEAD_INVALID')
    run_readonly(['/usr/bin/git','-C',str(REPO),'merge-base',
                  '--is-ancestor',SOURCE_COMMIT,'HEAD'])
    base=['/usr/bin/virsh','--readonly','-c','qemu:///system']
    nftcmd=['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j','-a',
            'list','table','bridge',TABLE]
    nft_first = audit_nft(run_readonly(nftcmd))
    filter_status = audit_filter(run_readonly(base+['nwfilter-dumpxml',FILTER]))
    nics = audit_domain_nics(
        run_readonly(base+['dumpxml',DOMAIN_PREFIX+'runner','--inactive']),
        run_readonly(base+['dumpxml',DOMAIN_PREFIX+'ftp','--inactive']))
    network = audit_network(run_readonly(base+['net-dumpxml',NET]))
    states = {r:run_readonly(base+['domstate',DOMAIN_PREFIX+r]).decode().strip().lower()
              for r in ('runner','ssh','ftp','smb')}
    active_nets = set(x.strip() for x in
                      run_readonly(base+['net-list','--name']).decode().splitlines() if x.strip())
    nft_second = audit_nft(run_readonly(nftcmd))
    need(nft_first==nft_second,'R34_CHANGED_DURING_READ')
    result = decide(nics,network=network,nft_status=nft_second,
        filter_status=filter_status,four_off=all(s=='shut off' for s in states.values()),
        ftp_network_inactive=NET not in active_nets)
    result['states'] = states
    result['observed_git_head'] = head
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-readonly',action='store_true',required=True)
    parser.parse_args()
    try:
        report=read_host()
    except (Blocked,ValueError,UnicodeError,KeyError,TypeError) as exc:
        print('R58A_FTP_READONLY=BLOCKED:'+str(exc)[:180])
        print('R58A_FTP_HOST_MUTATIONS=0')
        print('R58A_FTP_P8=NO-GO')
        return 23
    print(json.dumps(report,sort_keys=True,ensure_ascii=True,indent=2))
    return 21 if report['result']=='BLOCKED_FTP_RUNNER_NIC_MISSING' else 22

if __name__=='__main__':
    sys.exit(main())
