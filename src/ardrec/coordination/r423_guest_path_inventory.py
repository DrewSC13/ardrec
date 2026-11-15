"""P14-R42.3: receipt-bound guest route/neighbor inventory; no packet generator.

The only guest executables are exact /usr/bin/cat reads of four proc/sysfs
files. QGA control traffic is through libvirt; no ICMP/TCP/UDP guest probes.
All conclusions keep P8=NO-GO; a missing packet is never proof of isolation.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import re
import time
from typing import Any

from ardrec.coordination import r421_bounded_negative_probe as r421
from ardrec.coordination import r422_independent_packet_witness as r422
from ardrec.coordination import r42_isolation_baseline as r42
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r423-guest-route-neighbor-readonly-v1'
INTENT_SCHEMA = 'ardrec-p14-r423-guest-route-intent-v1'
STATUS_DIRECT = 'EXPECTED_GUEST_ROUTE_OBSERVED_NO_GO'
STATUS_REVIEW = 'GUEST_ROUTE_UNEXPECTED_REVIEW_NO_GO'
MAIN_PIN = '7e2936d0e9c61e42fbacae11affeee592abd4897'
R422_PIN = '7816e46d3fd4b24a50bce0171bffd4d3ea307167485f5111529b4b9ed10f3ae6'
PRIOR_FILES = frozenset({r422.INTENT, r422.RESULT, *r422.CAPTURES.values()})
INTENT = 'r423_intent.json'
RESULT = 'r423_guest_route_inventory.json'
FAILURE = 'r423_failure.json'
CAT = '/usr/bin/cat'
READ_PATHS = ('/proc/net/route','/proc/net/arp',
              '/sys/class/net/ens3/statistics/tx_packets',
              '/sys/class/net/ens3/statistics/rx_packets')
MAX_POLLS = 12
MAX_OUTPUT = 8192

class R423Error(ValueError):
    """Stable fail-closed error."""


def need(cond: bool, code: str) -> None:
    if not cond:
        raise R423Error(code)


def seal(doc: dict[str,Any]) -> dict[str,Any]:
    doc['sha256'] = r41.sha(r41.canon(doc))
    return doc


def cat_request(path: str) -> dict[str,Any]:
    need(type(path) is str and path in READ_PATHS, 'guest_path_not_allowlisted')
    return {'execute':'guest-exec','arguments':{'path':CAT,'arg':[path],
             'env':['LC_ALL=C'],'capture-output':True}}


def exact_request(request: Any) -> bool:
    if request in (r421.GUEST_PING, r421.GUEST_INTERFACES):
        return True
    if type(request) is not dict or set(request)!={'execute','arguments'}:
        return False
    if request['execute']=='guest-exec':
        return any(request==cat_request(p) for p in READ_PATHS)
    if request['execute']=='guest-exec-status':
        a=request['arguments']
        return (type(a) is dict and set(a)=={'pid'} and
                type(a['pid']) is int and 0<a['pid']<=2**31-1)
    return False


class Host(r421.Host):
    """QGA messages allowlisted to guest-ping, interfaces and fixed cat reads."""
    def qga(self, request: dict[str,Any]) -> Any:
        need(exact_request(request), 'qga_request_not_readonly_allowlisted')
        need(self.bin['virsh']=='/usr/bin/virsh', 'virsh_binary_drift')
        argv=[self.bin['sudo'],'-n','--',self.bin['virsh'],'-c','qemu:///system',
              'qemu-agent-command',r365.SSH_DOMAIN,'--timeout','5',
              r41.canon(request).decode('ascii')]
        response=r421.parse_json(self.run(argv,timeout=10))
        need(type(response) is dict and set(response)=={'return'}, 'qga_error')
        return response['return']


def decode_status(out: Any) -> bytes | None:
    need(type(out) is dict and type(out.get('exited')) is bool, 'guest_status_invalid')
    if out['exited'] is False:
        return None
    need(type(out.get('exitcode')) is int and out['exitcode']==0 and
         out.get('out-truncated') is not True and out.get('err-truncated') is not True,
         'guest_read_failed')
    stdout=out.get('out-data',''); stderr=out.get('err-data','')
    need(type(stdout) is str and type(stderr) is str and
         len(stdout)<=MAX_OUTPUT*2 and len(stderr)<=1024, 'guest_output_size')
    try:
        raw=base64.b64decode(stdout,validate=True)
        err=base64.b64decode(stderr,validate=True)
    except (ValueError,binascii.Error) as exc:
        raise R423Error('guest_base64_invalid') from exc
    need(len(raw)<=MAX_OUTPUT and len(err)<=512 and not err, 'guest_output_invalid')
    need(b'\x00' not in raw, 'guest_output_nul')
    return raw


def read_guest_file(h: Host, path: str) -> dict[str,Any]:
    pid=h.qga(cat_request(path))
    need(type(pid) is dict and set(pid)=={'pid'} and
         type(pid['pid']) is int and 0<pid['pid']<=2**31-1, 'guest_pid_invalid')
    data=None
    for _ in range(MAX_POLLS):
        data=decode_status(h.qga({'execute':'guest-exec-status','arguments':{'pid':pid['pid']}}))
        if data is not None:
            break
        time.sleep(0.20)
    need(data is not None, 'guest_read_outcome_uncertain')
    return {'path':path,'pid':pid['pid'],'raw':data,'sha256':r41.sha(data)}


def _plain(raw: bytes, *, maxlines: int) -> list[str]:
    need(type(raw) is bytes and len(raw)<=MAX_OUTPUT, 'guest_raw_size')
    try:
        s=raw.decode('ascii')
    except UnicodeError as exc:
        raise R423Error('guest_not_ascii') from exc
    need(all(c=='\n' or c=='\r' or c=='\t' or 32<=ord(c)<=126 for c in s),
         'guest_unprintable')
    lines=s.strip().splitlines()
    need(0<len(lines)<=maxlines, 'guest_lines_invalid')
    return lines


def analyze_route(raw: bytes) -> str:
    lines=_plain(raw,maxlines=128)
    need(lines[0].split()[:4]==['Iface','Destination','Gateway','Flags'],
         'route_header_invalid')
    net=IPv4Network(f'{r421.PROBE_SOURCE}/{r421.PROBE_PREFIX}',strict=False)
    dst=f'{int.from_bytes(net.network_address.packed,"little"):08X}'
    mask=f'{int.from_bytes(net.netmask.packed,"little"):08X}'
    matched=[]
    for line in lines[1:]:
        fields=line.split()
        need(len(fields)>=8 and fields[1].isalnum() and
             len(fields[1])==8 and len(fields[7])==8 and
             all(c in '0123456789abcdefABCDEF' for c in fields[1]+fields[2]+fields[7]),
             'route_row_invalid')
        if fields[1].upper()==dst and fields[7].upper()==mask:
            try: flags=int(fields[3],16)
            except ValueError as exc: raise R423Error('route_flags_invalid') from exc
            matched.append(fields[0]=='ens3' and fields[2]=='00000000' and flags&1==1)
    if matched==[True]:
        return 'DIRECT_ENS3_EXPECTED'
    if matched:
        return 'ROUTE_PRESENT_BUT_UNEXPECTED'
    return 'NO_EXPECTED_DIRECT_ROUTE'


def analyze_arp(raw: bytes) -> str:
    lines=_plain(raw,maxlines=128)
    need(lines[0].split()[:3]==['IP','address','HW'], 'arp_header_invalid')
    matches=[]
    for line in lines[1:]:
        fields=line.split()
        need(len(fields)==6, 'arp_row_invalid')
        if fields[0]==r421.PROBE_TARGET and fields[-1]=='ens3':
            try: flag=int(fields[2],16)
            except ValueError as exc: raise R423Error('arp_flags_invalid') from exc
            matches.append('RESOLVED' if flag&2 else 'INCOMPLETE')
    need(len(matches)<=1, 'duplicate_target_neighbor')
    return matches[0] if matches else 'ABSENT'


def parse_stat(raw:bytes)->int:
    lines=_plain(raw,maxlines=1)
    need(re.fullmatch(r'[0-9]{1,20}',lines[0]) is not None,'counter_format_invalid')
    val=int(lines[0])
    need(0<=val<=2**64-1,'counter_out_of_range')
    return val


def load_source(r422_dir:Path,r421_dir:Path,r420_dir:Path,r411_dir:Path,
                r41_dir:Path,r40_dir:Path,r39_dir:Path,pre_dir:Path,boot_dir:Path)->dict[str,str]:
    chain=r422.load_source(r421_dir,r420_dir,r411_dir,r41_dir,r40_dir,r39_dir,pre_dir,boot_dir)
    files=verified_directory(r422_dir,PRIOR_FILES)
    report=r422.verify_private_receipt(r422_dir)
    need(report['sha256']==R422_PIN and
         report['status']=='NO_GUEST_EGRESS_WITNESSED_NO_GO' and
         report['source_r421_report_sha256']==chain['source_r421_report_sha256'] and
         report['isolation_proven'] is False and report['p8_operational']=='NO-GO' and
         report['capture_files']['tap']['observed']['frames']==0 and
         report['capture_files']['bridge']['observed']['frames']==0,
         'r422_source_drift')
    return {'r422_report_sha256':report['sha256'],
            'r422_file_sha256':r41.sha(files[r422.RESULT]),
            'r421_report_sha256':chain['source_r421_report_sha256']}


def make_report(source:dict[str,str],before:dict[str,Any],after:dict[str,Any],
                readbacks:list[dict[str,Any]],stamp:str)->dict[str,Any]:
    need(source.get('r422_report_sha256')==R422_PIN and
         all(r41.r40.valid_hex(source.get(k)) for k in
             ('r422_file_sha256','r421_report_sha256')), 'source_invalid')
    r422.r411._validate_running(before)
    r422.r411._validate_running(after)
    need(before==after,'host_state_changed')
    need(type(readbacks) is list and len(readbacks)==len(READ_PATHS) and
         [r['path'] for r in readbacks]==list(READ_PATHS), 'guest_reads_incomplete')
    need(all(type(r['pid']) is int and r['pid']>0 and
             r['sha256']==r41.sha(r['raw']) for r in readbacks), 'guest_read_integrity')
    route=analyze_route(readbacks[0]['raw'])
    arp=analyze_arp(readbacks[1]['raw'])
    tx=parse_stat(readbacks[2]['raw']); rx=parse_stat(readbacks[3]['raw'])
    status=STATUS_DIRECT if route=='DIRECT_ENS3_EXPECTED' else STATUS_REVIEW
    r41.parse_utc(stamp)
    need(r41.parse_utc(stamp)<=datetime.now(timezone.utc), 'stamp_future')
    doc={'schema':SCHEMA,'status':status,'mode':'AUTHORIZED_GUEST_READONLY_PROC_SYSFS',
         'source_main':MAIN_PIN,'source_r422_report_sha256':R422_PIN,
         'source_r422_file_sha256':source['r422_file_sha256'],
         'source_r421_report_sha256':source['r421_report_sha256'],
         'captured_at_utc':stamp,'host_before':before,'host_after':after,
         'guest_nic_mac':r421.PROBE_MAC,'guest_ipv4':r421.PROBE_SOURCE,
         'guest_ipv4_prefix':r421.PROBE_PREFIX,'target_ipv4':r421.PROBE_TARGET,
         'guest_paths_read':list(READ_PATHS),
         'guest_read_sha256':[r['sha256'] for r in readbacks],
         'guest_route_state':route,'guest_arp_state':arp,
         'guest_tx_packets_snapshot':tx,'guest_rx_packets_snapshot':rx,
         'guest_readonly_commands_executed':True,
         'guest_ping_executed':False,'test_packets_injected':False,
         'pcap_capture_performed':False,'destination_positive_control_available':False,
         'guest_network_config_modified':False,'host_policy_modified':False,
         'vm_lifecycle_modified':False,'isolation_proven':False,
         'operational_dispatch':False,'automatic_retry':False,
         'real_service_testing':'NOT_EXECUTED','technical_truth_accredited':False,
         'final_risk':None,'published_generation':None,
         'experimental_validation':'ROUTE_NEIGHBOR_INVENTORY_ONLY',
         'p8_operational':'NO-GO',
         'next_gate':'SEPARATE_POSITIVE_DESTINATION_CONTROL_REQUIRED'}
    return seal(doc)


def verify_report(doc:dict[str,Any])->bool:
    need(type(doc) is dict and r41.r40.valid_hex(doc.get('sha256')) and
         doc['sha256']==r41.sha(r41.canon({k:v for k,v in doc.items() if k!='sha256'})),
         'report_digest_invalid')
    need(doc.get('schema')==SCHEMA and doc.get('status') in (STATUS_DIRECT,STATUS_REVIEW) and
         doc.get('mode')=='AUTHORIZED_GUEST_READONLY_PROC_SYSFS' and
         doc.get('source_main')==MAIN_PIN and
         doc.get('source_r422_report_sha256')==R422_PIN and
         all(r41.r40.valid_hex(doc.get(k)) for k in
             ('source_r422_file_sha256','source_r421_report_sha256')) and
         doc.get('guest_nic_mac')==r421.PROBE_MAC and
         doc.get('guest_ipv4')==r421.PROBE_SOURCE and
         doc.get('guest_ipv4_prefix')==r421.PROBE_PREFIX and
         doc.get('target_ipv4')==r421.PROBE_TARGET and
         doc.get('guest_paths_read')==list(READ_PATHS) and
         type(doc.get('guest_read_sha256')) is list and
         len(doc['guest_read_sha256'])==4 and
         all(r41.r40.valid_hex(k) for k in doc['guest_read_sha256']) and
         doc.get('guest_route_state') in ('DIRECT_ENS3_EXPECTED',
             'ROUTE_PRESENT_BUT_UNEXPECTED','NO_EXPECTED_DIRECT_ROUTE') and
         doc.get('guest_arp_state') in ('ABSENT','INCOMPLETE','RESOLVED') and
         all(type(doc.get(k)) is int and 0<=doc[k]<=2**64-1 for k in
             ('guest_tx_packets_snapshot','guest_rx_packets_snapshot')) and
         doc.get('status')==(STATUS_DIRECT if doc.get('guest_route_state')=='DIRECT_ENS3_EXPECTED' else STATUS_REVIEW) and
         doc.get('guest_readonly_commands_executed') is True and
         all(doc.get(k) is False for k in
             ('guest_ping_executed','test_packets_injected','pcap_capture_performed',
              'destination_positive_control_available','guest_network_config_modified',
              'host_policy_modified','vm_lifecycle_modified','isolation_proven',
              'operational_dispatch','automatic_retry','technical_truth_accredited')) and
         doc.get('real_service_testing')=='NOT_EXECUTED' and
         doc.get('final_risk') is None and doc.get('published_generation') is None and
         doc.get('experimental_validation')=='ROUTE_NEIGHBOR_INVENTORY_ONLY' and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('next_gate')=='SEPARATE_POSITIVE_DESTINATION_CONTROL_REQUIRED',
         'false_authority_or_semantics')
    r41.parse_utc(doc.get('captured_at_utc'))
    r422.r411._validate_running(doc.get('host_before'))
    r422.r411._validate_running(doc.get('host_after'))
    need(doc['host_before']==doc['host_after'],'host_drift')
    return True


def perform(*,r422_dir:Path,r421_dir:Path,r420_dir:Path,r411_dir:Path,
            r41_dir:Path,r40_dir:Path,r39_dir:Path,pre_dir:Path,boot_dir:Path,
            receipt_dir:Path,authorized:bool=False,preflight_only:bool=False,
            host:Host|None=None)->dict[str,Any]:
    source=load_source(r422_dir,r421_dir,r420_dir,r411_dir,r41_dir,r40_dir,r39_dir,pre_dir,boot_dir)
    h=host if host is not None else Host()
    ready=r422.preflight(h)
    need(ready['status']=='READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
         'host_not_ready')
    if preflight_only:
        need(authorized is False,'mixed_authorization_modes')
        return {'status':'READY_FOR_SEPARATE_AUTHORIZED_GUEST_READONLY_INSPECTION',
                'p8_operational':'NO-GO'}
    need(authorized is True, 'explicit_guest_read_authorization_required')
    before=ready['host_readback']
    r41._make_dir(receipt_dir)
    intent=seal({'schema':INTENT_SCHEMA,'source_main':MAIN_PIN,
                 'source_r422_report_sha256':R422_PIN,
                 'captured_at_utc':r41.now_utc(),
                 'authorized_by_operator_cli':True,'exact_paths':list(READ_PATHS),
                 'only_guest_cat':True,'no_packet_generators':True,
                 'no_automatic_retry':True,'p8_operational':'NO-GO'})
    raw=r41.canon(intent)+b'\n'
    r41._write_once(receipt_dir/INTENT,raw)
    try:
        need(h.qga(r421.GUEST_PING)=={},'guest_agent_unavailable')
        r421.validate_guest_nic(h.qga(r421.GUEST_INTERFACES))
        readings=[read_guest_file(h,p) for p in READ_PATHS]
        after=r422.preflight(h)['host_readback']
        result=make_report(source,before,after,readings,r41.now_utc())
        verify_report(result)
        out=r41.canon(result)+b'\n'
        r41._write_once(receipt_dir/RESULT,out)
        r41._write_once(receipt_dir/'SHA256SUMS',
            (r41.sha(raw)+'  '+INTENT+'\n'+r41.sha(out)+'  '+RESULT+'\n').encode('ascii'))
        return result
    except Exception as exc:
        failure=seal({'schema':'ardrec-p14-r423-guest-read-failure-v1',
                      'source_main':MAIN_PIN,'source_r422_report_sha256':R422_PIN,
                      'status':'READONLY_GUEST_INSPECTION_INCOMPLETE_NO_GO',
                      'failure_code':type(exc).__name__+':'+str(exc)[:150],
                      'automatic_retry':False,'test_packets_injected':False,
                      'p8_operational':'NO-GO'})
        out=r41.canon(failure)+b'\n'
        r41._write_once(receipt_dir/FAILURE,out)
        r41._write_once(receipt_dir/'SHA256SUMS',
            (r41.sha(raw)+'  '+INTENT+'\n'+r41.sha(out)+'  '+FAILURE+'\n').encode('ascii'))
        raise R423Error('GUEST_READ_REVIEW_NO_AUTOMATIC_RETRY:'+type(exc).__name__+':'+str(exc)[:130]) from exc
