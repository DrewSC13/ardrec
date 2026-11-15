"""P14-R42.2: bounded independent TAP/bridge packet witness for SSH laboratory.

A marked single guest ICMP attempt and two *passive* Linux pcap witnesses.
An observer is not a destination receipt or proof of containment. NO-GO always.
No SSH/network-policy/VM-lifecycle modifications, no shell invocation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import struct
import subprocess
import time
from typing import Any

from ardrec.coordination import r421_bounded_negative_probe as r421
from ardrec.coordination import r42_isolation_baseline as r42
from ardrec.coordination import r411_external_ssh_observation as r411
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r422-independent-ssh-pcap-witness-v1'
INTENT_SCHEMA = 'ardrec-p14-r422-capture-probe-intent-v1'
MAIN_PIN = '728a4b07219ba9a7f4e0d16cb2e05543d14849dd'
R421_REPORT_PIN = 'c59303812eba75bd44392a585de79f678070f49f276b32b7f5fff18a804f47d9'
PRIOR_FILES = frozenset({r421.INTENT, r421.RESULT})
RESULT = 'r422_packet_witness.json'
INTENT = 'r422_intent.json'
FAILURE = 'r422_failure.json'
CAPTURES = {'tap':'r422-tap.pcap', 'bridge':'r422-bridge.pcap'}
INTERFACES = {'tap':'a33d30t', 'bridge':'br33d30'}
CAPTURE_MAX_SECONDS = 18
MAX_CAPTURE_PACKETS = 12
MAX_CAPTURE_BYTES = 4096
SNAPLEN = 128
PCAP_HEADER_BYTES = 24
FILTER = 'ether src 52:54:00:ad:30:02 and (arp or icmp)'

class R422Error(ValueError):
    """Fail-closed independent witness exception."""

def need(cond: bool, reason: str) -> None:
    if not cond:
        raise R422Error(reason)

def seal(doc: dict[str,Any]) -> dict[str,Any]:
    doc['sha256'] = r41.sha(r41.canon(doc))
    return doc

def marked_command(marker: str) -> dict[str,Any]:
    need(type(marker) is str and len(marker) == 16 and
         all(x in '0123456789abcdef' for x in marker), 'marker_invalid')
    return {'execute':'guest-exec','arguments':{
        'path':'/usr/bin/ping',
        'arg':['-n','-I',r421.PROBE_SOURCE,'-c','1','-W','1',
               '-s','56','-p',marker,r421.PROBE_TARGET],
        'env':['LC_ALL=C'],'capture-output':True}}

def pcap_records(raw: bytes, marker: str) -> dict[str,int]:
    """Strict classic PCAP parser, Ethernet only, with IP/ARP causal fields.

    PCAP alone cannot prove no packets traversed a different interface.
    """
    need(type(raw) is bytes and 24 <= len(raw) <= MAX_CAPTURE_BYTES, 'pcap_size')
    need(raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                     b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'), 'pcap_magic')
    order = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    major,minor,_,_,snaplen,link = struct.unpack_from(order+'HHiIII',raw,4)
    need(major == 2 and minor == 4 and snaplen == SNAPLEN and link == 1,
         'pcap_header_contract')
    need(type(marker) is str and len(marker) == 16 and
         all(c in '0123456789abcdef' for c in marker), 'marker_invalid')
    pos, frames, arp, marked, other = 24, 0, 0, 0, 0
    expected_mac = bytes.fromhex(r421.PROBE_MAC.replace(':',''))
    from ipaddress import IPv4Address
    source = IPv4Address(r421.PROBE_SOURCE).packed
    target = IPv4Address(r421.PROBE_TARGET).packed
    pattern = bytes.fromhex(marker)
    while pos < len(raw):
        need(pos + 16 <= len(raw), 'pcap_truncated_record')
        _sec,_usec,incl,original = struct.unpack_from(order+'IIII',raw,pos)
        pos += 16
        need(14 <= incl <= SNAPLEN and incl <= original <= 65535 and
             pos + incl <= len(raw) and frames < MAX_CAPTURE_PACKETS,
             'pcap_record_invalid')
        frame=raw[pos:pos+incl]
        pos+=incl; frames+=1
        need(frame[6:12] == expected_mac,'unrelated_source_mac')
        ethertype=int.from_bytes(frame[12:14],'big')
        if ethertype==0x0806:
            need(len(frame)>=42,'truncated_arp')
            a=frame[14:42]
            if (a[:8]==b'\x00\x01\x08\x00\x06\x04\x00\x01' and
                a[8:14]==expected_mac and a[14:18]==source and a[24:28]==target):
                arp+=1
            else: other+=1
        elif ethertype==0x0800:
            need(len(frame)>=34, 'truncated_ipv4')
            ip=frame[14:]
            ihl=(ip[0]&15)*4
            need((ip[0]>>4)==4 and 20<=ihl<=60 and len(ip)>=ihl+8,
                 'ipv4_header_invalid')
            if ip[9]==1 and ip[12:16]==source and ip[16:20]==target:
                icmp=ip[ihl:]
                if (icmp[0]==8 and icmp[1]==0 and len(icmp)>=32 and
                        pattern in icmp[8:]):
                    marked+=1
                else: other+=1
            else: other+=1
        else:
            other+=1
    need(pos==len(raw), 'pcap_trailing_data')
    return {'frames':frames, 'matching_arp_requests':arp,
            'marked_icmp_echo_requests':marked,'other_frames':other}

def load_source(r421_dir:Path, r420_dir:Path, r411_dir:Path, r41_dir:Path,
                r40_dir:Path, r39_dir:Path, pre_dir:Path, boot_dir:Path) -> dict[str,str]:
    source = r421.source_chain(r420_dir,r411_dir,r41_dir,r40_dir,r39_dir,pre_dir,boot_dir)
    files = verified_directory(r421_dir,PRIOR_FILES)
    raw=files[r421.RESULT]
    doc=r365.read_json(raw)
    r421.verify_report(doc)
    need(doc['sha256']==R421_REPORT_PIN and
         doc['status']=='BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO' and
         doc['source_r420_report_sha256']==source['r420_report_sha256'] and
         doc['source_r420_file_sha256']==source['r420_file_sha256'] and
         doc['source_r411_report_sha256']==source['r411_report_sha256'] and
         doc['isolation_proven'] is False and
         doc['p8_operational']=='NO-GO', 'r421_source_pin_or_semantics_invalid')
    return {'source_r421_report_sha256':doc['sha256'],
            'source_r421_file_sha256':r41.sha(raw),
            'source_r420_report_sha256':source['r420_report_sha256']}

class Host(r421.Host):
    """R42.1 allowlist with only one extra exact marked guest-exec request."""
    def qga(self, request:dict[str,Any]) -> Any:
        if type(request) is dict and request.get('execute') == 'guest-exec':
            need(type(request.get('arguments')) is dict and
                 type(request['arguments'].get('arg')) is list and
                 len(request['arguments']['arg']) == 12,
                 'guest_exec_not_exact_marked_probe')
        if (type(request) is dict and request.get('execute')=='guest-exec' and
                type(request.get('arguments')) is dict and
                request['arguments'].get('path')=='/usr/bin/ping' and
                type(request['arguments'].get('arg')) is list and
                len(request['arguments']['arg'])==12):
            arg=request['arguments']['arg']
            marker=arg[10]
            need(request==marked_command(marker), 'guest_exec_not_exact_marked_probe')
            argv=[self.bin['sudo'],'-n','--',self.bin['virsh'],'-c','qemu:///system',
                  'qemu-agent-command',r365.SSH_DOMAIN,'--timeout','5',
                  r41.canon(request).decode('ascii')]
            response=r421.parse_json(self.run(argv,timeout=10))
            need(set(response)=={'return'},'guest_agent_error')
            return response['return']
        return super().qga(request)

class Observers:
    """Two short-lived, strictly fixed tcpdump processes. No network mutation."""
    def __init__(self, tcpdump: str, sudo: str, launcher=subprocess.Popen):
        need(tcpdump in ('/usr/bin/tcpdump','/usr/sbin/tcpdump'), 'tcpdump_binary_invalid')
        need(sudo in ('/usr/bin/sudo','/bin/sudo'), 'sudo_binary_invalid')
        self.tcpdump=tcpdump; self.sudo=sudo
        self.launcher=launcher
        self.jobs:dict[str,Any]={}
        self.head:dict[str,bytes]={}

    def start(self)->None:
        need(not self.jobs,'observers_already_started')
        for label,iface in INTERFACES.items():
            cmd=[self.sudo,'-n','--','/usr/bin/timeout','-s','INT',
                 str(CAPTURE_MAX_SECONDS),self.tcpdump,'-n','-p','-i',iface,
                 '-s',str(SNAPLEN),'-U','-c',str(MAX_CAPTURE_PACKETS),
                 '-w','-', FILTER]
            # Own process group for safe killpg, but retain the caller's
            # controlling TTY/session so sudo -n can use sudo -v timestamp.
            process=self.launcher(cmd,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,
                                  close_fds=True,process_group=0)
            self.jobs[label]=process
            # tcpdump writes its 24-byte PCAP global header immediately on startup.
            head=b''; deadline=time.monotonic()+4
            while len(head)<PCAP_HEADER_BYTES:
                need(time.monotonic()<deadline,'observer_not_ready_'+label)
                ready,_,_=select.select([process.stdout],[],[],min(0.5,max(0,deadline-time.monotonic())))
                if ready:
                    bit=os.read(process.stdout.fileno(),PCAP_HEADER_BYTES-len(head))
                    need(bit,'observer_exited_before_header_'+label)
                    head+=bit
                else:
                    need(process.poll() is None,'observer_early_exit_'+label)
            need(head[:4] in (b'\xd4\xc3\xb2\xa1',
                               b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',
                               b'\xa1\xb2\x3c\x4d'),'observer_pcap_header_invalid')
            self.head[label]=head

    def stop_and_read(self)->dict[str,bytes]:
        need(set(self.jobs)==set(INTERFACES) and set(self.head)==set(INTERFACES),
             'observers_not_both_ready')
        results={}
        for label,proc in self.jobs.items():
            if proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGINT)
                except ProcessLookupError:pass
            try:stdout,stderr=proc.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.communicate(timeout=3)
                raise R422Error('observer_stop_timeout_'+label)
            need(len(stdout)<=MAX_CAPTURE_BYTES and len(stderr)<=8192,
                 'observer_capture_size_'+label)
            need(proc.returncode in (0,124,130,-2), 'observer_exit_failed_'+label)
            results[label]=self.head[label]+stdout
        return results

    def abort(self)->None:
        for proc in self.jobs.values():
            if proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGINT)
                except ProcessLookupError:pass
            try:proc.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:pass

def tcpdump_path() -> str:
    found=shutil.which('tcpdump')
    need(found in ('/usr/bin/tcpdump','/usr/sbin/tcpdump'),
         'tcpdump_not_installed_or_outside_allowlist')
    need(Path('/usr/bin/timeout').is_file(), 'timeout_absent')
    return found

def preflight(host:Host|None=None, *, finder=tcpdump_path) -> dict[str,Any]:
    h=host if host is not None else Host()
    ready=r421.preflight(h)
    target=finder()
    need(ready['status']=='READY_FOR_SEPARATE_AUTHORIZED_ONE_PACKET_ATTEMPT',
         'prior_preflight_invalid')
    return {'status':'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
            'host_readback':ready['host_readback'],'capture_interfaces':list(INTERFACES.values()),
            'tcpdump_binary':target,'active_test_performed':False,
            'guest_agent_contacted':False,'p8_operational':'NO-GO'}

def make_report(source:dict[str,str], before:dict[str,Any], after:dict[str,Any],
                counters_before:dict[str,Any],counters_after:dict[str,Any],
                pcap:dict[str,bytes],marker:str,agent:dict[str,Any],stamp:str) -> dict[str,Any]:
    need(source.get('source_r421_report_sha256')==R421_REPORT_PIN and
         all(r41.r40.valid_hex(source.get(k)) for k in
             ('source_r421_file_sha256','source_r420_report_sha256')),
         'source_report_pin_invalid')
    r411._validate_running(before);r411._validate_running(after)
    need(before==after,'host_changed_during_capture')
    delta=r42.validate_samples(before,after,counters_before,counters_after)
    need(type(pcap) is dict and set(pcap)==set(CAPTURES),'pcap_set_invalid')
    observed={key:pcap_records(raw,marker) for key,raw in pcap.items()}
    need(type(agent) is dict and agent.get('guest_nic_confirmed') is True and
         agent.get('request')==marked_command(marker) and
         type(agent.get('guest_pid')) is int and agent['guest_pid']>0 and
         type(agent.get('exit')) is dict and agent['exit'].get('exited') is True,
         'agent_not_bounded')
    detail=agent['exit']
    if detail.get('received')==1:
        status='UNEXPECTED_REPLY_REVIEW_NO_GO'
    elif detail.get('transmitted')!=1 or detail.get('received')!=0:
        status='INCONCLUSIVE_PACKET_WITNESS_NO_GO'
    elif observed['tap']['matching_arp_requests']+observed['tap']['marked_icmp_echo_requests']==0:
        status='NO_GUEST_EGRESS_WITNESSED_NO_GO'
    elif observed['bridge']['matching_arp_requests']+observed['bridge']['marked_icmp_echo_requests']>0:
        status='BRIDGE_PACKET_WITNESSED_REVIEW_NO_GO'
    else:
        status='TAP_ONLY_PACKET_WITNESSED_NO_GO'
    at=r41.parse_utc(stamp)
    need(at<=datetime.now(timezone.utc),'timestamp_future')
    doc={'schema':SCHEMA,'source_main':MAIN_PIN,'status':status,
         'mode':'AUTHORIZED_BOUNDED_DUAL_PCAP_AND_ONE_GUEST_ICMP',
         'captured_at_utc':stamp,'source_r421_report_sha256':R421_REPORT_PIN,
         'source_r421_file_sha256':source['source_r421_file_sha256'],
         'source_r420_report_sha256':source['source_r420_report_sha256'],
         'host_before':before,'host_after':after,
         'counter_before':counters_before,'counter_after':counters_after,
         'counter_delta_unattributed':delta,'marker':marker,
         'capture_interfaces':INTERFACES.copy(),
         'capture_files':{key:{'filename':CAPTURES[key],'sha256':r41.sha(pcap[key]),
                               'length':len(pcap[key]),'observed':observed[key]}
                          for key in CAPTURES},
         'guest_agent_evidence':agent,'guest_reported_ipv4':r421.PROBE_SOURCE,
         'guest_reported_mac':r421.PROBE_MAC,'guest_verified_ipv4_prefix':28,
         'guest_target_ipv4':r421.PROBE_TARGET,'echo_request_limit':1,
         'independent_host_capture_performed':True,
         'independent_destination_witness_available':False,
         'tap_capture_is_proof_of_delivery':False,
         'bridge_silence_is_proof_of_block':False,
         'isolation_proven':False,'operational_dispatch':False,
         'host_network_policy_modified':False,'guest_network_config_modified':False,
         'vm_lifecycle_modified':False,'automatic_retry':False,
         'technical_truth_accredited':False,'real_service_testing':'NOT_EXECUTED',
         'final_risk':None,'published_generation':None,'p8_operational':'NO-GO',
         'experimental_validation':'DUAL_PCAP_OBSERVATION_ONLY',
         'next_gate':'SEPARATE_POSITIVE_DESTINATION_CONTROL_REQUIRED'}
    seal(doc);verify_report(doc)
    return doc

def verify_report(doc:dict[str,Any]) -> bool:
    need(type(doc) is dict and r41.r40.valid_hex(doc.get('sha256')) and
         doc['sha256']==r41.sha(r41.canon({k:v for k,v in doc.items() if k!='sha256'})),
         'report_digest_invalid')
    need(doc.get('schema')==SCHEMA and doc.get('source_main')==MAIN_PIN and
         doc.get('source_r421_report_sha256')==R421_REPORT_PIN and
         all(r41.r40.valid_hex(doc.get(k)) for k in
             ('source_r421_file_sha256','source_r420_report_sha256')) and
         doc.get('mode')=='AUTHORIZED_BOUNDED_DUAL_PCAP_AND_ONE_GUEST_ICMP' and
         doc.get('status') in ('UNEXPECTED_REPLY_REVIEW_NO_GO',
             'INCONCLUSIVE_PACKET_WITNESS_NO_GO','NO_GUEST_EGRESS_WITNESSED_NO_GO',
             'BRIDGE_PACKET_WITNESSED_REVIEW_NO_GO','TAP_ONLY_PACKET_WITNESSED_NO_GO') and
         doc.get('capture_interfaces')==INTERFACES and
         all(doc.get(k) is False for k in
             ('independent_destination_witness_available','tap_capture_is_proof_of_delivery',
              'bridge_silence_is_proof_of_block','isolation_proven','operational_dispatch',
              'host_network_policy_modified','guest_network_config_modified',
              'vm_lifecycle_modified','automatic_retry','technical_truth_accredited')) and
         doc.get('independent_host_capture_performed') is True and
         doc.get('guest_reported_ipv4')==r421.PROBE_SOURCE and
         doc.get('guest_reported_mac')==r421.PROBE_MAC and
         doc.get('guest_verified_ipv4_prefix')==28 and
         doc.get('guest_target_ipv4')==r421.PROBE_TARGET and
         doc.get('echo_request_limit')==1 and
         doc.get('real_service_testing')=='NOT_EXECUTED' and
         doc.get('final_risk') is None and doc.get('published_generation') is None and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('experimental_validation')=='DUAL_PCAP_OBSERVATION_ONLY' and
         doc.get('next_gate')=='SEPARATE_POSITIVE_DESTINATION_CONTROL_REQUIRED',
         'false_operational_authority')
    r41.parse_utc(doc.get('captured_at_utc'))
    delta=r42.validate_samples(doc.get('host_before'),doc.get('host_after'),
                               doc.get('counter_before'),doc.get('counter_after'))
    need(doc.get('counter_delta_unattributed')==delta, 'counter_delta_incorrect')
    marker=doc.get('marker');marked_command(marker)
    agent=doc.get('guest_agent_evidence')
    need(type(agent) is dict and agent.get('guest_nic_confirmed') is True and
         agent.get('request')==marked_command(marker) and
         type(agent.get('guest_pid')) is int and agent['guest_pid']>0 and
         type(agent.get('exit')) is dict and agent['exit'].get('exited') is True,
         'agent_evidence_invalid')
    captures=doc.get('capture_files')
    need(type(captures) is dict and set(captures)==set(CAPTURES),'capture_file_inventory_invalid')
    for key in CAPTURES:
        row=captures[key]
        need(type(row) is dict and row.get('filename')==CAPTURES[key] and
             r41.r40.valid_hex(row.get('sha256')) and
             type(row.get('length')) is int and 24<=row['length']<=MAX_CAPTURE_BYTES and
             type(row.get('observed')) is dict and
             set(row['observed'])=={'frames','matching_arp_requests',
                'marked_icmp_echo_requests','other_frames'} and
             all(type(x) is int and 0<=x<=MAX_CAPTURE_PACKETS for x in row['observed'].values()) and
             row['observed']['frames']==sum(row['observed'][k] for k in
                 ('matching_arp_requests','marked_icmp_echo_requests','other_frames')),
             'capture_evidence_invalid')
    detail=agent['exit']
    needed=('UNEXPECTED_REPLY_REVIEW_NO_GO' if detail.get('received')==1 else
            'INCONCLUSIVE_PACKET_WITNESS_NO_GO' if detail.get('transmitted')!=1 or
                     detail.get('received')!=0 else
            'NO_GUEST_EGRESS_WITNESSED_NO_GO' if
                captures['tap']['observed']['matching_arp_requests']+
                captures['tap']['observed']['marked_icmp_echo_requests']==0 else
            'BRIDGE_PACKET_WITNESSED_REVIEW_NO_GO' if
                captures['bridge']['observed']['matching_arp_requests']+
                captures['bridge']['observed']['marked_icmp_echo_requests']>0 else
            'TAP_ONLY_PACKET_WITNESSED_NO_GO')
    need(doc['status']==needed,'observation_status_falsified')
    return True

def verify_private_receipt(directory: Path) -> dict[str,Any]:
    """Verify hashes AND independent PCAP bytes, never infer external authenticity."""
    need(directory.is_absolute() and not any(p.is_symlink() for p in
         (directory,*directory.parents)), 'receipt_path_invalid')
    files=verified_directory(directory,frozenset({INTENT,RESULT,*CAPTURES.values()}))
    doc=r365.read_json(files[RESULT]);verify_report(doc)
    intent=r365.read_json(files[INTENT])
    need(type(intent) is dict and intent.get('schema')==INTENT_SCHEMA and
         intent.get('source_main')==MAIN_PIN and
         intent.get('source_r421_report_sha256')==R421_REPORT_PIN and
         intent.get('exact_guest_command')==marked_command(doc['marker']) and
         intent.get('authorized_by_operator_cli') is True and
         intent.get('guest_attempt_limit')==1 and
         intent.get('p8_operational')=='NO-GO', 'intent_binding_invalid')
    need(intent.get('sha256')==r41.sha(r41.canon({k:v for k,v in intent.items()
              if k!='sha256'})), 'intent_digest_invalid')
    for key,name in CAPTURES.items():
        payload=files[name]
        expected=doc['capture_files'][key]
        need(r41.sha(payload)==expected['sha256'] and
             len(payload)==expected['length'] and
             pcap_records(payload,doc['marker'])==expected['observed'],
             'pcap_receipt_tampered_'+key)
    return doc

def persist(directory:Path, doc:dict[str,Any], pcaps:dict[str,bytes], intent:bytes)->None:
    verify_report(doc)
    need(set(pcaps)==set(CAPTURES),'persist_pcap_inventory_invalid')
    for key in CAPTURES:
        need(pcap_records(pcaps[key],doc['marker'])==doc['capture_files'][key]['observed'] and
             r41.sha(pcaps[key])==doc['capture_files'][key]['sha256'] and
             len(pcaps[key])==doc['capture_files'][key]['length'],
             'pcap_content_not_bound')
    lines=[r41.sha(intent)+'  '+INTENT]
    for key in CAPTURES:
        r41._write_once(directory/CAPTURES[key],pcaps[key])
        lines.append(r41.sha(pcaps[key])+'  '+CAPTURES[key])
    body=r41.canon(doc)+b'\n'
    r41._write_once(directory/RESULT,body)
    lines.append(r41.sha(body)+'  '+RESULT)
    r41._write_once(directory/'SHA256SUMS', ('\n'.join(lines)+'\n').encode('ascii'))

def attempt(*,r421_dir:Path,r420_dir:Path,r411_dir:Path,r41_dir:Path,
            r40_dir:Path,r39_dir:Path,pre_dir:Path,boot_dir:Path,
            receipt_dir:Path,authorized:bool=False,
            host:Host|None=None,observer_factory=None) -> dict[str,Any]:
    need(authorized is True,'new_operator_authorization_required')
    source=load_source(r421_dir,r420_dir,r411_dir,r41_dir,r40_dir,r39_dir,pre_dir,boot_dir)
    h=host if host is not None else Host()
    ready=preflight(h)
    before,counters_before=r421.snapshot(h)
    need(before==ready['host_readback'], 'preflight_to_attempt_host_drift')
    marker=secrets.token_hex(8)
    cmd=marked_command(marker)
    r41._make_dir(receipt_dir)
    intent=seal({'schema':INTENT_SCHEMA,'source_main':MAIN_PIN,
                 'source_r421_report_sha256':R421_REPORT_PIN,
                 'captured_at_utc':r41.now_utc(),
                 'authorized_by_operator_cli':True,'exact_guest_command':cmd,
                 'guest_attempt_limit':1, 'network_policy_changes':False,
                 'no_guest_start_yet':True,'p8_operational':'NO-GO'})
    intent_raw=r41.canon(intent)+b'\n'
    r41._write_once(receipt_dir/INTENT,intent_raw)
    observers=None
    try:
        need(h.qga(r421.GUEST_PING)=={},'agent_unavailable')
        nic=h.qga(r421.GUEST_INTERFACES)
        r421.validate_guest_nic(nic)
        mid,_=r421.snapshot(h)
        need(mid==before,'host_changed_before_capture')
        if observer_factory is None:
            observers=Observers(tcpdump_path(),h.bin['sudo'])
        else:
            observers=observer_factory()
        observers.start()
        # Guard each observer's readiness before the only guest-exec request.
        need(set(observers.head)==set(INTERFACES) and
             set(observers.jobs)==set(INTERFACES) and
             all(process.poll() is None for process in observers.jobs.values()),
             'capture_readiness_incomplete')
        proc=h.qga(cmd)
        need(type(proc) is dict and set(proc)=={'pid'} and
             type(proc['pid']) is int and 0<proc['pid']<=2**31-1,
             'guest_process_id_invalid')
        outcome=None
        for _ in range(r421.MAX_STATUS_CHECKS):
            data=h.qga({'execute':'guest-exec-status','arguments':{'pid':proc['pid']}})
            outcome=r421.safe_agent_status(data)
            if outcome['exited']:break
            time.sleep(0.35)
        need(type(outcome) is dict and outcome.get('exited') is True,
             'guest_process_outcome_unknown')
        raw_capture=observers.stop_and_read()
        after,counters_after=r421.snapshot(h)
        detail={'guest_nic_confirmed':True,'guest_pid':proc['pid'],
                'request':cmd,'exit':outcome}
        report=make_report(source,before,after,counters_before,counters_after,
                           raw_capture,marker,detail,r41.now_utc())
        persist(receipt_dir,report,raw_capture,intent_raw)
        return report
    except Exception as exc:
        # No retry: guest-exec may have reached the VM. Retain original intent.
        failure=seal({'schema':'ardrec-p14-r422-action-uncertain-v1',
                      'source_main':MAIN_PIN,'source_r421_report_sha256':R421_REPORT_PIN,
                      'status':'REVIEW_REQUIRED_GUEST_ACTION_POSSIBLE',
                      'error_code':type(exc).__name__+':'+str(exc)[:150],
                      'automatic_retry':False,'isolation_proven':False,
                      'p8_operational':'NO-GO'})
        body=r41.canon(failure)+b'\n'
        # Partial outputs are never overwritten; forensic review is required.
        if not (receipt_dir/FAILURE).exists():
            r41._write_once(receipt_dir/FAILURE,body)
        if not (receipt_dir/'SHA256SUMS').exists():
            r41._write_once(receipt_dir/'SHA256SUMS',
                            (r41.sha(intent_raw)+'  '+INTENT+'\n'+
                             r41.sha(body)+'  '+FAILURE+'\n').encode('ascii'))
        raise R422Error('REVIEW_REQUIRED_GUEST_ACTION_POSSIBLE:'+
                        type(exc).__name__+':'+str(exc)[:130]) from exc
    finally:
        if observers is not None:
            observers.abort()
