"""P14-R42.1: exactly one operator-authorized ICMP echo from SSH guest.

Guest-agent evidence + nft bridge counters are recorded without claiming global
isolation: the expected receiver (offline runner) is not an independent witness.
No network configuration, VM lifecycle, firewall writes, shell or SSH is used.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import json
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import re
import time
from typing import Any

from ardrec.coordination import r42_isolation_baseline as r42
from ardrec.coordination import r411_external_ssh_observation as r411
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r421-bounded-ssh-negative-probe-v1'
INTENT_SCHEMA = 'ardrec-p14-r421-one-probe-intent-v1'
MAIN_PIN = '0770059dfadb829b9b8e119db7a2defa9a058931'
R420_PIN = '8ccd4f7374ce8f4b030b191185d527b8886f55edddd40229e7798c14be4930b1'
FILES = frozenset({'r42_counter_baseline.json'})
RESULT = 'r421_negative_probe.json'
INTENT = 'r421_intent.json'
PROBE_TARGET = '10.203.30.1'  # runner IP, runner VM must remain OFF
PROBE_SOURCE = '10.203.30.2'
PROBE_MAC = '52:54:00:ad:30:02'
PROBE_PREFIX = 28  # Observed 2026-11-14: SSH ens3 10.203.30.2/28
GUEST_PING = {'execute':'guest-ping'}
GUEST_INTERFACES = {'execute':'guest-network-get-interfaces'}
GUEST_EXEC = {'execute':'guest-exec','arguments':{
    'path':'/usr/bin/ping',
    'arg':['-n','-I',PROBE_SOURCE,'-c','1','-W','1',PROBE_TARGET],
    'env':['LC_ALL=C'], 'capture-output':True}}
MAX_STATUS_CHECKS = 8


class R421Error(ValueError):
    """Stable fail-closed reason code."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise R421Error(code)


def canonical(value: Any) -> bytes:
    return r41.canon(value)


def seal(doc: dict[str,Any]) -> dict[str,Any]:
    doc['sha256'] = r41.sha(canonical(doc))
    return doc


def parse_json(raw: bytes) -> dict[str,Any]:
    need(type(raw) is bytes and 0 < len(raw) < 16384, 'agent_json_size')
    return r365.read_json(raw)


def source_chain(r420_dir: Path, r411_dir: Path, r41_dir: Path,
                 r40_dir: Path, r39_dir: Path, pre_dir: Path, boot_dir: Path) -> dict[str,str]:
    files = verified_directory(r420_dir, FILES)
    raw = files[r42.OUTPUT]
    previous = r365.read_json(raw)
    r42.verify_report(previous)
    need(previous['sha256'] == R420_PIN and previous['source_main'] == r42.MAIN_PIN,
         'r420_pin_mismatch')
    prior = r42.load_source(r411_dir, r41_dir, r40_dir, r39_dir, pre_dir, boot_dir)
    need(previous['source_r411_report_sha256'] == prior['r411_report_sha256'] and
         previous['source_r411_file_sha256'] == prior['r411_file_sha256'] and
         previous['source_r41_preflight_report_sha256'] == prior['r41_report_sha256'],
         'r420_history_mismatch')
    need(r41.parse_utc(previous['captured_at_utc']) <= datetime.now(timezone.utc),
         'r420_future_baseline')
    return {'r420_report_sha256':previous['sha256'],
            'r420_file_sha256':r41.sha(raw),
            'r411_report_sha256':prior['r411_report_sha256']}


class Host(r42.ReadOnlyHost):
    """R42 readback plus tightly allowlisted QGA messages (only in execute mode)."""
    def qga(self, request:dict[str,Any]) -> dict[str,Any]:
        need(request in (GUEST_PING, GUEST_INTERFACES, GUEST_EXEC) or
             (type(request) is dict and set(request) == {'execute','arguments'} and
              request['execute'] == 'guest-exec-status' and
              type(request['arguments']) is dict and
              set(request['arguments']) == {'pid'} and
              type(request['arguments']['pid']) is int and
              0 < request['arguments']['pid'] <= 2**31-1),
             'qga_command_outside_allowlist')
        need(self.bin['virsh'] == '/usr/bin/virsh', 'virsh_binary_drift')
        argv = [self.bin['sudo'],'-n','--',self.bin['virsh'],'-c','qemu:///system',
                'qemu-agent-command',r365.SSH_DOMAIN,'--timeout','5',
                canonical(request).decode('ascii')]
        response = parse_json(self.run(argv, timeout=10))
        need(set(response) == {'return'}, 'qga_error_or_unexpected_response')
        return response['return']


def validate_guest_nic(interfaces:Any) -> None:
    need(type(interfaces) is list and 1 <= len(interfaces) <= 128,
         'guest_interface_inventory_invalid')
    # The target and source must be in the same strictly pinned guest subnet.
    # R33 preserves the static guest configuration and does not prescribe /24.
    subnet = IPv4Network(f'{PROBE_SOURCE}/{PROBE_PREFIX}', strict=False)
    need(IPv4Address(PROBE_TARGET) in subnet and
         IPv4Address(PROBE_SOURCE) in subnet and
         PROBE_SOURCE != PROBE_TARGET,
         'probe_destination_outside_expected_subnet')
    found=[]
    for row in interfaces:
        need(type(row) is dict, 'guest_interface_invalid')
        if not isinstance(row.get('hardware-address'), str) or \
                row['hardware-address'].lower() != PROBE_MAC:
            continue
        addrs=row.get('ip-addresses',[])
        need(type(addrs) is list, 'guest_ip_inventory_invalid')
        ipv4=[(item.get('ip-address'), item.get('prefix'))
              for item in addrs if type(item) is dict and
              item.get('ip-address-type') == 'ipv4']
        found.append(ipv4 == [(PROBE_SOURCE,PROBE_PREFIX)])
    need(found == [True], 'guest_expected_nic_and_ipv4_not_confirmed')


def safe_agent_status(out:Any) -> dict[str,Any]:
    need(type(out) is dict and type(out.get('exited')) is bool,
         'guest_exec_status_invalid')
    if not out['exited']:
        return {'exited':False}
    need(type(out.get('exitcode')) is int and out['exitcode'] in (0,1,2) and
         out.get('out-truncated') is not True and out.get('err-truncated') is not True,
         'guest_exit_or_output_invalid')
    decoded=[]
    for key in ('out-data','err-data'):
        raw=out.get(key,'')
        need(type(raw) is str and len(raw)<=8192,'guest_output_too_large')
        try:
            val=base64.b64decode(raw,validate=True)
            need(len(val)<=4096,'guest_output_decoded_too_large')
            decoded.append(val.decode('utf-8'))
        except (ValueError,UnicodeError,binascii.Error) as exc:
            raise R421Error('guest_output_encoding_invalid') from exc
    stdout, stderr=decoded
    count=re.search(r'\b(\d+) packets? transmitted\b', stdout)
    recvd=re.search(r'\b(\d+) (?:packets? )?received\b', stdout)
    tx=int(count.group(1)) if count else None
    rx=int(recvd.group(1)) if recvd else None
    need(tx is None or tx in (0,1), 'guest_transmitted_over_limit')
    need(rx is None or rx in (0,1), 'guest_received_over_limit')
    return {'exited':True,'exitcode':out['exitcode'],'transmitted':tx,
            'received':rx,'stdout_sha256':r41.sha(stdout.encode('utf-8')),
            'stderr_sha256':r41.sha(stderr.encode('utf-8')),
            'guest_output_complete':True}


def snapshot(host:Host) -> tuple[dict[str,Any],dict[str,Any]]:
    first=r411.readback(host)
    counters=r42.capture_counters(host)
    last=r411.readback(host)
    need(first == last,'host_changed_during_snapshot')
    return first,counters


def _require_quiet(before:dict[str,Any], after:dict[str,Any]) -> None:
    delta=r42.validate_samples({'phase':'SSH_RUNNING', **_host_known_fields()},
                               {'phase':'SSH_RUNNING', **_host_known_fields()},before,after)
    need(all(v['packets']==0 and v['bytes']==0 for v in delta.values()),
         'background_counter_activity_before_probe')


def _host_known_fields() -> dict[str,Any]:
    # Only for validating counter identity; live host is checked separately by snapshot.
    from ardrec.coordination import r35_inactive_deployment as r35
    return {'active_networks':[r365.SSH_NETWORK], 'active_domains':[r365.SSH_DOMAIN],
            'reserved_links':sorted([r365.t33.NET_BRIDGE['ssh'],'a33d30t']),
            'bridge_macs':r35.R354_EXISTING_BRIDGE_MACS,
            'deny_first_still_verified':True}


def preflight(host:Host|None=None) -> dict[str,Any]:
    h=host if host is not None else Host()
    live,first=snapshot(h)
    live2,second=snapshot(h)
    need(live==live2, 'host_drift_during_preflight')
    _require_quiet(first,second)
    return {'status':'READY_FOR_SEPARATE_AUTHORIZED_ONE_PACKET_ATTEMPT',
            'host_readback':live,'counter_handles':{k:v['handle'] for k,v in first.items()},
            'guest_agent_contacted':False,'packets_injected':False,'p8_operational':'NO-GO'}


def report(source:dict[str,str], before:dict[str,Any], after:dict[str,Any],
           counters_before:dict[str,Any],counters_after:dict[str,Any],
           agent:dict[str,Any],*,captured_at_utc:str) -> dict[str,Any]:
    delta=r42.validate_samples(before,after,counters_before,counters_after)
    need(source.get('r420_report_sha256')==R420_PIN and
         all(r41.r40.valid_hex(source.get(x)) for x in
             ('r420_file_sha256','r411_report_sha256')), 'r421_source_invalid')
    r41.parse_utc(captured_at_utc)
    need(type(agent) is dict and agent.get('guest_nic_confirmed') is True and
         type(agent.get('guest_pid')) is int and agent['guest_pid']>0 and
         agent.get('request') == GUEST_EXEC and
         type(agent.get('exit')) is dict and agent['exit'].get('exited') is True,
         'r421_agent_evidence_invalid')
    detail=agent['exit']
    expected=(detail.get('transmitted') == 1 and
              detail.get('received') == 0 and detail.get('exitcode') == 1)
    reply=detail.get('received') == 1
    status=('BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO' if expected else
            'UNEXPECTED_REPLY_REVIEW_NO_GO' if reply else
            'INCONCLUSIVE_GUEST_PROBE_NO_GO')
    doc={'schema':SCHEMA,'source_main':MAIN_PIN, 'status':status,
         'mode':'AUTHORIZED_ONE_ICMP_GUEST_AGENT_PROBE',
         'source_r420_report_sha256':source['r420_report_sha256'],
         'source_r420_file_sha256':source['r420_file_sha256'],
         'source_r411_report_sha256':source['r411_report_sha256'],
         'captured_at_utc':captured_at_utc,'host_before':before,'host_after':after,
         'counter_before':counters_before,'counter_after':counters_after,
         'counter_delta_unattributed':delta,
         'guest_reported_ipv4':PROBE_SOURCE, 'guest_reported_mac':PROBE_MAC,
         'guest_verified_ipv4_prefix':PROBE_PREFIX,
         'target_ipv4':PROBE_TARGET,'icmp_echo_request_limit':1,
         'agent_evidence':agent,
         'guest_agent_command_executed':True,
         'nft_counter_delta_proves_causality':False,
         'independent_destination_witness_available':False,
         'isolation_proven':False,'guest_isolation_accepted':False,
         'guest_isolation_tested':False,'guest_identity_attested':False,
         'network_probe_attempted':True,
         'independent_network_capture_obtained':False,
         'host_network_policy_modified':False,'guest_network_config_modified':False,
         'vm_lifecycle_modified':False,'automatic_recovery':False,
         'operational_dispatch':False,'real_service_testing':'NOT_EXECUTED',
         'technical_truth_accredited':False,'final_risk':None,
         'published_generation':None,'experimental_validation':'NEGATIVE_PROBE_OBSERVATION_ONLY',
         'p8_operational':'NO-GO','next_gate':'INDEPENDENT_DELIVERY_WITNESS_REQUIRED'}
    seal(doc)
    verify_report(doc)
    return doc


def verify_report(doc:dict[str,Any]) -> bool:
    need(type(doc) is dict and r41.r40.valid_hex(doc.get('sha256')) and
         doc['sha256']==r41.sha(canonical({k:v for k,v in doc.items() if k!='sha256'})),
         'report_sha256_invalid')
    need(doc.get('schema')==SCHEMA and doc.get('source_main')==MAIN_PIN and
         doc.get('status') in ('BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO',
                                'UNEXPECTED_REPLY_REVIEW_NO_GO',
                                'INCONCLUSIVE_GUEST_PROBE_NO_GO') and
         doc.get('mode')=='AUTHORIZED_ONE_ICMP_GUEST_AGENT_PROBE' and
         doc.get('source_r420_report_sha256')==R420_PIN and
         all(r41.r40.valid_hex(doc.get(k)) for k in
             ('source_r420_file_sha256','source_r411_report_sha256')) and
         doc.get('guest_reported_ipv4')==PROBE_SOURCE and
         doc.get('guest_reported_mac')==PROBE_MAC and
         doc.get('guest_verified_ipv4_prefix')==PROBE_PREFIX and
         doc.get('target_ipv4')==PROBE_TARGET and
         doc.get('icmp_echo_request_limit')==1 and
         doc.get('guest_agent_command_executed') is True and
         doc.get('nft_counter_delta_proves_causality') is False and
         doc.get('independent_destination_witness_available') is False and
         doc.get('isolation_proven') is False and
         doc.get('guest_isolation_accepted') is False and
         doc.get('guest_isolation_tested') is False and
         doc.get('guest_identity_attested') is False and
         doc.get('network_probe_attempted') is True and
         doc.get('independent_network_capture_obtained') is False and
         all(doc.get(x) is False for x in
             ('host_network_policy_modified','guest_network_config_modified',
              'vm_lifecycle_modified','automatic_recovery','operational_dispatch',
              'technical_truth_accredited')) and
         doc.get('real_service_testing')=='NOT_EXECUTED' and
         doc.get('final_risk') is None and doc.get('published_generation') is None and
         doc.get('experimental_validation')=='NEGATIVE_PROBE_OBSERVATION_ONLY' and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('next_gate')=='INDEPENDENT_DELIVERY_WITNESS_REQUIRED',
         'false_authority_claim')
    need(type(doc.get('agent_evidence')) is dict and
         doc['agent_evidence'].get('request')==GUEST_EXEC and
         doc['agent_evidence'].get('guest_nic_confirmed') is True and
         type(doc['agent_evidence'].get('guest_pid')) is int and
         doc['agent_evidence']['guest_pid']>0 and
         type(doc['agent_evidence'].get('exit')) is dict and
         doc['agent_evidence']['exit'].get('exited') is True,
         'agent_report_tampered')
    delta=r42.validate_samples(doc.get('host_before'),doc.get('host_after'),
                               doc.get('counter_before'),doc.get('counter_after'))
    need(doc.get('counter_delta_unattributed')==delta,'counter_delta_tampered')
    e=doc['agent_evidence']['exit']
    needed=('BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO' if
            e.get('transmitted')==1 and e.get('received')==0 and
            e.get('exitcode')==1 else
            'UNEXPECTED_REPLY_REVIEW_NO_GO' if e.get('received')==1 else
            'INCONCLUSIVE_GUEST_PROBE_NO_GO')
    need(doc.get('status')==needed and
         e.get('exitcode') in (0,1,2) and
         e.get('transmitted') in (None,0,1) and
         e.get('received') in (None,0,1) and
         type(e.get('stdout_sha256')) is str and
         type(e.get('stderr_sha256')) is str and
         r41.r40.valid_hex(e['stdout_sha256']) and
         r41.r40.valid_hex(e['stderr_sha256']),
         'probe_status_false_claim')
    r41.parse_utc(doc.get('captured_at_utc'))
    return True


def attempt(*,r420_dir:Path,r411_dir:Path,r41_dir:Path,r40_dir:Path,
            r39_dir:Path,pre_dir:Path,boot_dir:Path,receipt_dir:Path,
            authorized:bool=False,host:Host|None=None) -> dict[str,Any]:
    need(authorized is True, 'explicit_operator_authorization_required')
    source=source_chain(r420_dir,r411_dir,r41_dir,r40_dir,r39_dir,pre_dir,boot_dir)
    h=host if host is not None else Host()
    p=preflight(h)  # no guest control used here
    first_live,first_counters=snapshot(h)
    need(first_live==p['host_readback'] and
         all(first_counters[k]['handle']==p['counter_handles'][k] for k in r42.EXPECTED_RULES),
         'preflight_to_attempt_host_drift')
    r41._make_dir(receipt_dir)
    stamp=r41.now_utc()
    intent=seal({'schema':INTENT_SCHEMA,'source_main':MAIN_PIN,
                 'source_r420_report_sha256':R420_PIN,'captured_at_utc':stamp,
                 'authorized_by_operator_cli':True,
                 'exact_guest_command':GUEST_EXEC,'attempt_limit':1,
                 'guest_start_not_attempted_yet':True,
                 'p8_operational':'NO-GO'})
    intent_raw=canonical(intent)+b'\n'
    r41._write_once(receipt_dir/INTENT,intent_raw)
    # Every action from this point may have had a guest-side effect. Fail closed;
    # do not automatically retry, re-arm or start/stop a VM.
    try:
        need(h.qga(GUEST_PING)=={},'guest_agent_ping_invalid')
        interfaces=h.qga(GUEST_INTERFACES)
        validate_guest_nic(interfaces)
        active,_=snapshot(h)
        need(active==first_live,'host_changed_before_guest_exec')
        pid=h.qga(GUEST_EXEC)
        need(type(pid) is dict and set(pid)=={'pid'} and
             type(pid['pid']) is int and 0<pid['pid']<=2**31-1,
             'guest_pid_invalid')
        state=None
        for _ in range(MAX_STATUS_CHECKS):
            response=h.qga({'execute':'guest-exec-status','arguments':{'pid':pid['pid']}})
            state=safe_agent_status(response)
            if state['exited']:
                break
            time.sleep(0.35)
        need(state is not None and state.get('exited') is True,
             'guest_exec_may_still_be_running')
        last_live,last_counters=snapshot(h)
        need(last_live==first_live,'host_drift_after_guest_attempt')
        evidence={'guest_nic_confirmed':True,'guest_pid':pid['pid'],
                  'request':GUEST_EXEC,'exit':state}
        doc=report(source,first_live,last_live,first_counters,last_counters,evidence,
                   captured_at_utc=r41.now_utc())
        body=canonical(doc)+b'\n'
        r41._write_once(receipt_dir/RESULT,body)
        r41._write_once(receipt_dir/'SHA256SUMS',
                        (r41.sha(intent_raw)+'  '+INTENT+'\n'+
                         r41.sha(body)+'  '+RESULT+'\n').encode('ascii'))
        return doc
    except Exception as exc:
        # Keep private intent. The command may already have reached the guest.
        failure=seal({'schema':'ardrec-p14-r421-attempt-failed-v1',
                      'source_main':MAIN_PIN,'source_r420_report_sha256':R420_PIN,
                      'status':'REVIEW_REQUIRED_GUEST_ACTION_POSSIBLE',
                      'failure_code':type(exc).__name__+':'+str(exc)[:140],
                      'automatic_retry':False,'guest_action_unknown':True,
                      'p8_operational':'NO-GO','final_risk':None})
        body=canonical(failure)+b'\n'
        r41._write_once(receipt_dir/'r421_failure.json',body)
        r41._write_once(receipt_dir/'SHA256SUMS',
                        (r41.sha(intent_raw)+'  '+INTENT+'\n'+
                         r41.sha(body)+'  r421_failure.json\n').encode('ascii'))
        raise R421Error('REVIEW_REQUIRED_GUEST_ACTION_POSSIBLE:'+
                        type(exc).__name__+':'+str(exc)[:140]) from exc
