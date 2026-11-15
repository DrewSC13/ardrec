"""P14 R50-A: bounded QGA guest-network inventory for two running, denied VMs.

Read-only QGA guest-ping and guest-network-get-interfaces only. No guest-exec,
packet probes, policy changes, VM lifecycle changes or operational permission.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable

from ardrec.coordination import r45_ssh_positive_candidate as r45
from ardrec.coordination import r46_ssh_transition_audit as r46
from ardrec.coordination import r49_runner_first_boot as r49
from ardrec.coordination import r421_bounded_negative_probe as r421

# Preserve the v1 schema and its exact /24 evaluation for the already sealed
# physical receipt. This version was an erroneous expectation, not a guest drift.
SCHEMA='ardrec-p14-r50a-guest-pair-network-readonly-v1'
SCHEMA_V2='ardrec-p14-r50a-guest-pair-network-readonly-v2'
RECON_SCHEMA='ardrec-p14-r50a-prefix-reconciliation-v1'
LEGACY_PREFIX=24
EXPECTED_PREFIX=r421.PROBE_PREFIX
HIST_PHYSICAL_PIN='aea38a60711471e6d08a2b3a7c9f0f78cab0c515e15863bb8724276032c7732d'

BASE_MAIN='f59d7ace03aa6ff296b3f425e14a38c005610ecc'
R49_DEFINE_PIN='70f273c30b4b3a4e9c39328013cdd506a3b8d5a3780be8476c10cea3e4d15d98'
R49_BOOT_PIN='82f6a4101802bb35043e35c741731cc2b99fd12bb6a3f7054280e5d9a0c9e303'
ROLES={'ssh':(r49.SSH,r45.SOURCE_MAC,r45.SOURCE_IP),
       'runner':(r49.RUNNER,r45.DEST_MAC,r45.DEST_IP)}
INTENT='r50a-intent.json'
REPORT='r50a-report.json'
FAILURE='r50a-failure.json'
SUMS='SHA256SUMS'
RAW={'ssh':'qga-ssh-interfaces.json','runner':'qga-runner-interfaces.json'}
MAX_RAW=32768

class R50Error(ValueError):
    pass

def need(ok:bool, reason:str)->None:
    if not ok:raise R50Error(reason)

def canon(x:Any)->bytes:
    return json.dumps(x,ensure_ascii=True,allow_nan=False,sort_keys=True,
                      separators=(',',':')).encode('ascii')

def sha(x:bytes)->str:
    return hashlib.sha256(x).hexdigest()

def unique_pairs(pairs:list[tuple[str,Any]])->dict[str,Any]:
    out={}
    for k,v in pairs:
        need(k not in out,'qga_duplicate_json_key')
        out[k]=v
    return out

def read_json(raw:bytes)->Any:
    need(type(raw) is bytes and 0<len(raw)<=MAX_RAW,'qga_response_size')
    try:
        return json.loads(raw,object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(R50Error('qga_nonfinite')))
    except R50Error:
        raise
    except (UnicodeError,ValueError) as e:
        raise R50Error('qga_invalid_json') from e

def reply(raw:bytes, kind:str)->Any:
    value=read_json(raw)
    need(type(value) is dict and set(value)=={'return'},'qga_error_or_unknown_response')
    obj=value['return']
    if kind=='ping':need(type(obj) is dict and not obj,'qga_ping_unexpected')
    if kind=='interfaces':need(type(obj) is list and len(obj)<=32,'qga_interfaces_unexpected')
    return obj

def prefix_source_guard()->None:
    # The already published R42.1 guest observation is the authoritative /28.
    need(EXPECTED_PREFIX==28 and r421.PROBE_PREFIX==28 and
         r421.PROBE_SOURCE==r45.SOURCE_IP and
         r421.PROBE_TARGET==r45.DEST_IP,'r421_prefix_or_pair_drift')


def summarize(raw:bytes,role:str,*,expected_prefix:int|None=None)->dict[str,Any]:
    prefix_source_guard()
    if expected_prefix is None:
        expected_prefix=EXPECTED_PREFIX
    need(type(expected_prefix) is int and expected_prefix in
         (EXPECTED_PREFIX,LEGACY_PREFIX),'prefix_policy_unknown')
    need(role in ROLES,'role_unknown')
    interfaces=reply(raw,'interfaces')
    names=set(); matches=[]; unexpected=[]
    expect_mac=ROLES[role][1]; expect_ip=ROLES[role][2]
    for nic in interfaces:
        need(type(nic) is dict and type(nic.get('name')) is str and
             re.fullmatch(r'[a-zA-Z0-9_.:@-]{1,64}',nic['name']) is not None and
             nic['name'] not in names,'guest_interface_name_invalid')
        names.add(nic['name'])
        rawmac=nic.get('hardware-address')
        need(rawmac is None or (type(rawmac) is str and
             re.fullmatch(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}',rawmac) is not None),
             'guest_interface_mac_invalid')
        mac=rawmac.lower() if rawmac is not None else None
        addrs=nic.get('ip-addresses',[])
        need(type(addrs) is list and len(addrs)<=32,'guest_ip_inventory_invalid')
        ipv4=[]
        for addr in addrs:
            need(type(addr) is dict and type(addr.get('ip-address-type')) is str and
                 type(addr.get('ip-address')) is str and
                 type(addr.get('prefix')) is int,'guest_address_invalid')
            typ=addr['ip-address-type']
            need(typ in ('ipv4','ipv6'),'guest_address_family_invalid')
            if typ=='ipv4':
                import ipaddress
                try: ip=ipaddress.IPv4Address(addr['ip-address'])
                except ipaddress.AddressValueError as e:raise R50Error('guest_ipv4_invalid') from e
                need(0<=addr['prefix']<=32,'guest_ipv4_prefix_invalid')
                ipv4.append({'ip':str(ip),'prefix':addr['prefix']})
        if mac==expect_mac:
            matches.append({'name':nic['name'],'mac':mac,'ipv4':ipv4})
        elif mac is not None and nic['name']!='lo':
            unexpected.append({'name':nic['name'],'mac':mac,'ipv4':ipv4})
    matching=len(matches)==1 and matches[0]['ipv4']==[{'ip':expect_ip,'prefix':expected_prefix}]
    status='EXPECTED_IP_MAC_OBSERVED_NO_GO' if matching and not unexpected else 'GUEST_IP_OR_NIC_REVIEW_NO_GO'
    return {'role':role,'domain':ROLES[role][0],
            'status':status,'expected_mac':expect_mac,'expected_ipv4':expect_ip,
            'matched_interfaces':matches,'other_mac_interfaces':unexpected,
            'interfaces_seen':len(interfaces),'qga_raw_sha256':sha(raw),
            'p8_operational':'NO-GO'}

def host_check(dirs:dict[str,Path])->dict[str,str]:
    report=r49.verify_boot(dirs['r45'],dirs['r46'],dirs['r47'],dirs['r48'],
                           dirs['definition'],dirs['boot'])
    need(report['sha256']==R49_BOOT_PIN and
         report['defined_receipt_sha256']==R49_DEFINE_PIN,
         'r49_physical_boot_receipt_mismatch')
    return {'r49_boot_sha256':report['sha256'],
            'r49_definition_sha256':report['defined_receipt_sha256']}

def qga(role:str,request:dict[str,Any],run:Callable[...,Any]=subprocess.run)->bytes:
    need(role in ROLES and request in ({'execute':'guest-ping'},
           {'execute':'guest-network-get-interfaces'}),'qga_request_not_readonly_allowlisted')
    domain=ROLES[role][0]
    cmd=['/usr/bin/sudo','-n','--','/usr/bin/virsh','-c','qemu:///system',
         'qemu-agent-command',domain,'--timeout','5',canon(request).decode('ascii')]
    try:
        p=run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
              timeout=12,check=False,close_fds=True)
    except (OSError,subprocess.TimeoutExpired) as e:raise R50Error('qga_command_unavailable') from e
    need(type(p.returncode) is int and p.returncode==0 and
         type(p.stdout) is bytes and len(p.stdout)<=MAX_RAW and
         type(p.stderr) is bytes and len(p.stderr)<=1024,'qga_request_failed_'+role)
    return p.stdout

def _private(path:Path,existing:bool)->None:
    need(isinstance(path,Path) and path.is_absolute() and
         re.fullmatch(r'r50a-guest-pair-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}',path.name) is not None and
         not any(p.is_symlink() for p in (path,*path.parents)), 'receipt_path_invalid')
    parent=path.parent
    need(parent.is_dir() and parent.stat().st_uid==os.getuid() and
         stat.S_IMODE(parent.stat().st_mode)==0o700,'private_parent_required')
    need(path.is_dir() if existing else not path.exists(),'receipt_collision_or_missing')
    if existing:need(path.stat().st_uid==os.getuid() and stat.S_IMODE(path.stat().st_mode)==0o700,
                     'receipt_root_permissions')

def _write(path:Path,raw:bytes)->None:
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def _digest_file(root:Path,names:list[str])->None:
    _write(root/SUMS,(''.join(f'{sha((root/n).read_bytes())}  {n}\n' for n in sorted(names))).encode('ascii'))

def _timestamp()->str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def preflight(dirs:dict[str,Path])->dict[str,Any]:
    base=host_check(dirs)
    return {'schema':SCHEMA,'source_main':BASE_MAIN,'mode':'HOST_QGA_READONLY_PREFLIGHT',
            **base,'domains':[ROLES[r][0] for r in ('ssh','runner')],
            'qga_contacted':False,'guest_commands_executed':False,
            'vm_or_network_modified':False,'packets_injected':False,
            'isolation_proven':False,'operational_dispatch':False,
            'p8_operational':'NO-GO'}

def capture(dirs:dict[str,Path],root:Path,*,
            check:Callable[[dict[str,Path]],dict[str,Any]]=preflight,
            query:Callable[[str,dict[str,Any]],bytes]=qga)->dict[str,Any]:
    _private(root,False)
    plan=check(dirs)
    need(plan['mode']=='HOST_QGA_READONLY_PREFLIGHT' and
         plan['r49_boot_sha256']==R49_BOOT_PIN,'host_preflight_invalid')
    root.mkdir(mode=0o700)
    _write(root/INTENT,canon(plan)+b'\n')
    collected=[INTENT]
    try:
        results={}
        for role in ('ssh','runner'):
            reply(query(role,{'execute':'guest-ping'}),'ping')
            raw=query(role,{'execute':'guest-network-get-interfaces'})
            need(type(raw) is bytes and 0<len(raw)<=MAX_RAW, 'qga_response_size')
            _write(root/RAW[role],raw)
            collected.append(RAW[role])
            result=summarize(raw,role)
            results[role]=result
        post=check(dirs)
        need(post==plan,'host_policy_or_state_drift')
        status=('GUEST_PAIR_EXPECTED_IP_MAC_OBSERVED_NO_GO' if
                all(x['status']=='EXPECTED_IP_MAC_OBSERVED_NO_GO' for x in results.values())
                else 'GUEST_PAIR_CONFIG_REVIEW_NO_GO')
        doc={'schema':SCHEMA_V2,'source_main':BASE_MAIN,'mode':'AUTHORIZED_QGA_NETWORK_READS_ONLY',
             'expected_ipv4_prefix':EXPECTED_PREFIX,
             'status':status,'captured_at_utc':_timestamp(),
             'r49_boot_sha256':R49_BOOT_PIN,'r49_definition_sha256':R49_DEFINE_PIN,
             'roles':results,'host_before_after_verified':True,
             'qga_queries_per_guest':['guest-ping','guest-network-get-interfaces'],
             'guest_exec_used':False,'guest_network_config_modified':False,
             'packet_probes_executed':False,'host_policy_modified':False,
             'vm_lifecycle_modified':False,'isolation_proven':False,
             'operational_dispatch':False,'p8_operational':'NO-GO'}
        doc['sha256']=sha(canon(doc))
        _write(root/REPORT,canon(doc)+b'\n');collected.append(REPORT)
        _digest_file(root,collected)
        return doc
    except Exception as e:
        error={'schema':SCHEMA,'status':'QGA_READONLY_CAPTURE_INCOMPLETE_NO_GO',
               'failure':type(e).__name__+':'+str(e)[:120],
               'files_preserved':list(collected),'p8_operational':'NO-GO',
               'automatic_retry':False}
        _write(root/FAILURE,canon(error)+b'\n');collected.append(FAILURE)
        _digest_file(root,collected)
        raise R50Error('QGA_CAPTURE_INCOMPLETE_NO_RETRY:'+str(e)[:130]) from e

def verify(dirs:dict[str,Path],root:Path,
           *,check:Callable[[dict[str,Path]],dict[str,Any]]=preflight)->dict[str,Any]:
    _private(root,True)
    required={INTENT,REPORT,SUMS,*RAW.values()}
    need({x.name for x in root.iterdir()}==required,'receipt_files_invalid')
    data={}
    for name in required:
        path=root/name;st=path.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,
             'receipt_file_mode_'+name)
        data[name]=path.read_bytes()
    sums=(''.join(f'{sha(data[n])}  {n}\n' for n in sorted(required-{SUMS}))).encode('ascii')
    need(data[SUMS]==sums,'receipt_hash_mismatch')
    intent=read_json(data[INTENT]);doc=read_json(data[REPORT])
    need(intent==check(dirs),'live_host_no_longer_matches')
    # A historical signed v1 report must remain verifiable under its original
    # /24 rule. Never silently promote or modify that immutable evidence.
    historical=doc.get('schema')==SCHEMA
    need(doc.get('schema') in (SCHEMA,SCHEMA_V2),'receipt_schema_invalid')
    criterion=LEGACY_PREFIX if historical else EXPECTED_PREFIX
    expected_roles={role:summarize(data[RAW[role]],role,expected_prefix=criterion)
                    for role in ('ssh','runner')}
    need((('expected_ipv4_prefix' not in doc) if historical else
          doc.get('expected_ipv4_prefix')==EXPECTED_PREFIX) and
         doc.get('source_main')==BASE_MAIN and
         doc.get('mode')=='AUTHORIZED_QGA_NETWORK_READS_ONLY' and
         doc.get('r49_boot_sha256')==R49_BOOT_PIN and
         doc.get('r49_definition_sha256')==R49_DEFINE_PIN and
         doc.get('roles')==expected_roles and
         doc.get('status')==('GUEST_PAIR_EXPECTED_IP_MAC_OBSERVED_NO_GO' if
             all(x['status']=='EXPECTED_IP_MAC_OBSERVED_NO_GO' for x in expected_roles.values())
             else 'GUEST_PAIR_CONFIG_REVIEW_NO_GO') and
         doc.get('qga_queries_per_guest')==['guest-ping','guest-network-get-interfaces'] and
         doc.get('host_before_after_verified') is True and
         all(doc.get(n) is False for n in ('guest_exec_used','guest_network_config_modified',
             'packet_probes_executed','host_policy_modified','vm_lifecycle_modified',
             'isolation_proven','operational_dispatch')) and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('sha256')==sha(canon({k:v for k,v in doc.items() if k!='sha256'})),
         'receipt_report_invalid')
    return doc


def historical_expected_intent_offline()->dict[str,Any]:
    """Reconstruct the sealed R50-A v1 preflight claim without reading host state.

    This authenticates what the *historical capture stated*, not the current
    health or presence of R34; it grants no networking or P8 authority.
    """
    prefix_source_guard()
    return {'schema':SCHEMA,'source_main':BASE_MAIN,
            'mode':'HOST_QGA_READONLY_PREFLIGHT',
            'r49_boot_sha256':R49_BOOT_PIN,
            'r49_definition_sha256':R49_DEFINE_PIN,
            'domains':[ROLES[r][0] for r in ('ssh','runner')],
            'qga_contacted':False,'guest_commands_executed':False,
            'vm_or_network_modified':False,'packets_injected':False,
            'isolation_proven':False,'operational_dispatch':False,
            'p8_operational':'NO-GO'}


def verify_historical_offline(root:Path)->dict[str,Any]:
    """Check old QGA bytes, original v1 rules, pinned report and SHA256SUMS.

    Never run r49.verify_boot(), nft, virsh, QGA or a subprocess. Current host
    state MUST be independently inspected before any network/VM operation.
    """
    result=verify({},root,check=lambda _dirs:historical_expected_intent_offline())
    need(result.get('schema')==SCHEMA and
         result.get('sha256')==HIST_PHYSICAL_PIN and
         result.get('status')=='GUEST_PAIR_CONFIG_REVIEW_NO_GO',
         'historical_receipt_pin_or_status_invalid')
    return result


# R50-A-F1: independent historical-evidence reconciliation, never QGA.
# The v1 receipt is verified without any changes and remains REVIEW.
def _private_recon(root:Path,*,existing:bool)->None:
    need(isinstance(root,Path) and root.is_absolute() and
         re.fullmatch(r'r50a-prefix-review-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}',root.name) is not None and
         not any(p.is_symlink() for p in (root,*root.parents)),
         'reconciliation_path_invalid')
    parent=root.parent
    need(parent.is_dir() and parent.stat().st_uid==os.getuid() and
         stat.S_IMODE(parent.stat().st_mode)==0o700,'reconciliation_parent_insecure')
    need(root.is_dir() if existing else not root.exists(), 'reconciliation_exists_or_missing')
    if existing:
        need(root.stat().st_uid==os.getuid() and
             stat.S_IMODE(root.stat().st_mode)==0o700,
             'reconciliation_root_insecure')


def _reconcile_doc(legacy:dict[str,Any],raw_dir:Path,stamp:str)->dict[str,Any]:
    prefix_source_guard()
    need(legacy.get('schema')==SCHEMA and
         legacy.get('sha256')==HIST_PHYSICAL_PIN and
         legacy.get('status')=='GUEST_PAIR_CONFIG_REVIEW_NO_GO',
         'historical_receipt_pin_or_status_invalid')
    roles={role:summarize((raw_dir/RAW[role]).read_bytes(),role)
           for role in ('ssh','runner')}
    need(all(x['status']=='EXPECTED_IP_MAC_OBSERVED_NO_GO' for x in roles.values()),
         'not_just_a_prefix_discrepancy')
    for role in ('ssh','runner'):
        prior=legacy['roles'][role]
        matches=prior.get('matched_interfaces')
        need(prior.get('status')=='GUEST_IP_OR_NIC_REVIEW_NO_GO' and
             type(matches) is list and len(matches)==1 and
             matches[0].get('mac')==ROLES[role][1] and
             matches[0].get('ipv4')==
             [{'ip':ROLES[role][2],'prefix':EXPECTED_PREFIX}] and
             prior.get('other_mac_interfaces')==[],
             'unexpected_historical_discrepancy_'+role)
    doc={
        'schema':RECON_SCHEMA,'source_main':BASE_MAIN,
        'historical_receipt_schema':SCHEMA,
        'historical_report_sha256':HIST_PHYSICAL_PIN,
        'historical_status':legacy['status'],
        'status':'PREFIX_CRITERION_RECONCILED_FROM_HISTORICAL_QGA_NO_GO',
        'corrected_result':'GUEST_PAIR_EXPECTED_IP_MAC_OBSERVED_NO_GO',
        'criteria_source':'r421_bounded_negative_probe.PROBE_PREFIX',
        'historical_criterion_prefix':LEGACY_PREFIX,
        'corrected_criterion_prefix':EXPECTED_PREFIX,
        'source_guest_ipv4':r421.PROBE_SOURCE,
        'target_guest_ipv4':r421.PROBE_TARGET,
        'raw_qga_sha256':{role:legacy['roles'][role]['qga_raw_sha256']
                          for role in ('ssh','runner')},
        'corrected_roles':roles,
        'reconciled_at_utc':stamp,
        'recomputed_from_original_bytes':True,
        'historical_receipt_modified':False,
        'new_guest_qga_queries':False,
        'guest_exec_used':False,'packets_injected':False,
        'host_policy_modified':False,'vm_lifecycle_modified':False,
        'isolation_proven':False,'operational_dispatch':False,
        'experimental_validation':'GUEST_IP_MAC_INVENTORY_ONLY',
        'p8_operational':'NO-GO',
    }
    doc['sha256']=sha(canon(doc))
    return doc


def reconcile_prefix(dirs:dict[str,Path],legacy_dir:Path,out:Path)->dict[str,Any]:
    _private_recon(out,existing=False)
    historical=verify_historical_offline(legacy_dir)
    report=_reconcile_doc(historical,legacy_dir,_timestamp())
    out.mkdir(mode=0o700)
    _write(out/'r50a-prefix-reconciliation.json',canon(report)+b'\n')
    _digest_file(out,['r50a-prefix-reconciliation.json'])
    return report


def verify_prefix_reconciliation(dirs:dict[str,Path],legacy_dir:Path,
                                 receipt_dir:Path)->dict[str,Any]:
    _private_recon(receipt_dir,existing=True)
    need({p.name for p in receipt_dir.iterdir()}==
         {'r50a-prefix-reconciliation.json',SUMS},'reconciliation_file_set')
    for name in ('r50a-prefix-reconciliation.json',SUMS):
        st=(receipt_dir/name).lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,
             'reconciliation_file_insecure')
    raw=(receipt_dir/'r50a-prefix-reconciliation.json').read_bytes()
    sums=(receipt_dir/SUMS).read_bytes()
    need(sums==(sha(raw)+'  r50a-prefix-reconciliation.json\n').encode('ascii'),
         'reconciliation_sha256sums_invalid')
    report=read_json(raw)
    historical=verify_historical_offline(legacy_dir)
    expected=_reconcile_doc(historical,legacy_dir,report.get('reconciled_at_utc'))
    need(report==expected,'reconciliation_report_invalid')
    return report
