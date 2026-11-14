"""P14-R34: scoped deny-first host containment and inactive libvirt definitions.

No VM start, no network activation, no global firewall flush or automatic rollback.
Physical actions require a separate explicit opt-in and private receipts.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any, Callable
import uuid
import xml.etree.ElementTree as ET

from ardrec.coordination import r33_offline_topology as t33

SCHEMA = 'ardrec-p14-r34-deny-first-containment-v1'
SOURCE_FILE_SHA = '1b55caefef6808fbfddf32a66a19be7f23c3f63b226799b098380fd93627421c'
NFT_TABLE = 'ardrec_r34_guard'
BRIDGE_NFT_FILE = 'bridge-deny.nft'
FILTER_XML_FILE = 'nwfilter-deny.xml'
POLICY_RECEIPT = 'r34_containment_receipt.json'
INSTALL_RECEIPT = 'r34_inactive_deployment.json'
TAPS = tuple(tap for r in t33.ROLES for _, _, _, tap in t33.RESOURCE[r]['nics'])
BRIDGES = tuple(t33.NET_BRIDGE.values())
MAX_JSON = 131072
DIGEST = re.compile(r'[0-9a-f]{64}\Z')

class ContainmentError(ValueError):
    pass

def need(value: bool, code: str) -> None:
    if not value:
        raise ContainmentError(code)

def canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('ascii')

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def pairs(items):
    out = {}
    for k,v in items:
        need(k not in out,'duplicate_json_key')
        out[k]=v
    return out

def secure_file(path: Path, *, owner: bool = True) -> bytes:
    need(isinstance(path,Path) and path.is_absolute(), 'file_path_invalid')
    for parent in (path,*path.parents):
        need(not parent.is_symlink(),'symlink_component_forbidden')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         (not owner or st.st_uid == os.geteuid()) and
         (stat.S_IMODE(st.st_mode)&0o077)==0 and st.st_size <= MAX_JSON,
         'file_provenance_or_mode_invalid')
    return path.read_bytes()

def read_json_file(path:Path) -> tuple[dict[str,Any],bytes]:
    raw=secure_file(path)
    try:
        d=json.loads(raw, object_pairs_hook=pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ContainmentError('nonfinite_json')))
    except (ValueError,UnicodeError,TypeError) as e:
        raise ContainmentError('json_invalid') from e
    need(type(d) is dict,'json_not_object')
    return d,raw

def source_load(path: Path, expected_sha: str) -> tuple[dict[str,Any],dict[str,bytes]]:
    need(type(expected_sha) is str and expected_sha==SOURCE_FILE_SHA, 'source_pin_invalid')
    need(path.name == 'r33_topology_receipt.json','source_filename_invalid')
    report,raw=read_json_file(path)
    need(sha(raw)==expected_sha,'source_file_hash_invalid')
    t33.verify_report(report)
    need(report['mode']=='XML_PREPARED_ONLY' and report['topology_xml_prepared'] is True and
         report['mandatory_absent_filter']==t33.DENY_FILTER and
         report['p8_operational']=='NO-GO','source_not_prepared')
    data=t33.render_xml(t33.R32_RECEIPT_FILE_SHA256)
    need(set(x['filename'] for x in report['files'])==set(data),'source_file_set_invalid')
    for filename,content in data.items():
        need(secure_file(path.parent/filename)==content,'source_xml_drift_'+filename)
    return report,data

def deny_filter_xml() -> bytes:
    root=ET.Element('filter',{'name':t33.DENY_FILTER,'chain':'root'})
    ET.SubElement(root,'uuid').text=str(uuid.uuid5(uuid.NAMESPACE_URL,
                                'urn:ardrec:r34:'+SOURCE_FILE_SHA+':nwfilter'))
    rule=ET.SubElement(root,'rule',{'action':'drop','direction':'inout','priority':'1000'})
    ET.SubElement(rule,'all')
    ET.indent(root,space='  ')
    raw=ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'
    verify_filter(raw)
    return raw

def verify_filter(raw: bytes) -> None:
    need(type(raw) is bytes and len(raw)<8192,'filter_xml_invalid')
    root=ET.fromstring(raw)
    rules=root.findall('rule')
    need(root.tag=='filter' and root.attrib=={'name':t33.DENY_FILTER,'chain':'root'} and
         len(root.findall('uuid'))==1 and len(rules)==1 and
         rules[0].attrib=={'action':'drop','direction':'inout','priority':'1000'} and
         len(rules[0])==1 and rules[0][0].tag=='all' and not rules[0][0].attrib and
         len(root)==2, 'filter_not_full_deny')

def nft_bytes() -> bytes:
    interfaces=', '.join(f'"{name}"' for name in sorted(TAPS))
    script=(f'table bridge {NFT_TABLE} {{\n'
            '  chain input {\n'
            '    type filter hook input priority -200; policy accept;\n'
            f'    iifname {{ {interfaces} }} counter drop\n'
            '  }\n'
            '  chain output {\n'
            '    type filter hook output priority -200; policy accept;\n'
            f'    oifname {{ {interfaces} }} counter drop\n'
            '  }\n'
            '  chain forward {\n'
            '    type filter hook forward priority -200; policy accept;\n'
            f'    iifname {{ {interfaces} }} counter drop\n'
            f'    oifname {{ {interfaces} }} counter drop\n'
            '  }\n'
            '}\n').encode('ascii')
    verify_nft(script)
    return script

def verify_nft(raw: bytes) -> None:
    need(raw==_expected_nft(), 'nft_policy_drift')

def _expected_nft():
    interfaces=', '.join(f'"{name}"' for name in sorted(TAPS))
    return (f'table bridge {NFT_TABLE} {{\n'
            '  chain input {\n'
            '    type filter hook input priority -200; policy accept;\n'
            f'    iifname {{ {interfaces} }} counter drop\n'
            '  }\n'
            '  chain output {\n'
            '    type filter hook output priority -200; policy accept;\n'
            f'    oifname {{ {interfaces} }} counter drop\n'
            '  }\n'
            '  chain forward {\n'
            '    type filter hook forward priority -200; policy accept;\n'
            f'    iifname {{ {interfaces} }} counter drop\n'
            f'    oifname {{ {interfaces} }} counter drop\n'
            '  }\n'
            '}\n').encode('ascii')

def policy_files() -> dict[str,bytes]:
    return {BRIDGE_NFT_FILE:nft_bytes(), FILTER_XML_FILE:deny_filter_xml()}

def report(source:dict, *, prepared:bool=False) -> dict[str,Any]:
    t33.verify_report(source)
    need(source['mode']=='XML_PREPARED_ONLY','source_mode_invalid')
    contents=policy_files()
    d={'schema':SCHEMA, 'source_r33_file_sha256':SOURCE_FILE_SHA,
       'source_r33_report_sha256':source['sha256'],
       'mode':'OFFLINE_PREPARED' if prepared else 'PLAN_ONLY',
       'policy_files':[{'filename':name,'sha256':sha(raw)} for name,raw in sorted(contents.items())],
       'network_names':source['network_names'], 'domain_names':source['domain_names'],
       'filter_name':t33.DENY_FILTER,'nft_table':NFT_TABLE,
       'scoped_taps':list(sorted(TAPS)),'bridges':list(BRIDGES),
       'offline_policies_prepared':prepared,'host_containment_installed':False,
       'libvirt_definitions_created':False,'network_started':False,'vm_started':False,
       'host_non_ardrec_firewall_changed':False,'operational_dispatch':False,
       'technical_truth_accredited':False,'can_restore':False,
       'p8_operational':'NO-GO','final_risk':None,'published_generation':None,
       'experimental_validation':'NOT_RUN'}
    d['sha256']=sha(canon(d))
    verify_report(d)
    return d

def verify_report(d:dict) -> bool:
    need(type(d) is dict and type(d.get('sha256')) is str and DIGEST.fullmatch(d['sha256']) is not None and
         sha(canon({k:v for k,v in d.items() if k!='sha256'}))==d['sha256'], 'r34_digest_invalid')
    contents=policy_files()
    need(d.get('schema')==SCHEMA and d.get('source_r33_file_sha256')==SOURCE_FILE_SHA and
         type(d.get('source_r33_report_sha256')) is str and DIGEST.fullmatch(d['source_r33_report_sha256']) is not None and
         d.get('mode') in ('PLAN_ONLY','OFFLINE_PREPARED') and
         d.get('offline_policies_prepared') is (d['mode']=='OFFLINE_PREPARED') and
         d.get('policy_files')==[{'filename':name,'sha256':sha(raw)} for name,raw in sorted(contents.items())] and
         d.get('network_names')==[t33.NETWORK_PREFIX+x for x in t33.NET_BRIDGE] and
         d.get('domain_names')==[t33.DOMAIN_PREFIX+x for x in t33.ROLES] and
         d.get('scoped_taps')==sorted(TAPS) and d.get('bridges')==list(BRIDGES) and
         d.get('filter_name')==t33.DENY_FILTER and d.get('nft_table')==NFT_TABLE and
         all(d.get(k) is False for k in ('host_containment_installed','libvirt_definitions_created',
             'network_started','vm_started','host_non_ardrec_firewall_changed',
             'operational_dispatch','technical_truth_accredited','can_restore')) and
         d.get('p8_operational')=='NO-GO' and d.get('final_risk') is None and
         d.get('published_generation') is None and d.get('experimental_validation')=='NOT_RUN',
         'r34_scope_invalid')
    return True

def private_empty(directory:Path):
    need(isinstance(directory,Path) and directory.is_absolute(),'output_directory_invalid')
    for parent in (directory,*directory.parents):
        need(not parent.is_symlink(),'output_symlink')
    s=directory.stat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
         (s.st_mode&0o077)==0 and not any(directory.iterdir()),'output_not_private_empty')

def write_exclusive(path:Path,data:bytes):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())

def prepare(directory:Path,source:dict) -> dict:
    private_empty(directory)
    files=policy_files()
    d=report(source,prepared=True)
    for name,raw in sorted(files.items()):
        write_exclusive(directory/name,raw)
        need((directory/name).read_bytes()==raw,'written_content_mismatch')
    write_exclusive(directory/POLICY_RECEIPT,canon(d)+b'\n')
    return d

def load_prepared(directory:Path,source:dict):
    need(directory.is_absolute() and directory.name.startswith('recibos-r34-policy-'),
         'prepared_directory_name_invalid')
    d,raw=read_json_file(directory/POLICY_RECEIPT)
    verify_report(d)
    need(d['mode']=='OFFLINE_PREPARED' and d['source_r33_report_sha256']==source['sha256'],
         'prepared_source_mismatch')
    for filename,data in policy_files().items():
        need(secure_file(directory/filename)==data,'prepared_policy_drift')
    return d

# No libvirt or host modification in R34: actual application is a distinct R35 gate.

HOST_SCHEMA='ardrec-p14-r34-host-readonly-preflight-v1'

def _executable(name:str,allowed:tuple[str,...])->str:
    found=shutil.which(name)
    need(found is not None and found in allowed,'binary_unavailable_or_outside_scope_'+name)
    return found

def host_preflight(source:dict,policy_directory:Path,*, runner:Callable[...,Any]=subprocess.run)->dict:
    """Inspect current local host; never install rules, define objects or start guests."""
    d=load_prepared(policy_directory,source)
    nft=_executable('nft',('/usr/sbin/nft','/usr/bin/nft'))
    ip=_executable('ip',('/usr/sbin/ip','/usr/bin/ip'))
    virsh=_executable('virsh',('/usr/bin/virsh',))
    xmlcheck=_executable('virt-xml-validate',('/usr/bin/virt-xml-validate',))

    def run(cmd:list[str], *, input_bytes:bytes|None=None, timeout:int=20)->bytes:
        # Only call from literal commands below; no shell. stdout/stderr strictly bounded.
        try:
            kwargs={'stdout':subprocess.PIPE,'stderr':subprocess.PIPE,'check':False,
                    'timeout':timeout,'close_fds':True}
            if input_bytes is not None: kwargs['input']=input_bytes
            else: kwargs['stdin']=subprocess.DEVNULL
            r=runner(cmd,**kwargs)
        except (OSError,subprocess.TimeoutExpired) as e:
            raise ContainmentError('readonly_command_unavailable') from e
        need(type(r.returncode) is int and r.returncode==0 and
             type(r.stdout) is bytes and len(r.stdout)<=131072 and
             type(r.stderr) is bytes and len(r.stderr)<=131072,
             'readonly_command_failed_'+Path(cmd[-1]).name[:40])
        return r.stdout

    # libvirt must be queryable via unprivileged READONLY connection.
    base=[virsh,'--readonly','-c','qemu:///system']
    domains=run(base+['list','--all','--name']).decode('utf-8').splitlines()
    active_domains=run(base+['list','--name']).decode('utf-8').splitlines()
    networks=run(base+['net-list','--all','--name']).decode('utf-8').splitlines()
    filters=run(base+['nwfilter-list']).decode('utf-8')
    need(not any(x.strip().startswith(('ardrec-r33-','ardrec-dev-')) for x in domains),
         'ardrec_domain_collision')
    need(not any(x.strip().startswith(('ardrec-r33-','ardrec-dev-')) for x in networks),
         'ardrec_network_collision')
    need(not any(x.strip()==y for x in active_domains for y in d['domain_names']),
         'lab_active_domain')
    need(d['filter_name'] not in filters, 'nwfilter_name_collision')

    raw=run([ip,'-j','link','show'])
    try:
        links=json.loads(raw)
        need(type(links) is list and all(type(x) is dict and type(x.get('ifname')) is str for x in links),
             'link_inventory_invalid')
    except (TypeError,ValueError) as e:
        raise ContainmentError('link_inventory_invalid') from e
    names={x['ifname'] for x in links}
    need(not names.intersection(set(TAPS)|set(BRIDGES)), 'tap_or_bridge_collision')

    raw=run(['/usr/bin/sudo','-n','--',nft,'-j','list','tables'])
    try: tables=json.loads(raw)['nftables']
    except (ValueError,TypeError,KeyError) as e: raise ContainmentError('nft_table_inventory_invalid') from e
    need(type(tables) is list and not any(type(x) is dict and type(x.get('table')) is dict and
         x['table'].get('family')=='bridge' and x['table'].get('name')==NFT_TABLE for x in tables),
         'nft_table_collision')
    run(['/usr/bin/sudo','-n','--',nft,'-c','-f','-'],input_bytes=nft_bytes())

    # The actual host validates nwfilter, R33 networks and R33 domains without installing.
    run([xmlcheck,str(policy_directory/FILTER_XML_FILE),'nwfilter'])
    # R33 XML bytes were already checked against the pinned R33 generator.
    out={'schema':HOST_SCHEMA,'source_r34_sha256':d['sha256'],'source_r33_report_sha256':source['sha256'],
         'mode':'READONLY_HOST_PREFLIGHT','nft_syntax_validated':True,
         'nwfilter_schema_validated':True,'libvirt_query_pass':True,
         'scoped_taps_absent':True,'scoped_bridges_absent':True,'name_collisions_absent':True,
         'firewall_modified':False,'libvirt_definitions_created':False,
         'network_started':False,'vm_started':False,'operational_dispatch':False,
         'p8_operational':'NO-GO','final_risk':None,'can_restore':False}
    out['sha256']=sha(canon(out))
    verify_host_report(out)
    return out

def verify_host_report(d:dict)->bool:
    need(type(d) is dict and type(d.get('sha256')) is str and DIGEST.fullmatch(d['sha256']) is not None and
         sha(canon({k:v for k,v in d.items() if k!='sha256'}))==d['sha256'] and
         d.get('schema')==HOST_SCHEMA and d.get('mode')=='READONLY_HOST_PREFLIGHT' and
         type(d.get('source_r34_sha256')) is str and DIGEST.fullmatch(d['source_r34_sha256']) is not None and
         type(d.get('source_r33_report_sha256')) is str and DIGEST.fullmatch(d['source_r33_report_sha256']) is not None and
         all(d.get(k) is True for k in ('nft_syntax_validated','nwfilter_schema_validated','libvirt_query_pass',
              'scoped_taps_absent','scoped_bridges_absent','name_collisions_absent')) and
         all(d.get(k) is False for k in ('firewall_modified','libvirt_definitions_created',
              'network_started','vm_started','operational_dispatch','can_restore')) and
         d.get('p8_operational')=='NO-GO' and d.get('final_risk') is None,
         'host_false_claim')
    return True
