#!/usr/bin/env python3
"""ARDREC F11-P: strict host READ-ONLY boot gate audit. NEVER execute boot-guard.

No VM starts, guest traffic, nft writes, systemctl transitions, daemon reload,
file writes, sudo prompts, or modification of host/libvirt. Fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from xml.etree import ElementTree as ET

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ANCESTOR = 'c238f44a7f8cb9f8c251424fa7b5d9c9e9c7e94d'
BOOT = 'ardrec-r34-boot-deny.service'
R34 = 'ardrec_r34_guard'
FILTER = 'ardrec-r33-block-until-containment'
TAPS = {'a33d30r', 'a33d30t', 'a33d31r', 'a33d31t', 'a33d32r', 'a33d32t'}
STAGE = Path('/var/lib/ardrec/r58a-r34-boot')
BUNDLE = {
    'boot-guard.py': 'd2b25156272c111112956351f4314a034fdc8dc1f93e846460870dd4119f0bb6',
    'r34-deny.nft': '8e971f03602418742db7f7ba3dbde475f0a48d98c6661bc62a99b285f34b1f94',
    'manifest.json': '7b944380771f63c0c0a366dac771fc9995250efe3a3b863d090d81617f80f132',
}
UNIT_PATH = '/etc/systemd/system/ardrec-r34-boot-deny.service'
LINK = Path('/etc/systemd/system/multi-user.target.wants/ardrec-r34-boot-deny.service')
BOOT_PROPERTIES = ('LoadState', 'UnitFileState', 'ActiveState', 'SubState', 'NeedDaemonReload',
                   'ExecMainStartTimestamp', 'ExecMainExitTimestamp', 'InvocationID',
                   'Result', 'FragmentPath', 'Type', 'RemainAfterExit')
LIBVIRT_PROPERTIES = ('LoadState', 'ActiveState', 'Requires', 'Requisite', 'BindsTo',
                      'Wants', 'After')

class Blocked(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Blocked(reason)


def sha(raw: bytes):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(raw: bytes):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'JSON_DUPLICATE_KEY')
            result[key] = value
        return result
    need(0 < len(raw) < 300_000, 'JSON_SIZE')
    return json.loads(raw, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda _: need(False, 'JSON_NONFINITE'))


def audit_nft(raw: bytes) -> str:
    doc=canonical_json(raw)
    need(type(doc) is dict and set(doc)=={'nftables'} and
         type(doc['nftables']) is list, 'R34_NFT_SHAPE')
    entries=doc['nftables']
    nonmeta=[r for r in entries if not (type(r) is dict and set(r)=={'metainfo'})]
    need(len(nonmeta)==8 and all(type(r) is dict and len(r)==1 for r in nonmeta),
         'R34_NFT_OBJECT_COUNT')
    tables=[]; chains={}; rules=set()
    expected={('input','iifname'), ('output','oifname'), ('forward','iifname'),('forward','oifname')}
    for obj in nonmeta:
        typ,row=next(iter(obj.items()))
        need(type(row) is dict, 'R34_NFT_OBJECT')
        if typ=='table':
            need(set(row) <= {'family','name','handle'} and
                 row.get('family')=='bridge' and row.get('name')==R34,'R34_NFT_TABLE')
            tables.append(row)
        elif typ=='chain':
            name=row.get('name')
            need(name in ('input','output','forward') and name not in chains and
                 set(row) <= {'family','table','name','handle','type','hook','prio','policy'} and
                 row.get('family')=='bridge' and row.get('table')==R34 and
                 row.get('type')=='filter' and row.get('hook')==name and
                 type(row.get('prio')) is int and row['prio']==-200 and
                 row.get('policy')=='accept', 'R34_NFT_CHAIN')
            chains[name]=row
        elif typ=='rule':
            need(set(row) <= {'family','table','chain','handle','expr'} and
                 row.get('family')=='bridge' and row.get('table')==R34 and
                 type(row.get('expr')) is list and len(row['expr'])==3,
                 'R34_NFT_RULE_SHAPE')
            match, count, verdict=row['expr']
            need(type(match) is dict and set(match)=={'match'} and
                 type(match['match']) is dict and
                 set(match['match'])=={'left','op','right'} and
                 match['match']['op']=='==', 'R34_NFT_MATCH')
            m=match['match']; left=m['left']; right=m['right']
            need(type(left) is dict and type(left.get('meta')) is dict and
                 type(right) is dict and type(right.get('set')) is list and
                 len(right['set'])==6 and set(right['set'])==TAPS,
                 'R34_NFT_SET')
            side=left['meta'].get('key'); identifier=(row['chain'],side)
            need(identifier in expected and identifier not in rules,'R34_NFT_RULE_IDENTITY')
            need(type(count) is dict and set(count)=={'counter'} and
                 type(count['counter']) is dict and set(count['counter'])=={'packets','bytes'} and
                 all(type(v) is int and v>=0 for v in count['counter'].values()) and
                 verdict=={'drop':None}, 'R34_NFT_RULE_VERDICT')
            rules.add(identifier)
        else:
            need(False,'R34_NFT_UNEXPECTED_ITEM')
    need(len(tables)==1 and set(chains)=={'input','output','forward'} and
         rules==expected, 'R34_NFT_INCOMPLETE')
    return 'DENY_STRUCTURALLY_VERIFIED'


def audit_filter(raw: bytes) -> str:
    need(0<len(raw)<16_384 and b'<!DOCTYPE' not in raw and
         b'<!ENTITY' not in raw, 'NWFILTER_XML_UNSAFE')
    root=ET.fromstring(raw)
    rules=root.findall('rule')
    need(root.tag=='filter' and root.attrib=={'name':FILTER,'chain':'root'} and
         len(root.findall('uuid'))==1 and len(rules)==1 and
         rules[0].attrib=={'action':'drop','direction':'inout','priority':'1000'} and
         len(rules[0])==1 and rules[0][0].tag=='all' and
         not rules[0][0].attrib and len(root)==2, 'NWFILTER_NOT_DENY')
    return 'DROP_ALL_DEFINITION_VERIFIED'


def parse_properties(raw: bytes, keys: tuple[str,...]):
    need(0<len(raw)<25_000, 'SYSTEMD_SHOW_SIZE')
    values={}
    for line in raw.decode('utf-8','strict').splitlines():
        need('=' in line,'SYSTEMD_SHOW_LINE')
        key,value=line.split('=',1)
        need(key in keys and key not in values, 'SYSTEMD_SHOW_UNEXPECTED_OR_DUPLICATE')
        values[key]=value
    need(set(values)==set(keys),'SYSTEMD_SHOW_INCOMPLETE')
    return values


def parse_hashes(raw: bytes):
    need(0<len(raw)<8_192,'SHA256SUM_OUTPUT_SIZE')
    result={}
    for line in raw.decode('ascii').splitlines():
        m=re.fullmatch(r'([0-9a-f]{64})  (/var/lib/ardrec/r58a-r34-boot/[A-Za-z0-9.-]+)',line)
        need(m is not None,'SHA256SUM_FORMAT')
        path=Path(m.group(2))
        need(path.parent==STAGE and path.name in BUNDLE and path.name not in result,
             'SHA256SUM_PATH')
        result[path.name]=m.group(1)
    need(result==BUNDLE,'ROOT_BUNDLE_HASH_MISMATCH')
    return 'THREE_ROOT_BUNDLE_HASHES_MATCH_PIN'


def audit_root_permissions(raw: bytes):
    need(0<len(raw)<4096,'ROOT_STAT_OUTPUT_SIZE')
    rows=raw.decode('utf-8','strict').splitlines()
    need(len(rows)==4,'ROOT_STAT_ROW_COUNT')
    expected=[('0','0','700','directory'),
              ('0','0','600','regular file'),
              ('0','0','600','regular file'),
              ('0','0','600','regular file')]
    for index,(line,expect) in enumerate(zip(rows,expected)):
        parts=line.split('|')
        # Directory st_nlink depends on the filesystem (commonly >=2 on ext4).
        # Only the three root-owned regular files must have exactly one hard link.
        need(len(parts)==5 and parts[:3]==list(expect[:3]) and
             parts[4]==expect[3] and
             re.fullmatch(r'[1-9][0-9]*',parts[3]) is not None and
             (index==0 or parts[3]=='1'), 'ROOT_STAT_PERMISSION_DRIFT')
    return 'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK'


def audit_unit_text(raw: bytes):
    need(0<len(raw)<20_000,'UNIT_TEXT_SIZE')
    text=raw.decode('utf-8','strict')
    need(text.startswith('# '+UNIT_PATH+'\n') and
         text.count('\n[Unit]\n')==1 and
         text.count('\n[Service]\n')==1 and
         text.count('\n[Install]\n')==1 and
         not ('\n# /etc/systemd/system/ardrec-r34-boot-deny.service.d/' in text),
         'UNIT_OR_DROPIN_DRIFT')
    lines=[s.strip() for s in text.splitlines()]
    expected={
        'Type=oneshot', 'User=root','Group=root','RemainAfterExit=yes',
        'ExecStart=/usr/bin/python3 -I -B /var/lib/ardrec/r58a-r34-boot/boot-guard.py',
        'WantedBy=multi-user.target','ProtectSystem=strict','NoNewPrivileges=yes',
        'PrivateTmp=yes','ProtectHome=yes','ProtectKernelTunables=yes',
        'ProtectKernelModules=yes','ProtectControlGroups=yes','TimeoutStartSec=60',
        'Before=libvirtd.service multi-user.target',
        'RequiresMountsFor=/var/lib/ardrec/r58a-r34-boot'
    }
    need(expected <= set(lines),'UNIT_CONTRACT_DRIFT')
    return 'EXACT_EXPECTED_BOOT_EXECSTART_AND_ROOT_CONTRACT'


def assess(*, hashes: bytes, root_stat: bytes, boot_show: bytes, libvirt_show: bytes,
           unit_text: bytes, nft_first: bytes, nft_second: bytes,
           filter_xml: bytes, vm_states: dict[str,str], active_networks: set[str],
           link_target: str | None, source_head: str) -> dict:
    need(re.fullmatch(r'[0-9a-f]{40}',source_head) is not None,'GIT_HEAD_INVALID')
    boot=parse_properties(boot_show,BOOT_PROPERTIES)
    libvirt=parse_properties(libvirt_show,LIBVIRT_PROPERTIES)
    audit_unit_text(unit_text)
    parse_hashes(hashes)
    audit_root_permissions(root_stat)
    audit_nft(nft_first); audit_nft(nft_second)
    audit_filter(filter_xml)
    need(boot['LoadState']=='loaded' and boot['UnitFileState']=='enabled' and
         boot['NeedDaemonReload']=='no' and boot['FragmentPath']==UNIT_PATH and
         boot['Type']=='oneshot' and boot['RemainAfterExit']=='yes' and
         link_target==UNIT_PATH,'BOOT_UNIT_NOT_EFFECTIVELY_ENABLED_AS_EXPECTED')
    need(libvirt['LoadState']=='loaded' and
         libvirt['ActiveState'] in ('active','inactive'), 'LIBVIRT_STATE_UNEXPECTED')
    need(set(vm_states)=={'runner','ssh','ftp','smb'} and
         all(v=='shut off' for v in vm_states.values()), 'DEV_VM_NOT_ALL_OFF')
    need('ardrec-r33-dev-net-ftp' not in active_networks, 'FTP_NETWORK_ACTIVE')
    requires=set(libvirt['Requires'].split())
    requisite=set(libvirt['Requisite'].split())
    binds_to=set(libvirt['BindsTo'].split())
    after=set(libvirt['After'].split())
    hard=BOOT in requires or BOOT in requisite or BOOT in binds_to
    first_start=bool(boot['ExecMainStartTimestamp'] and boot['InvocationID'])
    active=(boot['ActiveState']=='active' and boot['SubState']=='exited')
    # Service runtime state is not proof of execution *during a reboot*.
    # Even Requires would not independently cover manual VM boot paths.
    return {
        'schema':'ardrec-r58a-f11p-readonly-boot-gate-v1',
        'decision':('BLOCKED_F11_BOOT_GUARD_UNSTARTED'
                    if not first_start else 'BLOCKED_F11_NO_INDEPENDENT_BOOT_ATTESTATION'),
        'baseline_main_merge':ANCESTOR,
        'observed_git_head':source_head,
        'root_bundle':'THREE_ROOT_BUNDLE_HASHES_MATCH_PIN',
        'root_permissions':'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK',
        'boot_unit':'ENABLED_UNCHANGED',
        'boot_service_active':active,
        'boot_service_start_recorded':first_start,
        'libvirt_active':libvirt['ActiveState']=='active',
        'libvirt_order_after_boot_guard':BOOT in after,
        'libvirt_hard_dependency_on_boot_guard':hard,
        'libvirt_dependency_class':'HARD_UNIT_DEPENDENCY_PRESENT' if hard else 'ORDER_ONLY_NO_REQUIRED_BOOT_GUARD',
        'first_boot_attested':False,
        'manual_vm_boot_block_attested':False,
        'independent_runtime_watchdog_attested':False,
        'nft_r34':'DENY_STRUCTURALLY_VERIFIED_TWICE',
        'nwfilter_r34':'DROP_ALL_DEFINITION_VERIFIED',
        'dev_vms_off':True,
        'ftp_network_inactive':True,
        'host_mutations':0,
        'guest_traffic_generated':False,
        'experimental_validation':'NOT_RUN',
        'p8':'NO-GO',
        'next_gate':'DESIGN_AND_ATTEST_FAIL_CLOSED_F11_BOOT_ORDER_AND_MANUAL_VM_BLOCK',
    }


def run_readonly(argv):
    exe_git=['/usr/bin/git','-C',str(REPO)]
    nft=['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j','-a','list','table','bridge',R34]
    paths=[str(STAGE/name) for name in ('boot-guard.py','manifest.json','r34-deny.nft')]
    sha_cmd=['/usr/bin/sudo','-n','--','/usr/bin/sha256sum',*paths]
    stat_cmd=['/usr/bin/sudo','-n','--','/usr/bin/stat','-c','%u|%g|%a|%h|%F',str(STAGE),*paths]
    allowed=[
        exe_git+['rev-parse','HEAD'],
        exe_git+['merge-base','--is-ancestor',ANCESTOR,'HEAD'],
        ['systemctl','show',BOOT,'--no-pager',*[f'-p{x}' for x in BOOT_PROPERTIES]],
        ['systemctl','show','libvirtd.service','--no-pager',*[f'-p{x}' for x in LIBVIRT_PROPERTIES]],
        ['systemctl','cat',BOOT,'--no-pager'], sha_cmd,stat_cmd,nft,
        ['/usr/bin/virsh','--readonly','-c','qemu:///system','nwfilter-dumpxml',FILTER],
        ['/usr/bin/virsh','--readonly','-c','qemu:///system','net-list','--name'],
    ]
    allowed += [['/usr/bin/virsh','--readonly','-c','qemu:///system','domstate',
                 'ardrec-r33-dev-'+role] for role in ('runner','ssh','ftp','smb')]
    need(argv in allowed,'HOST_COMMAND_NOT_ALLOWLISTED')
    try:
        cp=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,check=False,timeout=35,
                          close_fds=True,env={**os.environ,'LC_ALL':'C','LANG':'C'})
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Blocked('HOST_READ_UNAVAILABLE') from exc
    need(cp.returncode==0 and len(cp.stdout)<300_000 and len(cp.stderr)<10_000,
         'HOST_READ_FAILED')
    return cp.stdout


def host_readonly():
    need(Path.cwd().resolve()==REPO,'MUST_RUN_FROM_REPOSITORY')
    git=['/usr/bin/git','-C',str(REPO)]
    source_head=run_readonly(git+['rev-parse','HEAD']).decode().strip()
    run_readonly(git+['merge-base','--is-ancestor',ANCESTOR,'HEAD'])
    boot=run_readonly(['systemctl','show',BOOT,'--no-pager',*[f'-p{x}' for x in BOOT_PROPERTIES]])
    libvirt=run_readonly(['systemctl','show','libvirtd.service','--no-pager',*[f'-p{x}' for x in LIBVIRT_PROPERTIES]])
    unit_text=run_readonly(['systemctl','cat',BOOT,'--no-pager'])
    sha_cmd=['/usr/bin/sudo','-n','--','/usr/bin/sha256sum',*[str(STAGE/name)
                  for name in ('boot-guard.py','manifest.json','r34-deny.nft')]]
    hashes=run_readonly(sha_cmd)
    stat_cmd=['/usr/bin/sudo','-n','--','/usr/bin/stat','-c','%u|%g|%a|%h|%F',str(STAGE),*[str(STAGE/name) for name in ('boot-guard.py','manifest.json','r34-deny.nft')]]
    root_stat=run_readonly(stat_cmd)
    nft=['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j','-a','list','table','bridge',R34]
    nf=['/usr/bin/virsh','--readonly','-c','qemu:///system','nwfilter-dumpxml',FILTER]
    base=['/usr/bin/virsh','--readonly','-c','qemu:///system']
    first=run_readonly(nft)
    filt=run_readonly(nf)
    vm={r:run_readonly(base+['domstate','ardrec-r33-dev-'+r]).decode().strip().lower()
        for r in ('runner','ssh','ftp','smb')}
    active_nets=set(run_readonly(base+['net-list','--name']).decode().split())
    second=run_readonly(nft)
    head_last=run_readonly(git+['rev-parse','HEAD']).decode().strip()
    need(source_head==head_last,'GIT_CHANGED_DURING_READ')
    # readlink(): no filesystem modification, no sudo, no command invocation
    link_target=os.readlink(LINK) if LINK.is_symlink() else None
    return assess(hashes=hashes,root_stat=root_stat,boot_show=boot,libvirt_show=libvirt,
                  unit_text=unit_text,nft_first=first,nft_second=second,
                  filter_xml=filt,vm_states=vm,active_networks=active_nets,
                  link_target=link_target,source_head=source_head)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host-readonly',action='store_true',required=True)
    p.parse_args()
    try:
        report=host_readonly()
    except (Blocked,ValueError,TypeError,KeyError,OSError,UnicodeError,ET.ParseError) as exc:
        print('R58A_F11P=BLOCKED:'+str(exc)[:140])
        print('R58A_F11P_HOST_MUTATIONS=0')
        print('R58A_F11P_P8=NO-GO')
        return 23
    print(json.dumps(report,ensure_ascii=True,sort_keys=True,indent=2))
    return 21 if not report['boot_service_start_recorded'] else 22

if __name__=='__main__':
    raise SystemExit(main())
