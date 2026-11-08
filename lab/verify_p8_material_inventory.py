#!/usr/bin/env python3
"""P8-R9: material inventory and 29 deny-only candidate slots.

Default: pure public-repo consistency checking.
Optional --offline-image: checks operator-owned pinned QCOW2 via *read-only*
qemu-img, virt-cat and guestfish. No guest binaries, sockets, services or VMs
of the ARDREC laboratory are executed. Never call this script via sudo.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = '9bb8e06c5d007cac82a102a97a87ab909bb35d7b'
THESIS = '6a6d2d7889a683e459da46559c03dcd62616141b39f0e744c46c72'
P7_SHA = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
P8_SHA = 'fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3'
IMAGE_SHA = 'fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
IMAGE_PATH = '/var/lib/libvirt/images/ardrec-dev-point4-v4/runner-base.qcow2'
INV_PATH = 'lab/p8-material-inventory-v1/inventory.json'
CMP_PATH = 'lab/p8-material-inventory-v1/compatibility.json'
P7_PATH = 'lab/operational-catalog-v1/catalog.json'
P8_PATH = 'lab/execution-profiles-v1/profiles.json'
PACKAGE_EXPECTED = {
    'openssh-client': '1:10.0p1-7+deb13u4',
    'curl': '8.14.1-2+deb13u7',
    'smbclient': '2:4.22.11+dfsg-0+deb13u1',
    'python3': '3.13.5-1',
}
BINARY_ROWS = (
    ('ssh', 'af3b04ec5653755032fc18ad02445e4e51170e75d8bac4265647d423caa9a83e', 1047584),
    ('curl', '52e9ceef96bd7c7dd4c2c9d8ac4c5f466c563dc0d16817720518b430da7a94b7', 321880),
    ('smbclient', 'f7f2e53588c472c91fb7da57431aa76e014f746587a51dc4012ac93caaea14d6', 154016),
    ('python3.13', '889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9', 6832784),
    ('ssh-keyscan', '0a17e9f79c816a13c174747c8a7a89bf0f0c04ca9977181be59932762db596dc', None),
    ('ssh-keygen', '4a16f170f7c80d6643d3ffada36d396c9d7b1d63238a218628e37af38d6107c0', None),
    ('ssh-add', '64ae57eb0787b1c39af387edefb42456a8261830f1612fe77549a679067edfa0', None),
    ('ssh-agent', '2e5cdfc7a49f257608fcca315671f419878e26f719c88b7305710f314bfc8937', None),
    ('sftp', '82db87c4c00f6c817eb771b8a273bf81d35107f70c2bdb6c6af75a5f85c81e29', None),
    ('scp', 'bde7f8e3badea00a86faa4522efcac312dafe6fae5bf3d9dcd6d5beb4de036e9', None),
    ('openssl', 'acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549', None),
    ('rpcclient', 'e6d9d49c3f75b7081e324ff22cc715718803a276cc78bb6d4126473257f703d8', None),
    ('smbcacls', '8e40dcdbbfff5e183ea5eb59f616dd458128fdad13ff8df37780edd6e5ca289e', None),
    ('smbget', '149c17357d8c5e949d4dfc21ed73d3eec8e24d8c04d34b1ca8627608705b01f9', None),
    ('smbtar', '8a875756574997f884bd8dbf25db1b4e005af23371441ffc864dfcf830253f0b', None),
)


class InventoryError(ValueError):
    """Conservative schema, source, or offline-image failure."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise InventoryError(reason)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def parse(raw: bytes):
    require(len(raw) <= 1024 * 1024, 'json_size_limit')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InventoryError('nonfinite_json')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as err:
        raise InventoryError('invalid_json') from err


def read(root: Path, name: str, *, digest: str | None = None):
    require('/' not in name[:1] and '..' not in name.split('/'), 'unsafe_repo_path')
    target = root / name
    require(target.is_file() and not target.is_symlink(), 'missing_or_linked_source: '+name)
    raw = target.read_bytes()
    if digest is not None:
        require(hashlib.sha256(raw).hexdigest() == digest, 'source_digest_mismatch: '+name)
    return parse(raw)


def strict(obj, keys, name):
    require(type(obj) is dict and set(obj) == set(keys), 'schema_drift: '+name)


def canonical_ids():
    return (
        [f'SSH-T{i:02d}-BASE' for i in range(1, 9)] +
        ['FTP-T01-BASE', 'FTP-T02-CONTROL', 'FTP-T02-DATA'] +
        [f'FTP-T{i:02d}-BASE' for i in range(3, 8)] +
        ['FTP-T08-READ', 'FTP-T08-WRITE', 'SMB-T01-BASE', 'SMB-T02-BASE',
         'SMB-T03-SIGNING', 'SMB-T03-ENCRYPTION'] +
        [f'SMB-T{i:02d}-BASE' for i in range(4, 9)] +
        ['SMB-T09-READ', 'SMB-T09-WRITE']
    )


def validate(inv, compat, p7, p8, stages) -> dict:
    strict(inv, {'schema_version','roadmap_step','increment','base_commit','thesis_sha256',
                 'record_kind','image','guest_package_matches','binary_observations',
                 'absent_paths','trusted_issuer_verified','private_authorization_verified',
                 'future_runtime_material_identity_verified','selected_profile_count',
                 'authorized_case_count','dispatch_allowed','experiments_performed',
                 'limitations'}, 'inventory')
    require(inv['schema_version'] == '1.0' and type(inv['roadmap_step']) is int and inv['roadmap_step'] == 8 and
            inv['increment'] == 'P8-R9' and inv['base_commit'] == BASE and inv['thesis_sha256'] == THESIS,
            'inventory_identity')
    require(inv['record_kind'] == 'OPERATOR_REPORTED_OFFLINE_IMAGE_OBSERVATION_NOT_AUTHORITY',
            'observation_claim')
    strict(inv['image'], {'path','sha256','format','virtual_size_bytes','backing_file',
                          'observed_mode','observed_link_count','observed_file_bytes'}, 'image')
    im = inv['image']
    require(im == {'path':IMAGE_PATH,'sha256':IMAGE_SHA,'format':'qcow2',
                   'virtual_size_bytes':24*1024**3,'backing_file':None,'observed_mode':'0444',
                   'observed_link_count':1,'observed_file_bytes':1345847296}, 'image_pin_changed')
    require(inv['guest_package_matches'] == PACKAGE_EXPECTED, 'package_versions_drift')
    require(type(inv['binary_observations']) is list and len(inv['binary_observations']) == 15,
            'inventory_count')
    for item,(name,digest,size) in zip(inv['binary_observations'], BINARY_ROWS):
        strict(item, {'absolute_path','file_type','sha256','observed_file_bytes','status'}, 'artifact')
        require(item == {'absolute_path':'/usr/bin/'+name,'file_type':'REGULAR','sha256':digest,
                         'observed_file_bytes':size,'status':'IMAGE_BYTES_OBSERVED_NOT_LIVE_PIN'},
                'material_record_changed:'+name)
    require(inv['absent_paths'] == ['/usr/bin/sshpass'], 'absent_tool_drift')
    for field in ('trusted_issuer_verified','private_authorization_verified',
                  'future_runtime_material_identity_verified','dispatch_allowed','experiments_performed'):
        require(inv[field] is False, 'unauthorized_promotion: '+field)
    for field in ('selected_profile_count','authorized_case_count'):
        require(type(inv[field]) is int and inv[field] == 0, 'premature_count: '+field)
    require(inv['limitations'] == [
                'PACKAGE_VERSION_MATCH_NOT_PER_BINARY_PROVENANCE',
                'BASE_IMAGE_PIN_NOT_FUTURE_RUNTIME_PIN',
                'GUESTFS_READ_ONLY_OBSERVATION_NOT_ATTESTED_RUNTIME',
                'NO_PRIVATE_CASE_AUTHORITY', 'NO_PILOT_FROZEN_BUDGETS',
                'NO_TYPED_ARGV_FROZEN', 'NO_TRUSTED_REVOCATION_REGISTER',
            ], 'lost_limitations')
    strict(compat, {'schema_version','roadmap_step','increment','base_commit','image_sha256',
                    'mapping_kind','profiles','approved_profiles','dispatch_allowed','scope','warnings'}, 'compatibility')
    require(compat['schema_version']=='1.0' and type(compat['roadmap_step']) is int and
            compat['roadmap_step']==8 and compat['increment']=='P8-R9' and compat['base_commit']==BASE and
            compat['image_sha256']==IMAGE_SHA and
            compat['mapping_kind']=='PROTOCOL_LEVEL_CANDIDATE_NOT_PROFILE_CAPABILITY_PROOF' and
            compat['scope']=='CANDIDATE_MAPPING_ONLY', 'compat_identity')
    require(compat['approved_profiles'] == 0 and type(compat['approved_profiles']) is int and
            compat['dispatch_allowed'] is False and
            compat['warnings']==['NO_COMMAND_OR_OPTION_APPROVED','NO_PROFILE_AUTHORITY',
                                 'NO_EXECUTION','NO_P9_SUPERVISOR'], 'compat_promotion')
    require(type(p7.get('families')) is list and len(p7['families'])==25, 'p7_family_count')
    fids={p['id']:p['protocol'] for p in p7['families']}
    require(len(fids)==25 and set(fids)==({f'SSH-T{i:02d}' for i in range(1,9)}|
           {f'FTP-T{i:02d}' for i in range(1,9)}|{f'SMB-T{i:02d}' for i in range(1,10)}),
            'p7_family_identity')
    require(type(p8.get('profiles')) is list and p8.get('profile_slot_count')==29 and
            p8.get('count_by_protocol')=={'ssh':8,'ftp':10,'smb':11} and
            p8.get('execution_enabled') is False and p8.get('profile_frozen') is False and
            p8.get('cases_authorized')==0 and p8.get('real_cases')==0,
            'p8_contract_state')
    require(p8.get('policy',{}).get('pilot_numeric_limits') is None and
            p8.get('status')=='P8_R1_UNBOUND_PROFILE_DESIGN_ONLY', 'p8_limits_or_state')
    expected=canonical_ids()
    require([p['profile_id'] for p in p8['profiles']]==expected,
            'p8_profile_identity_or_order_changed')
    require(len(compat['profiles'])==29 and [p['profile_id'] for p in compat['profiles']]==expected,
            'compat_profile_identity_or_order_changed')
    for slot,row in zip(p8['profiles'], compat['profiles']):
        strict(row, {'profile_id','candidate_primary_binary','capability_tested',
                     'case_binding_verified','argv_frozen','resource_budget_frozen',
                     'approval_verified','status','additional_gate'}, 'compat_row')
        pid=slot['profile_id']
        family=pid.rsplit('-',1)[0] if pid.endswith('-BASE') else pid.rsplit('-',1)[0]
        require(slot['family_id'] in fids and slot['protocol']==fids[slot['family_id']],
                'profile_family_mismatch')
        require(type(slot['binding']) is dict and len(slot['binding'])==12 and
                all(v is None for v in slot['binding'].values()) and
                slot['status']=='BLOCKED_UNBOUND_NO_EXECUTION', 'profile_bindings_present')
        primary={'ssh':'/usr/bin/ssh','ftp':'/usr/bin/curl','smb':'/usr/bin/smbclient'}[slot['protocol']]
        gate=('PASSWORD_MECHANISM_NOT_VERIFIED' if pid=='SSH-T03-BASE' else
              'WRITE_CLEANUP_NOT_VERIFIED' if pid in {
                  'SSH-T07-BASE','FTP-T07-BASE','FTP-T08-WRITE',
                  'SMB-T08-BASE','SMB-T09-WRITE'} else 'EXACT_OPERATION_NOT_VERIFIED')
        require(row['candidate_primary_binary']==primary and row['additional_gate']==gate and
                row['status']=='BLOCKED_UNBOUND_NO_EXECUTION', 'candidate_drift: '+pid)
        for field in ('capability_tested','case_binding_verified','argv_frozen',
                      'resource_budget_frozen','approval_verified'):
            require(row[field] is False, 'candidate_promotion: '+pid+'.'+field)
    require(set(stages)=={'dev','pilot','exp'}, 'stage_registry')
    for stage,data in stages.items():
        require(data['stage']==stage and data['status']=='RESERVED_NOT_DEPLOYED',
                'stage_unexpected: '+stage)
        for field in ('services','scenarios','cases','executions','attempts','units'):
            require(data[field]==[], 'stage_no_longer_empty: '+stage+'/'+field)
    return {'status':'PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL',
            'source_base_commit':BASE,'image_sha256':IMAGE_SHA,
            'binary_hashes':len(inv['binary_observations']),'absent_tools':len(inv['absent_paths']),
            'candidate_profile_slots':len(compat['profiles']),
            'profile_capabilities_verified':0,'authorized_profiles':0,
            'real_cases':0,'dispatch_allowed':False,'physical_laboratory':'NOT_TOUCHED'}


def verify_repository(root: Path = ROOT):
    inv=read(root,INV_PATH)
    compat=read(root,CMP_PATH)
    p7=read(root,P7_PATH,digest=P7_SHA)
    p8=read(root,P8_PATH,digest=P8_SHA)
    stages={stage:read(root,'lab/scenario-separation-v1/'+stage+'.json')
            for stage in ('dev','pilot','exp')}
    return validate(inv,compat,p7,p8,stages)


def checked_command(argv: list[str], *, input: str | None = None, timeout: int = 300):
    result=subprocess.run(argv,input=input,text=True,capture_output=True,timeout=timeout,
                          check=False)
    require(result.returncode==0,'tool_read_failed: '+argv[0]+': '+result.stderr[-500:])
    return result.stdout


def verify_offline_image(inv):
    """Read pinned bytes in a QCOW2. Never use a user-editable script as root."""
    require(os.geteuid()!=0, 'do_not_run_repository_python_as_root')
    image=inv['image']['path']
    require(image==IMAGE_PATH, 'image_path_drift')
    actual=checked_command(['sudo','-n','stat','-c','%F|%h|%a|%s',image]).strip()
    require(actual=='regular file|1|444|1345847296', 'image_metadata_drift')
    require(checked_command(['sudo','-n','sha256sum',image]).split()[0]==IMAGE_SHA,
            'image_sha256_mismatch')
    info=parse(checked_command(['sudo','-n','qemu-img','info','-f','qcow2','--output=json',image]).encode())
    require(info.get('format')=='qcow2' and info.get('virtual-size')==24*1024**3 and
            not info.get('backing-filename'), 'unexpected_qcow2_structure')
    def guest(ops):
        out=checked_command(['sudo','-n','guestfish','--ro','--format=qcow2','-a',image,'-i'],
                            input='\n'.join(ops)+'\n')
        values=[s.strip() for s in out.splitlines() if s.strip()]
        require(len(values)==len(ops),'guestfs_output_cardinality')
        return values
    expected=inv['binary_observations']
    present=guest(['exists '+a['absolute_path'] for a in expected]+['exists /usr/bin/sshpass'])
    require(present==['true']*15+['false'],'guest_file_existence_changed')
    regular=guest(['is-file '+a['absolute_path'] for a in expected])
    require(regular==['true']*15,'guest_regular_file_changed')
    links=guest(['is-symlink '+a['absolute_path'] for a in expected])
    require(links==['false']*15,'guest_symlink_detected')
    hashes=guest(['checksum sha256 '+a['absolute_path'] for a in expected])
    require(hashes==[a['sha256'] for a in expected],'guest_binary_hash_changed')
    raw=checked_command(['sudo','-n','virt-cat','--format=qcow2','-a',image,'/var/lib/dpkg/status'])
    packages={}
    for para in raw.split('\n\n'):
        fields={}
        for line in para.splitlines():
            if line and not line[0].isspace() and ': ' in line:
                a,b=line.split(': ',1);fields[a]=b
        if fields.get('Status')=='install ok installed':
            packages[fields.get('Package')]=fields.get('Version')
    require(all(packages.get(k)==v for k,v in PACKAGE_EXPECTED.items()),'guest_package_version_changed')
    require(checked_command(['sudo','-n','sha256sum',image]).split()[0]==IMAGE_SHA,
            'post_observation_image_sha256_changed')
    return {'status':'PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION',
            'image_sha256':IMAGE_SHA,'binary_hashes':15,'packages_compared':4,
            'authorized_profiles':0,'dispatch_allowed':False,
            'guest_binaries_executed':False,'future_runtime_pin_verified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-image',action='store_true',
                        help='Validate pinned original image using sudo -n and read-only guestfs')
    args=parser.parse_args()
    try:
        record=verify_repository()
        print(json.dumps(record,sort_keys=True))
        if args.offline_image:
            inv=read(ROOT,INV_PATH)
            print(json.dumps(verify_offline_image(inv),sort_keys=True))
    except (InventoryError,OSError,subprocess.TimeoutExpired) as exc:
        print('ARDREC_P8_R9=FAIL_CLOSED: '+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
