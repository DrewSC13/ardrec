#!/usr/bin/env python3
"""ARDREC P8-R11: check observed QCOW2 manpages and declared dependencies.

Default reads only public versioned files. With --offline-image, sudo -n reads
only the pinned, operator-owned QCOW2 via stat, sha256sum, qemu-img and virt-cat.
Never executes ssh/curl/smbclient, boots guests, establishes sockets, renders
commands, or grants permission. Never run this repository Python with sudo.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import verify_p8_profile_contracts as r10

ROOT = Path(__file__).resolve().parents[1]
BASE = '4412a1093eafbfcf61b52c647963511f01725576'
IMAGE_PATH = '/var/lib/libvirt/images/ardrec-dev-point4-v4/runner-base.qcow2'
IMAGE_SHA = 'fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
R10_SHA = 'f09e92f395928a52e3c826a11aeef8ed13acb07299b322d173cc03fcf55b4f41'
EVIDENCE = 'lab/p8-cli-source-v1/evidence.json'
R10_CONTRACTS = 'lab/p8-profile-contract-v1/contracts.json'
R9_INV = 'lab/p8-material-inventory-v1/inventory.json'

class EvidenceError(ValueError):
    """Invalid versioned observation or mismatch with an image."""

def need(value, reason):
    if not value: raise EvidenceError(reason)

def exact(obj, fields, context):
    need(type(obj) is dict and set(obj)==set(fields),'fields_changed:'+context)

def unique_pairs(pairs):
    out={}
    for key,value in pairs:
        need(key not in out, 'duplicate_json_key')
        out[key]=value
    return out

def decode(raw):
    need(len(raw)<=512*1024, 'large_json')
    try:
        return json.loads(raw.decode('utf-8'),object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError('nonfinite_json')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as err:
        raise EvidenceError('invalid_json') from err

def checked_source(root, relative, digest=None):
    need(type(relative) is str and not relative.startswith('/') and
         all(part not in ('','.','..') for part in relative.split('/')),
         'invalid_source_path')
    path=root/relative
    need(path.is_file() and not path.is_symlink(),'missing_or_linked_source:'+relative)
    raw=path.read_bytes()
    if digest is not None:
        need(hashlib.sha256(raw).hexdigest()==digest,'upstream_source_drift:'+relative)
    return decode(raw)

# These constants were transcribed from the operator's P8-R11 read-only output.
# They are independent pins, not regenerated from the JSON being checked.
MANUALS = (('/usr/share/man/man1/ssh.1.gz', '78a8c50b4eecf26228707878018ca314aea3008c87caef6724030fc856e50481', 15310, 48413), ('/usr/share/man/man5/ssh_config.5.gz', '7860149efded4d0d863e3227c78780137ee78ce437cca61aad74bdd425498b37', 20952, 73459), ('/usr/share/man/man1/ssh-keyscan.1.gz', '9853bddce174b54203038fc07a8efe432cb52891e456d31eab6ff58984f3dadc', 2296, 4828), ('/usr/share/man/man1/sftp.1.gz', '14866f5f918982483f7bfa5d4c53fcc2662ab0d86db6d7113309fbc5a5dc53e0', 6331, 18055), ('/usr/share/man/man1/curl.1.gz', 'c890fbab33db8ed67773ffa4d422ed78da17f16d827f6615d94111923d242c16', 72618, 255928), ('/usr/share/man/man1/smbclient.1.gz', 'aca2de052bb22fa7fb03451de4f7cd2c235af5a84372e623d9b49863262ef77b', 13812, 47640), ('/usr/share/man/man1/rpcclient.1.gz', 'f264e9e8c4c1eece7688a1d1813974211f4969ec51e3e8a944d4ae40d26ba05a', 10872, 37432))
PACKAGES = (('openssh-client', '1:10.0p1-7+deb13u4', 'adduser, init-system-helpers (>= 1.66~), passwd, libc6 (>= 2.38), libedit2 (>= 2.11-20080614-0), libfido2-1 (>= 1.8.0), libgssapi-krb5-2 (>= 1.17), libselinux1 (>= 3.1~), libssl3t64 (>= 3.0.0), zlib1g (>= 1:1.1.4)'), ('curl', '8.14.1-2+deb13u7', 'libc6 (>= 2.34), libcurl4t64 (= 8.14.1-2+deb13u7), zlib1g (>= 1:1.1.4)'), ('smbclient', '2:4.22.11+dfsg-0+deb13u1', 'samba-common, samba-libs (= 2:4.22.11+dfsg-0+deb13u1), libarchive13t64 (>= 3.0.4), libbsd0 (>= 0.0), libc6 (>= 2.38), libgnutls30t64 (>= 3.7.0), libndr6 (>= 2:4.20.0~rc1), libpopt0 (>= 1.14), libreadline8t64 (>= 6.0), libsmbclient0 (>= 2:4.10.0+dfsg), libtalloc2 (>= 2.4.0), libtevent0t64 (>= 0.15.0)'), ('python3', '3.13.5-1', 'python3.13 (>= 3.13.5-1~), libpython3-stdlib (= 3.13.5-1)'))
LIMITATIONS = ['OPERATOR_REPORTED_NOT_INDEPENDENT_TRUSTED_ATTESTATION', 'MANPAGE_HASH_MATCH_DOES_NOT_VERIFY_FLAGS_OR_SEMANTICS', 'PACKAGE_DEPENDS_DECLARATION_NOT_RUNTIME_DEPENDENCY_CLOSURE', 'NO_CLI_GRAMMAR_OR_ARGV_SERIALIZER', 'NO_SSH_REMOTE_COMMAND_OR_SMBCLIENT_LANGUAGE', 'NO_PRIVATE_CREDENTIALS_OR_CASES', 'NO_RUNTIME_BINARIES_PINNED', 'NO_PILOT_BUDGETS', 'NO_EFFECTIVE_EXECUTOR_SUPERVISION']

EVIDENCE_FIELDS = ('schema_version','roadmap_step','increment','base_commit','kind',
 'image_sha256','r10_contracts_sha256','manual_sources','declared_packages',
 'profile_documentation_candidates','profiles','manual_semantic_reviews_completed',
 'effective_cli_grammars','capabilities_verified','authorized_cases',
 'authorized_profiles','dispatch_allowed','algorithms_started','physical_laboratory_contact','limitations')
PROFILE_FIELDS = ('profile_id','operation_id','candidate_binary','candidate_binary_sha256',
 'documentation_candidates','cli_argument_grammar','rendered_argv','remote_command_ast',
 'smb_command_ast','accepted_option_tokens','manual_option_semantics_reviewed',
 'tool_capability_verified','dependency_closure_verified','credential_delivery','environment',
 'auxiliary_resolution','case_authorization','budget','cleanup_receipt','dispatch_allowed','status')
MANUAL_FIELDS = ('absolute_path','compressed_sha256','compressed_bytes','decompressed_bytes',
 'documentation_semantics_verified','source_role')
PACKAGE_FIELDS = ('name','version','depends_declaration','dependency_closure_verified',
 'runtime_loader_resolution_verified')

def documents_for(pid,proto):
    if proto=='ssh':
        paths=[MANUALS[0][0],MANUALS[1][0]]
        if pid=='SSH-T01-BASE':paths.append(MANUALS[2][0])
        if pid in ('SSH-T06-BASE','SSH-T07-BASE'):paths.append(MANUALS[3][0])
        return paths
    if proto=='ftp':return [MANUALS[4][0]]
    if proto=='smb':
        return [MANUALS[5][0]]+([MANUALS[6][0]] if pid=='SMB-T02-BASE' else [])
    raise EvidenceError('unknown_protocol')

def validate(record,prior,inventory):
    exact(record,EVIDENCE_FIELDS,'evidence')
    need(record['schema_version']=='1.0' and type(record['roadmap_step']) is int and
         record['roadmap_step']==8 and record['increment']=='P8-R11' and
         record['base_commit']==BASE and record['image_sha256']==IMAGE_SHA and
         record['r10_contracts_sha256']==R10_SHA and
         record['kind']=='OPERATOR_REPORTED_OFFLINE_QCOW2_MANUAL_AND_DPKG_OBSERVATIONS_NOT_CAPABILITY_PROOF',
         'evidence_identity_changed')
    need(inventory['image']['sha256']==IMAGE_SHA and
         inventory['guest_package_matches']=={name:version for name,version,_ in PACKAGES},
         'prior_inventory_mismatch')
    need(type(record['manual_sources']) is list and len(record['manual_sources'])==7,'manual_count')
    for m,(path,digest,size,uncompressed) in zip(record['manual_sources'],MANUALS):
        exact(m,MANUAL_FIELDS,'manual')
        need(m=={'absolute_path':path,'compressed_sha256':digest,
                 'compressed_bytes':size,'decompressed_bytes':uncompressed,
                 'documentation_semantics_verified':False,
                 'source_role':'VERSION_PINNED_DOCUMENTATION_CANDIDATE_NOT_CLI_CAPABILITY'},
             'manual_observation_drift:'+path)
    need(type(record['declared_packages']) is list and len(record['declared_packages'])==4,
         'package_count')
    for pkg,(name,version,depends) in zip(record['declared_packages'],PACKAGES):
        exact(pkg,PACKAGE_FIELDS,'package')
        need(pkg=={'name':name,'version':version,'depends_declaration':depends,
                    'dependency_closure_verified':False,'runtime_loader_resolution_verified':False},
             'package_declaration_drift:'+name)
    need(type(record['profile_documentation_candidates']) is list and
         type(prior['profiles']) is list and len(record['profile_documentation_candidates'])==29 and
         len(prior['profiles'])==29,'profile_count')
    seen=set()
    for current,old in zip(record['profile_documentation_candidates'],prior['profiles']):
        exact(current,PROFILE_FIELDS,'profile')
        pid=old['profile_id']
        need(type(pid) is str and pid not in seen and current['profile_id']==pid,
             'profile_sequence_changed')
        seen.add(pid)
        need(current['operation_id']==old['semantic_operation_id'] and
             current['candidate_binary']==old['candidate_binary'] and
             current['candidate_binary_sha256']==old['candidate_binary_sha256'] and
             current['documentation_candidates']==documents_for(pid,old['protocol']),
             'candidate_source_mismatch:'+pid)
        for k in ('cli_argument_grammar','rendered_argv','remote_command_ast',
                  'smb_command_ast','credential_delivery','environment','auxiliary_resolution',
                  'case_authorization','budget','cleanup_receipt'):
            need(current[k] is None,'unverified_material_promoted:'+pid+':'+k)
        need(current['accepted_option_tokens']==[] and type(current['accepted_option_tokens']) is list,
             'unreviewed_cli_option_promoted:'+pid)
        for k in ('manual_option_semantics_reviewed','tool_capability_verified',
                  'dependency_closure_verified','dispatch_allowed'):
            need(current[k] is False,'authority_or_capability_promoted:'+pid+':'+k)
        need(current['status']=='BLOCKED_DOCUMENTARY_SOURCE_ONLY','profile_unblocked:'+pid)
    for k,n in [('profiles',29),('manual_semantic_reviews_completed',0),
                ('effective_cli_grammars',0),('capabilities_verified',0),
                ('authorized_cases',0),('authorized_profiles',0)]:
        need(type(record[k]) is int and record[k]==n,'invalid_count:'+k)
    need(record['dispatch_allowed'] is False and record['algorithms_started'] is False and
         record['physical_laboratory_contact']=='NONE', 'execution_claim')
    need(record['limitations']==LIMITATIONS,'limitations_removed')
    return {'status':'PASS_P8_R11_MANUAL_DPKG_SOURCES_DENY_ALL','manuals':7,
            'package_declarations':4,'profile_documentary_candidates':len(seen),
            'effective_cli_grammars':0,'manual_semantic_reviews_completed':0,
            'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
            'image_sha256':IMAGE_SHA,'algorithms_started':False}

def verify_repository(root=ROOT):
    root=Path(root)
    if root==ROOT:
        r10.verify_repository()  # P8-R9/P8-R10, 29 slots blocked, P6 empty.
    record=checked_source(root,EVIDENCE)
    prior=checked_source(root,R10_CONTRACTS,R10_SHA)
    inventory=checked_source(root,R9_INV,r10.R9_INV_SHA)
    return validate(record,prior,inventory)

def safe_command(argv,*,timeout=300,stdin_data=None):
    result=subprocess.run(argv,input=stdin_data,capture_output=True,timeout=timeout,check=False)
    need(result.returncode==0,'inspection_utility_failed:'+argv[2]+':' +
         result.stderr[-250:].decode('utf-8',errors='replace'))
    return result.stdout

def parse_dpkg(raw):
    need(len(raw)<=12*1024*1024,'dpkg_status_too_large')
    installed={}
    for para in raw.decode('utf-8','strict').split('\n\n'):
        fields={}; current=None
        for line in para.splitlines():
            if line.startswith(' ') and current:
                fields[current]+=' '+line.strip()
            elif ': ' in line and not line[0].isspace():
                key,value=line.split(': ',1)
                need(key not in fields,'duplicate_dpkg_field')
                fields[key]=value
                current=key
        if fields.get('Status')=='install ok installed':
            name=fields.get('Package')
            need(name not in installed,'duplicate_installed_package')
            installed[name]=fields
    return installed

def verify_offline_image(record):
    need(os.geteuid()!=0,'do_not_run_repository_script_as_root')
    path=IMAGE_PATH
    observed=safe_command(['sudo','-n','stat','-c','%F|%h|%a|%s',path]).decode().strip()
    need(observed=='regular file|1|444|1345847296','image_metadata_drift')
    def verify_sha():
        actual=safe_command(['sudo','-n','sha256sum',path]).decode().split()[0]
        need(actual==IMAGE_SHA,'image_digest_changed')
    verify_sha()
    info=decode(safe_command(['sudo','-n','qemu-img','info','-f','qcow2','--output=json',path]))
    need(info.get('format')=='qcow2' and info.get('virtual-size')==24*1024**3 and
         not info.get('backing-filename'), 'image_structure_changed')
    paths=[m['absolute_path'] for m in record['manual_sources']]
    guest_ops=(['exists '+p for p in paths]+['is-file '+p for p in paths]+
               ['is-symlink '+p for p in paths])
    guest_result=safe_command(
        ['sudo','-n','guestfish','--ro','--format=qcow2','-a',path,'-i'],
        stdin_data=('\n'.join(guest_ops)+'\n').encode('utf-8'))
    guest_lines=[x.strip() for x in guest_result.decode('utf-8').splitlines() if x.strip()]
    need(guest_lines==['true']*14+['false']*7,'manual_path_type_changed')
    for manual in record['manual_sources']:
        source=manual['absolute_path']
        # The local tool is virt-cat, NEVER a guest binary. No content is printed.
        raw=safe_command(['sudo','-n','virt-cat','--format=qcow2','-a',path,source])
        need(len(raw)==manual['compressed_bytes'],'manpage_size_changed:'+source)
        need(hashlib.sha256(raw).hexdigest()==manual['compressed_sha256'],
             'manpage_hash_changed:'+source)
        need(len(raw)<=1024*1024 and raw.startswith(b'\x1f\x8b'),
             'unsafe_gzip_header:'+source)
        try:plain=gzip.decompress(raw)
        except (EOFError,OSError) as exc:
            raise EvidenceError('invalid_manual_gzip:'+source) from exc
        need(len(plain)==manual['decompressed_bytes'] and len(plain)<=1024*1024,
             'decompressed_manual_size_changed:'+source)
    installed=parse_dpkg(safe_command(['sudo','-n','virt-cat','--format=qcow2',
                                       '-a',path,'/var/lib/dpkg/status']))
    for package in record['declared_packages']:
        got=installed.get(package['name'])
        need(got is not None and got.get('Version')==package['version'] and
             got.get('Depends')==package['depends_declaration'],
             'package_or_dependencies_changed:'+package['name'])
    verify_sha()
    return {'status':'PASS_P8_R11_QCOW2_DOCUMENTATION_READ_ONLY',
            'manuals_rechecked':7,'packages_rechecked':4,
            'guest_binaries_executed':False,'manual_options_validated':False,
            'runtime_dependency_closure_verified':False,
            'authorized_profiles':0,'dispatch_allowed':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-image',action='store_true')
    args=parser.parse_args()
    try:
        record=checked_source(ROOT,EVIDENCE)
        print(json.dumps(verify_repository(),sort_keys=True))
        if args.offline_image:
            print(json.dumps(verify_offline_image(record),sort_keys=True))
    except (EvidenceError,r10.ContractError,r10.r9.InventoryError,OSError,
            subprocess.TimeoutExpired,UnicodeError) as err:
        print('ARDREC_P8_R11=FAIL_CLOSED: '+str(err),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
