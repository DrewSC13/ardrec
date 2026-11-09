#!/usr/bin/env python3
"""P8-R18 static CI gate: pin the R9 candidate inventory, test offline interface.

CI does NOT access the private QCOW2. Private observations require --collect separately.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r18_elf_metadata as elf
import verify_p8_material_inventory as r9
import verify_p8_r17_material_closure as r17

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'lab/p8-r18-elf-metadata-v1/spec.json'
SPEC_SHA = 'c0e992971b2ecba63480a8aa93496144485c808cc0cca2568537d92ef82e135b'


def verify():
    r9_result = r9.verify_repository()
    r17_result = r17.verify()
    elf.need(r9_result['status'] == 'PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL',
             'r9_chain')
    elf.need(r17_result['status'] == 'PASS_DENY_ONLY_29_PROFILE_MATERIAL_GAPS',
             'r17_chain')
    raw = SPEC.read_bytes()
    elf.need(hashlib.sha256(raw).hexdigest() == SPEC_SHA, 'spec_hash')
    obj = json.loads(raw)
    elf.need(set(obj) == {'schema_version','scope','base_main_commit','image_path',
                         'image_sha256','binary_candidates','authorizations',
                         'proof_limitations'}, 'spec_fields')
    inv = r9.read(ROOT, r9.INV_PATH)
    elf.need(obj['schema_version'] == '1.0' and
             obj['scope'] == 'OFFLINE_ELF64_DIRECT_METADATA_ONLY' and
             obj['base_main_commit'] == '05513b28af3ffa23ef98cef3fd4e2dcf2a71eea8' and
             obj['image_path'] == r9.IMAGE_PATH and
             obj['image_sha256'] == r9.IMAGE_SHA, 'spec_identity')
    expected = {row['absolute_path']: row['sha256']
                for row in inv['binary_observations']
                if row['absolute_path'] in ('/usr/bin/ssh','/usr/bin/curl','/usr/bin/smbclient')}
    elf.need(obj['binary_candidates'] == expected and len(expected) == 3,
             'binary_candidate_pins')
    elf.need(obj['authorizations'] == {'profiles': 0,'cases': 0,'dispatch_allowed': False},
             'authorizations')
    elf.need(obj['proof_limitations'] == [
        'DIRECT_NEEDED_ONLY_NOT_TRANSITIVE_CLOSURE',
        'NOT_LOADER_SEARCH_PATH_RESOLUTION',
        'NOT_RUNTIME_BINARY_IDENTITY',
        'NOT_EFFECTIVE_CONFIGURATION_OR_CLI_APPROVAL',
        'NO_PRIVATE_CASE_AUTHORITY',
    ], 'proof_limitations')
    return {'status':'PASS_P8_R18_STATIC_OFFLINE_ELF_INTERFACE_DENY_ONLY',
            'base_main_commit':obj['base_main_commit'],
            'candidate_binaries':len(expected), 'execution_enabled':False,
            'offline_image_attested_by_ci':False,'runtime_dependency_closure_verified':False,
            'approved_profiles':0,'dispatch_allowed':False}


if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True))
    except (OSError,ValueError,KeyError,TypeError,elf.ElfEvidenceError) as exc:
        print('P8_R18=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
