"""R55.8: independent, versioned, deny-only recovery upgrade contract.

Build from authenticated R55.2-F1 source. All pure functions; no privileges,
network, libvirt, nftables or systemd effects.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

from ardrec.coordination import r553_transition_guard as r553

SCHEMA = 'ardrec-r558-deny-only-root-bundle-v1'
BASE = '04dc845983ffe53925498c47e142b3924319bf1c'
DEST = Path('/var/lib/ardrec/r558-deny-guard')
SOURCE_PLAN = Path('/home/cicada/ardrec-lab/r55-transition/r552-f1-plan-20261115T152309Z-39487')
R557_RECEIPT = Path('/home/cicada/ardrec-lab/r557-physical-deny/r557-f1-20261115T174044Z-67263')
R557_RESULT_SHA256 = '9a8ec90ff3a411c059d54e7b9933546705e16b968bec0c1121b5869c7e84c37d'
SOURCE_HELPER_NAME = 'ardrec_p14_r558_root_recover.py'
HELPER_SHA = '7064b56d81b65cd6c137faa5c4272cbe2f4ca41626331fc65be9b3d2461a6c1f'
PAYLOADS = ('root-recover.py','r34-deny-restore.nft','ssh-original.xml',
            'ssh-candidate.xml','runner-original.xml','runner-candidate.xml')
FILES = frozenset((*PAYLOADS,'manifest.json'))
PRIVATE_FILES = frozenset((*FILES,'contract.json','SHA256SUMS'))
RECEIPT_PATTERN = re.compile(r'r558-prepared-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]{0,9}\Z')

class R558Error(ValueError):
    pass

def need(value:bool, reason:str)->None:
    if not value:
        raise R558Error(reason)

def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def canon(doc:dict)->bytes:
    return (json.dumps(doc,sort_keys=True,ensure_ascii=True,
                separators=(',',':'),allow_nan=False)+'\n').encode('ascii')

def attest_r557(doc:dict)->None:
    need(type(doc) is dict and doc.get('schema')=='ardrec-r557-f1-physical-deny-v1' and
         doc.get('status')=='PHYSICAL_DENY_AND_TIMER_PASS_NO_GO' and
         doc.get('physical_deny_verified') is True and
         doc.get('timer_armed') is True and
         doc.get('timer_fired_verified') is True and
         doc.get('worker_killed') is True and
         doc.get('traffic_opened') is False and
         doc.get('p8_operational') == 'NO-GO', 'r557_proof_invalid')

def prepare(plan_files:dict[str,bytes], helper:bytes)->dict[str,bytes]:
    need(type(plan_files) is dict and set(plan_files)==r553.FILES,
         'r552_file_set_invalid')
    r553.verify_plan(plan_files)
    need(sha(plan_files['plan.json'])==r553.PLAN_SHA256, 'source_plan_drift')
    need(type(helper) is bytes and sha(helper)==HELPER_SHA,
         'root_helper_hash_changed')
    payload = {
        'root-recover.py':helper,
        'r34-deny-restore.nft':plan_files['nft-deny-restore-NOT-EXECUTED.nft'],
        'ssh-original.xml':plan_files['ssh-binding-original.xml'],
        'ssh-candidate.xml':plan_files['ssh-binding-candidate.xml'],
        'runner-original.xml':plan_files['runner-binding-original.xml'],
        'runner-candidate.xml':plan_files['runner-binding-candidate.xml'],
    }
    need(payload['r34-deny-restore.nft']==r553.expected_nft(allow=False),
         'deny_restore_not_exact')
    manifest = {
        'schema':SCHEMA,
        'source_main':BASE,
        'r552_plan_sha256':r553.PLAN_SHA256,
        'r557_result_sha256':R557_RESULT_SHA256,
        'permission':'DENY_ONLY_RESTORATION',
        'traffic_allowed':False,
        'p8_operational':'NO-GO',
        'sha256':{name:sha(payload[name]) for name in PAYLOADS},
    }
    payload['manifest.json'] = canon(manifest)
    need(set(payload)==FILES,'root_payload_set_invalid')
    return payload

def check_bundle(payload:dict[str,bytes], helper:bytes)->None:
    need(type(payload) is dict and set(payload)==FILES,'root_files_invalid')
    prepare_with_manifest(payload,helper)

def prepare_with_manifest(payload,helper):
    """Internal non-recursive validation of a preassembled 7-file payload."""
    need(payload.get('root-recover.py')==helper and sha(helper)==HELPER_SHA,
         'root_helper_invalid')
    doc = json.loads(payload['manifest.json'])
    need(type(doc) is dict and set(doc)=={
         'schema','source_main','r552_plan_sha256','r557_result_sha256',
         'permission','traffic_allowed','p8_operational','sha256'},'manifest_fields_invalid')
    need(doc['schema']==SCHEMA and doc['source_main']==BASE and
         doc['r552_plan_sha256']==r553.PLAN_SHA256 and
         doc['r557_result_sha256']==R557_RESULT_SHA256 and
         doc['permission']=='DENY_ONLY_RESTORATION' and
         doc['traffic_allowed'] is False and doc['p8_operational']=='NO-GO',
         'manifest_authority_invalid')
    need(type(doc['sha256']) is dict and set(doc['sha256'])==set(PAYLOADS) and
         all(doc['sha256'][name]==sha(payload[name]) for name in PAYLOADS),
         'manifest_checksums_invalid')
    need(payload['r34-deny-restore.nft']==r553.expected_nft(allow=False),
         'deny_policy_invalid')
    for role in ('ssh','runner'):
        old, candidate = (payload[role+'-original.xml'],payload[role+'-candidate.xml'])
        need(r553.binding_identity(old,role=role,candidate=False)==
             r553.binding_identity(candidate,role=role,candidate=True),
             'binding_identity_invalid_'+role)
    return payload

def stage_commands(source:Path)->list[list[str]]:
    need(isinstance(source,Path) and source.is_absolute() and
         '..' not in source.parts and
         RECEIPT_PATTERN.fullmatch(source.name) is not None and
         str(source.parent)=='/home/cicada/ardrec-lab/r58-root-recovery',
         'source_path_invalid')
    result=[
        ['/usr/bin/install','-d','-m','0700','-o','0','-g','0',str(DEST.parent)],
        ['/usr/bin/install','-d','-m','0700','-o','0','-g','0',str(DEST)],
    ]
    for name in sorted(FILES):
        result.append(['/usr/bin/install','-m','0600','-o','0','-g','0','--',
                       str(source/name),str(DEST/name)])
    need(len(result)==9,'root_command_count_invalid')
    return result

def obligations():
    return {
        'schema':'ardrec-r558-recovery-v2-contract-v1',
        'base_main':BASE,'root_target':str(DEST),
        'r557_result_sha256':R557_RESULT_SHA256,
        'missing_binding_handling':'RECONCILE_ONLY_IF_LIST_ABSENT_AND_LIVE_IDENTITY_VERIFIED',
        'unknown_binding':'BLOCK_UNDER_R34_DENY',
        'timer_installed':False,'traffic_allowed':False,
        'physical_fault_injection':False,'p8_operational':'NO-GO',
    }
