"""R55.5: offline authenticated root recovery bundle and independent timer plan.

Pure generation, no sudo, systemd, nft, libvirt, shell, guest operations.
Root-owned staging and all physical recovery are separate explicit gates.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

SCHEMA='ardrec-r555-deny-only-root-bundle-v1'
SOURCE_MAIN='1866af3a4f0ceb64b92f39a924ef00eacf56b169'
PLAN_SHA='b32855a66b5a7df8960e29c805a17f11b2e3b9902cd53ba8a44d6193b5fe33eb'
ROOT_DIR='/var/lib/ardrec/r555-deny-guard'
ROOT_HELPER=ROOT_DIR+'/root-recover.py'
ROOT_HELPER_SHA256='0e649f408d53afeba0cd0c26920f7b6cb0e4f16fed052c2900bda5ca281f7fa7'
PREFIX='ardrec-r555-deny-watch'
PAYLOADS=('root-recover.py','r34-deny-restore.nft',
          'ssh-original.xml','ssh-candidate.xml',
          'runner-original.xml','runner-candidate.xml')
SAFE_REGEX=re.compile(r'ardrec-r555-deny-watch-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]{0,9}\Z')

class R555Error(ValueError):
    pass

def need(ok,reason):
    if not ok:
        raise R555Error(reason)

def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def canon(doc:dict)->bytes:
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),
            ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def prepare(files:dict[str,bytes],helper:bytes)->dict[str,bytes]:
    """Only signed R55.2-F1 verified material can be consumed."""
    need(type(files) is dict and 'plan.json' in files,
         'source_file_inventory_invalid')
    need(sha(files['plan.json'])==PLAN_SHA,'r552_plan_hash_invalid')
    from ardrec.coordination import r553_transition_guard as r553
    need(set(files)==r553.FILES,
         'source_file_inventory_invalid')
    plan=r553.verify_plan(files)
    need(plan['p8_operational']=='NO-GO' and
         plan['host_mutations']==0 and
         plan['restoration_executed'] is False and
         plan['operational_dispatch'] is False,
         'source_must_be_deny_only')
    need(type(helper) is bytes and sha(helper)==ROOT_HELPER_SHA256 and
         5000 < len(helper) < 100000 and
         b'--restore-deny' in helper and b'--check-root-bundle' in helper and
         b'--allow-traffic' not in helper and b'--open' not in helper,
         'root_recovery_helper_contract_invalid')
    payloads={
        'root-recover.py':helper,
        'r34-deny-restore.nft':files['nft-deny-restore-NOT-EXECUTED.nft'],
        'ssh-original.xml':files['ssh-binding-original.xml'],
        'ssh-candidate.xml':files['ssh-binding-candidate.xml'],
        'runner-original.xml':files['runner-binding-original.xml'],
        'runner-candidate.xml':files['runner-binding-candidate.xml'],
    }
    need(set(payloads)==set(PAYLOADS),'root_bundle_payload_inventory_invalid')
    need(payloads['r34-deny-restore.nft']==r553.expected_nft(allow=False),
         'r34_deny_not_exact')
    manifest={
        'schema':SCHEMA,
        'source_main':SOURCE_MAIN,
        'r552_plan_sha256':PLAN_SHA,
        'permission':'DENY_ONLY_RESTORATION',
        'traffic_allowed':False,
        'p8_operational':'NO-GO',
        'sha256':{n:sha(payloads[n]) for n in PAYLOADS},
    }
    payloads['manifest.json']=canon(manifest)
    return payloads

def watchdog_argv(unit:str,seconds:int)->list[str]:
    need(type(unit) is str and SAFE_REGEX.fullmatch(unit) is not None,
         'timer_unit_identity_invalid')
    need(type(seconds) is int and 30 <= seconds <= 180,
         'timer_duration_out_of_range')
    # NEVER execute these bytes from a user-writable checkout; the path must be
    # staged root:root 0700 with file 0600 and reverified by the root helper.
    return ['/usr/bin/sudo','-n','--','/usr/bin/systemd-run','--system',
            '--unit='+unit,'--on-active='+str(seconds)+'s',
            '--timer-property=AccuracySec=1s',
            '/usr/bin/python3',ROOT_HELPER,'--restore-deny']

def verify_timer_argv(argv:list[str],unit:str,seconds:int)->None:
    need(type(argv) is list and argv==watchdog_argv(unit,seconds),
         'watchdog_command_changed')

def obligations()->dict:
    return {'schema':'ardrec-r555-root-recovery-contract-v1',
            'base_main':SOURCE_MAIN,
            'root_bundle_expected':ROOT_DIR,
            'recovery_behavior':'DENY_ONLY',
            'root_staging_performed':False,
            'systemd_system_timer_armed':False,
            'recovery_executed':False,
            'binding_restoration_executed':False,
            'physical_isolation_witness':False,
            'required_before_opening':[
                'root_owned_staging_and_identity_attestation',
                'supervisor_arming_confirmation',
                'independent_system_manager_test_under_SIGKILL',
                'deny_first_physical_restore_under_partial_binding_fault',
                'positive_and_negative_packet_witnesses',
                'separate_change_authorization'],
            'p8_operational':'NO-GO'}
