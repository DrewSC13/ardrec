#!/usr/bin/env python3
"""Reconcile ORIGINAL physical F8 failure without another boot.

No host mutations or network grants. Writes one new receipt to a private directory
only if original evidence and an independent present-state reading both validate.
Cannot by itself grant P8, attest service SSH or finish R112.
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
import tempfile
import time

REPO = Path('/home/cicada/Development/GitHub/ardrec')
BASE = Path('/home/cicada/ardrec-lab/r112-f8-real-ssh-boot-v1')
PLAN = BASE / 'plan-ld19q3ok'
BOOT = BASE / 'boot-bgtqj5r2'
OUTPUT = Path('/home/cicada/ardrec-lab/r112-f8s-reconciliation-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
COMMIT = 'b39dac34e9b7af9134d72373c3a9076208293dba'
EXPECTED_SOURCE_SHA = '514a2a6e7b749b5b400553bced11308cbfb2aa9431fe480d69a0618ddea7f485'
EXPECTED = {
  'plan/before.json':'87555186d31282f162a7c11117193ec02c15f03350a6cf8e6ed8887510cde1f5',
  'plan/plan.json':'13fd5a99d515c9d3684467083d6197e6b384210a675e28c6ce2b24819e8cf2fb',
  'plan/manifest.json':'0c8b2a01567f03175dce485785f77e3b6f5facf3852e649b9f5a3fa208a21dbb',
  'plan/boot.once':'6fd8f7a187cfc650d4757c98de0a7bb6f4c2e1ed877ab27ea13af484aa7d35b3',
  'boot/after.json':'99be06aed46f3ad74c51913023aa9714e86604f7153abd2ecc61669166337e2a',
  'boot/claim-readback.json':'0faf9e54af06b2cdcfcb2b9a6a0e052398e5ce001597e7c0bfcc644a5cc7fd6a',
  'boot/live-xml.json':'f50fa9e2b259f16ddc32b55a36e9a8ab829b031236d1fccf50777563ac80a28f',
  'boot/start-command.json':'3d94619a4840328cdf53e0bb885ca15cc7ae4f8967a46f38ba0c326b93065ee2',
  'boot/grant-dir-command.json':'9347abb015429b8a7818f0824a4defa084c00f4bd406c4a016bc35bf1dee92b0',
  'boot/grant-file-command.json':'9347abb015429b8a7818f0824a4defa084c00f4bd406c4a016bc35bf1dee92b0',
  'boot/grant-readback.json':'8176615bb84913109bd0a9815357132ee464113de9c4330b7b3a07e30db05b5d',
  'boot/intent.json':'0843609d498d2febf8c6b89fa6bda74f5fd250d906c1a2b102c437d034dd8ff8',
  'boot/ticket.json':'cc72c61520bd3fdd453bcbb94a1c19996db84bc9af8a25725467cec4039eb316',
}

class Stop(Exception):
    pass

def need(condition, error):
    if not condition:
        raise Stop(error)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def command(*args, timeout=25):
    p=subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                     timeout=timeout,check=False)
    return p.returncode,p.stdout.strip(),p.stderr.strip()

def read_original():
    need(PLAN.is_dir() and not PLAN.is_symlink(), 'PLAN_DIRECTORY_INVALID')
    need(BOOT.is_dir() and not BOOT.is_symlink(), 'BOOT_DIRECTORY_INVALID')
    need({x.name for x in PLAN.iterdir()}=={'before.json','plan.json','manifest.json','boot.once'},'PLAN_FILE_SET_DRIFT')
    need({x.name for x in BOOT.iterdir()}=={k.split('/',1)[1] for k in EXPECTED if k.startswith('boot/')},'BOOT_FILE_SET_DRIFT')
    data={}
    for key,hexhash in EXPECTED.items():
        prefix,name=key.split('/',1)
        path=(PLAN if prefix=='plan' else BOOT)/name
        need(path.is_file() and not path.is_symlink(), 'ORIGINAL_NOT_REGULAR_'+key)
        raw=path.read_bytes()
        need(digest(raw)==hexhash, 'ORIGINAL_HASH_DRIFT_'+key)
        if key.endswith('.json'):
            def no_duplicates(pairs):
                result={}
                for k,v in pairs:
                    if k in result:
                        raise Stop('DUPLICATE_JSON_KEY_'+key)
                    result[k]=v
                return result
            try:
                data[key]=json.loads(raw,object_pairs_hook=no_duplicates)
            except (ValueError,UnicodeError) as error:
                raise Stop('JSON_INVALID_'+key) from error
        elif key=='plan/boot.once':
            need(raw==b'ATTEMPTED\n','ORIGINAL_ATTEMPT_MARKER')
    return data

def validate_historical(core, legacy, f4, f6, data):
    before=data['plan/before.json']; after=data['boot/after.json']
    proposal=data['plan/plan.json']; manifest=data['plan/manifest.json']
    intent=data['boot/intent.json']; ticket=data['boot/ticket.json']
    grant=data['boot/grant-readback.json']; claims=data['boot/claim-readback.json']
    start=data['boot/start-command.json']; live=data['boot/live-xml.json']
    need(type(proposal) is dict and proposal.get('schema')==core.SCHEMA+'-plan', 'PLAN_SCHEMA')
    need(proposal.get('source_parent')==core.PARENT,'PARENT_WRONG')
    need(proposal.get('guest')==core.GUEST and proposal.get('command')==list(core.START),'PLAN_COMMAND_WRONG')
    need(proposal.get('physical_host_before_sha256')==core.sha(before),'PLAN_BEFORE_WRONG')
    need(proposal.get('r34_policy')=='DENY_ALL_TRAFFIC_PRESERVED' and
         proposal.get('p8_operational')=='NO-GO','PLAN_POLICY_WRONG')
    need(isinstance(proposal.get('source_f7_physical_negative_sha256'),str)
         and re.fullmatch('[0-9a-f]{64}',proposal['source_f7_physical_negative_sha256']),
         'F7_SOURCE_SHA_MISSING')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                   'before_sha256':core.sha(before),
                   'plan_sha256':core.sha(proposal),
                   'p8_operational':'NO-GO'},'PLAN_MANIFEST_WRONG')
    need(intent=={'schema':core.SCHEMA+'-intent',
                  'plan_sha256':core.sha(proposal),
                  'guest':core.GUEST,'one_real_qemu_start':True,
                  'command':list(core.START),
                  'network_opening_authorized':False,
                  'p8_operational':'NO-GO'},'INTENT_MISMATCH')
    need(type(ticket) is dict and ticket==core.ticket(ticket['issued_at'],ticket['nonce']), 'TICKET_MISMATCH')
    for key in ('grant-dir-command.json','grant-file-command.json'):
        result=data['boot/'+key]
        need(type(result) is dict and result['rc']==0 and
             result['timeout'] is False and result['truncated'] is False,
             'GRANT_COMMAND_FAILED_'+key)
    need(type(live) is dict and live.get('rc')==0 and live.get('timeout') is False
         and live.get('truncated') is False,'LIVE_DOMAIN_XML_COMMAND_FAILED')
    need(start.get('rc')==0 and start.get('timeout') is False
         and start.get('truncated') is False,'ORIGINAL_VIRSH_START_UNCERTAIN')
    # Crucial: reuse the tenured F8 classification exactly, including F11 stages,
    # 29 authenticated probes and R34 semantic guard; no fabricated observations.
    result=core.classify(before,after,start,live['stdout'],ticket,grant,claims,legacy,f4,f6)
    need(result['guest_running'] is True and result['traffic_granted'] is False and
         result['service_protocol_verified'] is False and result['p8_operational']=='NO-GO',
         'CLASSIFICATION_SCOPE_CHANGED')
    return result

def validate_current(core, legacy, f4, f6, after):
    # Re-read physical state via preexisting audited 29-probe inventory;
    # reads only. sudo -n must be cached by the caller for privileged nft/hook.
    current=f6.capture()
    core.audited(current,ssh_running=True,legacy=legacy,f4=f4,f6=f6)
    a=after['snapshot']['probes']; b=current['snapshot']['probes']
    stable=([f'vm-{role}-{field}' for role in core.ROLES
             for field in ('inactive-xml','block')]
            + ['f11-hook-stat','f11-hook-hash','deny-nwfilter-xml'])
    for key in stable:
        need(a[key]['stdout']==b[key]['stdout'],'CURRENT_STATIC_DRIFT_'+key)
    for role in core.NETWORKS:
        key='net-'+role+'-xml'
        need(core._r112_f8_static_network_xml(a[key]['stdout'])==
             core._r112_f8_static_network_xml(b[key]['stdout']),
             'CURRENT_NETWORK_DRIFT_'+key)
    from ardrec.coordination import r112_runner_nic_definition as nic
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']),
         'CURRENT_R34_NFT_DRIFT')
    need(after['other_domains']==current['other_domains'],
         'CURRENT_UNRELATED_SCOPE_DRIFT')
    return core.sha(current)

def create_private_receipt(record):
    need(OUTPUT.parent.is_dir() and not OUTPUT.parent.is_symlink(),'PRIVATE_BASE_MISSING')
    if not OUTPUT.exists():
        OUTPUT.mkdir(mode=0o700)
    need(OUTPUT.is_dir() and not OUTPUT.is_symlink(),'RECEIPT_PARENT_INVALID')
    need((OUTPUT.stat().st_mode & 0o077)==0,'RECEIPT_PARENT_PERMISSIONS')
    directory=Path(tempfile.mkdtemp(prefix='reconcile-',dir=OUTPUT))
    os.chmod(directory,0o700)
    target=directory/'receipt.json'
    raw=(json.dumps(record,sort_keys=True,ensure_ascii=True,
                    separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        dirfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
    except BaseException:
        raise
    return str(target),digest(raw)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reconcile-existing-only',action='store_true',required=True)
    p.add_argument('--no-new-boot',action='store_true',required=True)
    a=p.parse_args()
    need(Path.cwd().resolve()==REPO,'MAIN_REPO_REQUIRED')
    rc,branch,_=command('git','branch','--show-current')
    need(rc==0 and branch==BRANCH,'BRANCH_MISMATCH')
    rc,head,_=command('git','rev-parse','HEAD')
    need(rc==0 and head==COMMIT,'HEAD_CHANGED')
    source=REPO/'src/ardrec/coordination/r112_f8_ssh_positive_boot.py'
    need(source.is_file() and not source.is_symlink() and digest(source.read_bytes())==EXPECTED_SOURCE_SHA,
         'F8_SOURCE_SHA_CHANGED')
    sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
    from ardrec.coordination import r112_f8_ssh_positive_boot as core
    import ardrec_p14_r111_legacy_host_snapshot as legacy
    import ardrec_p14_r112_f4_isolated_networks as f4
    import ardrec_p14_r112_f6_hook_lifecycle as f6
    original=read_original()
    classified=validate_historical(core,legacy,f4,f6,original)
    current_sha=validate_current(core,legacy,f4,f6,original['boot/after.json'])
    rec={
        'schema':'ardrec-r112-f8s-original-incident-reconciliation-v1',
        'source_commit':COMMIT,
        'source_original_plan':str(PLAN),
        'source_original_incident':str(BOOT),
        'source_file_sha256':EXPECTED,
        'original_outcome':'POSITIVE_BOOT_NOT_ATTESTED_PRESERVED',
        'reason_original':'STATIC_RESOURCE_CHANGED_net-ssh-xml',
        'reclassified_original_event':classified,
        'current_audited_snapshot_sha256':current_sha,
        'reconciliation_timestamp_utc_seconds':int(time.time()),
        'repeated_start':False,
        'host_mutations':False,
        'p8_operational':'NO-GO',
        'service_protocol_tested':False,
        'permit_traffic':False,
        'a5_dispatch':False,
        'f7_original_provenance_sha_present_not_independently_replayed':True,
        'requirement':'F8S_RECONCILED_BOOT_ONLY_NOT_R112_OR_P8_FINAL_ACCEPTANCE'
    }
    path,receipt_sha=create_private_receipt(rec)
    print('R112_F8S_HISTORICAL_CLASSIFY=PASS')
    print('R112_F8S_CURRENT_HOST_AUDIT=PASS')
    print('R112_F8S_RECONCILIATION=BOOT_ONLY_ATTESTED_FROM_ORIGINAL_RECORDS')
    print('R112_F8S_NEW_PRIVATE_RECEIPT='+path)
    print('R112_F8S_RECEIPT_SHA256='+receipt_sha)
    print('R112_F8S_ORIGINAL_FAILURE=UNCHANGED')
    print('R112_F8S_PHYSICAL_STARTS=0')
    print('R112_F8S_R34_TRAFFIC=NOT_AUTHORIZED')
    print('R112_F8S_P8=NO-GO')
    print('R112_F8S_A5_A6_A7_A9=NOT_ATTESTED')
    return 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (Stop,ValueError,OSError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
        print('R112_F8S=STOP_'+type(exc).__name__+':'+str(exc)[:160])
        print('R112_F8S_P8=NO-GO')
        print('R112_F8S_NO_RETRY_OR_HOST_MUTATION=TRUE')
        raise SystemExit(24)
