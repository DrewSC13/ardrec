"""R168-F5 — single FTP DENY boot with R168-F2 Runner predecessor, distinct signed one-start permits.

Physical commands are never invoked by inspection, plan replay or installer.
Actual boot requires F7 signed boot authority with fresh independent revocation,
F6 FTP-T01 signed scope, git-signed committed source, explicit operator CLI flag,
verified predecessor receipt and live R34/F11 pre/post audit.

All attempts are claimed durably before privileged writes. Uncertainty is a
non-retryable incident. This module does not authorize P8 or network traffic.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import argparse
import os
from pathlib import Path
import time

from ardrec.coordination import r167_f7d_controlled_boot as f7
from ardrec.coordination import r168_f5_ftp_release_gate as release_guard
from ardrec.coordination import r168_f2_runner_ftp_boot as prior_runner
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r112_f9_runner_boot as f9
from ardrec.coordination import r112_f10_targets_boot as f10

ROOT = Path('/home/cicada/ardrec-lab/r168-f5-ftp-deny-v1')
SCHEMA = 'ARDREC-R168-F5-FTP-DENY-v1'
ROLES = ('ftp',)
MAX_PLAN_AGE = 3600

class Stop(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise Stop(code)

def _write(path, value):
    f7._save(path, value)

def _load(path):
    return f7._load(path)

def _private(path):
    f2.private_parent(path)

def _receipt_dir(path, root, prefix):
    need(isinstance(path, Path) and path.is_absolute() and
         path.parent == root and path.name.startswith(prefix), 'RECEIPT_PATH_SCOPE')
    _private(root)
    _private(path)
    return path

def _new(prefix):
    return f7._create(ROOT, prefix)

def _claimed(role):
    need(role in ROLES, 'ROLE_NOT_ALLOWED')
    return ROOT / ('one-' + role + '.once')

def _no_attempt(role):
    claim = _claimed(role)
    need(not claim.exists() and not claim.is_symlink(), 'ROLE_ALREADY_ATTEMPTED')

def predecessor(role, plan_dir, boot_dir):
    """Revalidate immutable R168-F2 Runner receipt, never trust a JSON label."""
    need(role == 'ftp', 'FTP_ONLY_PREDECESSOR')
    _receipt_dir(plan_dir, prior_runner.ROOT, 'plan-')
    _receipt_dir(boot_dir, prior_runner.ROOT, 'boot-')
    receipt = prior_runner.replay(plan_dir, boot_dir)
    need(receipt['role'] == 'runner' and
         receipt['state'] == 'RUNNER_RUNNING_DENY_ATTESTED' and
         receipt['traffic_authorized'] is False and receipt['p8'] == 'NO-GO',
         'RUNNER_PREDECESSOR_NOT_ATTESTED')
    return {'role': 'runner', 'plan_dir': str(plan_dir),
            'boot_dir': str(boot_dir), 'receipt_sha256': f7.digest(receipt)}

def plan_spec(role, head, contract_raw, authorization_raw, pre, before_legacy,
              previous, now):
    need(role in ROLES, 'ROLE_NOT_ALLOWED')
    gate = f7.state_gate(pre, role)
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'BAD_HEAD')
    need(type(previous) is dict and
         set(previous) == {'role', 'plan_dir', 'boot_dir', 'receipt_sha256'} and
         previous['role'] == ('ssh' if role == 'runner' else 'runner') and
         f1.SHA.fullmatch(previous['receipt_sha256']), 'BAD_PREDECESSOR')
    return {
        'schema': SCHEMA + '-plan', 'role':role, 'guest':f7.guest(role),
        'head':head, 'command':list(f7.command(role)),
        'created_at':f2.iso(now),
        'expires_at':f2.iso(now+timedelta(seconds=MAX_PLAN_AGE)),
        'contract_sha256':f1.digest(contract_raw),
        'authorization_sha256':f1.digest(authorization_raw),
        'f5_snapshot_sha256':f1.digest(f1.canonical(pre)),
        'r112_snapshot_sha256':f1.digest(f1.canonical(before_legacy)),
        'f5_stage_gate':gate,
        'predecessor':previous,
        'traffic_authorized':False, 'a5':'NO-GO', 'a6':'ND', 'p8':'NO-GO',
    }

def verify_spec(plan, pre, legacy, previous, *, head, now):
    need(type(plan) is dict and set(plan)=={
         'schema','role','guest','head','command','created_at','expires_at',
         'contract_sha256','authorization_sha256','f5_snapshot_sha256',
         'r112_snapshot_sha256','f5_stage_gate','predecessor',
         'traffic_authorized','a5','a6','p8'}, 'PLAN_FIELDS')
    need(plan['schema']==SCHEMA+'-plan' and plan['role'] in ROLES and
         plan['head']==head and plan['guest']==f7.guest(plan['role']) and
         plan['command']==list(f7.command(plan['role'])) and
         plan['predecessor']==previous and
         plan['traffic_authorized'] is False and
         plan['a5']=='NO-GO' and plan['a6']=='ND' and plan['p8']=='NO-GO',
         'PLAN_SCOPE_CHANGED')
    first, last = f7._instant(plan['created_at']), f7._instant(plan['expires_at'])
    need(first <= now < last and 0 < (last-first).total_seconds() <= MAX_PLAN_AGE,
         'PLAN_EXPIRED_OR_FUTURE')
    need(plan['f5_snapshot_sha256']==f1.digest(f1.canonical(pre)) and
         plan['r112_snapshot_sha256']==f1.digest(f1.canonical(legacy)) and
         plan['f5_stage_gate']==f7.state_gate(pre, plan['role']),
         'PLAN_SNAPSHOT_CHANGED')
    return plan

def _legacy_proof(role, before, after, started, live, ticket, grant, claims):
    import ardrec_p14_r111_legacy_host_snapshot as legacy
    import ardrec_p14_r112_f4_isolated_networks as f4
    if role == 'runner':
        return f9.classify(before, after, started, live, ticket, grant, claims,
                           legacy=legacy, f4=f4)
    if role == 'ftp':
        return f10.classify(before, after, started, live, ticket, grant, claims,
                            role, legacy=legacy, f4=f4)
    raise Stop('BAD_CLASSIFIER_ROLE')

def _read_plan(path):
    _receipt_dir(path, ROOT, 'plan-')
    names = {'plan.json','pre-f5.json','pre-r112.json','manifest.json'}
    need({x.name for x in path.iterdir()} in (names, names|{'boot.once'}),
         'PLAN_FILES_CHANGED')
    m = _load(path/'manifest.json')
    need(type(m) is dict and set(m)=={'schema','sha256'} and
         m['schema']==SCHEMA+'-plan-manifest' and
         set(m['sha256'])==names-{'manifest.json'}, 'PLAN_MANIFEST_INVALID')
    for name, sha in m['sha256'].items():
        need(f1.digest(f7._read_large(path/name))==sha, 'PLAN_BYTES_CHANGED_'+name)
    return (_load(path/'plan.json'), _load(path/'pre-f5.json'),
            _load(path/'pre-r112.json'))

def _read_boot(folder):
    _receipt_dir(folder, ROOT, 'boot-')
    names = {'intent.json', 'ticket.json','before-f5.json','before-r112.json',
             'root-dir-command.json','root-lease-command.json','grant.json',
             'start-command.json','after-f5.json','after-r112.json',
             'live-xml-command.json','claims.json','r112-proof.json',
             'receipt.json'}
    need({x.name for x in folder.iterdir()} == names, 'BOOT_FILES_CHANGED')
    return {name:_load(folder/name) for name in names}

def replay(plan_dir, boot_dir):
    plan, pre, legacy = _read_plan(plan_dir)
    need(plan['role'] in ROLES, 'REPLAY_BAD_ROLE')
    prior=predecessor(plan['role'],Path(plan['predecessor']['plan_dir']),
                      Path(plan['predecessor']['boot_dir']))
    need(prior==plan['predecessor'], 'PREDECESSOR_RECEIPT_CHANGED')
    created=f7._instant(plan['created_at'])
    verify_spec(plan,pre,legacy,prior,head=plan['head'],
                now=created+timedelta(seconds=1))
    need(f2.private_read(_claimed(plan['role']))==b'ATTEMPTED\n',
         'MISSING_ROLE_CLAIM')
    need(f2.private_read(plan_dir/'boot.once')==b'ATTEMPTED\n',
         'MISSING_PLAN_CLAIM')
    docs = _read_boot(boot_dir)
    precheck = docs['before-f5.json']
    after = docs['after-f5.json']
    f7.state_gate(precheck, plan['role'])
    f7.state_gate(after, plan['role'], after=True)
    f7._audit_legacy(docs['before-r112.json'], plan['role'])
    f7._audit_legacy(docs['after-r112.json'], plan['role'], after=True)
    started=docs['start-command.json']
    need(started['argv']==list(f7.command(plan['role'])), 'BOOT_COMMAND_CHANGED')
    f7.ok(started, 'START_NOT_ATTESTED')
    xml=docs['live-xml-command.json']
    need(xml['argv']==['virsh','--readonly','-c','qemu:///system',
                        'dumpxml',f7.guest(plan['role'])], 'LIVE_XML_COMMAND_CHANGED')
    proof=_legacy_proof(plan['role'], docs['before-r112.json'],
                        docs['after-r112.json'],
                        {k:started[k] for k in ('rc','stdout','stderr','timeout','truncated')},
                        f7.ok(xml,'LIVE_XML_NOT_ATTESTED'),docs['ticket.json'],
                        docs['grant.json'],docs['claims.json'])
    need(docs['r112-proof.json']==proof, 'R112_PROOF_CHANGED')
    receipt=docs['receipt.json']
    intent=docs['intent.json']
    need(intent=={'schema':SCHEMA+'-intent', 'role':plan['role'],
                  'plan_sha256':f7.digest(plan),
                  'predecessor':plan['predecessor'],
                  'command':list(f7.command(plan['role'])),
                  'traffic_authorized':False, 'p8':'NO-GO'},
         'BOOT_INTENT_CHANGED')
    expected={'schema':SCHEMA+'-receipt', 'role':plan['role'],
              'state':plan['role'].upper()+'_RUNNING_DENY_ATTESTED',
              'plan_sha256':f7.digest(plan), 'intent_sha256':f7.digest(intent),
              'before_f5_sha256':f7.digest(precheck),
              'after_f5_sha256':f7.digest(after),
              'r112_proof_sha256':f7.digest(proof),
              'ticket_sha256':f7.digest(docs['ticket.json']),
              'predecessor_sha256':plan['predecessor']['receipt_sha256'],
              'vm_starts':1, 'traffic_authorized':False,
              'a5':'NO-GO','a6':'ND','p8':'NO-GO'}
    need(receipt==expected, 'BOOT_RECEIPT_CHANGED')
    need(plan['r112_snapshot_sha256']==f7.digest(legacy) and
         plan['f5_snapshot_sha256']==f7.digest(pre), 'PLAN_PROVENANCE_CHANGED')
    return receipt

def _check_sources():
    head=f7.git_guard(for_boot=True)
    for name in ('src/ardrec/coordination/r168_f5_ftp_boot.py',):
        need(f7._run(('git','ls-files','--error-unmatch',name))['rc']==0,
             'F8_SOURCE_NOT_COMMITTED_'+name)
        need(f7._run(('git','diff','--quiet','HEAD','--',name))['rc']==0,
             'F8_SOURCE_DRIFT_'+name)
    return head

def plan(role, contract_path, auth_path, prior_plan, prior_boot, *, clock=f7.utcnow):
    need(role in ROLES,'ROLE_NOT_ALLOWED')
    head=_check_sources()
    now=clock()
    contract, auth = f2.private_read(contract_path), f2.private_read(auth_path)
    f7.scope_required(contract, auth, now=now)
    previous=predecessor(role,prior_plan,prior_boot)
    snap=f5.capture(clock=clock)
    f7.state_gate(snap,role)
    old=f7._capture_legacy()
    f7._audit_legacy(old,role)
    f7._no_markers(role)
    _no_attempt(role)
    spec=plan_spec(role,head,contract,auth,snap,old,previous,now)
    root=_new('plan-')
    records={'plan.json':spec,'pre-f5.json':snap,'pre-r112.json':old}
    for name,data in records.items(): _write(root/name,data)
    _write(root/'manifest.json',{'schema':SCHEMA+'-plan-manifest',
            'sha256':{name:f7.digest(value) for name,value in records.items()}})
    return root,spec

def boot(plan_dir,contract_path,auth_path,permit_path,*,clock=f7.utcnow):
    head=_check_sources()
    now=clock()
    spec,before,legacy_before=_read_plan(plan_dir)
    release_guard.require(spec,now=now)
    role=spec['role']
    need(role in ROLES,'ROLE_NOT_ALLOWED')
    previous=predecessor(role,Path(spec['predecessor']['plan_dir']),
                         Path(spec['predecessor']['boot_dir']))
    verify_spec(spec,before,legacy_before,previous,head=head,now=now)
    contract, auth, permit = (f2.private_read(x) for x in
                              (contract_path,auth_path,permit_path))
    f7.scope_required(contract,auth,now=now)
    reviewed=f7.signed_boot_permit(spec,contract,auth,permit,now=now)
    _no_attempt(role)
    need(not (plan_dir/'boot.once').exists(), 'PLAN_ALREADY_ATTEMPTED')
    fresh=f5.capture(clock=clock)
    f7.state_gate(fresh,role)
    fresh_legacy=f7._capture_legacy()
    f7._audit_legacy(fresh_legacy,role)
    import ardrec_p14_r111_legacy_host_snapshot as legacy
    import ardrec_p14_r112_f4_isolated_networks as f4
    if role=='runner':
        import ardrec_p14_r112_f6_hook_lifecycle as original_f6
        f7.f12.boundary(legacy_before,fresh_legacy,'runner',legacy,f4,original_f6)
    else:
        f10.audited(legacy_before,'ftp',after=False,legacy=legacy,f4=f4)
        f10.audited(fresh_legacy,'ftp',after=False,legacy=legacy,f4=f4)
    f7._no_markers(role)
    previous=predecessor(role,Path(spec['predecessor']['plan_dir']),
                         Path(spec['predecessor']['boot_dir']))
    need(previous==spec['predecessor'], 'PREDECESSOR_CHANGED')
    f7.scope_required(contract,auth,now=clock())
    reviewed=f7.signed_boot_permit(spec,contract,auth,permit,now=clock())
    need(clock()<f7._instant(reviewed['valid_until']), 'BOOT_PERMIT_EXPIRED')
    release_guard.require(spec,now=clock())

    attempt=_new('boot-')
    intent={'schema':SCHEMA+'-intent', 'role':role,
            'plan_sha256':f7.digest(spec), 'predecessor':previous,
            'command':list(f7.command(role)), 'traffic_authorized':False, 'p8':'NO-GO'}
    _write(attempt/'intent.json',intent)
    _write(attempt/'before-f5.json',fresh)
    _write(attempt/'before-r112.json',fresh_legacy)
    # Atomically consume BOTH role and plan before first root command.
    # If either write fails, STOP; never retry. No destructive cleanup.
    f2.exclusive(_claimed(role),b'ATTEMPTED\n')
    f2.exclusive(plan_dir/'boot.once',b'ATTEMPTED\n')
    ticket=f7._ticket(role)
    _write(attempt/'ticket.json',ticket)
    lease,markers,lease_root=f7._lease(role)
    try:
        def run(argv,timeout=20):return f7._run(argv,timeout=timeout)
        x=run(('sudo','-n','install','-d','-o','root','-g','root','-m','0700',lease_root))
        _write(attempt/'root-dir-command.json',x)
        f7.ok(x,'ROOT_LEASE_DIR_UNCERTAIN')
        x=run(('sudo','-n','install','-o','root','-g','root','-m','0600',
               str(attempt/'ticket.json'),lease))
        _write(attempt/'root-lease-command.json',x)
        f7.ok(x,'ROOT_LEASE_WRITE_UNCERTAIN')
        grant={'directory_stat':f7.ok(run(('sudo','-n','stat','-Lc','%u:%g %a %n',lease_root)),
                  'ROOT_DIR_STAT'),
               'lease_stat':f7.ok(run(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',lease)),
                  'ROOT_LEASE_STAT'),
               'lease_sha256':f7.ok(run(('sudo','-n','sha256sum',lease)),
                  'ROOT_LEASE_SHA').split()[0]}
        need(grant['lease_sha256']==f1.digest(f1.canonical(ticket)), 'LEASE_DIGEST_CHANGED')
        _write(attempt/'grant.json',grant)
        f7.scope_required(contract,auth,now=clock())
        reviewed=f7.signed_boot_permit(spec,contract,auth,permit,now=clock())
        need(clock()<f7._instant(reviewed['valid_until']) and
             int(time.time())<ticket['expires_at']-30,
             'BOOT_LEASE_OR_PERMIT_EXPIRED')
        release_guard.require(spec,now=clock())
        started=run(f7.command(role),timeout=90)
        _write(attempt/'start-command.json',started)
        f7.ok(started,'START_UNCERTAIN_NO_RETRY')
        after=f5.capture(clock=clock)
        f7.state_gate(after,role,after=True)
        _write(attempt/'after-f5.json',after)
        after_legacy=f7._capture_legacy()
        f7._audit_legacy(after_legacy,role,after=True)
        _write(attempt/'after-r112.json',after_legacy)
        live=run(('virsh','--readonly','-c','qemu:///system','dumpxml',f7.guest(role)))
        _write(attempt/'live-xml-command.json',live)
        xml=f7.ok(live,'LIVE_XML_UNREADABLE')
        claims={}
        for kind,path in markers.items():
            text=f7.ok(run(('sudo','-n','cat',path)),'F11_MARKER_READ_'+kind)+'\n'
            st=f7.ok(run(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path)),
                    'F11_MARKER_STAT_'+kind)
            claims[kind]={'content':text,'stat':st}
        _write(attempt/'claims.json',claims)
        proof=_legacy_proof(role,fresh_legacy,after_legacy,
                   {k:started[k] for k in ('rc','stdout','stderr','timeout','truncated')},
                   xml,ticket,grant,claims)
        _write(attempt/'r112-proof.json',proof)
        rec={'schema':SCHEMA+'-receipt','role':role,
             'state':role.upper()+'_RUNNING_DENY_ATTESTED',
             'plan_sha256':f7.digest(spec),'intent_sha256':f7.digest(intent),
             'before_f5_sha256':f7.digest(fresh),'after_f5_sha256':f7.digest(after),
             'r112_proof_sha256':f7.digest(proof),
             'ticket_sha256':f7.digest(ticket),
             'predecessor_sha256':previous['receipt_sha256'],
             'vm_starts':1,'traffic_authorized':False,
             'a5':'NO-GO','a6':'ND','p8':'NO-GO'}
        _write(attempt/'receipt.json',rec)
        return attempt,rec
    except (Exception,) as exc:
        # The root/plan claim remains, with no retry and no cleanup. Do not
        # catch SystemExit/KeyboardInterrupt to fabricate a successful receipt.
        _write(attempt/'incident.json',{'schema':SCHEMA+'-incident',
            'reason':type(exc).__name__+':'+str(exc)[:160],
            'retry_permitted':False,'automatic_cleanup':False,'p8':'NO-GO'})
        raise Stop('ATTEMPT_FAILED_OR_UNCERTAIN_RECEIPT_'+str(attempt)) from exc

def inspect(role='runner'):
    need(role in ROLES,'ROLE_NOT_ALLOWED')
    capture=f5.capture()
    report=f5.report(capture)
    try:
        state=f7.state_gate(capture,role)
        status='DENY_STAGE_READY_NO_BOOT_AUTHORITY'
        reason='BOOT_SCOPE_AND_PERMIT_NOT_EVALUATED'
    except (f7.Stop, f5.Stop) as exc:
        state=None
        status='NO-GO'
        reason=str(exc)
    return {'schema':SCHEMA+'-inspection','role':role,'status':status,
            'reason':reason,'state':state,'f5':report,
            'traffic_authorized':False,'a5':'NO-GO','a6':'ND','p8':'NO-GO'}

def main(argv=None):
    parser=argparse.ArgumentParser(description='R117-F4 runner+FTP one-start DENY-only')
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--inspect',action='store_true')
    group.add_argument('--plan',action='store_true')
    group.add_argument('--boot',action='store_true')
    group.add_argument('--replay',action='store_true')
    parser.add_argument('--role',choices=ROLES,default='ftp')
    parser.add_argument('--contract',type=Path)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--permit',type=Path)
    parser.add_argument('--prior-plan',type=Path)
    parser.add_argument('--prior-boot',type=Path)
    parser.add_argument('--plan-dir',type=Path)
    parser.add_argument('--boot-dir',type=Path)
    parser.add_argument('--i-authorize-one-physical-deny-boot',action='store_true')
    args=parser.parse_args(argv)
    try:
        need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
        if args.inspect:
            need(not any((args.contract,args.authorization,args.permit,args.plan_dir,
                          args.boot_dir,args.prior_plan,args.prior_boot)) and
                 not args.i_authorize_one_physical_deny_boot, 'INSPECT_ARG_SCOPE')
            out=inspect(args.role)
            folder=_new('inspect-')
            _write(folder/'report.json',out)
            print('R168_F5_CHAIN_INSPECT_RECEIPT='+str(folder))
            print('R168_F5_CHAIN_ROLE='+args.role.upper())
            print('R168_F5_CHAIN_STAGE='+out['status'])
            print('R168_F5_CHAIN_REASON='+out['reason'])
        elif args.plan:
            need(args.contract and args.authorization and args.prior_plan and
                 args.prior_boot and not args.permit and not args.plan_dir and
                 not args.boot_dir and not args.i_authorize_one_physical_deny_boot,
                 'PLAN_REQUIRES_SIGNED_SCOPE_AND_PREDECESSOR')
            folder,obj=plan(args.role,args.contract,args.authorization,
                            args.prior_plan,args.prior_boot)
            print('R168_F5_CHAIN_PLAN='+str(folder))
            print('R168_F5_CHAIN_PLAN_SHA256='+f7.digest(obj))
        elif args.boot:
            need(args.contract and args.authorization and args.permit and
                 args.plan_dir and not args.prior_plan and not args.prior_boot and
                 not args.boot_dir and args.i_authorize_one_physical_deny_boot,
                 'BOOT_REQUIRES_FRESH_SIGNED_PERMIT_AND_EXPLICIT_CONSENT')
            folder,receipt=boot(args.plan_dir,args.contract,args.authorization,args.permit)
            print('R168_F5_CHAIN_BOOT_RECEIPT='+str(folder))
            print('R168_F5_CHAIN_BOOT_SHA256='+f7.digest(receipt))
            print('R168_F5_CHAIN_VM_STARTS=ONE_ATTESTED')
        else:
            need(args.plan_dir and args.boot_dir and not any((args.contract,
                 args.authorization,args.permit,args.prior_plan,args.prior_boot)) and
                 not args.i_authorize_one_physical_deny_boot,
                 'REPLAY_REQUIRES_RECEIPTS_ONLY')
            r=replay(args.plan_dir,args.boot_dir)
            print('R168_F5_CHAIN_REPLAY=PASS')
            print('R168_F5_CHAIN_ROLE='+r['role'].upper())
            print('R168_F5_CHAIN_RECEIPT_SHA256='+f7.digest(r))
        print('R168_F5_CHAIN_TRAFFIC=0')
        print('R168_F5_CHAIN_A5=NO-GO')
        print('R168_F5_CHAIN_A6=ND')
        print('R168_F5_CHAIN_P8=NO-GO')
        return 0
    except (Stop,f7.Stop,f5.Stop,f2.Stop,f1.Rejected,OSError,ValueError,KeyError,TypeError) as exc:
        print('R168_F5_CHAIN_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R168_F5_CHAIN_ACTION=NO_AUTO_RETRY_NO_AUTO_CLEANUP')
        print('R168_F5_CHAIN_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
