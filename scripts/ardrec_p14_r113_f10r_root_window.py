#!/usr/bin/env python3
"""One-shot F10R root transaction for ARDREC isolated lab. No arbitrary commands/targets.

F6 is always executed BEFORE/AFTER window; independent systemd timer is armed
before changing any binding; nft candidate is applied LAST. Partial executions
are never retried or auto-cleaned. Root-owned immutable inputs only.
"""
from __future__ import annotations
import argparse, base64, fcntl, hashlib, json, os, re, secrets, stat
import subprocess, sys, time, xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path('/var/lib/ardrec/r113-f10r-window-v1')
sys.dont_write_bytecode=True
sys.path.insert(0, str(ROOT))
import contract as c
import semantic as semantic
F6 = str(c.F6_ROOT)
VIRSH = ['/usr/bin/virsh','-c','qemu:///system']
SYSENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
BUNDLE_FILES={'manifest.json','root-window.py','contract.py','semantic.py','policy-manifest.json','f9r-report.json'} | set(c.NAMES)


def secure_file(p, *, root=True):
    st=p.lstat()
    c.need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
           not p.is_symlink() and (not root or st.st_uid==0) and
           stat.S_IMODE(st.st_mode)==0o600 and 0<=st.st_size<250000,
           'UNSAFE_FILE_'+p.name)
    return p.read_bytes()

def save(folder,name,raw):
    c.need('/' not in name and name and len(raw)<300000,'UNSAFE_RECEIPT')
    fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def secure_bundle():
    c.need(os.geteuid()==0 and Path(__file__).resolve()==ROOT/'root-window.py','ROOT_STAGED_REQUIRED')
    st=ROOT.lstat()
    c.need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
           stat.S_IMODE(st.st_mode)==0o700,'ROOT_DIR_UNSAFE')
    c.need({p.name for p in ROOT.iterdir() if p.is_file()}<=BUNDLE_FILES|{'filters-installed.once','window-attempted.once'} and
           BUNDLE_FILES <= {p.name for p in ROOT.iterdir() if p.is_file()},'ROOT_FILE_SCOPE')
    raw={name:secure_file(ROOT/name) for name in BUNDLE_FILES}
    manifest=json.loads(raw['manifest.json'])
    c.need(manifest['schema']=='ARDREC-R113-F10R-ROOT-BUNDLE-v1' and
           manifest['policy_host_pass_hash']==c.F9R_HASH and
           set(manifest['sha256'])==BUNDLE_FILES-{'manifest.json'},'ROOT_MANIFEST_INVALID')
    for name in BUNDLE_FILES-{'manifest.json'}:
        c.need(manifest['sha256'][name]==c.sha(raw[name]),'ROOT_HASH_'+name)
    c.need(raw['root-window.py']==Path(__file__).read_bytes(),'ROOT_EXEC_CHANGED')
    md=json.loads(raw['policy-manifest.json'])
    c.need(md['schema']=='ARDREC-R113-F8R-CORRECTED-ARP-OFFLINE-v1' and
           md['safety']=={'policy_installed':False,'traffic_admitted':False,'p8':'NO-GO'} and
           set(md['sha256'])==set(c.NAMES), 'POLICY_MANIFEST_INVALID')
    doc=c.validate_f9r(raw['f9r-report.json'],raw['policy-manifest.json'])
    for name in c.NAMES:
        c.need(md['sha256'][name]==c.sha(raw[name]) and
               doc['candidate_files_sha256'][name]==c.sha(raw[name]),'F9R_FILE_LINK_INVALID_'+name)
    return raw

def run(label,argv,folder,*,stdin=None,timeout=12,ok=True):
    c.need(re.fullmatch('[a-z0-9_-]+',label) is not None,'LABEL_INVALID')
    c.need(all(isinstance(x,str) for x in argv),'ARGV_INVALID')
    try:
        p=subprocess.run(argv,input=stdin,stdin=subprocess.DEVNULL if stdin is None else None,
                         capture_output=True,timeout=timeout,env=SYSENV,check=False,
                         close_fds=True)
        rc,out,err=p.returncode,p.stdout,p.stderr
    except (OSError,subprocess.TimeoutExpired) as exc:
        rc=124 if isinstance(exc,subprocess.TimeoutExpired) else 127
        out=(exc.stdout or b'') if isinstance(exc,subprocess.TimeoutExpired) else b''
        err=(type(exc).__name__+':'+str(exc)).encode()[:4000]
    c.need(len(out)<200000 and len(err)<20000,'COMMAND_OUTPUT_LIMIT_'+label)
    save(folder,label+'.stdout',out);save(folder,label+'.stderr',err)
    print('F10_'+label.upper()+'_RC='+str(rc),flush=True)
    if ok:c.need(rc==0,'COMMAND_FAILED_'+label)
    return out,rc

def f6(label,flag,folder):
    c.need(flag in ('--check-root-bundle','--attest-deny','--restore-deny'),'F6_FLAG_INVALID')
    raw,_=run(label,['/usr/bin/python3',F6,flag],folder,timeout=35)
    result=json.loads(raw)
    expected={'--check-root-bundle':'ROOT_BUNDLE_VERIFIED',
              '--attest-deny':'SIX_BINDING_DENY_ATTESTED',
              '--restore-deny':'SIX_BINDING_DENY_RESTORED'}[flag]
    c.need(result.get('result')==expected and result.get('bindings')==6 and
           result.get('p8')=='NO-GO','F6_RESULT_INVALID_'+label)
    return result

def same_filter(live,expected):
    """Only root chain="root" and generated UUID are normalized."""
    expected_doc = ET.fromstring(expected)
    return semantic.semantically_identical(expected,live,
                         expected_name=expected_doc.attrib['name'])

def invariant_f11_and_watchdog(folder):
    h,_=run('f11_sha',['/usr/bin/sha256sum','/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny'],folder)
    c.need(h.decode().split()[0]=='1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b',
           'F11_HOOK_CHANGED')
    timer,_=run('r34_systemd_watchdog',['/usr/bin/systemctl','show','ardrec-r34-deny-watchdog.timer',
                 '--no-pager','-p','LoadState','-p','ActiveState'],folder)
    c.need(b'LoadState=loaded' in timer and b'ActiveState=active' in timer,
           'R34_INDEPENDENT_WATCHDOG_INACTIVE')

def filters_ready(folder,raw):
    for role in c.ROLES:
        xmlname=c.name(role)+'.xml'
        data,_=run('filter_check_'+role.replace('-','_'),VIRSH+['nwfilter-dumpxml',c.name(role)],folder)
        c.need(same_filter(data,raw[xmlname]),'FILTER_DEFINITION_DRIFT_'+role)

def receipt(folder,status):
    docs={p.name:c.sha(secure_file(p)) for p in folder.iterdir() if p.is_file() and p.name!='receipt.json'}
    r={'schema':'ARDREC-R113-F10R-ROOT-EVENT-v1','status':status,
       'files':docs,'traffic_scope':'THREE_FIXED_PRIVATE_TCP_PORTS',
       'p8':'NO-GO'}
    save(folder,'receipt.json',c.canonical(r))
    print('R113_F10_RECEIPT='+str(folder),flush=True)
    print('R113_F10_MANIFEST_SHA256='+c.sha(secure_file(folder/'receipt.json')),flush=True)

def session(prefix):
    name=prefix+'-'+secrets.token_hex(4)
    folder=ROOT/name
    folder.mkdir(mode=0o700)
    return folder

def adopt_filters(raw):
    """Read-only adoption of the six filters already defined by original F10.

    F10's prior one-shot marker is NEVER replayed. No define/redefine occurs.
    """
    c.need(not (ROOT/'filters-installed.once').exists(), 'FILTER_ADOPTION_ALREADY_ATTEMPTED')
    folder=session('filters')
    try:
        f6('f6_bundle','--check-root-bundle',folder)
        f6('f6_before','--attest-deny',folder)
        invariant_f11_and_watchdog(folder)
        # Check all six existing filters before declaring any readiness.
        filters_ready(folder,raw)
        f6('f6_after','--attest-deny',folder)
        receipt(folder,'FILTER_DEFINITIONS_VALIDATED_BINDINGS_DENY')
        save(ROOT,'filters-installed.once',b'R113_F10R_SIX_EXISTING_FILTERS_READONLY_ADOPTED\n')
        print('R113_F10R_FILTERS=PASS_ADOPTED_EXISTING_NO_DEFINES',flush=True)
        print('R113_F10R_TRAFFIC=NOT_AUTHORIZED',flush=True)
        return 0
    except Exception as exc:
        print('R113_F10R_ADOPTION_STOP='+type(exc).__name__+':'+str(exc)[:160],flush=True)
        print('R113_F10R_NO_AUTORETRY=TRUE',flush=True)
        return 23

def qga(folder):
    guest='ardrec-r33-dev-runner'
    src=c.probe_source()
    def agent_call(label,command,*,timeout=12):
        payload=json.dumps(command,sort_keys=True,separators=(',',':'))
        raw,_=run(label,VIRSH+['qemu-agent-command',guest,payload],folder,timeout=timeout)
        reply=json.loads(raw)
        c.need('return' in reply and 'error' not in reply,'QGA_REJECTED_'+label)
        return reply['return']
    started=agent_call('qga_start',{'execute':'guest-exec','arguments':{
        'path':'/usr/bin/python3','arg':['-c',src],'capture-output':True}})
    c.need(type(started.get('pid')) is int and started['pid']>0,'QGA_PID_INVALID')
    end=time.monotonic()+18
    i=0
    while time.monotonic()<end:
        time.sleep(0.6)
        i+=1
        state=agent_call('qga_status_'+str(i),{'execute':'guest-exec-status','arguments':{'pid':started['pid']}},timeout=6)
        if state.get('exited'):
            c.need(state.get('exitcode')==0,'RUNNER_GUEST_PROBE_FAILED')
            out=base64.b64decode(state.get('out-data',''),validate=True)
            err=base64.b64decode(state.get('err-data',''),validate=True)
            c.need(not err and len(out)<16000,'PROBE_OUTPUT_OR_STDERR_INVALID')
            save(folder,'runner-probe-stdout.json',out)
            doc=c.validate_probe(out)
            print('R113_F10_REAL_RESULTS='+json.dumps(doc['results'],sort_keys=True),flush=True)
            return doc
    raise c.Stop('QGA_STATUS_DEADLINE_NO_RETRY')

def window(raw):
    c.need((ROOT/'filters-installed.once').is_file(),'FILTER_INSTALL_NOT_ATTESTED')
    c.need(not (ROOT/'window-attempted.once').exists(),'WINDOW_ALREADY_ATTEMPTED')
    folder=session('window')
    opened=False
    final_ok=False
    armed=False
    try:
        f6('f6_bundle','--check-root-bundle',folder)
        f6('f6_before','--attest-deny',folder)
        invariant_f11_and_watchdog(folder)
        filters_ready(folder,raw)
        for role in ('ssh','runner','ftp','smb'):
            raw_state,_=run('vm_'+role,VIRSH+['domstate','ardrec-r33-dev-'+role],folder)
            c.need(raw_state.decode().strip() in ('running','ejecutando'),'GUEST_NOT_RUNNING_'+role)
        # Verify the runner QGA is operational before arming or opening traffic.
        agent,_=run('runner_guest_info',VIRSH+['qemu-agent-command',
            'ardrec-r33-dev-runner', '{"execute":"guest-info"}'],folder)
        c.need('return' in json.loads(agent),'RUNNER_QGA_MISSING')
        # Distinct systemd timer and service. No root shell or user-owned helper.
        token=secrets.token_hex(6)
        stem='ardrec-r113-f10r-deny-'+token
        save(folder,'timer-intent.json',c.canonical({'stem':stem,'duration':c.DURATION,
                      'recovery':F6,'traffic_authorized':False,'p8':'NO-GO'}))
        save(ROOT,'window-attempted.once',b'R113_F10_ONE_WINDOW_ATTEMPTED\n')
        run('timer_arm',['/usr/bin/systemd-run','--system','--unit='+stem,
            '--on-active='+str(c.DURATION)+'s','--timer-property=AccuracySec=1s',
            '--description=ARDREC F10 autonomous six-binding DENY restore',
            '/usr/bin/python3',F6,'--restore-deny'],folder,timeout=15)
        timer,_=run('timer_active',['/usr/bin/systemctl','show',stem+'.timer','--no-pager',
            '-p','LoadState','-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic'],folder)
        props=dict(x.split('=',1) for x in timer.decode().splitlines() if '=' in x)
        c.need(props.get('LoadState')=='loaded' and props.get('ActiveState')=='active' and
               props.get('Unit')==stem+'.service' and
               props.get('NextElapseUSecMonotonic') not in ('0','','infinity'),
               'INDEPENDENT_TIMER_NOT_ARMED')
        armed=True
        start=time.monotonic()
        save(folder,'binding-swap-started.once',b'SIX_BINDING_SWITCH_ATTEMPTED\n')
        # R34 remains in DENY for the entire multi-binding transition.
        for role,row in c.ROWS.items():
            c.need(time.monotonic()-start < c.OPEN_DEADLINE,'TRANSITION_DEADLINE')
            tap=row[2]
            run('delete_'+role.replace('-','_'),VIRSH+['nwfilter-binding-delete',tap],folder,timeout=8)
            run('create_'+role.replace('-','_'),VIRSH+['nwfilter-binding-create',
                '/var/lib/ardrec/r113-six-deny-guard-v1/'+role.replace('-','_')+'-candidate.xml'],folder,timeout=8)
            xml,_=run('binding_check_'+role.replace('-','_'),VIRSH+['nwfilter-binding-dumpxml',tap],folder)
            c.need('filter="'+c.name(role)+'"' in xml.decode() or
                   "filter='"+c.name(role)+"'" in xml.decode(), 'CANDIDATE_BINDING_MISSING_'+role)
        c.need(time.monotonic()-start < c.OPEN_DEADLINE,'WINDOW_NOT_OPENED_TIMER_MARGIN')
        timer,_=run('timer_last_check',['/usr/bin/systemctl','show',stem+'.timer','--no-pager',
            '-p','ActiveState'],folder)
        c.need(b'ActiveState=active' in timer,'TIMER_DISARMED_BEFORE_OPEN')
        # LAST opening operation: exact F8R candidate table. No global flush.
        run('nft_open',['/usr/sbin/nft','-f','-'],folder,stdin=raw['r34-window-CANDIDATE.nft'],timeout=10)
        opened=True
        save(folder,'traffic-window-open.once',b'R113_F10_NFT_SCOPED_ADMISSION_ATTEMPTED\n')
        live,_=run('nft_live_check',['/usr/sbin/nft','-j','-a','list','table',
                       'bridge','ardrec_r34_guard'],folder)
        nftdoc=json.loads(live)
        rows=nftdoc.get('nftables',[])
        rules=[x['rule'] for x in rows if 'rule' in x]
        c.need(len(rules)==16 and
               sum(1 for x in rules if any('accept' in e for e in x['expr']))==12 and
               sum(1 for x in rules if any('drop' in e for e in x['expr']))==4,
               'LIVE_NFT_POLICY_UNEXPECTED')
        qga(folder)
    except Exception as exc:
        print('R113_F10_WINDOW_STOP='+type(exc).__name__+':'+str(exc)[:180],flush=True)
        print('R113_F10_NO_AUTORETRY=TRUE',flush=True)
    finally:
        # ALWAYS restore: the independent timer is additional defense.
        try:
            f6('f6_restore_final','--restore-deny',folder)
            f6('f6_attest_final','--attest-deny',folder)
            final_ok=True
        except Exception as exc:
            print('R113_F10_CRITICAL_FINAL_DENY_UNKNOWN='+type(exc).__name__+':'+str(exc)[:180],flush=True)
            print('R113_F10_TIMER_BACKUP_ARMED='+str(armed).upper(),flush=True)
        status=('CLOSED_DENY_WITH_REAL_PROBES' if opened and (folder/'runner-probe-stdout.json').exists() and final_ok
                else 'PARTIAL_OR_BLOCKED_CLOSED_DENY' if final_ok else 'CRITICAL_DENY_UNVERIFIED')
        try:receipt(folder,status)
        except Exception as ex:print('R113_F10_RECEIPT_INCOMPLETE='+str(ex)[:100],flush=True)
    print('R113_F10_FINAL_DENY='+('PASS_SIX_BINDINGS' if final_ok else 'NOT_ATTESTED'),flush=True)
    print('R113_F10_WATCHDOG_ARMED='+str(armed).upper(),flush=True)
    print('R113_F10_P8=NO-GO',flush=True)
    return 0 if status=='CLOSED_DENY_WITH_REAL_PROBES' else 23

def replay(folder):
    c.need(folder.parent==ROOT and folder.name.startswith(('filters-','window-')) and
           folder.is_dir() and not folder.is_symlink(),'REPLAY_FOLDER_INVALID')
    doc=json.loads(secure_file(folder/'receipt.json'))
    c.need(doc.get('schema')=='ARDREC-R113-F10R-ROOT-EVENT-v1' and doc['p8']=='NO-GO' and
           doc.get('status') in ('FILTER_DEFINITIONS_VALIDATED_BINDINGS_DENY','CLOSED_DENY_WITH_REAL_PROBES','PARTIAL_OR_BLOCKED_CLOSED_DENY','CRITICAL_DENY_UNVERIFIED'), 'REPLAY_SCHEMA')
    c.need(set(doc['files'])=={p.name for p in folder.iterdir() if p.name!='receipt.json'}, 'REPLAY_FILES')
    for name,digest in doc['files'].items():
        c.need(c.sha(secure_file(folder/name))==digest,'REPLAY_CHANGED_'+name)
    if doc['status']=='CLOSED_DENY_WITH_REAL_PROBES':
        observed=secure_file(folder/'runner-probe-stdout.json')
        c.validate_probe(observed)
        statuses=sorted((name for name in doc['files'] if re.fullmatch(r'qga_status_[1-9][0-9]*\.stdout',name)),
                        key=lambda name:int(name.removeprefix('qga_status_').removesuffix('.stdout')))
        c.need(statuses,'QGA_EVIDENCE_MISSING')
        completed=json.loads(secure_file(folder/statuses[-1]))['return']
        c.need(completed.get('exited') is True and completed.get('exitcode')==0 and
               base64.b64decode(completed.get('out-data',''),validate=True)==observed,
               'QGA_RAW_EVIDENCE_MISMATCH')
    if doc['status']=='FILTER_DEFINITIONS_VALIDATED_BINDINGS_DENY':
        evidence=json.loads(secure_file(folder/'f6_after.stdout'))
        c.need(evidence.get('result')=='SIX_BINDING_DENY_ATTESTED','FILTERS_DENY_EVIDENCE_INVALID')
    else:
        c.need('f6_attest_final.stdout' in doc['files'],'MISSING_FINAL_DENY')
        if 'f6_attest_final.stdout' in doc['files']:
            evidence=json.loads(secure_file(folder/'f6_attest_final.stdout'))
            c.need(evidence.get('result')=='SIX_BINDING_DENY_ATTESTED','FINAL_DENY_EVIDENCE_INVALID')
    print('R113_F10_ROOT_REPLAY=PASS_RECEIPT_INTEGRITY',flush=True)
    print('R113_F10_SOURCE_OUTCOME='+doc['status'],flush=True)
    print('R113_F10_P8=NO-GO',flush=True)
    return 0

def main():
    ap=argparse.ArgumentParser(); group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--check',action='store_true');group.add_argument('--adopt-filters',action='store_true')
    group.add_argument('--window',action='store_true');group.add_argument('--replay',type=Path)
    args=ap.parse_args()
    try:
        raw=secure_bundle()
        if args.check: print('R113_F10R_ROOT_BUNDLE=VERIFIED');return 0
        if args.adopt_filters:return adopt_filters(raw)
        if args.window:return window(raw)
        return replay(args.replay)
    except Exception as exc:
        print('R113_F10_ROOT_STOP='+type(exc).__name__+':'+str(exc)[:180],flush=True)
        print('R113_F10_NO_AUTORETRY=TRUE',flush=True)
        print('R113_F10_P8=NO-GO',flush=True)
        return 23
if __name__=='__main__':raise SystemExit(main())
