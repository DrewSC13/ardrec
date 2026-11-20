"""R115-F4: opt-in host DENY readbacks, not an operational A3 grant.

Reuse the previously staged R113-F6 --attest-deny read-only mode. The only
privileged invocations are pinned sha256sum and this existing root helper.
"""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r113_f6_six_binding_guard as six

SCHEMA='ARDREC-R115-F4-READONLY-ROOT-DENY-v1'
ROOT=Path('/home/cicada/ardrec-lab/r115-f4-readonly-deny-v1')
HELPER=Path('/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py')
HELPER_SHA='3a9c2d0e70d7b6b808ee2eaf7382b11715c2e2d8e0f777ff627a1ed084a8bb05'
COMMANDS={
 'helper_sha':('/usr/bin/sudo','-n','--','/usr/bin/sha256sum',str(HELPER)),
 'hook_sha':('/usr/bin/sudo','-n','--','/usr/bin/sha256sum',str(f3.HOOK)),
 'deny_attest':('/usr/bin/sudo','-n','--','/usr/bin/python3',str(HELPER),'--attest-deny'),
}
LIMIT=32768

class Stop(ValueError): pass

def need(value,reason):
    if not value: raise Stop(reason)

def digest(data):return hashlib.sha256(data).hexdigest()

def capture_probe(name,runner=subprocess.run,clock=f2.utcnow):
    need(name in COMMANDS,'COMMAND_NOT_ALLOWLISTED')
    a=clock()
    try:
        p=runner(list(COMMANDS[name]),stdin=subprocess.DEVNULL,
                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,
                 shell=False,timeout=45,
                 env={'LC_ALL':'C','LANG':'C','PATH':'/usr/sbin:/usr/bin:/bin'})
        out,err,rc,timed=p.stdout,p.stderr,p.returncode,False
    except subprocess.TimeoutExpired as exc:
        out,err,rc,timed=exc.stdout or b'',exc.stderr or b'',None,True
    except (OSError,ValueError):
        out,err,rc,timed=b'',b'',None,False
    need(type(out) is bytes and type(err) is bytes,'OUTPUT_NOT_BYTES')
    b=clock()
    return {'rc':rc,'timeout':timed,'truncated':len(out)>LIMIT or len(err)>LIMIT,
            'start':f2.iso(a),'end':f2.iso(b),
            'stdout':base64.b64encode(out[:LIMIT]).decode(),
            'stderr':base64.b64encode(err[:LIMIT]).decode()}

def raw_ok(p):
    if p is None or p['rc']!=0 or p['timeout'] or p['truncated']:return None
    return base64.b64decode(p['stdout'],validate=True)

def sha_matches(raw,path,expected):
    if raw is None:return False
    try: words=raw.decode('ascii').strip().split()
    except UnicodeError:return False
    return words==[expected,str(path)]

def capture(*,root_readback=False,runner=subprocess.run,clock=f2.utcnow):
    need(type(root_readback) is bool,'READBACK_FLAG_INVALID')
    a=clock();base=f3.acquire(runner=runner,clock=clock);probes={}
    if root_readback:
        probes['helper_sha']=capture_probe('helper_sha',runner,clock)
        # Never invoke a root script which differs from the reviewed source.
        if sha_matches(raw_ok(probes['helper_sha']),HELPER,HELPER_SHA):
            probes['hook_sha']=capture_probe('hook_sha',runner,clock)
            if sha_matches(raw_ok(probes['hook_sha']),f3.HOOK,six.R34_HOOK):
                probes['deny_attest']=capture_probe('deny_attest',runner,clock)
    return {'schema':SCHEMA,'start':f2.iso(a),'end':f2.iso(clock()),
            'f3_capture':base,'root_readback_requested':root_readback,
            'probes':probes,'origin':'OPERATOR_REQUESTED_NO_AUTHORITY'}

def validate(doc):
    need(type(doc) is dict and set(doc)=={'schema','start','end','f3_capture',
         'root_readback_requested','probes','origin'},'CAPTURE_FIELDS')
    need(doc['schema']==SCHEMA and doc['origin']=='OPERATOR_REQUESTED_NO_AUTHORITY',
         'CAPTURE_SCHEMA')
    f3.check_capture(doc['f3_capture'])
    a=f3.time_utc(doc['start'],'START');b=f3.time_utc(doc['end'],'END')
    c=f3.time_utc(doc['f3_capture']['started_at'],'F3_START')
    d=f3.time_utc(doc['f3_capture']['captured_at'],'F3_END')
    need(a<=c<=d<=b and (b-a).total_seconds()<=190,'CAPTURE_TIME')
    flag=doc['root_readback_requested'];probes=doc['probes']
    need(type(flag) is bool and type(probes) is dict,'FLAG_OR_PROBES')
    need((not flag and not probes) or (flag and set(probes) in
         ({'helper_sha'},{'helper_sha','hook_sha'},set(COMMANDS))), 'UNEXPECTED_PROBES')
    for name,p in probes.items():
        need(type(p) is dict and set(p)=={'rc','timeout','truncated','start','end',
             'stdout','stderr'},'PROBE_FIELDS_'+name)
        need((p['rc'] is None or type(p['rc']) is int and -128<=p['rc']<=255)
             and type(p['timeout']) is bool and type(p['truncated']) is bool,
             'PROBE_STATUS_'+name)
        x=f3.time_utc(p['start'],'PROBE_START');y=f3.time_utc(p['end'],'PROBE_END')
        need(a<=x<=y<=b,'PROBE_TIME')
        for key in ('stdout','stderr'):
            value=p[key]
            need(type(value) is str and len(value)<=4*((LIMIT+2)//3)+4,
                 'PROBE_SIZE')
            try: decoded=base64.b64decode(value,validate=True)
            except (ValueError,base64.binascii.Error) as exc:
                raise Stop('PROBE_ENCODING') from exc
            need(len(decoded)<=LIMIT,'PROBE_EXCESS')
    return doc

def sha_status(p,path,expected):
    if p is None:return 'ND','NOT_REQUESTED_OR_HELPER_UNTRUSTED'
    raw=raw_ok(p)
    if raw is None:return 'ND','PERMISSION_OR_READ_FAILURE'
    if not sha_matches(raw,path,expected):return 'DRIFT','HASH_MISMATCH'
    return 'MATCH','PINNED_BYTES_OBSERVED'

def attest_status(p,helper_status):
    if helper_status!='MATCH':return 'ND','HELPER_NOT_PINNED'
    raw=raw_ok(p)
    if raw is None:return 'ND','F6_DENY_ATTESTATION_FAILED_OR_UNAVAILABLE'
    try: result=f1.load(raw)
    except (f1.Rejected,ValueError,TypeError):return 'DRIFT','INVALID_ATTESTATION_OUTPUT'
    expected={'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,
              'host_writes':0,'p8':'NO-GO'}
    if (type(result) is not dict or set(result)!=set(expected) or
        type(result['result']) is not str or type(result['bindings']) is not int or
        type(result['host_writes']) is not int or type(result['p8']) is not str or
        result!=expected):return 'DRIFT','ATTESTATION_RESULT_MISMATCH'
    return 'MATCH','SIX_DENY_FILTERBINDINGS_AND_NFT_MATCH_AT_CAPTURE'

def report(doc):
    validate(doc)
    base=f3.report(doc['f3_capture'])
    probes=doc['probes']
    helper,wh=sha_status(probes.get('helper_sha'),HELPER,HELPER_SHA)
    hook,wo=sha_status(probes.get('hook_sha'),f3.HOOK,six.R34_HOOK)
    deny,wd=attest_status(probes.get('deny_attest'),helper)
    states={'helper':helper,'hook':hook,'six_deny_bindings_and_nft':deny}
    reasons={'helper':wh,'hook':wo,'six_deny_bindings_and_nft':wd}
    gates=dict(base['a3_status']);why=dict(base['a3_reasons'])
    if 'DRIFT' in states.values():
        gates['LAB_ISOLATION_CONFIRMED']='FALSO'
        why['LAB_ISOLATION_CONFIRMED']='PRIVILEGED_READBACK_DRIFT'
    return {'schema':'ARDREC-R115-F4-NO-GO-REVIEW-v1',
            'capture_sha256':digest(f1.canonical(doc)),
            'checks':states,'check_reasons':reasons,
            'six_denies_at_capture':all(v=='MATCH' for v in states.values()),
            'a3_status':gates,'a3_reasons':why,
            'external_authority_attested':False,'operational_isolation_approved':False,
            'dispatch':'NO-GO','a6':'ND','p8':'NO-GO',
            'guest_starts':0,'network_probes':0,'read_only':True}

def save_private(doc,result,root=ROOT):
    need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
    if not root.exists():
        need(root.parent.is_dir() and not root.parent.is_symlink(),'ROOT_PARENT_MISSING')
        root.mkdir(mode=0o700)
    f2.private_parent(root)
    folder=Path(tempfile.mkdtemp(prefix='capture-',dir=root))
    f2.private_parent(folder)
    payload={'capture.json':f1.canonical(doc),'report.json':f1.canonical(result)}
    for name,raw in payload.items():f2.exclusive(folder/name,raw)
    f2.exclusive(folder/'manifest.json',f1.canonical({
        'schema':'ARDREC-R115-F4-RECEIPT-v1',
        'files_sha256':{k:digest(v) for k,v in payload.items()},
        'purpose':'READ_ONLY_NO_EXECUTION_NO_AUTHORITY'}))
    return folder

def main(argv=None):
    import argparse
    ap=argparse.ArgumentParser(description='R115-F4 read-only effective deny review')
    ap.add_argument('--capture',action='store_true',required=True)
    ap.add_argument('--with-privileged-readback',action='store_true')
    args=ap.parse_args(argv)
    try:
        need(os.geteuid()!=0,'ROOT_FORBIDDEN')
        doc=capture(root_readback=args.with_privileged_readback)
        result=report(doc);folder=save_private(doc,result)
    except (Stop,f1.Rejected,f2.Stop,f3.Stop,OSError,ValueError,TypeError) as exc:
        print('R115_F4_STOP='+type(exc).__name__+':'+str(exc))
        return 2
    print('R115_F4_CAPTURE=PASS_PRIVATE_READONLY')
    print('R115_F4_RECEIPT='+str(folder))
    print('R115_F4_SHA256='+result['capture_sha256'])
    for key in result['checks']:
        print('R115_F4_CHECK_'+key.upper()+'='+result['checks'][key])
        print('R115_F4_REASON_'+key.upper()+'='+result['check_reasons'][key])
    for key in f1.GATES:
        print('R115_F4_A3_'+key+'='+result['a3_status'][key])
    print('R115_F4_DENY_AT_CAPTURE='+('MATCH' if result['six_denies_at_capture'] else 'NOT_ATTESTED'))
    print('R115_F4_SCOPE_AUTHORITY=ND')
    print('R115_F4_DISPATCH=NO-GO')
    print('R115_F4_A6=ND')
    print('R115_F4_P8=NO-GO')
    print('R115_F4_VMS_STARTED=0')
    print('R115_F4_NETWORK_PROBES=0')
    return 0

if __name__=='__main__':raise SystemExit(main())
