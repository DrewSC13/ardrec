"""R115-F5: lifecycle-aware read-only DENY baseline for real libvirt guests.

Absence of live nwfilter bindings is expected when all guests are shut off.
A correct offline baseline is NOT an A3 isolation authorization. No execution,
no network sockets, no guest starts, and no modification of nftables/libvirt.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f4_effective_deny_readback as f4
from ardrec.coordination import r113_f6_six_binding_guard as six
from ardrec.coordination import r112_runner_nic_definition as nic

SCHEMA = 'ARDREC-R115-F5-LIFECYCLE-DENY-CAPTURE-v1'
REPORT_SCHEMA = 'ARDREC-R115-F5-LIFECYCLE-DENY-REVIEW-v1'
ROOT = Path('/home/cicada/ardrec-lab/r115-f5-lifecycle-deny-v1')
BASE = ('/usr/bin/virsh','-c','qemu:///system')
VMS = ('runner','ssh','ftp','smb')
READS = {
    'nft': ('/usr/sbin/nft','-j','-a','list','table','bridge','ardrec_r34_guard'),
    'helper_sha': ('/usr/bin/sha256sum',str(f4.HELPER)),
    'hook_sha': ('/usr/bin/sha256sum',str(f4.f3.HOOK)),
    'bindings_list': BASE + ('nwfilter-binding-list',),
}
for _role in VMS:
    READS['state_'+_role] = BASE + ('domstate','ardrec-r33-dev-'+_role)
    READS['xml_'+_role] = BASE + ('dumpxml','ardrec-r33-dev-'+_role)
for _key, (_,_,_tap,_) in six.ROLES.items():
    READS['binding_'+_key] = BASE + ('nwfilter-binding-dumpxml',_tap)
READS = dict(READS)
LIMIT = 262144

class Stop(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def _raw(probe):
    if probe['rc'] != 0 or probe['timeout'] or probe['truncated']:
        return None
    return base64.b64decode(probe['stdout'], validate=True)

def read_once(key, *, runner=subprocess.run, clock=f2.utcnow):
    need(key in READS, 'COMMAND_NOT_ALLOWED')
    started = clock()
    try:
        p = runner(['/usr/bin/sudo','-n','--',*READS[key]],
                   capture_output=True, stdin=subprocess.DEVNULL,
                   shell=False, check=False, timeout=12,
                   env={'LC_ALL':'C','LANG':'C','PATH':'/usr/sbin:/usr/bin:/bin'})
        out, err, rc, timeout = p.stdout, p.stderr, p.returncode, False
    except subprocess.TimeoutExpired as exc:
        out, err, rc, timeout = exc.stdout or b'', exc.stderr or b'', None, True
    except (OSError, ValueError):
        out, err, rc, timeout = b'', b'', None, False
    need(type(out) is bytes and type(err) is bytes,'NON_BYTES_OUTPUT')
    return {'rc':rc,'timeout':timeout,'truncated':len(out)>LIMIT or len(err)>32768,
            'start':f2.iso(started),'end':f2.iso(clock()),
            'stdout':base64.b64encode(out[:LIMIT]).decode('ascii'),
            'stderr':base64.b64encode(err[:32768]).decode('ascii')}

def capture(*, runner=subprocess.run, clock=f2.utcnow):
    a=clock()
    reads={name:read_once(name,runner=runner,clock=clock) for name in READS}
    return {'schema':SCHEMA,'start':f2.iso(a),'end':f2.iso(clock()),
            'probes':reads,'source':'LOCAL_ROOT_READONLY_NOT_AUTHORITY',
            'traffic_authorized':False}

def validate(doc):
    need(type(doc) is dict and set(doc)=={'schema','start','end','probes','source','traffic_authorized'},'CAPTURE_FIELDS')
    need(doc['schema']==SCHEMA and doc['source']=='LOCAL_ROOT_READONLY_NOT_AUTHORITY'
         and doc['traffic_authorized'] is False,'CAPTURE_SCOPE')
    start=f4.f3.time_utc(doc['start'],'F5_START')
    end=f4.f3.time_utc(doc['end'],'F5_END')
    need(start<=end and (end-start).total_seconds()<=330,'CAPTURE_DURATION')
    need(type(doc['probes']) is dict and set(doc['probes'])==set(READS),'CAPTURE_COMMAND_SET')
    for key,p in doc['probes'].items():
        need(type(p) is dict and set(p)=={'rc','timeout','truncated','start','end','stdout','stderr'},'PROBE_FIELDS_'+key)
        need((p['rc'] is None or (type(p['rc']) is int and -128<=p['rc']<=255))
             and type(p['timeout']) is bool and type(p['truncated']) is bool,
             'PROBE_STATUS_'+key)
        a=f4.f3.time_utc(p['start'],'READ_START')
        b=f4.f3.time_utc(p['end'],'READ_END')
        need(start<=a<=b<=end,'PROBE_TIMING_'+key)
        for field,cap in (('stdout',LIMIT),('stderr',32768)):
            value=p[field]
            need(type(value) is str and len(value)<=4*((cap+2)//3)+4,'PROBE_ENCODED_SIZE_'+key)
            try:
                raw=base64.b64decode(value,validate=True)
            except (ValueError,base64.binascii.Error) as exc:
                raise Stop('PROBE_INVALID_BASE64_'+key) from exc
            need(len(raw)<=cap and base64.b64encode(raw).decode('ascii')==value,
                 'PROBE_BASE64_CANONICAL_'+key)
    return doc

def _nft(raw):
    if raw is None:return 'ND'
    try:
        # Existing strict validator from R113-F6 is intentionally reused.
        import importlib.util
        helper_source = Path(__file__).resolve().parents[3] / 'scripts/ardrec_p14_r113_f6_root_recover.py'
        need(f1.digest(helper_source.read_bytes()) == f4.HELPER_SHA, 'SOURCE_HELPER_NOT_PINNED')
        spec=importlib.util.spec_from_file_location('r115_f5_pinned_deny_validator',helper_source)
        need(spec is not None and spec.loader is not None,'ROOT_VALIDATOR_LOAD_FAILED')
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.verify_nft(raw)
        return 'MATCH'
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError):
        return 'DRIFT'

def _vm(raw,role):
    if raw is None:return 'ND'
    try:
        nic.validate_domain(raw.decode('utf-8'),role,configured=(role=='runner'))
        return 'MATCH'
    except (ValueError,TypeError,UnicodeError,KeyError):
        return 'DRIFT'

def _state(raw):
    if raw is None:return 'ND'
    try: s=raw.decode('utf-8').strip().lower()
    except UnicodeError:return 'ND'
    if s in ('shut off','apagado'):return 'OFF'
    if s in ('running','ejecutando'):return 'RUNNING'
    return 'ND'

def _present(raw):
    if raw is None:return None
    try:
        txt=raw.decode('utf-8','strict')
        lines=[x.split() for x in txt.splitlines() if x.strip()]
        need(lines and any(k.lower()=='port' for k in lines[0]),'BINDING_LIST_HEADER')
        taps=[x[0] for x in lines[1:] if x and set(x[0])!={'-'}]
        need(len(taps)==len(set(taps)) and
             all(re.fullmatch(r'[A-Za-z0-9_.-]+',x) for x in taps),
             'BINDING_LIST_CONTENT')
        return set(taps)
    except (UnicodeError,ValueError,IndexError,TypeError):return None

def _binding(raw,key,domain):
    if raw is None or domain is None:return 'ND'
    try:
        uuid=six.binding(raw,key)
        from xml.etree import ElementTree as ET
        dom=ET.fromstring(domain)
        need(dom.findtext('uuid')==uuid,'BINDING_UUID_NOT_DOMAIN')
        return 'DENY_MATCH'
    except (six.GuardError,ValueError,TypeError,KeyError):return 'DRIFT'

def report(doc):
    validate(doc)
    reads={name:_raw(doc['probes'][name]) for name in READS}
    nft=_nft(reads['nft'])
    helper='MATCH' if f4.sha_matches(reads['helper_sha'],f4.HELPER,f4.HELPER_SHA) else 'ND'
    hook='MATCH' if f4.sha_matches(reads['hook_sha'],f4.f3.HOOK,six.R34_HOOK) else 'ND'
    if reads['helper_sha'] is not None and helper!='MATCH':helper='DRIFT'
    if reads['hook_sha'] is not None and hook!='MATCH':hook='DRIFT'
    states={k:_state(reads['state_'+k]) for k in VMS}
    definitions={k:_vm(reads['xml_'+k],k) for k in VMS}
    live=_present(reads['bindings_list'])
    bindings={}
    for key,(role,_,tap,_) in six.ROLES.items():
        if live is None:status='ND'
        elif tap not in live:
            status='ABSENT_WHILE_OFF' if states[role]=='OFF' else 'MISSING_OR_TRANSITION'
        else:
            status=_binding(reads['binding_'+key],key,reads['xml_'+role])
        bindings[key]=status
    all_off=all(v=='OFF' for v in states.values())
    all_running=all(v=='RUNNING' for v in states.values())
    all_defs=all(v=='MATCH' for v in definitions.values())
    all_absent=all(v=='ABSENT_WHILE_OFF' for v in bindings.values())
    all_deny=all(v=='DENY_MATCH' for v in bindings.values())
    if (nft=='MATCH' and helper=='MATCH' and hook=='MATCH' and
            all_off and all_defs and all_absent):
        stage='OFFLINE_DENY_BASELINE_MATCH'
    elif (nft=='MATCH' and helper=='MATCH' and hook=='MATCH' and
          all_running and all_defs and all_deny):
        stage='RUNNING_SIX_DENY_BINDINGS_MATCH'
    elif any(v=='DRIFT' for v in (nft,helper,hook,*definitions.values(),*bindings.values())):
        stage='DRIFT_NO_GO'
    else:
        stage='INCOMPLETE_OR_TRANSITION_NO_GO'
    # Neither a matching offline definition nor a 6/6 active DENY proves the
    # authority and service readiness needed to release the technical window.
    service='FALSO' if states['runner']=='OFF' or states['ftp']=='OFF' else 'ND'
    gates={key:'ND' for key in f1.GATES}
    gates['SERVICE_READY']=service
    if stage=='DRIFT_NO_GO':
        gates['LAB_ISOLATION_CONFIRMED']='FALSO'
    return {'schema':REPORT_SCHEMA,'capture_sha256':f1.digest(f1.canonical(doc)),
            'nft':nft,'helper':helper,'f11_hook':hook,
            'states':states,'vm_definitions':definitions,'bindings':bindings,
            'lifecycle_stage':stage,'a3':gates,'a5_dispatch':'NO-GO',
            'a6':'ND','p8':'NO-GO', 'authority_attested':False,
            'physical_network_probes':0,'guest_starts':0,
            'original_reads_are_current_at_capture_only':True}

def save_private(doc,result,root=ROOT):
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    if not root.exists():
        need(root.parent.is_dir() and not root.parent.is_symlink(),'RECEIPT_BASE_MISSING')
        root.mkdir(mode=0o700)
    f2.private_parent(root)
    folder=Path(tempfile.mkdtemp(prefix='capture-',dir=root))
    f2.private_parent(folder)
    payload={'capture.json':f1.canonical(doc),'report.json':f1.canonical(result)}
    for name,raw in payload.items():f2.exclusive(folder/name,raw)
    f2.exclusive(folder/'manifest.json',f1.canonical({
        'schema':'ARDREC-R115-F5-RECEIPT-v1',
        'files_sha256':{k:f1.digest(v) for k,v in payload.items()},
        'scope':'READ_ONLY_NO_DISPATCH_NO_AUTHORITY'}))
    return folder

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='R115-F5 lifecycle-aware, NO-GO, read-only')
    parser.add_argument('--capture',action='store_true',required=True)
    args=parser.parse_args(argv)
    try:
        need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
        doc=capture()
        result=report(doc)
        folder=save_private(doc,result)
    except (Stop, f1.Rejected, f2.Stop, ValueError, OSError, TypeError) as exc:
        print('R115_F5_STOP='+type(exc).__name__+':'+str(exc))
        return 2
    print('R115_F5_CAPTURE=PASS_PRIVATE_READONLY')
    print('R115_F5_RECEIPT='+str(folder))
    print('R115_F5_CAPTURE_SHA256='+result['capture_sha256'])
    for k in ('nft','helper','f11_hook','lifecycle_stage'):
        print('R115_F5_'+k.upper()+'='+result[k])
    for k,v in result['states'].items():print('R115_F5_VM_'+k.upper()+'='+v)
    for k,v in result['vm_definitions'].items():print('R115_F5_VMDEF_'+k.upper()+'='+v)
    for k,v in result['bindings'].items():print('R115_F5_BINDING_'+k.upper()+'='+v)
    for k,v in result['a3'].items():print('R115_F5_A3_'+k+'='+v)
    print('R115_F5_DISPATCH=NO-GO')
    print('R115_F5_A6=ND')
    print('R115_F5_P8=NO-GO')
    print('R115_F5_GUEST_STARTS=0')
    print('R115_F5_NETWORK_PROBES=0')
    return 0

if __name__=='__main__':raise SystemExit(main())
