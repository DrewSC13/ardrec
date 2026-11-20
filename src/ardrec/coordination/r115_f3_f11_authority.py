"""R115-F3: six NIC bindings, R34/F11 readbacks and signed authority review.

Read-only. Documentary cryptographic verification is NOT approval to dispatch.
Never starts guests, edits filters, uses sockets or writes confirmed state.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r112_runner_nic_definition as nic
from ardrec.coordination import r112_f4_isolated_networks as net4
from ardrec.coordination import r113_f6_six_binding_guard as six
from ardrec.evidence import r58f_signed_witness as signed

SCHEMA = 'ARDREC-R115-F3-F11-SIX-BINDINGS-SIGNED-REVIEW-v1'
CAPTURE = 'ARDREC-R115-F3-CAPTURE-v1'
AUTH_SCHEMA = 'ARDREC-R115-F3-FTP-T01-AUTHORIZATION-v1'
REVOCATION_SCHEMA = 'ARDREC-R115-F3-REVOCATION-REVIEW-v1'
TRUST_SCHEMA = 'ARDREC-R115-F3-EXTERNAL-TRUST-PINS-v1'
PREFIX_AUTH = b'ARDREC-R115-F3-AUTH-V1\x00'
PREFIX_REVOKE = b'ARDREC-R115-F3-REVOCATION-V1\x00'
ROOT = Path('/home/cicada/ardrec-lab/r115-f3-f11-authority-v1')
REPO = Path(__file__).resolve().parents[3]
HOOK = Path('/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny')
MAX_CAPTURE_SEC = 180
MAX_RAW = 192000
PREFIX = f2.PREFIX
COMMANDS = {
    'ssh_xml': PREFIX + ('dumpxml', 'ardrec-r33-dev-ssh'),
    'smb_xml': PREFIX + ('dumpxml', 'ardrec-r33-dev-smb'),
    'ssh_net_xml': PREFIX + ('net-dumpxml', 'ardrec-r33-dev-net-ssh'),
    'smb_net_xml': PREFIX + ('net-dumpxml', 'ardrec-r33-dev-net-smb'),
    'ssh_net_info': PREFIX + ('net-info', 'ardrec-r33-dev-net-ssh'),
    'smb_net_info': PREFIX + ('net-info', 'ardrec-r33-dev-net-smb'),
    'nwfilter_xml': PREFIX + ('nwfilter-dumpxml', nic.FILTER),
    'f11_hook_hash': ('/usr/bin/sha256sum', str(HOOK)),
    'boot_deny': ('/usr/bin/systemctl', 'show', 'ardrec-r34-boot-deny.service',
                  '--property=LoadState', '--property=ActiveState'),
}

class Stop(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return f1.canonical(obj)


def time_utc(value, name):
    try:
        return f1._instant(value, name)
    except f1.Rejected as exc:
        raise Stop(name + '_INVALID') from exc


def extra_probe(name, *, runner=subprocess.run, clock=f2.utcnow):
    need(name in COMMANDS, 'UNKNOWN_EXTRA_PROBE')
    a=clock()
    try:
        p=runner(list(COMMANDS[name]), stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, timeout=8, check=False, shell=False,
                 env={'LC_ALL':'C','LANG':'C','PATH':'/usr/sbin:/usr/bin:/bin'},
                 stdin=subprocess.DEVNULL)
        stdout,stderr,rc,timeout=p.stdout,p.stderr,p.returncode,False
    except subprocess.TimeoutExpired as exc:
        stdout,stderr,rc,timeout=exc.stdout or b'',exc.stderr or b'',None,True
    except (OSError, ValueError):
        stdout,stderr,rc,timeout=b'',b'',None,False
    b=clock()
    need(type(stdout) is bytes and type(stderr) is bytes, 'PROBE_NOT_BYTES')
    truncated=len(stdout)>MAX_RAW or len(stderr)>MAX_RAW
    return {'rc':rc, 'timed_out':timeout, 'truncated':truncated,
            'started_at':f2.iso(a),'completed_at':f2.iso(b),
            'stdout_b64':base64.b64encode(stdout[:MAX_RAW]).decode('ascii'),
            'stderr_b64':base64.b64encode(stderr[:MAX_RAW]).decode('ascii')}


def acquire(*, runner=subprocess.run, clock=f2.utcnow):
    start=clock()
    baseline=f2.collect(runner=runner, clock=clock)
    extra={name:extra_probe(name, runner=runner, clock=clock) for name in COMMANDS}
    end=clock()
    return {'schema':CAPTURE,'captured_at':f2.iso(end), 'started_at':f2.iso(start),
            'f2_snapshot':baseline,'extra':extra,
            'source_kind':'LOCAL_READONLY_COMMANDS_NOT_AUTHORITY'}


def check_capture(doc):
    need(type(doc) is dict and set(doc)=={'schema','captured_at','started_at',
         'f2_snapshot','extra','source_kind'}, 'CAPTURE_FIELDS')
    need(doc['schema']==CAPTURE and doc['source_kind']==
         'LOCAL_READONLY_COMMANDS_NOT_AUTHORITY','CAPTURE_SCHEMA')
    f2.check_snapshot(doc['f2_snapshot'])
    t0=time_utc(doc['started_at'],'F3_START')
    t1=time_utc(doc['captured_at'],'F3_END')
    need(t0<=t1 and (t1-t0).total_seconds()<=MAX_CAPTURE_SEC,
         'CAPTURE_WINDOW_TOO_LONG')
    b0=time_utc(doc['f2_snapshot']['started_at'],'F2_START')
    b1=time_utc(doc['f2_snapshot']['completed_at'],'F2_END')
    need(t0<=b0<=b1<=t1, 'BASELINE_OUTSIDE_CAPTURE')
    need(type(doc['extra']) is dict and set(doc['extra'])==set(COMMANDS),
         'EXTRA_PROBE_SET')
    for name,p in doc['extra'].items():
        need(type(p) is dict and set(p)=={'rc','timed_out','truncated',
             'started_at','completed_at','stdout_b64','stderr_b64'},
             'EXTRA_FIELDS_'+name)
        need((p['rc'] is None or (type(p['rc']) is int and -128<=p['rc']<=255))
             and type(p['timed_out']) is bool and type(p['truncated']) is bool,
             'EXTRA_STATUS_'+name)
        a=time_utc(p['started_at'],'EXTRA_START')
        b=time_utc(p['completed_at'],'EXTRA_END')
        need(t0<=a<=b<=t1, 'EXTRA_TIME_'+name)
        for field in ('stdout_b64','stderr_b64'):
            encoded=p[field]
            need(type(encoded) is str and len(encoded)<=4*((MAX_RAW+2)//3)+4,
                 'EXTRA_SIZE_'+name)
            try: raw=base64.b64decode(encoded,validate=True)
            except (ValueError,base64.binascii.Error) as exc:
                raise Stop('EXTRA_ENCODING_'+name) from exc
            need(len(raw)<=MAX_RAW,'EXTRA_OVERFLOW_'+name)
    return doc


def output(doc, key):
    if key in f2.COMMANDS:
        return f2.output(doc['f2_snapshot'],key)
    p=doc['extra'][key]
    if p['rc']!=0 or p['timed_out'] or p['truncated']:
        return None
    return base64.b64decode(p['stdout_b64'],validate=True)


def xml(raw):
    if raw is None: return None
    if b'<!' in raw or len(raw)>MAX_RAW: return None
    try: return ET.fromstring(raw.decode('utf-8'))
    except (UnicodeError,ET.ParseError,ValueError): return None


def six_definitions(doc):
    names={'ssh':'ssh_xml','ftp':'ftp_xml','smb':'smb_xml','runner':'runner_xml'}
    if any(output(doc,key) is None for key in names.values()):
        return 'ND','ONE_OR_MORE_VM_XML_UNREADABLE'
    try:
        for role,key in names.items():
            raw=output(doc,key)
            need(b'<!' not in raw, 'XML_ENTITIES_FORBIDDEN')
            nic.validate_domain(raw.decode('utf-8'),role,
                                configured=(role=='runner'))
    except (UnicodeError,ET.ParseError,ValueError,TypeError,KeyError):
        return 'DRIFT','SIX_PINNED_NIC_DEFINITIONS_MISMATCH'
    return 'MATCH','SIX_DEFINED_NICS_MATCH_NOT_LIVE_BINDING_PROOF'


def three_networks(doc):
    names={'ssh':'ssh_net_xml','ftp':'ftp_net_xml','smb':'smb_net_xml'}
    if any(output(doc,key) is None for key in names.values()):
        return 'ND','NETWORK_XML_UNREADABLE'
    try:
        for role,key in names.items():
            raw=output(doc,key)
            need(b'<!' not in raw, 'NETWORK_ENTITY_FORBIDDEN')
            nic._safe_net(raw.decode('utf-8'),role)
    except (UnicodeError,ET.ParseError,ValueError,TypeError,KeyError):
        return 'DRIFT','THREE_PINNED_NETWORK_XML_MISMATCH'
    return 'MATCH','THREE_PRIVATE_NETS_MATCH_NO_LIVE_FORWARDING_PROOF'


def filter_readback(doc):
    raw=output(doc,'nwfilter_xml')
    if raw is None: return 'ND','NWFILTER_UNREADABLE'
    root=xml(raw)
    if root is None: return 'DRIFT','NWFILTER_XML_INVALID'
    rules=root.findall('rule')
    if (root.tag!='filter' or root.get('name')!=nic.FILTER or
        len(rules)!=1 or rules[0].get('action')!='drop' or
        rules[0].get('direction')!='inout' or
        len(rules[0])!=1 or rules[0][0].tag!='all'):
        return 'DRIFT','NWFILTER_DENY_NOT_PINNED'
    return 'MATCH','NWFILTER_DROP_DEFINITION_ONLY'


def hook_readback(doc):
    raw=output(doc,'f11_hook_hash')
    if raw is None: return 'ND','F11_HOOK_UNREADABLE'
    try:
        words=raw.decode('ascii').strip().split()
    except UnicodeError:
        return 'DRIFT','F11_HOOK_HASH_ENCODING'
    if words==[six.R34_HOOK,str(HOOK)]:
        return 'MATCH','F11_HOOK_BYTES_MATCH_HISTORICAL_PIN'
    return 'DRIFT','F11_HOOK_HASH_DRIFT'


def boot_readback(doc):
    raw=output(doc,'boot_deny')
    if raw is None: return 'ND','BOOT_DENY_UNIT_UNREADABLE'
    try:
        lines=raw.decode('ascii').splitlines()
        pairs=[line.split('=',1) for line in lines]
        parsed=dict(pairs)
    except (UnicodeError,ValueError):
        return 'ND','BOOT_DENY_PARSE_FAILED'
    if len(lines)!=2 or len(parsed)!=2 or set(parsed)!={'LoadState','ActiveState'}:
        return 'ND','BOOT_DENY_UNIT_PROPERTIES_UNKNOWN'
    if parsed=={'LoadState':'loaded','ActiveState':'active'}:
        return 'MATCH','BOOT_DENY_ACTIVE_NOT_RUNTIME_REVOCATION_PROOF'
    return 'DRIFT','BOOT_DENY_NOT_LOADED_OR_ACTIVE'


def network_infos(doc):
    result=[]
    for role,key in [('ssh','ssh_net_info'),('ftp','ftp_net_info'),
                     ('smb','smb_net_info')]:
        raw=output(doc,key)
        if raw is None: return 'ND','NETWORK_RUNTIME_UNREADABLE_'+role
        try:
            info=net4.parse_net_info(raw.decode('ascii'),role)
        except (UnicodeError,ValueError,TypeError,KeyError,ET.ParseError):
            return 'DRIFT','NETWORK_RUNTIME_IDENTITY_DRIFT_'+role
        result.append(info)
    return 'MATCH','THREE_NETWORK_RUNTIME_IDENTITIES_'+'_'.join(result)


def exact(obj,keys,code):
    need(type(obj) is dict and set(obj)==set(keys),code)


def trust_check(policy):
    exact(policy,{'schema','scope_signer','revocation_signer'},'TRUST_FIELDS')
    need(policy['schema']==TRUST_SCHEMA,'TRUST_SCHEMA')
    hashes=[];ids=[]
    for role in ('scope_signer','revocation_signer'):
        e=policy[role]
        exact(e,{'key_id','public_key_pem'},'TRUST_KEY_FIELDS')
        need(type(e['key_id']) is str and f1.ID.fullmatch(e['key_id']),
             'TRUST_KEY_ID')
        need(type(e['public_key_pem']) is str,'TRUST_KEY_PEM_TYPE')
        try: key=e['public_key_pem'].encode('ascii')
        except UnicodeError as exc: raise Stop('TRUST_KEY_NOT_ASCII') from exc
        need(key.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
             key.endswith(b'-----END PUBLIC KEY-----\n') and len(key)<=1024,
             'TRUST_KEY_PEM_FORMAT')
        hashes.append(sha(key));ids.append(e['key_id'])
    need(len(set(hashes))==2 and len(set(ids))==2,'TRUST_ROLES_NOT_DISTINCT')
    return policy


def signed_bytes(payload,prefix):
    need(type(payload) is dict, 'SIGNED_PAYLOAD_REQUIRED')
    return prefix + canonical(payload)


def verified_signature(obj, payload, trust, prefix):
    exact(obj,{'statement','signer_key_id','signature_b64'},'SIGNED_OBJECT_FIELDS')
    need(obj['statement']==payload and obj['signer_key_id']==trust['key_id'],
         'UNTRUSTED_SIGNER_OR_STATEMENT')
    b64=obj['signature_b64']
    need(type(b64) is str and len(b64)<=128,'SIGNATURE_SIZE')
    try: sig=base64.b64decode(b64,validate=True)
    except (ValueError,base64.binascii.Error) as exc:
        raise Stop('SIGNATURE_ENCODING') from exc
    need(len(sig)==64 and base64.b64encode(sig).decode('ascii')==b64,
         'SIGNATURE_CANONICAL')
    try:
        signed._verify_signature(trust['public_key_pem'].encode('ascii'),
                                 signed_bytes(payload,prefix),sig)
    except signed.WitnessError as exc:
        raise Stop('SIGNATURE_NOT_VERIFIED') from exc


def auth_review(contract, authorization, revocation, trust, *, now):
    """Cryptographic/documentary review only. Trust policy is not anchored here."""
    exact(contract,{'schema','case_id','family_id','stage','created_at','valid_from',
          'valid_until','source_commit','catalog_sha256','target','client','profile',
          'authority','isolation','service','limits'},'F1_CONTRACT_FIELDS')
    trust_check(trust)
    exact(authorization,{'statement','signer_key_id','signature_b64'},
          'AUTH_WRAPPER')
    s=authorization['statement']
    exact(s,{'schema','authorization_id','case_id','family_id','stage',
          'valid_from','valid_until','target','client_sha256','profile_sha256',
          'catalog_sha256','limits'},'AUTH_SCOPE_FIELDS')
    need(s['schema']==AUTH_SCHEMA and s['case_id']==contract['case_id'] and
         s['family_id']=='FTP-T01' and s['stage']=='DEV' and
         s['valid_from']==contract['valid_from'] and
         s['valid_until']==contract['valid_until'] and
         s['target']==contract['target'] and
         s['client_sha256']==contract['client']['sha256'] and
         s['profile_sha256']==contract['profile']['sha256'] and
         s['catalog_sha256']==contract['catalog_sha256'] and
         s['limits']==contract['limits'], 'AUTH_SCOPE_OR_PROFILE_MISMATCH')
    need(type(s['authorization_id']) is str and
         f1.ID.fullmatch(s['authorization_id']) is not None,
         'AUTHORIZATION_ID_INVALID')
    # The contract's authority reference pins the entire signed object.
    need(sha(canonical(authorization))==contract['authority']['sha256'],
         'AUTHORITY_REFERENCE_MISMATCH')
    verified_signature(authorization,s,trust['scope_signer'],PREFIX_AUTH)
    exact(revocation,{'statement','signer_key_id','signature_b64'},
          'REVOCATION_WRAPPER')
    r=revocation['statement']
    exact(r,{'schema','authorization_sha256','authorization_id','issued_at',
          'valid_until','revoked','reason_code'},'REVOCATION_FIELDS')
    need(r['schema']==REVOCATION_SCHEMA and
         r['authorization_sha256']==sha(canonical(authorization)) and
         r['authorization_id']==s['authorization_id'] and
         type(r['revoked']) is bool and
         type(r['reason_code']) is str and
         f1.ID.fullmatch(r['reason_code']) is not None,
         'REVOCATION_SCOPE_INVALID')
    verified_signature(revocation,r,trust['revocation_signer'],PREFIX_REVOKE)
    present=time_utc(now,'NOW')
    start=time_utc(s['valid_from'],'AUTHORIZED_FROM')
    until=time_utc(s['valid_until'],'AUTHORIZED_UNTIL')
    issued=time_utc(r['issued_at'],'REVOCATION_ISSUED')
    rev_until=time_utc(r['valid_until'],'REVOCATION_UNTIL')
    need(start<until and issued<rev_until and issued<=present and
         (rev_until-issued).total_seconds()<=86400,
         'AUTH_TIME_INCOHERENT')
    # Stale revocation data never proves not-revoked.
    if r['revoked']:
        return {'status':'FALSO','reason':'SIGNED_REVOCATION_PRESENT',
                'crypto_verified':True,'host_trust_anchored':False,
                'authorization_sha256':sha(canonical(authorization))}
    if not (start<=present<until and issued<=present<rev_until):
        return {'status':'ND','reason':'OUTSIDE_SIGNED_SCOPE_OR_REVOCATION_WINDOW',
                'crypto_verified':True,'host_trust_anchored':False,
                'authorization_sha256':sha(canonical(authorization))}
    return {'status':'ND','reason':'CRYPTO_VALID_BUT_HOST_AUTHORITY_NOT_PINNED',
            'crypto_verified':True,'host_trust_anchored':False,
            'authorization_sha256':sha(canonical(authorization))}


def report(capture, *, authority=None):
    check_capture(capture)
    checks={
        'six_vm_nic_definitions':six_definitions(capture),
        'three_network_definitions':three_networks(capture),
        'three_network_runtime':network_infos(capture),
        'nwfilter_deny':filter_readback(capture),
        'f11_hook':hook_readback(capture),
        'r34_boot_deny':boot_readback(capture),
    }
    f2_report=f2.report(capture['f2_snapshot'])
    old=f2_report['source_checks']
    checks.update({'r34_nft':(old['r34_nft']['status'],old['r34_nft']['reason']),
                   'r34_watchdog':(old['r34_watchdog']['status'],old['r34_watchdog']['reason'])})
    status={key:val[0] for key,val in checks.items()}
    reasons={key:val[1] for key,val in checks.items()}
    gates=dict(f2_report['a3_status'])
    why=dict(f2_report['a3_reasons'])
    if any(value=='DRIFT' for value in status.values()):
        gates['LAB_ISOLATION_CONFIRMED']='FALSO'
        why['LAB_ISOLATION_CONFIRMED']='CURRENT_F11_R34_CONTROL_DRIFT'
    else:
        gates['LAB_ISOLATION_CONFIRMED']='ND'
        why['LAB_ISOLATION_CONFIRMED']='RUNTIME_SIX_BINDINGS_AND_EFFECTIVE_POLICY_NOT_ATTESTED'
    if status['six_vm_nic_definitions']=='DRIFT':
        gates['DESTINATION_AUTHORIZED']='FALSO'
        why['DESTINATION_AUTHORIZED']='PINNED_VIRTUAL_NIC_IDENTITY_DRIFT'
    if authority is not None:
        need(type(authority) is dict and set(authority)=={'contract','authorization',
             'revocation','trust'}, 'AUTHORITY_INPUT_FIELDS')
        need(all(authority[k] is not None for k in authority),
             'AUTHORITY_PARTIAL')
        review=auth_review(authority['contract'],authority['authorization'],
                           authority['revocation'],authority['trust'],
                           now=capture['captured_at'])
        if review['status']=='FALSO':
            gates['SCOPE_APPROVED']='FALSO'
            why['SCOPE_APPROVED']='SIGNED_REVOCATION_PRESENT'
    else:
        review={'status':'ND','reason':'INDEPENDENT_SIGNATURES_AND_TRUST_NOT_SUPPLIED',
                'crypto_verified':False,'host_trust_anchored':False,
                'authorization_sha256':None}
    # No service or client runtime check in F3. The honest outcome is NO-GO.
    return {'schema':SCHEMA,'capture_sha256':sha(canonical(capture)),
            'captured_at':capture['captured_at'],'source_checks':status,
            'source_reasons':reasons,'authority_review':review,
            'a3_status':gates,'a3_reasons':why,
            'six_defined_bindings_verified':status['six_vm_nic_definitions']=='MATCH',
            'six_runtime_bindings_attested':False,
            'effective_isolation_attested':False,
            'a5_executable':False,'a6_classification':'ND',
            'a7_confirmed_rf':None,'a9_published_generation':None,
            'dispatch_decision':'NO-GO','p8':'NO-GO',
            'physical_network_probes':0,'guest_starts':0,
            'read_only':True}


def private_read(path):
    return f2.private_read(path)


def save_private(capture,result, root=ROOT):
    need(os.geteuid()!=0,'NO_ROOT')
    if not root.exists():
        need(root.parent.is_dir() and not root.parent.is_symlink(),
             'PRIVATE_BASE_MISSING')
        need(not root.is_symlink(),'PRIVATE_ROOT_LINK')
        root.mkdir(mode=0o700)
    f2.private_parent(root)
    folder=Path(tempfile.mkdtemp(prefix='capture-',dir=root))
    f2.private_parent(folder)
    artifacts={'capture.json':canonical(capture),'report.json':canonical(result)}
    for n,raw in artifacts.items():
        f2.exclusive(folder/n,raw)
    manifest={'schema':'ARDREC-R115-F3-RECEIPT-v1',
              'files_sha256':{name:sha(raw) for name,raw in artifacts.items()},
              'mode':'READONLY_NO_DISPATCH_NO_AUTHORITY_GRANT'}
    f2.exclusive(folder/'manifest.json',canonical(manifest))
    return folder


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='R115-F3: read-only F11 and signed-authority review (NO-GO)')
    parser.add_argument('--capture',action='store_true',required=True)
    parser.add_argument('--contract',type=Path)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--revocation',type=Path)
    parser.add_argument('--trust',type=Path)
    args=parser.parse_args(argv)
    try:
        need(os.geteuid()!=0,'ROOT_FORBIDDEN')
        supplied=[args.contract,args.authorization,args.revocation,args.trust]
        need(not any(supplied) or all(supplied), 'AUTHORITY_SET_INCOMPLETE')
        review=None
        if all(supplied):
            c=f1.load(private_read(args.contract))
            catalog_raw=(REPO/'lab/operational-catalog-v1/catalog.json').read_bytes()
            f1.validate(c,f1.load(catalog_raw),catalog_raw)
            need(c['source_commit']==f2.BASE_COMMIT,'SOURCE_BASE_MISMATCH')
            review={'contract':c,
                    'authorization':f1.load(private_read(args.authorization)),
                    'revocation':f1.load(private_read(args.revocation)),
                    'trust':f1.load(private_read(args.trust))}
        snapshot=acquire()
        result=report(snapshot,authority=review)
        folder=save_private(snapshot,result)
    except (Stop,f1.Rejected,f2.Stop,ValueError,TypeError,OSError,
            json.JSONDecodeError,UnicodeError) as exc:
        print('R115_F3_STOP='+type(exc).__name__+':'+str(exc))
        return 2
    print('R115_F3_CAPTURE=PASS_PRIVATE_READONLY')
    print('R115_F3_PRIVATE_RECEIPT='+str(folder))
    print('R115_F3_CAPTURE_SHA256='+result['capture_sha256'])
    for name in result['source_checks']:
        print('R115_F3_CHECK_'+name.upper()+'='+result['source_checks'][name])
    for gate in f1.GATES:
        print('R115_F3_A3_'+gate+'='+result['a3_status'][gate])
        print('R115_F3_REASON_'+gate+'='+result['a3_reasons'][gate])
    print('R115_F3_AUTHORITY='+result['authority_review']['status'])
    print('R115_F3_SIX_RUNTIME_BINDINGS=NOT_ATTESTED')
    print('R115_F3_DISPATCH=NO-GO')
    print('R115_F3_A6=ND')
    print('R115_F3_P8=NO-GO')
    print('R115_F3_VM_STARTS=0')
    print('R115_F3_NETWORK_PROBES=0')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
