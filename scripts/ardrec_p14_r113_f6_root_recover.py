#!/usr/bin/env python3
"""Root-staged, self-authenticated six-binding DENY-only recovery. NO allow action.

Staging path fixed, F5 evidence pinned, only nft scoped table and six libvirt
nwfilter bindings may be changed. Test before use. Safe failures remain behind
R34 nft deny; there is intentionally no unbounded retry or cleanup.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

BUNDLE = Path('/var/lib/ardrec/r113-six-deny-guard-v1')
SCHEMA = 'ardrec-r113-f6-six-deny-root-v1'
F5_DIGEST = 'a29b0c0e91ca139f1e2969d81dec10677c64460f6c6aead397cc1a68d8bc43ba'
DENY = 'ardrec-r33-block-until-containment'
TABLE = 'ardrec_r34_guard'
ROLES = {
    'runner_ssh': ('runner','ssh','a33d30r','52:54:00:ad:30:01'),
    'ssh': ('ssh','ssh','a33d30t','52:54:00:ad:30:02'),
    'runner_ftp': ('runner','ftp','a33d31r','52:54:00:ad:31:01'),
    'ftp': ('ftp','ftp','a33d31t','52:54:00:ad:31:02'),
    'runner_smb': ('runner','smb','a33d32r','52:54:00:ad:32:01'),
    'smb': ('smb','smb','a33d32t','52:54:00:ad:32:02'),
}
TAPS = {x[2] for x in ROLES.values()}
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
FILES = {'manifest.json','root-recover.py','r34-deny-restore.nft','source-f5-manifest.json'} | {
    key+'-'+kind+'.xml' for key in ROLES for kind in ('original','candidate')
}

class DenyGuardError(ValueError):
    pass

def need(ok,why):
    if not ok:raise DenyGuardError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def pairs(values):
    out={}
    for key,val in values:
        need(key not in out,'duplicate_json_key')
        out[key]=val
    return out

def load_json(raw):
    need(type(raw) is bytes and len(raw)<524288,'json_too_large')
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _:need(False,'nonfinite_json'))

def expected_nft():
    taps=', '.join('"'+name+'"' for name in sorted(TAPS))
    rows=[
        f'flush table bridge {TABLE}',
        f'add rule bridge {TABLE} input iifname {{ {taps} }} counter drop',
        f'add rule bridge {TABLE} output oifname {{ {taps} }} counter drop',
        f'add rule bridge {TABLE} forward iifname {{ {taps} }} counter drop',
        f'add rule bridge {TABLE} forward oifname {{ {taps} }} counter drop',
    ]
    return ('\n'.join(rows)+'\n').encode('ascii')

def binding(raw,key,*,candidate=False):
    need(key in ROLES and type(raw) is bytes and 0<len(raw)<16384 and
         b'<!' not in raw,'binding_bytes_invalid')
    root=ET.fromstring(raw)
    role,net,tap,mac=ROLES[key]
    need(root.tag=='filterbinding' and not root.attrib and
         [e.tag for e in root]==['owner','portdev','mac','filterref','backend'],
         'binding_structure_'+key)
    owner,port,m,ref,backend=list(root)
    uuid=owner.findtext('uuid')
    need(not owner.attrib and [x.tag for x in owner]==['name','uuid'] and
         owner.findtext('name')=='ardrec-r33-dev-'+role and
         re.fullmatch('[0-9a-fA-F-]{36}',uuid or '') is not None and
         port.attrib=={'name':tap} and m.attrib=={'address':mac} and
         len(ref)==1 and ref[0].tag=='parameter' and
         ref[0].attrib=={'name':'MAC','value':mac} and len(ref[0])==0 and
         backend.attrib=={'name':'iptables'} and len(backend)==0,
         'binding_identity_'+key)
    label='ardrec-r113-'+key.replace('_','-')+'-tcp-v1' if candidate else DENY
    need(ref.attrib=={'filter':label},'binding_filter_'+key)
    return uuid

def xml_equal(a,b):
    def node(n):
        return (n.tag,tuple(sorted(n.attrib.items())),(n.text or '').strip(),
                tuple(node(c) for c in n))
    return node(ET.fromstring(a))==node(ET.fromstring(b))

def root_bundle():
    need(os.geteuid()==0,'root_required')
    need(Path(__file__).resolve()==BUNDLE/'root-recover.py',
         'executable_must_be_root_staged')
    for path in (BUNDLE,*BUNDLE.parents):
        need(not path.is_symlink(),'root_bundle_path_symlink')
    st=BUNDLE.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
         stat.S_IMODE(st.st_mode)==0o700,'root_bundle_permissions')
    for path in BUNDLE.parents:
        st=path.lstat()
        need(st.st_uid==0 and not (st.st_mode&0o022),
             'root_bundle_ancestor_insecure')
    need({p.name for p in BUNDLE.iterdir()}==FILES,'root_bundle_file_scope')
    raw={}
    for name in FILES:
        path=BUNDLE/name
        st=path.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
             0<st.st_size<524288,'root_file_permissions_'+name)
        raw[name]=path.read_bytes()
    doc=load_json(raw['manifest.json'])
    need(type(doc) is dict and set(doc)=={'schema','f5_sha256','purpose',
         'traffic_allowed','p8','sha256'} and doc['schema']==SCHEMA and
         doc['f5_sha256']==F5_DIGEST and
         doc['purpose']=='DENY_ONLY_SIX_BINDING_RECOVERY' and
         doc['traffic_allowed'] is False and doc['p8']=='NO-GO' and
         type(doc['sha256']) is dict and
         set(doc['sha256'])==FILES-{'manifest.json'},'root_manifest_invalid')
    for name in FILES-{'manifest.json'}:
        need(doc['sha256'][name]==sha(raw[name]),'root_file_hash_'+name)
    need(raw['root-recover.py']==Path(__file__).read_bytes(),
         'root_executable_hash_changed')
    need(raw['r34-deny-restore.nft']==expected_nft(),
         'root_nft_not_deny_only')
    need(sha(raw['source-f5-manifest.json'])==F5_DIGEST,
         'original_f5_manifest_not_pinned')
    f5=load_json(raw['source-f5-manifest.json'])
    need(f5.get('schema')=='ARDREC-R113-F5-readonly-preflight-v1' and
         f5.get('traffic_authorized') is False and f5.get('p8')=='NO-GO' and
         type(f5.get('files_sha256')) is dict,
         'f5_provenance_invalid')
    for key in ROLES:
        o=raw[key+'-original.xml']; c=raw[key+'-candidate.xml']
        need(binding(o,key)==binding(c,key,candidate=True),
             'root_binding_pair_invalid_'+key)
        tap=ROLES[key][2]
        need(sha(o)==f5['files_sha256']['binding_'+tap+'.stdout'],
             'historical_binding_hash_mismatch_'+key)
        root=ET.fromstring(o);root.find('filterref').set(
            'filter','ardrec-r113-'+key.replace('_','-')+'-tcp-v1')
        rendered=ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'
        need(xml_equal(rendered,c),'candidate_has_other_changes_'+key)
    return raw

def host(args, *, data=None, timeout=30):
    need(type(args) is list and args,'invalid_host_command')
    nft=args==['/usr/sbin/nft','-f','-'] or args==[
        '/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]
    allowed=False
    virsh=['/usr/bin/virsh','-c','qemu:///system']
    if args[:3]==virsh:
        allowed=args==virsh+['nwfilter-binding-list']
        for key,(role,net,tap,mac) in ROLES.items():
            allowed |= args in (
                virsh+['dumpxml','ardrec-r33-dev-'+role],
                virsh+['nwfilter-binding-dumpxml',tap],
                virsh+['nwfilter-binding-delete',tap],
                virsh+['nwfilter-binding-create',str(BUNDLE/(key+'-original.xml'))],
            )
    need(nft or allowed,'unapproved_host_command')
    if args==['/usr/sbin/nft','-f','-']:
        need(data==expected_nft(),'nft_restore_payload_invalid')
    else:
        need(data is None,'unexpected_stdin')
    p=subprocess.run(args,input=data,stdin=subprocess.DEVNULL if data is None else None,
                     capture_output=True,check=False,env=ENV,close_fds=True,timeout=timeout)
    need(p.returncode==0 and len(p.stdout)<262144 and len(p.stderr)<32768,
         'host_command_failed_'+args[0].rsplit('/',1)[-1])
    return p.stdout

def verify_nft(raw):
    d=load_json(raw)
    need(type(d) is dict and set(d)=={'nftables'},'nft_json_shape')
    rows=d['nftables']
    tables=[x['table'] for x in rows if 'table' in x]
    chains=[x['chain'] for x in rows if 'chain' in x]
    rules=[x['rule'] for x in rows if 'rule' in x]
    need(len(tables)==1 and len(chains)==3 and len(rules)==4 and
         tables[0].get('family')=='bridge' and tables[0].get('name')==TABLE,
         'nft_table_shape')
    need(set(c.get('name') for c in chains)=={'input','output','forward'} and
         all(c.get('policy')=='accept' and c.get('prio')==-200 and
             c.get('hook')==c.get('name') and c.get('type')=='filter' for c in chains),
         'nft_chain_shape')
    expected={('input','iifname'),('output','oifname'),('forward','iifname'),('forward','oifname')}
    seen=set()
    for r in rules:
        need(r.get('family')=='bridge' and r.get('table')==TABLE and
             len(r['expr'])==3,'nft_rule_shape')
        m,c,v=r['expr']
        need(v=={'drop':None} and set(c)=={'counter'} and
             set(c['counter'])=={'packets','bytes'} and
             all(type(x) is int and x>=0 for x in c['counter'].values()) and
             set(m)=={'match'},'nft_rule_not_deny')
        match=m['match']; left=match['left']
        need(match['op']=='==' and set(match['right']['set'])==TAPS and
             len(match['right']['set'])==6 and
             set(left)=={'meta'},'nft_match_scope')
        seen.add((r['chain'],left['meta']['key']))
    need(seen==expected,'nft_rules_missing_or_duplicate')


def verify_domain(raw,key,old):
    role,net,tap,mac=ROLES[key]
    need(b'<!' not in raw and 0<len(raw)<262144,'domain_xml_invalid')
    dom=ET.fromstring(raw)
    need(dom.tag=='domain' and dom.get('type')=='kvm' and
         dom.findtext('name')=='ardrec-r33-dev-'+role and
         dom.findtext('uuid')==binding(old,key),'domain_owner_invalid')
    matches=[]
    for nic in dom.findall('./devices/interface'):
        target=nic.find('target')
        if target is not None and target.get('dev')==tap:
            matches.append(nic)
    need(len(matches)==1,'domain_tap_count_invalid')
    nic=matches[0]; m=nic.find('mac'); src=nic.find('source')
    need(nic.get('type')=='network' and m is not None and
         m.get('address')==mac and src is not None and
         src.get('network')=='ardrec-r33-dev-net-'+net,
         'domain_mac_network_drift')


def present(raw,tap):
    txt=raw.decode('utf8','strict')
    rows=[x.strip().split() for x in txt.splitlines() if x.strip()]
    need(rows and any(x.lower()=='port' for x in rows[0]),
         'nwfilter_list_header_invalid')
    names=[row[0] for row in rows[1:] if row and set(row[0])!={'-'}]
    need(len(names)==len(set(names)) and
         all(re.fullmatch('[A-Za-z0-9_.-]+',x) for x in names),
         'nwfilter_list_invalid')
    return tap in names

@contextmanager
def lock():
    fd=os.open(BUNDLE/'manifest.json',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)

def restore(raw):
    events=[]
    virsh=['/usr/bin/virsh','-c','qemu:///system']
    # First privileged mutation: restore the scoped R34 DENY rules atomically.
    host(['/usr/sbin/nft','-f','-'],data=raw['r34-deny-restore.nft'])
    events.append('r34_atomic_deny_restored_first')
    verify_nft(host(['/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]))
    for key,(role,net,tap,mac) in ROLES.items():
        old=raw[key+'-original.xml']; candidate=raw[key+'-candidate.xml']
        verify_domain(host(virsh+['dumpxml','ardrec-r33-dev-'+role]),key,old)
        exists=present(host(virsh+['nwfilter-binding-list']),tap)
        if exists:
            current=host(virsh+['nwfilter-binding-dumpxml',tap])
            if xml_equal(current,old):
                events.append(key+'_already_deny');continue
            need(xml_equal(current,candidate),'unexpected_binding_'+key)
            host(virsh+['nwfilter-binding-delete',tap])
            events.append(key+'_known_candidate_removed')
        else:
            events.append(key+'_binding_missing')
        host(virsh+['nwfilter-binding-create',str(BUNDLE/(key+'-original.xml'))])
        need(xml_equal(host(virsh+['nwfilter-binding-dumpxml',tap]),old),
             'binding_restore_mismatch_'+key)
        events.append(key+'_deny_restored')
    verify_nft(host(['/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]))
    return {'result':'SIX_BINDING_DENY_RESTORED','events':events,
            'nft_deny_verified':True,'bindings':6,'traffic_allowed':False,'p8':'NO-GO'}

def main():
    ap=argparse.ArgumentParser()
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-root-bundle',action='store_true')
    group.add_argument('--attest-deny',action='store_true')
    group.add_argument('--restore-deny',action='store_true')
    args=ap.parse_args()
    try:
        raw=root_bundle()
        if args.check_root_bundle:
            report={'result':'ROOT_BUNDLE_VERIFIED','bindings':6,'host_writes':0,'p8':'NO-GO'}
        elif args.attest_deny:
            verify_nft(host(['/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]))
            for key,(role,net,tap,mac) in ROLES.items():
                base=['/usr/bin/virsh','-c','qemu:///system']
                old=raw[key+'-original.xml']
                verify_domain(host(base+['dumpxml','ardrec-r33-dev-'+role]),key,old)
                need(xml_equal(host(base+['nwfilter-binding-dumpxml',tap]),old),
                     'binding_deny_unverified_'+key)
            report={'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,
                    'host_writes':0,'p8':'NO-GO'}
        else:
            with lock():report=restore(raw)
        print(json.dumps(report,sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        print(json.dumps({'result':'STOP_DENY_REVIEW_REQUIRED','error':
                          type(exc).__name__+':'+str(exc)[:180],
                          'p8':'NO-GO'},sort_keys=True),file=sys.stderr)
        return 23

if __name__=='__main__':raise SystemExit(main())
