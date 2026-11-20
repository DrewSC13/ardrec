"""ARDREC R113-F6: build a six-NIC DENY-only recovery bundle from the pinned F5 capture.

No host changes. Only authenticated F5 evidence can become immutable root guard input.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from ardrec.coordination import r553_transition_guard as r553

SCHEMA = 'ardrec-r113-f6-six-deny-root-v1'
F5 = Path('/home/cicada/ardrec-lab/r113-f5-host-AI6gBysL')
F5_DIGEST = 'a29b0c0e91ca139f1e2969d81dec10677c64460f6c6aead397cc1a68d8bc43ba'
R34_HOOK = '1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b'
DEST = Path('/var/lib/ardrec/r113-six-deny-guard-v1')
DENY = 'ardrec-r33-block-until-containment'
ROLES = {
    'runner_ssh': ('runner','ssh','a33d30r','52:54:00:ad:30:01'),
    'ssh': ('ssh','ssh','a33d30t','52:54:00:ad:30:02'),
    'runner_ftp': ('runner','ftp','a33d31r','52:54:00:ad:31:01'),
    'ftp': ('ftp','ftp','a33d31t','52:54:00:ad:31:02'),
    'runner_smb': ('runner','smb','a33d32r','52:54:00:ad:32:01'),
    'smb': ('smb','smb','a33d32t','52:54:00:ad:32:02'),
}

class GuardError(ValueError):
    pass

def need(ok, msg):
    if not ok:
        raise GuardError(msg)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(doc):
    return (json.dumps(doc, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')

def pairs(entries):
    result={}
    for key,value in entries:
        need(key not in result,'DUPLICATE_JSON_KEY')
        result[key]=value
    return result

def load_json(raw):
    need(type(raw) is bytes and len(raw)<524288,'JSON_SIZE_INVALID')
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False,'JSON_NONFINITE'))

def binding(raw, key, *, allow=False):
    """Validate all identity and topology, never infer owner from port alone."""
    need(key in ROLES and type(raw) is bytes and len(raw) < 16384
         and b'<!' not in raw,'BINDING_BYTES_INVALID')
    try: root=ET.fromstring(raw)
    except ET.ParseError as exc: raise GuardError('BINDING_XML_INVALID') from exc
    role, network, tap, mac=ROLES[key]
    need(root.tag=='filterbinding' and not root.attrib and
         [child.tag for child in root]==['owner','portdev','mac','filterref','backend'],
         'BINDING_SHAPE_INVALID_'+key)
    owner,port,mac_elem,ref,backend=list(root)
    owner_name=owner.findtext('name')
    uuid=owner.findtext('uuid')
    need(not owner.attrib and [x.tag for x in owner]==['name','uuid'] and
         owner_name=='ardrec-r33-dev-'+role and
         re.fullmatch('[0-9a-fA-F-]{36}',uuid or '') is not None and
         port.attrib=={'name':tap} and mac_elem.attrib=={'address':mac} and
         len(port)==0 and len(mac_elem)==0 and
         len(ref)==1 and ref[0].tag=='parameter' and
         ref[0].attrib=={'name':'MAC','value':mac} and
         len(ref[0])==0 and
         backend.attrib=={'name':'iptables'} and len(backend)==0,
         'BINDING_IDENTITY_INVALID_'+key)
    expected=('ardrec-r113-'+key.replace('_','-')+'-tcp-v1') if allow else DENY
    need(ref.attrib=={'filter':expected},'BINDING_FILTER_INVALID_'+key)
    return uuid

def candidate(raw,key):
    binding(raw,key)
    root=ET.fromstring(raw)
    root.find('filterref').set('filter','ardrec-r113-'+key.replace('_','-')+'-tcp-v1')
    data=ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'
    need(binding(data,key,allow=True)==binding(raw,key),'CANDIDATE_IDENTITY_CHANGED')
    return data

def check_f5(files):
    """F5 captured bytes, not host probing. Fail closed on any missing or changed evidence."""
    need(type(files) is dict and 'manifest.json' in files,'F5_FILES_MISSING')
    need(sha(files['manifest.json'])==F5_DIGEST,'F5_MANIFEST_DRIFT')
    manifest=load_json(files['manifest.json'])
    need(manifest.get('schema')=='ARDREC-R113-F5-readonly-preflight-v1' and
         manifest.get('host_mutations')==0 and
         manifest.get('traffic_authorized') is False and
         manifest.get('p8')=='NO-GO','F5_NOT_READ_ONLY')
    declared=manifest.get('files_sha256')
    need(type(declared) is dict and set(declared)==set(files)-{'manifest.json'},
         'F5_FILES_SCOPE_CHANGED')
    need(all(sha(files[n])==declared[n] for n in declared),'F5_FILE_DRIFT')
    hook=files['f11_hook_sha256.stdout'].decode('ascii').split()
    need(hook and hook[0]==R34_HOOK,'F11_HOOK_CHANGED')
    xml=ET.fromstring(files['deny_filter.stdout'])
    rules=xml.findall('rule')
    need(xml.get('name')==DENY and len(rules)==1 and
         rules[0].get('action')=='drop' and rules[0].get('direction')=='inout' and
         rules[0].find('all') is not None,'DENY_FILTER_DRIFT')
    for key,(role,net,tap,mac) in ROLES.items():
        binding(files['binding_'+tap+'.stdout'],key)
        vm=ET.fromstring(files['vm_'+role+'_xml.stdout'])
        need(vm.findtext('name')=='ardrec-r33-dev-'+role and
             vm.findtext('uuid')==binding(files['binding_'+tap+'.stdout'],key),
             'VM_OWNER_DRIFT_'+key)
        matches=[]
        for nic in vm.findall('./devices/interface'):
            target=nic.find('target'); m=nic.find('mac'); src=nic.find('source')
            if target is not None and target.get('dev')==tap:
                matches.append((nic,m,src))
        need(len(matches)==1,'VM_TAP_DRIFT_'+key)
        nic,m,src=matches[0]
        need(nic.get('type')=='network' and m is not None and m.get('address')==mac
             and src is not None and src.get('network')=='ardrec-r33-dev-net-'+net,
             'VM_NETWORK_DRIFT_'+key)
    nft=load_json(files['nft_r34.stdout'])
    rows=nft.get('nftables',[])
    table=[x['table'] for x in rows if 'table' in x]
    chains=[x['chain'] for x in rows if 'chain' in x]
    rules=[x['rule'] for x in rows if 'rule' in x]
    need(len(table)==1 and table[0].get('name')=='ardrec_r34_guard' and
         table[0].get('family')=='bridge' and len(chains)==3 and len(rules)==4,
         'F5_NFT_SHAPE_INVALID')
    need(set(c['name'] for c in chains)=={'input','output','forward'} and
         all(c.get('policy')=='accept' and c.get('prio')==-200 for c in chains),
         'F5_NFT_CHAINS_INVALID')
    taps={v[2] for v in ROLES.values()}
    expected={('input','iifname'),('output','oifname'),('forward','iifname'),('forward','oifname')}
    seen=set()
    for rule in rules:
        match,counter,verdict=rule['expr']
        need(verdict=={'drop':None} and 'counter' in counter and 'match' in match,
             'F5_NFT_NON_DENY')
        m=match['match']
        key=m['left']['meta']['key']
        need(m.get('op')=='==' and set(m['right']['set'])==taps,'F5_NFT_WRONG_SCOPE')
        seen.add((rule['chain'],key))
    need(seen==expected,'F5_NFT_RULESET_DRIFT')
    return True

def prepare(files, root_helper):
    check_f5(files)
    need(type(root_helper) is bytes and len(root_helper)<50000,'HELPER_INVALID')
    payload={
        'root-recover.py':root_helper,
        'r34-deny-restore.nft':r553.expected_nft(allow=False),
        'source-f5-manifest.json':files['manifest.json'],
    }
    for key,(_,_,tap,_) in ROLES.items():
        original=files['binding_'+tap+'.stdout']
        payload[key+'-original.xml']=original
        payload[key+'-candidate.xml']=candidate(original,key)
    doc={'schema':SCHEMA,'f5_sha256':F5_DIGEST,
         'purpose':'DENY_ONLY_SIX_BINDING_RECOVERY',
         'traffic_allowed':False,'p8':'NO-GO',
         'sha256':{n:sha(v) for n,v in sorted(payload.items())}}
    payload['manifest.json']=canonical(doc)
    return payload
