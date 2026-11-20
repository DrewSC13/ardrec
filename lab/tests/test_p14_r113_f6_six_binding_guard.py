"""R113-F6 negative/offline acceptance tests. Never calls real virsh/nft/sudo."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r113_f6_six_binding_guard as g

P=ROOT/'scripts/ardrec_p14_r113_f6_root_recover.py'
spec=importlib.util.spec_from_file_location('root_recover_f6',P)
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
UUID={'ssh':'11111111-2222-4333-8444-555555555555',
      'runner':'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      'ftp':'99999999-aaaa-4bbb-8ccc-dddddddddddd',
      'smb':'22222222-3333-4444-8555-666666666666'}


def binding(key,candidate=False):
    role,net,tap,mac=h.ROLES[key]
    root=ET.Element('filterbinding')
    own=ET.SubElement(root,'owner')
    ET.SubElement(own,'name').text='ardrec-r33-dev-'+role
    ET.SubElement(own,'uuid').text=UUID[role]
    ET.SubElement(root,'portdev',{'name':tap})
    ET.SubElement(root,'mac',{'address':mac})
    ref=ET.SubElement(root,'filterref',{
        'filter': 'ardrec-r113-'+key.replace('_','-')+'-tcp-v1'
                  if candidate else h.DENY})
    ET.SubElement(ref,'parameter',{'name':'MAC','value':mac})
    ET.SubElement(root,'backend',{'name':'iptables'})
    return ET.tostring(root,encoding='utf8',xml_declaration=True)+b'\n'

def domain(key):
    role,net,tap,mac=h.ROLES[key]
    root=ET.Element('domain',{'type':'kvm','id':'7'})
    ET.SubElement(root,'name').text='ardrec-r33-dev-'+role
    ET.SubElement(root,'uuid').text=UUID[role]
    dev=ET.SubElement(root,'devices')
    for label,(otherrole,othernet,othertap,othermac) in h.ROLES.items():
        if otherrole!=role:continue
        nic=ET.SubElement(dev,'interface',{'type':'network'})
        ET.SubElement(nic,'mac',{'address':othermac})
        ET.SubElement(nic,'source',{'network':'ardrec-r33-dev-net-'+othernet})
        ET.SubElement(nic,'target',{'dev':othertap})
    return ET.tostring(root,encoding='utf8')

def nft():
    rows=[{'table':{'family':'bridge','name':h.TABLE}}]
    for chain in ('input','output','forward'):
        rows.append({'chain':{'family':'bridge','table':h.TABLE,'name':chain,
                              'hook':chain,'type':'filter','prio':-200,'policy':'accept'}})
    for chain,key in (('input','iifname'),('output','oifname'),
                      ('forward','iifname'),('forward','oifname')):
        rows.append({'rule':{'family':'bridge','table':h.TABLE,'chain':chain,
                   'expr':[{'match':{'left':{'meta':{'key':key}},'op':'==',
                                     'right':{'set':sorted(h.TAPS)}}},
                           {'counter':{'packets':0,'bytes':0}}, {'drop':None}]}})
    return json.dumps({'nftables':rows}).encode()

def f5():
    rows={}
    rows['f11_hook_sha256.stdout']=(g.R34_HOOK+'  /etc/libvirt/hooks/test\n').encode()
    root=ET.Element('filter',{'name':g.DENY})
    rule=ET.SubElement(root,'rule',{'action':'drop','direction':'inout'})
    ET.SubElement(rule,'all')
    rows['deny_filter.stdout']=ET.tostring(root)
    rows['nft_r34.stdout']=nft()
    for key,(role,net,tap,mac) in h.ROLES.items():
        rows['binding_'+tap+'.stdout']=binding(key)
        rows['vm_'+role+'_xml.stdout']=domain(key)
    doc={'schema':'ARDREC-R113-F5-readonly-preflight-v1',
         'host_mutations':0,'traffic_authorized':False,'p8':'NO-GO',
         'files_sha256':{key:g.sha(value) for key,value in rows.items()}}
    rows['manifest.json']=g.canonical(doc)
    return rows

class FakeHost:
    def __init__(self, states=None):
        self.states={k:(states or {}).get(k,'deny') for k in h.ROLES}
        self.calls=[]
        self.fault=None
    def __call__(self,args,*,data=None,timeout=30):
        self.calls.append((tuple(args),data))
        if self.fault and self.fault(args):raise h.DenyGuardError('mock_host_fault')
        if args[:2]==['/usr/sbin/nft','-f']:
            if data!=h.expected_nft():raise ValueError('unexpected nft')
            return b''
        if args[:1]==['/usr/sbin/nft']:
            return nft()
        operation=args[3]
        if operation=='nwfilter-binding-list':
            active=[h.ROLES[k][2] for k,v in self.states.items() if v!='missing']
            return ('Port dev    Filter\n--------------------\n'+
                    ''.join(x+'    any-filter\n' for x in active)).encode()
        if operation=='dumpxml':
            role=args[4].replace('ardrec-r33-dev-','')
            return domain(next(k for k,v in h.ROLES.items() if v[0]==role))
        if operation=='nwfilter-binding-dumpxml':
            key=next(k for k,v in h.ROLES.items() if v[2]==args[4])
            state=self.states[key]
            if state=='deny':return binding(key)
            if state=='candidate':return binding(key,True)
            if state=='unknown':return binding(key).replace(h.DENY.encode(),b'foreign-filter')
            raise ValueError('missing')
        if operation=='nwfilter-binding-delete':
            key=next(k for k,v in h.ROLES.items() if v[2]==args[4])
            self.states[key]='missing'
            return b''
        if operation=='nwfilter-binding-create':
            key=Path(args[4]).name.removesuffix('-original.xml')
            self.states[key]='deny'
            return b''
        raise AssertionError(args)

def root_payload():
    raw={'r34-deny-restore.nft':h.expected_nft()}
    for key in h.ROLES:
        raw[key+'-original.xml']=binding(key)
        raw[key+'-candidate.xml']=binding(key,True)
    return raw

class Contract(unittest.TestCase):
    def test_exact_six_taps(self):self.assertEqual(len(h.TAPS),6)
    def test_exact_six_roles(self):self.assertEqual(set(h.ROLES),set(g.ROLES))
    def test_source_role_agreement(self):self.assertEqual(g.ROLES,h.ROLES)
    def test_nft_equals_existing_r553(self):
        from ardrec.coordination import r553_transition_guard as r553
        self.assertEqual(h.expected_nft(),r553.expected_nft(allow=False))
    def test_nft_no_accept(self):self.assertNotIn(b'counter accept',h.expected_nft())
    def test_no_global_flush(self):self.assertNotIn(b'flush ruleset',h.expected_nft())
    def test_original_all_six(self):
        for key in h.ROLES:self.assertEqual(h.binding(binding(key),key),UUID[h.ROLES[key][0]])
    def test_candidate_all_six(self):
        for key in h.ROLES:self.assertEqual(h.binding(binding(key,True),key,candidate=True),UUID[h.ROLES[key][0]])
    def test_candidate_from_original(self):
        for key in g.ROLES:self.assertTrue(h.xml_equal(g.candidate(binding(key),key),binding(key,True)))
    def test_wrong_mac_rejected(self):
        with self.assertRaises(g.GuardError):
            g.binding(binding('ssh').replace(b'ad:30:02',b'ad:30:03'),'ssh')
    def test_wrong_filter_rejected(self):
        with self.assertRaises(g.GuardError):
            g.binding(binding('ftp',True),'ftp')
    def test_wrong_role_rejected(self):
        with self.assertRaises(g.GuardError):g.binding(binding('ssh'),'ftp')
    def test_xml_entity_rejected(self):
        with self.assertRaises(h.DenyGuardError):h.binding(b'<!ENTITY x "y">','ssh')
    def test_f5_fixture_structure_valid(self):
        f=f5()
        with patch.object(g,'F5_DIGEST',g.sha(f['manifest.json'])):
            self.assertTrue(g.check_f5(f))
    def test_f5_tampered_capture_rejected(self):
        f=f5()
        with patch.object(g,'F5_DIGEST',g.sha(f['manifest.json'])):
            f['binding_a33d31t.stdout']+=b'\n'
            with self.assertRaises(g.GuardError):g.check_f5(f)
    def test_f5_missing_binding_rejected(self):
        f=f5()
        with patch.object(g,'F5_DIGEST',g.sha(f['manifest.json'])):
            del f['binding_a33d32r.stdout']
            with self.assertRaises(g.GuardError):g.check_f5(f)
    def test_f5_bad_firewall_rejected(self):
        f=f5();doc=json.loads(f['nft_r34.stdout']);doc['nftables'][-1]['rule']['expr'][-1]={'accept':None}
        f['nft_r34.stdout']=json.dumps(doc).encode()
        m=json.loads(f['manifest.json']);m['files_sha256']['nft_r34.stdout']=g.sha(f['nft_r34.stdout'])
        f['manifest.json']=g.canonical(m)
        with patch.object(g,'F5_DIGEST',g.sha(f['manifest.json'])):
            with self.assertRaises(g.GuardError):g.check_f5(f)
    def test_f5_bundle_deterministic(self):
        f=f5()
        with patch.object(g,'F5_DIGEST',g.sha(f['manifest.json'])):
            one=g.prepare(f,b'root-helper-test'); two=g.prepare(f,b'root-helper-test')
        self.assertEqual(one,two)
        self.assertEqual(len(one),16)
    def test_verify_live_nft(self):h.verify_nft(nft())
    def test_verify_live_nft_allow_rejected(self):
        d=json.loads(nft());d['nftables'][-1]['rule']['expr'][-1]={'accept':None}
        with self.assertRaises(h.DenyGuardError):h.verify_nft(json.dumps(d).encode())
    def test_verify_domain_each(self):
        for key in h.ROLES:h.verify_domain(domain(key),key,binding(key))
    def test_domain_drift_rejected(self):
        with self.assertRaises(h.DenyGuardError):
            h.verify_domain(domain('ssh'), 'runner_smb',binding('runner_smb'))
    def test_restore_all_six_deny_no_binding_changes(self):
        fake=FakeHost()
        with patch.object(h,'host',fake):d=h.restore(root_payload())
        self.assertEqual(d['result'],'SIX_BINDING_DENY_RESTORED')
        self.assertEqual(set(fake.states.values()),{'deny'})
        self.assertFalse(any(x[0][3]=='nwfilter-binding-delete' for x in fake.calls if len(x[0])>3))
        self.assertEqual(fake.calls[0][0],('/usr/sbin/nft','-f','-'))
    def test_restore_all_six_candidates(self):
        fake=FakeHost({k:'candidate' for k in h.ROLES})
        with patch.object(h,'host',fake):h.restore(root_payload())
        self.assertEqual(set(fake.states.values()),{'deny'})
        self.assertEqual(sum(c[0][3]=='nwfilter-binding-delete' for c in fake.calls if len(c[0])>3),6)
    def test_restore_missing_binding(self):
        fake=FakeHost({'ftp':'missing'})
        with patch.object(h,'host',fake):h.restore(root_payload())
        self.assertEqual(fake.states['ftp'],'deny')
    def test_unknown_binding_never_deleted(self):
        fake=FakeHost({'smb':'unknown'})
        with patch.object(h,'host',fake):
            with self.assertRaises(h.DenyGuardError):h.restore(root_payload())
        self.assertEqual(fake.states['smb'],'unknown')
        self.assertEqual(fake.calls[0][0],('/usr/sbin/nft','-f','-'))
        self.assertFalse(any(x[0][3]=='nwfilter-binding-delete' for x in fake.calls if len(x[0])>3))
    def test_fault_before_binding_write(self):
        fake=FakeHost({'ftp':'candidate'})
        fake.fault=lambda x: x[:2]==['/usr/sbin/nft','-f']
        with patch.object(h,'host',fake):
            with self.assertRaises(h.DenyGuardError):h.restore(root_payload())
        self.assertFalse(any('nwfilter-binding' in c[0] for c in fake.calls if len(c[0])>3))
    def test_host_allowlist_rejects_guest_exec(self):
        with self.assertRaises(h.DenyGuardError):h.host(['/usr/bin/virsh','-c','qemu:///system','qemu-agent-command','x'])
    def test_host_allowlist_rejects_service_start(self):
        with self.assertRaises(h.DenyGuardError):h.host(['/usr/bin/systemctl','start','smbd.service'])
    def test_host_nft_input_must_match_exactly(self):
        with self.assertRaises(h.DenyGuardError):h.host(['/usr/sbin/nft','-f','-'],data=b'flush ruleset\n')
    def test_filter_unknown_rejected(self):
        with self.assertRaises(h.DenyGuardError):h.binding(binding('ssh').replace(h.DENY.encode(),b'foreign'), 'ssh')

if __name__=='__main__':unittest.main()
