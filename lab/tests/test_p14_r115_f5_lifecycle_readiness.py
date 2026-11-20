"""F5 regression: isolated mocks only, zero sudo/libvirt/nft executions."""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from ardrec.coordination import r115_f5_lifecycle_readiness as f
from ardrec.coordination import r113_f6_six_binding_guard as six

UUID = {'runner':'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        'ssh':'11111111-2222-4333-8444-555555555555',
        'ftp':'99999999-aaaa-4bbb-8ccc-dddddddddddd',
        'smb':'22222222-3333-4444-8555-666666666666'}


def nft():
    taps=sorted(x[2] for x in six.ROLES.values())
    rows=[{'table':{'family':'bridge','name':'ardrec_r34_guard'}}]
    for chain in ('input','output','forward'):
        rows.append({'chain':{'family':'bridge','table':'ardrec_r34_guard',
                              'name':chain,'hook':chain,'type':'filter','prio':-200,
                              'policy':'accept'}})
    for chain,key in (('input','iifname'),('output','oifname'),('forward','iifname'),('forward','oifname')):
        rows.append({'rule':{'family':'bridge','table':'ardrec_r34_guard',
                             'chain':chain,'expr':[
            {'match':{'left':{'meta':{'key':key}},'op':'==','right':{'set':taps}}},
            {'counter':{'packets':0,'bytes':0}},{'drop':None}]}})
    return json.dumps({'nftables':rows}).encode()


def domain(role):
    root=ET.Element('domain',{'type':'kvm'})
    ET.SubElement(root,'name').text='ardrec-r33-dev-'+role
    ET.SubElement(root,'uuid').text=UUID[role]
    dev=ET.SubElement(root,'devices')
    ET.SubElement(dev,'disk',{'device':'disk'})
    for key,(r,net,tap,mac) in six.ROLES.items():
        if r!=role:continue
        nic=ET.SubElement(dev,'interface',{'type':'network'})
        ET.SubElement(nic,'mac',{'address':mac})
        ET.SubElement(nic,'source',{'network':'ardrec-r33-dev-net-'+net})
        ET.SubElement(nic,'target',{'dev':tap})
        ET.SubElement(nic,'model',{'type':'virtio'})
        ET.SubElement(nic,'filterref',{'filter':six.DENY})
    return ET.tostring(root,encoding='utf8')


def binding(key,active_deny=True):
    role,net,tap,mac=six.ROLES[key]
    root=ET.Element('filterbinding')
    owner=ET.SubElement(root,'owner')
    ET.SubElement(owner,'name').text='ardrec-r33-dev-'+role
    ET.SubElement(owner,'uuid').text=UUID[role]
    ET.SubElement(root,'portdev',{'name':tap})
    ET.SubElement(root,'mac',{'address':mac})
    label=six.DENY if active_deny else 'ardrec-r113-'+key.replace('_','-')+'-tcp-v1'
    ref=ET.SubElement(root,'filterref',{'filter':label})
    ET.SubElement(ref,'parameter',{'name':'MAC','value':mac})
    ET.SubElement(root,'backend',{'name':'iptables'})
    return ET.tostring(root,encoding='utf8')


def fixture(*, states=None, active=(), nft_bytes=None):
    states=states or {k:'OFF' for k in f.VMS}
    when='2026-11-20T14:30:00Z'
    active=set(active)
    taps=[six.ROLES[k][2] for k in active]
    listing='Port dev    Filter\n----------------------\n'+''.join(t+'    '+six.DENY+'\n' for t in taps)
    outputs={
        'nft':nft_bytes if nft_bytes is not None else nft(),
        'helper_sha': (f.f4.HELPER_SHA+'  '+str(f.f4.HELPER)+'\n').encode(),
        'hook_sha': (six.R34_HOOK+'  '+str(f.f4.f3.HOOK)+'\n').encode(),
        'bindings_list':listing.encode(),
    }
    for k in f.VMS:
        outputs['state_'+k]=b'shut off\n' if states[k]=='OFF' else b'running\n'
        outputs['xml_'+k]=domain(k)
    for key in six.ROLES:
        outputs['binding_'+key]=binding(key) if key in active else None
    probes={}
    for k in f.READS:
        raw=outputs[k]
        probes[k]={'rc':0 if raw is not None else 1,
                   'timeout':False,'truncated':False,'start':when,'end':when,
                   'stdout':base64.b64encode(raw or b'').decode(),
                   'stderr':base64.b64encode(b'not found' if raw is None else b'').decode()}
    return {'schema':f.SCHEMA,'start':when,'end':when,'probes':probes,
            'source':'LOCAL_ROOT_READONLY_NOT_AUTHORITY','traffic_authorized':False}

class Lifecycle(unittest.TestCase):
    def test_only_static_read_allowlist(self):
        self.assertEqual(len(f.READS),18)
        text='\n'.join(' '.join(v) for v in f.READS.values())
        for dangerous in ('start','nwfilter-binding-create','nwfilter-binding-delete','-f -','--restore-deny'):
            self.assertNotIn(dangerous,text)
    def test_offline_all_absent_expected(self):
        r=f.report(fixture())
        self.assertEqual(r['lifecycle_stage'],'OFFLINE_DENY_BASELINE_MATCH')
        self.assertEqual(r['nft'],'MATCH')
        self.assertEqual(set(r['bindings'].values()),{'ABSENT_WHILE_OFF'})
        self.assertEqual(r['a3']['SERVICE_READY'],'FALSO')
        self.assertEqual(r['a3']['LAB_ISOLATION_CONFIRMED'],'ND')
        self.assertEqual(r['a5_dispatch'],'NO-GO')
    def test_no_bindings_while_running_blocks(self):
        r=f.report(fixture(states={k:'RUNNING' for k in f.VMS}))
        self.assertEqual(r['lifecycle_stage'],'INCOMPLETE_OR_TRANSITION_NO_GO')
        self.assertEqual(set(r['bindings'].values()),{'MISSING_OR_TRANSITION'})
        self.assertEqual(r['a3']['SERVICE_READY'],'ND')
    def test_partial_lifecycle_blocks(self):
        r=f.report(fixture(states={'runner':'RUNNING','ssh':'OFF','ftp':'OFF','smb':'OFF'}))
        self.assertEqual(r['lifecycle_stage'],'INCOMPLETE_OR_TRANSITION_NO_GO')
        self.assertEqual(r['a3']['SERVICE_READY'],'FALSO')
    def test_six_running_denies_do_not_grant(self):
        d=fixture(states={k:'RUNNING' for k in f.VMS},active=six.ROLES)
        r=f.report(d)
        self.assertEqual(r['lifecycle_stage'],'RUNNING_SIX_DENY_BINDINGS_MATCH')
        self.assertEqual(set(r['bindings'].values()),{'DENY_MATCH'})
        self.assertEqual(r['a3']['LAB_ISOLATION_CONFIRMED'],'ND')
        self.assertEqual(r['a5_dispatch'],'NO-GO')
    def test_nft_wrong_rule(self):
        v=nft().replace(b'"drop": null',b'"accept": null')
        self.assertEqual(f.report(fixture(nft_bytes=v))['lifecycle_stage'],'DRIFT_NO_GO')
    def test_candidate_binding_is_not_deny(self):
        d=fixture(states={k:'RUNNING' for k in f.VMS},active=six.ROLES)
        raw=binding('ftp',False)
        d['probes']['binding_ftp']['stdout']=base64.b64encode(raw).decode()
        self.assertEqual(f.report(d)['bindings']['ftp'],'DRIFT')
        self.assertEqual(f.report(d)['lifecycle_stage'],'DRIFT_NO_GO')
    def test_domain_identity_mismatch(self):
        d=fixture()
        raw=domain('ftp').replace(b'52:54:00:ad:31:02',b'52:54:00:ad:31:03')
        d['probes']['xml_ftp']['stdout']=base64.b64encode(raw).decode()
        self.assertEqual(f.report(d)['vm_definitions']['ftp'],'DRIFT')
    def test_bad_helper_hash(self):
        d=fixture();raw=b'0'*64+b'  '+str(f.f4.HELPER).encode()+b'\n'
        d['probes']['helper_sha']['stdout']=base64.b64encode(raw).decode()
        self.assertEqual(f.report(d)['helper'],'DRIFT')
    def test_unreadable_helper_not_approved(self):
        d=fixture();d['probes']['helper_sha']['rc']=1
        self.assertEqual(f.report(d)['lifecycle_stage'],'INCOMPLETE_OR_TRANSITION_NO_GO')
    def test_wrong_hook(self):
        d=fixture();raw=b'0'*64+b'  '+str(f.f4.f3.HOOK).encode()+b'\n'
        d['probes']['hook_sha']['stdout']=base64.b64encode(raw).decode()
        self.assertEqual(f.report(d)['f11_hook'],'DRIFT')
    def test_invalid_rc_bool(self):
        d=fixture();d['probes']['nft']['rc']=False
        with self.assertRaises(f.Stop):f.report(d)
    def test_unexpected_extra_probe(self):
        d=fixture();d['probes']['anything_else']=d['probes']['nft']
        with self.assertRaises(f.Stop):f.report(d)
    def test_reject_bad_b64(self):
        d=fixture();d['probes']['nft']['stdout']='!!'
        with self.assertRaises(f.Stop):f.report(d)
    def test_reject_noncanonical_b64(self):
        d=fixture();d['probes']['nft']['stdout']='a=== '
        with self.assertRaises(f.Stop):f.report(d)
    def test_binding_list_unreadable_stays_nd(self):
        d=fixture();d['probes']['bindings_list']['rc']=1
        self.assertEqual(set(f.report(d)['bindings'].values()),{'ND'})
    def test_elapsed_window_rejected(self):
        d=fixture();d['end']='2026-11-20T14:41:00Z'
        with self.assertRaises(f.Stop):f.report(d)
    def test_capture_runs_allowlisted_reads_only(self):
        calls=[]
        def runner(args,**kwargs):
            calls.append(tuple(args))
            self.assertTrue(args[:3]==['/usr/bin/sudo','-n','--'])
            self.assertNotIn('shell',args)
            return subprocess.CompletedProcess(args,0,b'',b'')
        when=lambda:datetime(2026,11,20,14,30,tzinfo=timezone.utc)
        d=f.capture(runner=runner,clock=when)
        self.assertEqual(len(calls),18)
        f.validate(d)
    def test_offline_with_unexpected_binding_stays_blocked(self):
        r=f.report(fixture(active=('ftp',)))
        self.assertEqual(r['lifecycle_stage'],'INCOMPLETE_OR_TRANSITION_NO_GO')
        self.assertEqual(r['a5_dispatch'],'NO-GO')
    def test_missing_service_is_not_vulnerability(self):
        r=f.report(fixture())
        self.assertEqual(r['a6'],'ND')
        self.assertEqual(r['p8'],'NO-GO')
        self.assertFalse(r['authority_attested'])

if __name__=='__main__':unittest.main()
