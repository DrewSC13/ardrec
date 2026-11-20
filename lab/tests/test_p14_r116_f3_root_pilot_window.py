"""R116-F3 adversarial, nonroot test: no root staging or network access."""
from __future__ import annotations
import base64
from datetime import datetime,timezone,timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r116_f3_pilot_session_policy as m

REPO=Path(__file__).resolve().parents[2]
STAGE=REPO/'scripts/ardrec_p14_r116_f3_root_stage.py'
ROOT=REPO/'scripts/ardrec_p14_r116_f3_root_pilot.py'
LOCK=REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json'

def import_script(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

r=import_script(ROOT,'test_r116_f3_root_pilot')
s=import_script(STAGE,'test_r116_f3_root_stage')
NOW=datetime(2026,11,20,17,0,0,tzinfo=timezone.utc)
HEAD='e193b1dcf97f72ba4245fc7dfc6d0d4b9814eecc'
CAT='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'

def budget():return dict(max_connections=1,ordinary_attempts=1,additional_attempts=0,timeout_seconds=8,max_recv_bytes=1024,max_recv_calls=8,
                         max_lines=10,read_size=256,max_output_bytes=4096,memory_mib=128)

def review():return {'document_status':'DOCUMENT_SIGNED','head':HEAD,'catalog_sha256':CAT,
    'family_id':'FTP-T01','physical_pilot_session_attested':False,
    'authorized_to_connect_by_module':False,'p8':'NO-GO','a6':'ND',
    'budget':budget(),'pilot_sha256':'a'*64,'scope_authorization_sha256':'b'*64}

def guard():return {'deny':'MATCH','p8':'NO-GO','host_writes':0,
    'states':{'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'},
    'policy':{'active':list(m.ALLOWED_BINDINGS),'absent':['smb'],
              'active_count':5,'absent_count':1,'allow_traffic':False,'p8':'NO-GO'}}

def nft():
    rows=[b'flush table bridge ardrec_r34_guard\n']
    for i in range(4):
        direction=(b'a33d31r" oifname "a33d31t' if i<2 else
                   b'a33d31t" oifname "a33d31r')
        proto=(b'ether type arp ' if i%2==0 else b'ip protocol tcp tcp dport 21 ')
        rows.append(b'add rule bridge ardrec_r34_guard forward iifname "'+direction+
           b'" ip saddr 10.203.31.1 ip daddr 10.203.31.2 '+proto+b'counter accept\n')
    for chain in ('input','output','forward','forward'):
        rows.append(('add rule bridge ardrec_r34_guard '+chain+' counter drop\n').encode())
    return b''.join(rows)

class Policy(unittest.TestCase):
    def test_schema(self):self.assertIn('ROOT-SESSION',m.SCHEMA)
    def test_capabilities(self):self.assertFalse(m.capabilities()['installs_or_arms_automatically'])
    def test_session_valid(self):self.assertEqual(m.session_id('a'*16),'a'*16)
    def test_session_upper_refused(self):
        with self.assertRaises(m.Stop):m.session_id('A'*16)
    def test_session_length(self):
        for v in ('','a'*15,'a'*17,'hello','a'*15+'z'):
            with self.subTest(v=v),self.assertRaises(m.Stop):m.session_id(v)
    def test_time_naive(self):
        with self.assertRaises(m.Stop):m.timestamp(datetime(2026,1,1))
    def test_time_aware(self):self.assertEqual(m.timestamp(NOW),NOW)
    def test_signed(self):
        x=m.signed_grant(review(),head=HEAD,catalog_sha=CAT,now=NOW,
                         permit_expiry=NOW+timedelta(seconds=50))
        self.assertEqual(x['p8'],'NO-GO')
    def test_signed_missing(self):
        d=review();d['document_status']='ND'
        with self.assertRaises(m.Stop):m.signed_grant(d,head=HEAD,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_signed_head(self):
        with self.assertRaises(m.Stop):m.signed_grant(review(),head='c'*40,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_signed_catalog(self):
        with self.assertRaises(m.Stop):m.signed_grant(review(),head=HEAD,catalog_sha='c'*64,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_signed_p8_false_assertion(self):
        x=review();x['p8']='GO'
        with self.assertRaises(m.Stop):m.signed_grant(x,head=HEAD,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_signed_a6_false_assertion(self):
        x=review();x['a6']='VERDADERO'
        with self.assertRaises(m.Stop):m.signed_grant(x,head=HEAD,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_signed_physical_false_assertion(self):
        x=review();x['physical_pilot_session_attested']=True
        with self.assertRaises(m.Stop):m.signed_grant(x,head=HEAD,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_budget_hard_caps(self):
        for field,value in [('timeout_seconds',11),('max_recv_bytes',4097),
            ('max_recv_calls',17),('read_size',513),('max_lines',17),
            ('max_output_bytes',8193),('memory_mib',513)]:
            x=review();x['budget'][field]=value
            with self.subTest(field=field),self.assertRaises(m.Stop):
                m.signed_grant(x,head=HEAD,catalog_sha=CAT,now=NOW,
                    permit_expiry=NOW+timedelta(seconds=50))
    def test_budget_bool(self):
        x=review();x['budget']['timeout_seconds']=True
        with self.assertRaises(m.Stop):m.signed_grant(x,head=HEAD,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW+timedelta(seconds=50))
    def test_signed_expired(self):
        with self.assertRaises(m.Stop):m.signed_grant(review(),head=HEAD,catalog_sha=CAT,
            now=NOW,permit_expiry=NOW)
    def test_denies(self):self.assertTrue(m.five_one(guard()))
    def test_deny_missing(self):
        x=guard();x['policy']['active_count']=4
        with self.assertRaises(m.Stop):m.five_one(x)
    def test_deny_smb_running(self):
        x=guard();x['states']['smb']='RUNNING'
        with self.assertRaises(m.Stop):m.five_one(x)
    def test_deny_allow(self):
        x=guard();x['policy']['allow_traffic']=True
        with self.assertRaises(m.Stop):m.five_one(x)
    def test_nft(self):self.assertTrue(m.candidate_rules(nft()))
    def test_nft_nonftp_accept(self):
        with self.assertRaises(m.Stop):m.candidate_rules(nft().replace(b'a33d31r',b'a33d30'))
    def test_nft_port_change(self):
        with self.assertRaises(m.Stop):m.candidate_rules(nft().replace(b'tcp dport 21',b'tcp dport 22'))
    def test_nft_extra_accept(self):
        with self.assertRaises(m.Stop):m.candidate_rules(nft()+b'add rule bridge ardrec_r34_guard forward counter accept\n')
    def test_nft_global_flush(self):
        with self.assertRaises(m.Stop):m.candidate_rules(nft().replace(b'flush table bridge',b'flush ruleset'))
    def test_timer_valid(self):
        p={'LoadState':'loaded','ActiveState':'active','Unit':'unit.service',
           'NextElapseUSecMonotonic':'145000000'}
        self.assertEqual(m.timer_remaining(p,monotonic_seconds=100,expected_unit='unit'),45.0)
    def test_timer_expired(self):
        p={'LoadState':'loaded','ActiveState':'active','Unit':'unit.service',
           'NextElapseUSecMonotonic':'100000000'}
        with self.assertRaises(m.Stop):m.timer_remaining(p,monotonic_seconds=100,expected_unit='unit')
    def test_timer_not_active(self):
        p={'LoadState':'loaded','ActiveState':'inactive','Unit':'unit.service',
           'NextElapseUSecMonotonic':'145000000'}
        with self.assertRaises(m.Stop):m.timer_remaining(p,monotonic_seconds=100,expected_unit='unit')
    def test_timer_max(self):
        p={'LoadState':'loaded','ActiveState':'active','Unit':'unit.service',
           'NextElapseUSecMonotonic':'200000000'}
        with self.assertRaises(m.Stop):m.timer_remaining(p,monotonic_seconds=100,expected_unit='unit')
    def test_signed_margin(self):self.assertEqual(m.permit_margin(now=NOW,
       permit_expiry=NOW+timedelta(seconds=55),timer_seconds=40),40)
    def test_signed_margin_low(self):
        with self.assertRaises(m.Stop):m.permit_margin(now=NOW,
           permit_expiry=NOW+timedelta(seconds=24),timer_seconds=60)

class RootHarness(unittest.TestCase):
    def test_no_runtime_auto(self):
        self.assertEqual(r.F1.name,'root-guard.py')
        self.assertEqual(r.ONE,'pilot-attempted.once')
    def test_run_reject_arbitrary_binary(self):
        with self.assertRaises(r.Stop):r.run(('/usr/bin/bash','-c','exit 0'))
    def test_run_reject_nontypes(self):
        with self.assertRaises(r.Stop):r.run(('/usr/bin/python3',None))
    def test_root_guard_only_flags(self):
        with self.assertRaises(r.Stop):r.root_guard('--allow-ports')
    def test_root_capabilities_without_root(self):
        from contextlib import redirect_stdout
        import io
        output=io.StringIO()
        with redirect_stdout(output):code=r.main(['--capabilities'])
        self.assertEqual(code,0);self.assertIn('source_install_opens_traffic',output.getvalue())
    def test_f1_arm_requires_timer(self):
        with patch.object(r,'run',return_value=json.dumps({'timer_verified':False,'duration_seconds':60,
            'opens_ports':False}).encode()):
            with self.assertRaises(r.Stop):r.f1_arm('a'*16)
    def test_root_timer_readback(self):
        with patch.object(r,'run',return_value=b'LoadState=loaded\nActiveState=active\n'):
            self.assertEqual(r.timer('ardrec-r116-f1-deny-'+'a'*16)['LoadState'],'loaded')
    def test_boot_replay_scripts_source_available(self):
        import inspect
        self.assertIn('ardrec/scripts',inspect.getsource(r.review_boot_provenance))
    def test_boot_path_reject(self):
        with patch.object(r,'safe',return_value=r.canon({'schema':r.SCHEMA+'-f8-boot-reference',
            'plan':'/etc/passwd','boot':'/etc/group'})):
            with self.assertRaises(r.Stop):r.review_boot_provenance({'head':HEAD})
    def test_root_probe_no_retries(self):
        response={'schema':'ARDREC-R116-F3-FTP-T01-PILOT-PROBE-v1','src':'10.203.31.1',
            'dst':'10.203.31.2','port':21,'case_id':'FTP-T01-S01-01','tcp':'CONNECTED','response':'RECEIVED',
            'response_hex':b'220 Test\r\n'.hex()}
        status={'return':{'exited':True,'exitcode':0,
            'out-data':base64.b64encode(r.canon(response)).decode(), 'err-data':''}}
        calls=[]
        def fake(cmd,**kwargs):
            calls.append(cmd)
            return (b'{"return":{"pid":17}}' if len(calls)==1 else r.canon(status))
        with tempfile.TemporaryDirectory() as td:
            with patch.object(r,'run',side_effect=fake),patch.object(r.time,'sleep'):
                result=r.execute_one_guest_probe(Path(td),lambda:None,budget=budget(),case_id='FTP-T01-S01-01')
            self.assertEqual(result['response_hex'],response['response_hex'])
            self.assertEqual(len(calls),2)
            self.assertTrue((Path(td)/'guest-result.json').is_file())
    def test_root_probe_malicious_peer(self):
        response={'schema':'ARDREC-R116-F3-FTP-T01-PILOT-PROBE-v1','src':'10.203.31.1',
            'dst':'10.203.31.3','port':21,'case_id':'FTP-T01-S01-01','tcp':'CONNECTED','response':'RECEIVED',
            'response_hex':b'220 Test\r\n'.hex()}
        status={'return':{'exited':True,'exitcode':0,
            'out-data':base64.b64encode(r.canon(response)).decode(), 'err-data':''}}
        calls=[]
        def fake(cmd,**kwargs):
            calls.append(cmd)
            return (b'{"return":{"pid":17}}' if len(calls)==1 else r.canon(status))
        with tempfile.TemporaryDirectory() as td:
            with patch.object(r,'run',side_effect=fake),patch.object(r.time,'sleep'):
                with self.assertRaises(r.Stop):
                    r.execute_one_guest_probe(Path(td),lambda:None,budget=budget(),case_id='FTP-T01-S01-01')
    def test_stage_sources_read_only_capabilities(self):
        self.assertIn('ROOT_REQUIRED',s.checked.__code__.co_consts)
    def test_lock_source_pin(self):
        doc=json.loads(LOCK.read_text())
        self.assertTrue(doc['root_source_only'])
        self.assertEqual(doc['window_seconds'],60)
        self.assertEqual(doc['p8'],'NO-GO')
        for dest,digest in doc['files'].items():
            source=(REPO/'scripts/ardrec_p14_r116_f3_root_pilot.py' if dest=='root-pilot.py'
                else REPO/'src'/dest.removeprefix('runtime/'))
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),digest)
        self.assertEqual(len(doc['files']),31)
    def test_stage_no_implicit(self):
        self.assertNotIn('--stage-root',r.main.__code__.co_consts)
    def test_stage_reject_nonroot(self):
        with patch.object(s.os,'geteuid',return_value=1000):
            with self.assertRaises(s.Stop):s.checked()

if __name__=='__main__':unittest.main()
