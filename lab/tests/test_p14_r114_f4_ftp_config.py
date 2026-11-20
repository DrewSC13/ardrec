"""All inputs here are synthetic unit TEST fixtures. No physical result is simulated as accredited."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r114_f4_ftp_config_observation as c
from ardrec.coordination import r114_f3_asset_anchor as f3
import ardrec_p14_r114_f4_ftp_config as cli

F6=c.canonical({'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,'p8':'NO-GO','host_writes':0})
CONFIG=b'listen=YES\nanonymous_enable=NO\n'
VM_XML=b'''<domain><devices><interface><mac address="52:54:00:ad:31:02"/><filterref filter="ardrec-r33-block-until-containment"/></interface></devices></domain>'''
AGENT=c.canonical({'return':{'supported_commands':[
 {'name':'guest-exec','enabled':True},{'name':'guest-exec-status','enabled':True}]}})
START=c.canonical({'return':{'pid':42}})
COMPLETION=c.canonical({'return':{'exited':True,'exitcode':0,
                 'out-data':base64.b64encode(CONFIG).decode('ascii'), 'err-data':''}})

def fixtures():
 asset={'asset_anchor_id':'ASSET_'+ 'A'*32,'role':'ftp','target_vm':c.VM,
   'target_mac':c.EXPECTED_MAC,'target_ipv4_cidr':c.EXPECTED_CIDR,
   'tcp_port':21,'tcp_real_observed':True,'a5_case_binding_accredited':False,
   'a6_condition':'ND','confirmed_rf':None}
 candidate={'candidate_planning_id':'PLAN_'+'B'*32,
  'asset_anchor_id':asset['asset_anchor_id'],'family_id':'FTP-T01',
  'variant':None,'case_id_a5':None,'a5_attempt_started':False,
  'a6_classification':'ND','confirmed_rf':None,
  'catalogue_required_supports_not_admitted':['CONTROL_CHANNEL_RESPONSE']}
 report={'schema':f3.SCHEMA,'asset_count':3,'candidate_count':29,
    'a5_starts':0,'a6_admitted_conditions':0,'a7_risk_recalculated':False,
    'p8':'NO-GO','assets':[asset], 'case_planning_candidates':[candidate]}
 report['sha256']=c.sha(c.canonical(report))
 manifest={'schema':'ARDREC-R114-F3-PRIVATE-REPLAY-v1',
   'report_sha256':c.F3_REPORT_PIN,'a5_starts':0,'a6_admitted':0,'p8':'NO-GO'}
 return report,manifest

def rehash(report):
 report['sha256']=c.sha(c.canonical({k:v for k,v in report.items() if k!='sha256'}))

def make_report(config=CONFIG,completion=COMPLETION,before=F6,after=F6):
 r,m=fixtures()
 plan=c.plan(r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 report=c.classify(plan,completion,config,f6_before_raw=before,
   f6_after_raw=after,f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,
   rsha=c.F3_REPORT_PIN)
 return r,m,plan,report

class F3Contract(unittest.TestCase):
 def test_01_fixture_accepted(self):
  r,m=fixtures();self.assertEqual(c.validate_f3(r,m,msha=c.F3_MANIFEST_PIN,
   rsha=c.F3_REPORT_PIN)[0]['role'],'ftp')
 def test_02_wrong_manifest_pin(self):
  r,m=fixtures();self.assertRaises(c.Guard,c.validate_f3,r,m,msha='0'*64,rsha=c.F3_REPORT_PIN)
 def test_03_wrong_report_pin(self):
  r,m=fixtures();self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha='0'*64)
 def test_04_wrong_manifest_schema(self):
  r,m=fixtures();m['schema']='other';self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_05_attempt_started(self):
  r,m=fixtures();r['a5_starts']=1;rehash(r);self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_06_report_digest(self):
  r,m=fixtures();r['candidate_count']=28;self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_07_tamper_mac(self):
  r,m=fixtures();r['assets'][0]['target_mac']='52:54:00:00:00:00';rehash(r)
  self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_08_tamper_ip(self):
  r,m=fixtures();r['assets'][0]['target_ipv4_cidr']='10.203.31.3/28';rehash(r)
  self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_09_tamper_port(self):
  r,m=fixtures();r['assets'][0]['tcp_port']=2121;rehash(r)
  self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_10_tamper_family(self):
  r,m=fixtures();r['case_planning_candidates'][0]['family_id']='FTP-T02';rehash(r)
  self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_11_case_promotion(self):
  r,m=fixtures();r['case_planning_candidates'][0]['case_id_a5']=c.CASE;rehash(r)
  self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_12_no_support(self):
  r,m=fixtures();r['case_planning_candidates'][0]['catalogue_required_supports_not_admitted']=[];rehash(r)
  self.assertRaises(c.Guard,c.validate_f3,r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_13_plan_never_authorizes(self):
  r,m=fixtures();p=c.plan(r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
  self.assertFalse(p['physical_attempt_authorized']);self.assertFalse(p['method_completed'])
  self.assertEqual(p['guest_exec_args'],['/etc/vsftpd.conf'])
 def test_14_plan_case_fixed(self):
  r,m=fixtures();p=c.plan(r,m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
  self.assertEqual(p['case_id_proposed'],'FTP-T01-S01-01')
 def test_15_no_acceptance_as_a6(self):
  r,m,_,doc=make_report();self.assertEqual(doc['a6_classification'],'ND')
  self.assertFalse(doc['a5_case_start_independently_accredited'])
  self.assertEqual(doc['a6_supports_admitted'],[])

class CaptureClassifier(unittest.TestCase):
 def test_16_report_valid(self):
  r,m,p,doc=make_report();self.assertTrue(c.verify_report(doc,p,COMPLETION,CONFIG,
   f6_before=F6,f6_after=F6,f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN))
 def test_17_hash_real_bytes(self):
  _,_,_,doc=make_report();self.assertEqual(doc['config_file_sha256'],hashlib.sha256(CONFIG).hexdigest())
 def test_18_full_config_not_effective(self):
  _,_,_,doc=make_report();self.assertFalse(doc['effective_configuration_accredited'])
  self.assertFalse(doc['a5_family_execution_completed'])
 def test_19_intent_schema(self):
  _,_,_,doc=make_report();self.assertEqual(doc['case_intent']['family_id'],'FTP-T01')
  self.assertEqual(doc['case_intent']['configuration_sha256'],c.sha(CONFIG))
 def test_20_tampered_output_bytes(self):
  r,m,p,_=make_report();self.assertRaises(c.Guard,c.classify,p,COMPLETION,b'OTHER',
   f6_before_raw=F6,f6_after_raw=F6,f3_report=r,f3_manifest=m,
   msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_21_nonzero_exit(self):
  r,m,p,_=make_report();bad=c.canonical({'return':{'exited':True,'exitcode':1,'out-data':'','err-data':''}})
  self.assertRaises(c.Guard,c.classify,p,bad,b'',f6_before_raw=F6,f6_after_raw=F6,
   f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_22_not_exited(self):
  r,m,p,_=make_report();bad=c.canonical({'return':{'exited':False,'out-data':'','err-data':''}})
  self.assertRaises(c.Guard,c.classify,p,bad,CONFIG,f6_before_raw=F6,f6_after_raw=F6,
   f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_23_bad_base64(self):
  r,m,p,_=make_report();bad=c.canonical({'return':{'exited':True,'exitcode':0,'out-data':'X=%%','err-data':''}})
  self.assertRaises(c.Guard,c.classify,p,bad,CONFIG,f6_before_raw=F6,f6_after_raw=F6,
   f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_24_stderr_must_be_empty(self):
  r,m,p,_=make_report();bad=c.canonical({'return':{'exited':True,'exitcode':0,
   'out-data':base64.b64encode(CONFIG).decode(),'err-data':base64.b64encode(b'x').decode()}})
  self.assertRaises(c.Guard,c.classify,p,bad,CONFIG,f6_before_raw=F6,f6_after_raw=F6,
   f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_25_empty_file(self):
  r,m,p,_=make_report();bad=c.canonical({'return':{'exited':True,'exitcode':0,'out-data':'','err-data':''}})
  self.assertRaises(c.Guard,c.classify,p,bad,b'',f6_before_raw=F6,f6_after_raw=F6,
   f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_26_null_file(self):
  r,m,p,_=make_report();bad=c.canonical({'return':{'exited':True,'exitcode':0,
   'out-data':base64.b64encode(b'a\0b').decode(),'err-data':''}})
  self.assertRaises(c.Guard,c.classify,p,bad,b'a\0b',f6_before_raw=F6,f6_after_raw=F6,
   f3_report=r,f3_manifest=m,msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_27_oversized_file(self):
  large=b'x'*(c.MAX_DATA+1)
  bad=c.canonical({'return':{'exited':True,'exitcode':0,
   'out-data':base64.b64encode(large).decode(),'err-data':''}})
  r,m,p,_=make_report();self.assertRaises(c.Guard,c.classify,p,bad,large,
   f6_before_raw=F6,f6_after_raw=F6,f3_report=r,f3_manifest=m,
   msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_28_deny_before_changed(self):
  bad=c.canonical({'result':'OTHER','bindings':6,'p8':'NO-GO','host_writes':0})
  r,m,p,_=make_report();self.assertRaises(c.Guard,c.classify,p,COMPLETION,CONFIG,
   f6_before_raw=bad,f6_after_raw=F6,f3_report=r,f3_manifest=m,
   msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_29_deny_after_changed(self):
  bad=c.canonical({'result':'OTHER','bindings':6,'p8':'NO-GO','host_writes':0})
  r,m,p,_=make_report();self.assertRaises(c.Guard,c.classify,p,COMPLETION,CONFIG,
   f6_before_raw=F6,f6_after_raw=bad,f3_report=r,f3_manifest=m,
   msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_30_report_tampered(self):
  r,m,p,doc=make_report();doc['confirmed_vulnerability']=True
  self.assertRaises(c.Guard,c.verify_report,doc,p,COMPLETION,CONFIG,
   f6_before=F6,f6_after=F6,f3_report=r,f3_manifest=m,
   msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)
 def test_31_plan_changed(self):
  r,m,p,_=make_report();p['guest_exec_path']='/bin/sh'
  self.assertRaises(c.Guard,c.classify,p,COMPLETION,CONFIG,f6_before_raw=F6,
   f6_after_raw=F6,f3_report=r,f3_manifest=m,
   msha=c.F3_MANIFEST_PIN,rsha=c.F3_REPORT_PIN)

class PhysicalOperatorUnit(unittest.TestCase):
 def test_32_mac_xml_accepts(self): cli.xml_identity(VM_XML)
 def test_33_mac_xml_rejects(self):
  self.assertRaises(cli.Stop,cli.xml_identity,VM_XML.replace(b'31:02',b'31:03'))
 def test_34_filter_xml_rejects(self):
  self.assertRaises(cli.Stop,cli.xml_identity,VM_XML.replace(b'ardrec-r33-block-until-containment',b'other'))
 def test_35_mocked_capture_full_flow(self):
  # This is a purely synthetic controller test, NEVER a physical observation.
  calls=[]
  def mock_qga(payload):
   name=payload['execute'];calls.append(name)
   return {'guest-info':AGENT,'guest-exec':START,
           'guest-exec-status':COMPLETION}[name]
  with tempfile.TemporaryDirectory() as d:
   base=Path(d)/'root'
   with patch.object(cli,'ROOT',base), patch.object(cli,'source',return_value=fixtures()), \
        patch.object(cli,'f6_attest',return_value=F6), \
        patch.object(cli,'cmd',return_value=VM_XML), \
        patch.object(cli,'qga',side_effect=mock_qga), \
        patch.object(cli.os,'geteuid',return_value=1000), \
        patch.object(cli.time,'sleep',return_value=None):
    self.assertEqual(cli.capture(),0)
    self.assertEqual(calls,['guest-info','guest-exec','guest-exec-status'])
    dirs=list(base.glob('capture-*'));self.assertEqual(len(dirs),1)
    self.assertEqual(cli.replay(dirs[0]),0)
    self.assertRaises(cli.Stop,cli.capture)
 def test_36_manifest_authority(self):
  r,m,p,doc=make_report();v=cli.manifest({'intent.json':c.sha(c.canonical(p))},doc)
  self.assertEqual(v['a6_conditions_admitted'],0)
  self.assertFalse(v['a5_family_completed'])
 def test_37_replay_synthetic_fixture(self):
  r,m,p,doc=make_report()
  with tempfile.TemporaryDirectory() as d:
   base=Path(d)/'root';base.mkdir(mode=0o700)
   folder=base/'capture-0123abcd';folder.mkdir(mode=0o700)
   files={'intent.json':c.canonical(p),'vm.xml':VM_XML,
     'f6_before.stdout':F6,'f6_after.stdout':F6,'guest_info.stdout':AGENT,
     'started-ftp.once':c.canonical({'vm':c.VM,'command':c.CMD,
                               'one_physical_attempt':True,'p8':'NO-GO'}),
     'qga_start.stdout':START,'status-01.json':COMPLETION,
     'qga_completion.json':COMPLETION,'config.bytes':CONFIG,
     'report.json':c.canonical(doc)}
   for name,raw in files.items():cli.write(folder/name,raw)
   md=cli.manifest({k:c.sha(v) for k,v in files.items()},doc)
   cli.write(folder/'manifest.json',c.canonical(md))
   with patch.object(cli,'ROOT',base), patch.object(cli,'source',return_value=(r,m)), patch.object(cli.os,'geteuid',return_value=1000):
    self.assertEqual(cli.replay(folder),0)
    (folder/'config.bytes').write_bytes(b'evil')
    self.assertRaises(cli.Stop,cli.replay,folder)
 def test_38_bad_receipt_path(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);p.chmod(0o700)
   with patch.object(cli,'ROOT',p),patch.object(cli,'source',return_value=fixtures()):
    self.assertRaises(cli.Stop,cli.replay,p)
 def test_39_read_file_empty_allowed(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'empty';p.write_bytes(b'');p.chmod(0o600)
   self.assertEqual(cli.read(p,allow_empty=True),b'')
 def test_40_no_read_file_empty_without_flag(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'empty';p.write_bytes(b'');p.chmod(0o600)
   self.assertRaises(cli.Stop,cli.read,p)

if __name__=='__main__':unittest.main()
