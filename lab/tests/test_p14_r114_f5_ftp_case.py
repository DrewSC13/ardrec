"""R114-F5: offline falsification tests. No actual guest, nft, sudo or network calls."""
from __future__ import annotations
import base64,copy,json,unittest
from pathlib import Path
from ardrec.coordination import r114_f5_ftp_case as m

REPO=Path(__file__).resolve().parents[2]

class F5Case(unittest.TestCase):
 def base(self):
  return {'schema':m.PROBE_SCHEMA,'src':m.SRC_IP,'dst':m.DST_IP,
   'port':m.DST_PORT,'case_id':m.CASE,'attempt':m.ATTEMPT,
   'tcp':'CONNECTED','response':'BANNER_RECEIVED','response_hex':b'220 (vsFTPd 3.0.5)\r\n'.hex()}
 def qga(self,raw):
  return m.canon({'return':{'exited':True,'exitcode':0,
              'out-data':base64.b64encode(raw).decode(),'err-data':''}})
 def f6(self):
  return m.canon({'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,
                   'host_writes':0,'p8':'NO-GO'})
 def result(self,probe=None,qga=None,f6=None):
  raw=m.canon(self.base() if probe is None else probe)
  return m.classify_attempt(raw_probe=raw,qga_raw_status=self.qga(raw) if qga is None else qga,
      f6_final_raw=self.f6() if f6 is None else f6,
      f4_manifest_sha=m.F4_MANIFEST_SHA,f4_report_sha='a'*64)
 def test_01_true_physical_banner_candidate(self):
  r=self.result();self.assertTrue(r['ftp_220_response_observed']);self.assertTrue(r['a5_one_physical_attempt_recorded'])
 def test_02_no_a6_risk_or_p8(self):
  r=self.result();self.assertEqual((r['a6_classification'],r['a7_final_risk'],r['p8']),('ND',None,'NO-GO'))
 def test_03_case_id_exact(self):
  self.assertEqual(self.result()['case_id'],'FTP-T01-S01-01')
 def test_04_source_target_macs(self):
  r=self.result();self.assertEqual((r['source_mac'],r['target_mac']),(m.SRC_MAC,m.DST_MAC))
 def test_05_raw_probe_digest(self):
  r=self.result();self.assertEqual(r['raw_banner_sha256'],m.sha(b'220 (vsFTPd 3.0.5)\r\n'))
 def test_06_qga_byte_mismatch_rejected(self):
  with self.assertRaises(m.Stop):self.result(qga=self.qga(b'{}'))
 def test_07_qga_nonzero_rejected(self):
  raw=m.canon(self.base());q=json.loads(self.qga(raw));q['return']['exitcode']=1
  with self.assertRaises(m.Stop):self.result(qga=m.canon(q))
 def test_08_qga_not_exited_rejected(self):
  raw=m.canon(self.base());q=json.loads(self.qga(raw));q['return']['exited']=False
  with self.assertRaises(m.Stop):self.result(qga=m.canon(q))
 def test_09_qga_stderr_rejected(self):
  raw=m.canon(self.base());q=json.loads(self.qga(raw));q['return']['err-data']='YQ=='
  with self.assertRaises(m.Stop):self.result(qga=m.canon(q))
 def test_10_f6_unsafe_rejected(self):
  d=json.loads(self.f6());d['bindings']=5
  with self.assertRaises(m.Stop):self.result(f6=m.canon(d))
 def test_11_f6_host_writes_rejected(self):
  d=json.loads(self.f6());d['host_writes']=1
  with self.assertRaises(m.Stop):self.result(f6=m.canon(d))
 def test_12_wrong_source_must_reject(self):
  p=self.base();p['src']='10.203.31.3'
  with self.assertRaises(m.Stop):self.result(p)
 def test_13_wrong_port_must_reject(self):
  p=self.base();p['port']=445
  with self.assertRaises(m.Stop):self.result(p)
 def test_14_bogus_case_reject(self):
  p=self.base();p['case_id']='FTP-T02-S01-01'
  with self.assertRaises(m.Stop):self.result(p)
 def test_15_bad_schema_reject(self):
  p=self.base();p['schema']='FAKE'
  with self.assertRaises(m.Stop):self.result(p)
 def test_16_extra_field_reject(self):
  p=self.base();p['password']='foo'
  with self.assertRaises(m.Stop):self.result(p)
 def test_17_response_overflow_reject(self):
  p=self.base();p['response_hex']=(b'a'*257).hex()
  with self.assertRaises(m.Stop):self.result(p)
 def test_18_valid_failed_connect_unresolved(self):
  p=self.base();p.update(tcp='FAILED',response='NO_CONNECT',response_hex='',error='TimeoutError')
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_19_empty_greeting_unresolved(self):
  p=self.base();p.update(response='EMPTY_GREETING',response_hex='')
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_20_timeout_greeting_unresolved(self):
  p=self.base();p.update(response='GREETING_TIMEOUT',response_hex='')
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_21_non220_response_not_admitted(self):
  p=self.base();p['response_hex']=b'530 Login incorrect\r\n'.hex()
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_22_multiple_lines_not_admitted(self):
  p=self.base();p['response_hex']=b'220 first\r\n220 second\r\n'.hex()
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_23_noncrlf_not_admitted(self):
  p=self.base();p['response_hex']=b'220 hello\n'.hex()
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_24_nul_not_admitted(self):
  p=self.base();p['response_hex']=b'220 hello\x00\r\n'.hex()
  self.assertFalse(self.result(p)['ftp_220_response_observed'])
 def test_25_probe_source_only_ftp(self):
  src=m.runner_source();self.assertIn(m.SRC_IP,src);self.assertIn(m.DST_IP,src)
  self.assertNotIn('10.203.30.2',src);self.assertNotIn('10.203.32.2',src)
 def test_26_probe_source_no_auth(self):
  src=m.runner_source()
  for item in ('USER ','PASS ','LIST','RETR','STOR','subprocess','os.system','systemctl'):
   self.assertNotIn(item,src)
 def test_27_bad_hex_rejected(self):
  p=self.base();p['response_hex']='xyz'
  with self.assertRaises(m.Stop):self.result(p)
 def test_28_ftp220_bad_status_not_credential(self):
  self.assertTrue(m.valid_ftp_220(b'220 ready\r\n'))
  self.assertFalse(m.valid_ftp_220(b'230 logged in\r\n'))
 def test_29_f4_digest_guard(self):
  with self.assertRaises(m.Stop):m.classify_attempt(raw_probe=m.canon(self.base()),
       qga_raw_status=self.qga(m.canon(self.base())),f6_final_raw=self.f6(),
       f4_manifest_sha='0'*64,f4_report_sha='a'*64)
 def test_30_f4_p8_rejected(self):
  r={'schema':'ARDREC-R114-F4-FTP-CONFIG-SOURCE-OBSERVATION-v1',
     'vm':m.VM_TARGET,'mac':m.DST_MAC,'ipv4_cidr':m.DST_IP+'/28',
     'observed_file':'/etc/vsftpd.conf','config_file_sha256':m.F4_CONFIG_SHA,
     'case_intent':{'family_id':'FTP-T01','derived_case_id':m.CASE},
     'a5_family_execution_completed':False,'effective_configuration_accredited':False,
     'a6_classification':'ND','p8':'GO'}
  manifest={'schema':'ARDREC-R114-F4-FTP-QGA-PARTIAL-REPLAY-v1',
    'report_sha256':'a'*64,'source_f3_manifest_sha256':'9a216b641f01fdeba5c5e559bb4819393212ecc6c5bbc6f7d90e79f8663f2acf',
    'a5_family_completed':False,'a6_conditions_admitted':0,'new_network_connections':0,
    'risk_recalculated':False,'p8':'NO-GO','files_sha256':{'config.bytes':m.F4_CONFIG_SHA}}
  with self.assertRaises(m.Stop):m.validate_f4_source(r,manifest,manifest_sha=m.F4_MANIFEST_SHA,report_sha='a'*64)

class F5RootSource(unittest.TestCase):
 def test_31_root_source_files_are_present(self):
  for filename in ('ardrec_p14_r114_f5_root_window.py','ardrec_p14_r114_f5_root_stage.py'):
   self.assertTrue((REPO/'scripts'/filename).is_file())
 def test_32_control_manifest_does_not_allow_a6(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f5_root_window.py').read_text()
  self.assertIn("'a6_admitted':0",raw)
 def test_33_stage_has_ftp_only_nft(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f5_root_stage.py').read_text()
  self.assertIn('def select_ftp_nft(',raw)
  self.assertIn("b'a33d30' not in x",raw)
 def test_34_timer_armed_before_open(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f5_root_window.py').read_text()
  self.assertLess(raw.index("run('nft_candidate_check'"),raw.index("run('timer_arm'"))
  self.assertLess(raw.index("run('timer_arm'"),raw.index("run('nft_open'"))
 def test_35_backup_and_final_restore(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f5_root_window.py').read_text()
  self.assertIn("f6('f6_restore_final'",raw)
  self.assertIn("f6('f6_attest_final'",raw)
 def test_36_no_replay_host_commands(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f5_root_window.py').read_text()
  segment=raw.split('def replay(folder):',1)[1].split('def main():',1)[0]
  self.assertNotIn('run(',segment);self.assertNotIn('agent(',segment)

if __name__=='__main__':unittest.main()
