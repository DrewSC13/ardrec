"""R56.0 tests: source-ledger and gate negative controls. Never execute host commands."""
from __future__ import annotations
import copy
import json
import unittest
from ardrec.coordination import r560_service_acceptance as c


def fixtures():
    families=[{'id':f'{r.upper()}-T{i:02d}'} for r in c.ROLES for i in range(1,c.SERVICES[r]['families']+1)]
    catalog={'execution_enabled':False,'catalog_frozen':False,'derived_real_cases':0,
             'counts':{'ssh':8,'ftp':8,'smb':9,'total':25},'families':families}
    units=[]
    for role in c.ROLES:
        data=c.SERVICES[role]
        units.append({'protocol':role, 'unit_id':'DEV-'+role.upper()+'-001',
                      'libvirt_target_domain':data['domain'],
                      'libvirt_network_name':data['network'],
                      'expected_target_ip':data['ip'],
                      'expected_runner_ip':data['runner'],
                      'expected_network_cidr':data['cidr'],
                      'server_tcp_port':data['port'],
                      'config_source_sha256':c.CONFIG_HASHES[role],
                      'case_families':[{'family_id':f'{role.upper()}-T{i:02d}',
                                        'coverage':'PENDING', 'case_executable':False,
                                        'evidence_admitted_by_A6':False}
                                       for i in range(1,data['families']+1)]})
    manifest={'schema':'ardrec-p14-r51-dev-three-services-v1','units':units}
    historical={'status':'RECORDED_HOST_SERVICE_SMOKE_PASS','experimental_data':False,
                'checks':[{'check':name,'result':'PASS'} for r in c.ROLES for name in c.SERVICES[r]['checks']]}
    return manifest,historical,catalog

class Acceptance(unittest.TestCase):
    def test_role_count(self):self.assertEqual(len(c.ROLES),3)
    def test_family_count(self):self.assertEqual(sum(c.SERVICES[r]['families'] for r in c.ROLES),25)
    def test_historical_checks(self):self.assertEqual(sum(len(c.SERVICES[r]['checks']) for r in c.ROLES),17)
    def test_config_hashes_are_distinct(self):self.assertEqual(len(set(c.CONFIG_HASHES.values())),3)
    def test_fixed_git_base(self):self.assertEqual(len(c.MAIN),40)
    def test_r559_receipt_pinned(self):self.assertEqual(len(c.R559F1_REPORT_SHA),64)
    def test_plan_denies_p8(self):
        d=c.plan({'historical_checks':17,'families':25});c.validate_plan(d)
        self.assertEqual(d['operational_p8'],'NO-GO')
    def test_plan_no_accepted_families(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertTrue(all(x['accepted_family_count']==0 for x in d['roles']))
    def test_plan_no_physical_claim(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertTrue(all(x['current_smoke_status']=='NOT_EXECUTED' for x in d['roles']))
    def test_plan_no_watchdog_claim(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertTrue(all(not x['independent_watchdog_armed'] for x in d['roles']))
    def test_plan_requires_separate_authorization(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertIn('AUTHORIZED_ROLE_SCOPED_TRANSPORT_WINDOW',d['roles'][0]['prerequisites'])
    def test_plan_requires_negative_witness(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertIn('AUTHORIZED_L2_L3_POSITIVE_AND_NEGATIVE_WITNESSES',d['roles'][0]['prerequisites'])
    def test_ftp_passive_exact(self):
        self.assertIn('PASSIVE_50000_50009',c.SERVICES['ftp']['transport'])
    def test_smb_only_445(self):self.assertEqual(c.SERVICES['smb']['transport'],'TCP_445_ONLY')
    def test_no_operational_risk(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertIsNone(d['rf']);self.assertIsNone(d['confirmed_generation'])
    def test_different_roles_not_cross_admitted(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertEqual(set(d['roles'][0]['historical_checks']).intersection(d['roles'][2]['historical_checks']),set())
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(c.ClosureError):c.parse(b'{"x":NaN}')
    def test_duplicate_json_rejected(self):
        with self.assertRaises(c.ClosureError):c.parse(b'{"x":1,"x":2}')
    def test_empty_json_rejected(self):
        with self.assertRaises(c.ClosureError):c.parse(b'')
    def test_wrong_provenance_rejected(self):
        with self.assertRaises(c.ClosureError):c.plan({'historical_checks':16,'families':25})
    def test_plan_forged_p8_rejected(self):
        d=c.plan({'historical_checks':17,'families':25});d['operational_p8']='GO'
        with self.assertRaises(c.ClosureError):c.validate_plan(d)
    def test_plan_forged_acceptance_rejected(self):
        d=c.plan({'historical_checks':17,'families':25});d['roles'][0]['accepted_service']=True
        with self.assertRaises(c.ClosureError):c.validate_plan(d)
    def test_plan_forged_family_rejected(self):
        d=c.plan({'historical_checks':17,'families':25});d['roles'][0]['accepted_family_count']=8
        with self.assertRaises(c.ClosureError):c.validate_plan(d)
    def test_plan_forged_window_rejected(self):
        d=c.plan({'historical_checks':17,'families':25});d['roles'][0]['independent_watchdog_armed']=True
        with self.assertRaises(c.ClosureError):c.validate_plan(d)
    def test_plan_forged_smoke_rejected(self):
        d=c.plan({'historical_checks':17,'families':25});d['roles'][0]['current_smoke_status']='PASS'
        with self.assertRaises(c.ClosureError):c.validate_plan(d)
    def test_missing_historical_check_rejected(self):
        m,h,k=fixtures();h['checks'].pop()
        with self.assertRaises(c.ClosureError):c.validate_sources(m,{},h,k)
    def test_wrong_historical_status_rejected(self):
        m,h,k=fixtures();h['status']='CURRENT_PASS'
        with self.assertRaises(c.ClosureError):c.validate_sources(m,{},h,k)
    def test_catalog_enabled_rejected(self):
        m,h,k=fixtures();k['execution_enabled']=True
        with self.assertRaises(c.ClosureError):c.validate_sources(m,{},h,k)
    def test_config_inventory_rejected(self):
        m,h,k=fixtures()
        with self.assertRaises(c.ClosureError):c.validate_sources(m,{'ssh':b''},h,k)
    def test_forged_unit_acceptance_rejected(self):
        m,h,k=fixtures();m['units'][0]['case_families'][0]['case_executable']=True
        with self.assertRaises(c.ClosureError):c.validate_sources(m,{},h,k)
    def test_cross_role_network_rejected(self):
        m,h,k=fixtures();m['units'][0]['expected_target_ip']='10.203.31.2'
        with self.assertRaises(c.ClosureError):c.validate_sources(m,{},h,k)
    def test_guest_protocol_no_ftp_active(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertNotIn('FTP_ACTIVE',d['roles'][1]['transport'])
    def test_three_service_readiness_not_accepted(self):
        d=c.plan({'historical_checks':17,'families':25})
        self.assertTrue(all(not x['accepted_service'] for x in d['roles']))

if __name__=='__main__':unittest.main()
