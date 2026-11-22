"""R148 unit/negative tests: no physical authorization or synthetic thesis data."""
from __future__ import annotations
import copy
from decimal import Decimal
import os
from pathlib import Path
import tempfile
import unittest

from ardrec.experiments import r148_paired_register as m

HERE=Path(__file__).resolve().parents[2]
CAT=(HERE/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD='04e49d26f5dc32cebaa6b911fb9781428bba104f'
DIGEST='a'*64

class R148Tests(unittest.TestCase):
    def setUp(self):
        self.protocol,self.registry=m.build(CAT,HEAD)

    def seal(self,doc):
        doc.pop('sha256',None)
        doc['sha256']=m.digest(m.canonical(doc))

    def valid(self):
        return m.validate(self.protocol,self.registry,CAT)

    def slot(self,i, status='RECORDED_UNVERIFIED'):
        s=self.registry['slots'][i]
        s['status']=status
        s['scenario_id']=f'scenario-{i}'
        s['case_id']=f'case-{i}'
        s['family_id']={'SSH':'SSH-T01','FTP':'FTP-T01','SMB':'SMB-T01'}[s['protocol']]
        if status=='RECORDED_UNVERIFIED':
            s['static_estimate']='8'
            s['ardrec_estimate']='2'
            s['independent_reference']='1'
            for k in m.REFS:s[k]=DIGEST
            self.registry['common_scale']={'lower':'0','upper':'10'}
        else:
            s['exclusion_reason']='Inestabilidad tecnica justificada'
            s['exclusion_decision_sha256']=DIGEST
        self.seal(self.registry)

    def test_01_protocol(self):self.assertEqual(self.protocol['schema'],m.PROTOCOL_SCHEMA)
    def test_02_registry(self):self.assertEqual(self.registry['schema'],m.REGISTRY_SCHEMA)
    def test_03_54(self):self.assertEqual(len(self.registry['slots']),54)
    def test_04_each(self):self.assertEqual(self.valid()['by_protocol'],m.COUNTS)
    def test_05_no_fake(self):self.assertEqual(self.valid()['confirmed_physical_observations'],0)
    def test_06_ssh(self):self.assertEqual(self.registry['slots'][0]['slot_id'],'SSH-01')
    def test_07_ftp(self):self.assertEqual(self.registry['slots'][18]['slot_id'],'FTP-01')
    def test_08_smb(self):self.assertEqual(self.registry['slots'][36]['slot_id'],'SMB-01')
    def test_09_end(self):self.assertEqual(self.registry['slots'][-1]['slot_id'],'SMB-18')
    def test_10_no_case(self):self.assertTrue(all(x['case_id'] is None for x in self.registry['slots']))
    def test_11_no_p8(self):self.assertEqual(self.valid()['p8'],'NO-GO')
    def test_12_no_a9(self):self.assertEqual(self.valid()['a9'],'NOT_PUBLISHED')
    def test_13_canonical(self):self.assertEqual(m.decode(m.canonical(self.protocol)),self.protocol)
    def test_14_duplicate_json(self):
        with self.assertRaises(m.Stop):m.decode(b'{"a":1,"a":2}\n')
    def test_15_bad_head(self):
        with self.assertRaises(m.Stop):m.build(CAT,'wrong')
    def test_16_catalog_pin(self):
        with self.assertRaises(Exception):m.build(CAT+b' ',HEAD)
    def test_17_protocol_digest_tamper(self):
        self.protocol['head']='b'*40
        with self.assertRaisesRegex(m.Stop,'PROTOCOL_SEAL_INVALID'):self.valid()
    def test_18_registry_digest_tamper(self):
        self.registry['slots'][0]['case_id']='fake'
        with self.assertRaisesRegex(m.Stop,'REGISTRY_SEAL_INVALID'):self.valid()
    def test_19_no_53(self):
        self.registry['slots'].pop();self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'SLOTS_NOT_54'):self.valid()
    def test_20_duplicate_slot(self):
        self.registry['slots'][1]['slot_id']='SSH-01';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'SLOT_IDENTITY_ORDER_INVALID'):self.valid()
    def test_21_planned_has_no_case(self):
        self.registry['slots'][0]['case_id']='fake';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'PLANNED_SLOT_CANNOT_HAVE_DATA'):self.valid()
    def test_22_plan_frozen_forged(self):
        self.protocol['p7']='FROZEN';self.seal(self.protocol)
        with self.assertRaisesRegex(m.Stop,'PROTOCOL_FIELDS_INVALID'):self.valid()
    def test_23_unauthorized_p8(self):
        self.protocol['p8']='GO';self.seal(self.protocol)
        with self.assertRaisesRegex(m.Stop,'PROTOCOL_FIELDS_INVALID'):self.valid()
    def test_24_single_record(self):
        self.slot(0)
        self.assertEqual(self.valid()['statuses']['RECORDED_UNVERIFIED'],1)
    def test_25_wilcoxon_pair(self):
        self.slot(0);self.slot(1)
        report=m.analyze(self.protocol,self.registry,CAT)
        self.assertEqual(report['primary_comparison']['p_fraction'],'1/4')
    def test_26_stat_ref_missing(self):
        self.slot(0);self.registry['slots'][0]['common_evidence_sha256']=None;self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'MEASUREMENT_REFERENCE_MISSING'):self.valid()
    def test_27_cross_protocol_family(self):
        self.slot(18);self.registry['slots'][18]['family_id']='SSH-T01';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'RECORDED_CASE_SCENARIO_FAMILY_INVALID'):self.valid()
    def test_28_duplicate_case(self):
        self.slot(0);self.slot(1)
        self.registry['slots'][1]['case_id']='case-0';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'DUPLICATE_CASE_OR_SCENARIO'):self.valid()
    def test_29_duplicate_scenario(self):
        self.slot(0);self.slot(1)
        self.registry['slots'][1]['scenario_id']='scenario-0';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'DUPLICATE_CASE_OR_SCENARIO'):self.valid()
    def test_30_scale_required(self):
        self.slot(0);self.registry['common_scale']=None;self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'COMMON_SCALE_REQUIRED'):self.valid()
    def test_31_out_of_scale(self):
        self.slot(0);self.registry['slots'][0]['static_estimate']='12';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'VALUES_OUTSIDE_COMMON_SCALE'):self.valid()
    def test_32_no_floats(self):
        self.slot(0);self.registry['slots'][0]['static_estimate']=8.0;self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'DECIMAL_TEXT_REQUIRED'):self.valid()
    def test_33_no_nan(self):
        self.slot(0);self.registry['slots'][0]['static_estimate']='NaN';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'DECIMAL_RANGE_OR_FINITE'):self.valid()
    def test_34_exclusion(self):
        self.slot(0,'EXCLUDED_UNVERIFIED');self.assertEqual(self.valid()['statuses']['EXCLUDED_UNVERIFIED'],1)
    def test_35_exclusion_missing_decision(self):
        self.slot(0,'EXCLUDED_UNVERIFIED');self.registry['slots'][0]['exclusion_decision_sha256']=None;self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'EXCLUSION_RECORD_INCOMPLETE'):self.valid()
    def test_36_stat_all_zero(self):
        x=m.wilcoxon_exact([Decimal('0'),Decimal('0')]);self.assertIsNone(x['p_one_sided_exact']);self.assertEqual(x['n_zero'],2)
    def test_37_stat_one_positive(self):self.assertEqual(m.wilcoxon_exact([Decimal('1')])['p_fraction'],'1/2')
    def test_38_stat_two_positive(self):self.assertEqual(m.wilcoxon_exact([Decimal('1'),Decimal('2')])['p_fraction'],'1/4')
    def test_39_stat_two_negative(self):self.assertEqual(m.wilcoxon_exact([Decimal('-1'),Decimal('-2')])['p_fraction'],'1/1')
    def test_40_stat_mixed(self):self.assertEqual(m.wilcoxon_exact([Decimal('-1'),Decimal('1')])['p_fraction'],'3/4')
    def test_41_stat_ties(self):
        v=m.wilcoxon_exact([Decimal('1'),Decimal('1'),Decimal('1')]);self.assertEqual(v['p_fraction'],'1/8');self.assertEqual(v['w_total_twice'],12)
    def test_42_stat_zero_retained(self):
        v=m.wilcoxon_exact([Decimal('0'),Decimal('1')]);self.assertEqual((v['n_pairs'],v['n_nonzero'],v['n_zero']),(2,1,1))
    def test_43_stat_54(self):
        v=m.wilcoxon_exact([Decimal(1)]*54);self.assertEqual(v['p_fraction'],'1/18014398509481984')
    def test_44_no_analysis_as_auth(self):
        rep=m.analyze(self.protocol,self.registry,CAT);self.assertEqual(rep['claim'],'EXPLORATORY_UNVERIFIED_NOT_THESIS_RESULT')
    def test_45_no_results_when_empty(self):
        rep=m.analyze(self.protocol,self.registry,CAT);self.assertEqual(rep['primary_comparison']['decision'],'NOT_TESTABLE_ALL_ZERO_OR_NO_PAIRS')
    def test_46_csv_rows(self):
        raw=m.export_csv(self.registry);self.assertEqual(len(raw.splitlines()),55)
    def test_47_bad_pilot_ref(self):
        self.registry['pilot_receipt_sha256']='invalid';self.seal(self.registry)
        with self.assertRaisesRegex(m.Stop,'EXTERNAL_RECEIPT_DIGEST_INVALID'):self.valid()
    def test_48_protocol_direction_lock(self):
        self.protocol['analysis']['alternative']='REVERSED';self.seal(self.protocol)
        with self.assertRaisesRegex(m.Stop,'ANALYSIS_PROTOCOL_MUTATED'):self.valid()
    def test_49_no_external_import_data_proved(self):
        self.slot(0)
        self.assertFalse(self.valid()['independent_reference_attested'])
    def test_50_consistent_report_seal(self):
        rep=m.analyze(self.protocol,self.registry,CAT);m._verify_seal(rep)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_51_prepare_private(self):
        with tempfile.TemporaryDirectory() as t:
            dest=Path(t)/'r148'
            a=m.initialize(dest,CAT,HEAD)
            self.assertEqual(a['planned'],54)
            self.assertEqual(m.read(dest,CAT)[1],self.registry)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_52_no_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            with self.assertRaisesRegex(m.Stop,'DESTINATION_MUST_BE_NEW'):m.initialize(p,CAT,HEAD)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_53_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            p.chmod(0o755)
            with self.assertRaisesRegex(m.Stop,'PRIVATE_DIRECTORY_UNSAFE'):m.read(p,CAT)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_54_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            fake=p/'observations.json';fake.unlink();fake.symlink_to(p/'protocol.json')
            with self.assertRaises(OSError):m.read(p,CAT)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_55_hardlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            os.link(p/'observations.json',p/'other.json')
            with self.assertRaisesRegex(m.Stop,'PRIVATE_FILE_METADATA_INVALID'):m.read(p,CAT)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_56_file_mode(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            (p/'protocol.json').chmod(0o644)
            with self.assertRaisesRegex(m.Stop,'PRIVATE_FILE_METADATA_INVALID'):m.read(p,CAT)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_57_target_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'real';p.mkdir(mode=0o700)
            (Path(t)/'alias').symlink_to(p,target_is_directory=True)
            with self.assertRaisesRegex(m.Stop,'DESTINATION_MUST_BE_NEW'):
                m.initialize(Path(t)/'alias',CAT,HEAD)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_58_registry_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            a=p/'observations.json';raw=a.read_bytes();a.write_bytes(raw+b' ')
            with self.assertRaises(m.Stop):m.read(p,CAT)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_59_parent_writable_reject(self):
        with tempfile.TemporaryDirectory() as t:
            parent=Path(t);parent.chmod(0o777)
            with self.assertRaisesRegex(m.Stop,'PARENT_DIRECTORY_UNSAFE'):
                m.initialize(parent/'register',CAT,HEAD)

    @unittest.skipIf(os.geteuid()==0,'private fixture requires unprivileged user')
    def test_60_read_replay_stable(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'register';m.initialize(p,CAT,HEAD)
            a=m.read(p,CAT);b=m.read(p,CAT)
            self.assertEqual(a,b)

if __name__=='__main__':unittest.main()
