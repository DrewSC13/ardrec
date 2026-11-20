"""R114-F2 unit fixtures are synthetic; physical results ONLY come from F1 receipts."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
from ardrec.coordination import r114_f2_family_gap as c
from test_p14_r114_f1_real_receipt import fixture,review


def sample():
    doc=review(fixture())
    # Unit fixture has an invented in-memory root receipt. Pin only the metadata
    # in this isolated test; physical CLI separately REVERIFIES real F1 bytes.
    doc['root_receipt_sha256']=c.f1.F10R_RECEIPT_SHA
    return doc


def build(doc=None):
    return c.make_report(sample() if doc is None else doc,
                         f1_report_sha256='a'*64,
                         f1_manifest_sha256=c.F1_MANIFEST_PIN)


class PhysicalFamilyMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.realistic=sample()
        cls.report=build(cls.realistic)

    def changed(self,**kw):
        report=copy.deepcopy(self.realistic)
        report.update(kw)
        return report

    def test_01_catalog_has_exact_25_families(self):
        self.assertEqual(self.report['family_count'],25)
        self.assertEqual(len({x['family_id'] for x in self.report['family_requirements']}),25)

    def test_02_catalog_has_exact_29_paths(self):
        self.assertEqual(len(self.report['family_requirements']),29)
        self.assertEqual(self.report['variant_path_count'],29)

    def test_03_ssh_has_8_paths(self):
        self.assertEqual(sum(x['service_id']=='SSH_DEV' for x in self.report['family_requirements']),8)

    def test_04_ftp_has_10_paths(self):
        self.assertEqual(sum(x['service_id']=='FTP_DEV' for x in self.report['family_requirements']),10)

    def test_05_smb_has_11_paths(self):
        self.assertEqual(sum(x['service_id']=='SMB_DEV' for x in self.report['family_requirements']),11)

    def test_06_ftp_control_vs_data_not_conflated(self):
        a=[x for x in self.report['family_requirements'] if x['family_id']=='FTP-T02']
        self.assertEqual([x['variant'] for x in a],['CONTROL','DATA'])
        self.assertNotEqual(a[0]['catalogue_required_supports'],a[1]['catalogue_required_supports'])

    def test_07_ftp_write_requires_cleanup(self):
        a={x['variant']:x for x in self.report['family_requirements'] if x['family_id']=='FTP-T08'}
        self.assertFalse(a['READ']['cleanup_required_for_family'])
        self.assertTrue(a['WRITE']['cleanup_required_for_family'])

    def test_08_smb_signing_not_encryption(self):
        a={x['variant']:x for x in self.report['family_requirements'] if x['family_id']=='SMB-T03'}
        self.assertIn('SMB_SIGNATURE',a['SIGNING']['catalogue_required_supports'])
        self.assertNotIn('SMB_ENCRYPTION',a['SIGNING']['catalogue_required_supports'])
        self.assertIn('SMB_ENCRYPTION',a['ENCRYPTION']['catalogue_required_supports'])
        self.assertNotIn('SMB_SIGNATURE',a['ENCRYPTION']['catalogue_required_supports'])

    def test_09_smb_write_requires_cleanup(self):
        a={x['variant']:x for x in self.report['family_requirements'] if x['family_id']=='SMB-T09'}
        self.assertFalse(a['READ']['cleanup_required_for_family'])
        self.assertTrue(a['WRITE']['cleanup_required_for_family'])

    def test_10_all_29_variants_have_no_case(self):
        self.assertTrue(all(x['derived_case_id'] is None and x['assessment_index'] is None
                            for x in self.report['family_requirements']))

    def test_11_all_29_variants_have_a6_nd(self):
        self.assertTrue(all(x['a6_classification']=='ND' and not x['a6_technical_truth_accredited']
                            for x in self.report['family_requirements']))

    def test_12_no_risk_or_state_output(self):
        self.assertIsNone(self.report['confirmed_final_risk'])
        self.assertFalse(self.report['risk_recalculation_performed'])
        self.assertFalse(self.report['state_transition_applied'])
        self.assertIsNone(self.report['published_generation'])

    def test_13_no_network_or_guest_calls(self):
        self.assertEqual([self.report[x] for x in ('network_operations','guest_exec','root_operations')],[0,0,0])

    def test_14_smb_remains_tcp_only(self):
        o=self.report['real_observations'][2]
        self.assertEqual(o['response_bytes'],0)
        self.assertEqual(o['classification'],'SMB_TCP_CONNECTED_NO_SMB2_RESPONSE_VERIFIED')

    def test_15_ssh_banner_not_a_support(self):
        o=next(x for x in self.report['family_requirements'] if x['family_id']=='SSH-T01')
        self.assertIn('TRANSPORT_NEGOTIATION',o['required_supports_uncredited_for_A6'])
        self.assertTrue(o['candidate_fact_only_no_support_claim'])

    def test_16_ftp_greeting_not_a6_admitted(self):
        o=next(x for x in self.report['family_requirements'] if x['family_id']=='FTP-T01')
        self.assertIn('CONTROL_CHANNEL_RESPONSE',o['required_supports_uncredited_for_A6'])
        self.assertIsNone(o['derived_case_id'])

    def test_17_smb_dialect_not_claimed(self):
        o=next(x for x in self.report['family_requirements'] if x['family_id']=='SMB-T01')
        self.assertIn('SMB_DIALECT',o['required_supports_uncredited_for_A6'])
        self.assertIsNone(o['technical_contribution'])

    def test_18_exact_catalog_pin(self):
        self.assertEqual(self.report['source_catalog_sha256'],
                         '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e')

    def test_19_f1_pin(self):
        self.assertEqual(self.report['source_f1_manifest_sha256'],c.F1_MANIFEST_PIN)

    def test_20_f10r_root_pin(self):
        self.assertEqual(self.report['source_f10r_receipt_sha256'],c.f1.F10R_RECEIPT_SHA)

    def test_21_reject_f1_manifest_substitution(self):
        with self.assertRaisesRegex(c.GapError,'F1_MANIFEST_NOT_PINNED'):
            c.make_report(self.realistic,f1_report_sha256='a'*64,f1_manifest_sha256='0'*64)

    def test_22_reject_f1_report_empty_sha(self):
        with self.assertRaisesRegex(c.GapError,'F1_REPORT_SHA_INVALID'):
            c.make_report(self.realistic,f1_report_sha256='bad',f1_manifest_sha256=c.F1_MANIFEST_PIN)

    def test_23_reject_synthetic_root_authority(self):
        with self.assertRaisesRegex(c.GapError,'F1_AUTHORITY_OR_STATUS_DRIFT'):
            build(self.changed(root_receipt_sha256='f'*64))

    def test_24_reject_false_a6_count(self):
        doc=copy.deepcopy(self.realistic)
        doc['counts']['a6_conditions_admitted']=1
        with self.assertRaisesRegex(c.GapError,'F1_AUTHORITY_OR_STATUS_DRIFT'):build(doc)

    def test_25_reject_fake_case_assignment(self):
        doc=copy.deepcopy(self.realistic)
        doc['observations'][0]['case_identity']='CASE_FAKE'
        with self.assertRaisesRegex(c.GapError,'F1_REAL_EVIDENCE_OR_CASE_DRIFT_ssh'):build(doc)

    def test_26_reject_ftp_changed_target(self):
        doc=copy.deepcopy(self.realistic)
        doc['observations'][1]['target_ip']='10.203.31.9'
        with self.assertRaisesRegex(c.GapError,'F1_REAL_EVIDENCE_OR_CASE_DRIFT_ftp'):build(doc)

    def test_27_reject_smb_fake_response(self):
        doc=copy.deepcopy(self.realistic)
        doc['observations'][2]['response_length']=9
        with self.assertRaisesRegex(c.GapError,'F1_SMB2_MUST_REMAIN_ND'):build(doc)

    def test_28_reject_risk_claim(self):
        with self.assertRaisesRegex(c.GapError,'F1_AUTHORITY_OR_STATUS_DRIFT'):
            build(self.changed(confirmed_final_risk='0.99'))

    def test_29_replay_detects_report_edit(self):
        forged=copy.deepcopy(self.report)
        forged['a6_technical_conditions_admitted']=1
        with self.assertRaisesRegex(c.GapError,'REPORT_NOT_REPRODUCIBLE'):
            c.verify(forged,self.realistic,f1_report_sha256='a'*64,
                     f1_manifest_sha256=c.F1_MANIFEST_PIN)

    def test_30_verified_report_reproducible(self):
        self.assertTrue(c.verify(self.report,self.realistic,
                                 f1_report_sha256='a'*64,f1_manifest_sha256=c.F1_MANIFEST_PIN))

if __name__=='__main__':unittest.main()
