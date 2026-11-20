"""Synthetic unit fixtures only. NEVER evidence that physical A5/A6 occurred."""
import copy
import unittest
from ardrec.coordination import r114_f3_asset_anchor as c
from ardrec.coordination import r113_f2_agent_ip_identity as q
from test_p14_r114_f2_family_gap import build as f2_sample


def identity():
    return {
        'schema':q.SCHEMA,'verified_interface_count':6,
        'verified_network_count':3,'source':'real_qemu_guest_agent_mac_bound',
        'services_tested':False,'traffic_authorized':False,
        'p8_operational':'NO-GO',
        'endpoints':{
            role:{net:{'mac':mac,'ipv4_cidr':cidr,'bridge':q.BRIDGES[net]}
                  for net,(mac,cidr) in nets.items()}
            for role,nets in q.EXPECTED.items()
        },
    }


def make(matrix=None,ident=None,**args):
    return c.make_report(
        f2_sample() if matrix is None else matrix,
        identity() if ident is None else ident,
        matrix_manifest_sha256=args.get('matrix_sha',c.F2_MATRIX_MANIFEST_PIN),
        identity_manifest_sha256=args.get('ident_sha',c.R113_F2_IDENTITY_MANIFEST_PIN),
        matrix_report_sha256=args.get('report_sha',c.F2_MATRIX_REPORT_PIN),
    )


class RealAssetAnchorContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix=f2_sample()
        cls.ident=identity()
        cls.report=make(cls.matrix,cls.ident)

    def bad_matrix(self,fn):
        obj=copy.deepcopy(self.matrix)
        fn(obj)
        with self.assertRaises(c.AnchorError):make(matrix=obj)

    def bad_identity(self,fn):
        obj=copy.deepcopy(self.ident)
        fn(obj)
        with self.assertRaises(c.AnchorError):make(ident=obj)

    def test_01_three_assets(self):
        self.assertEqual(len(self.report['assets']),3)
    def test_02_three_physical_roles(self):
        self.assertEqual([a['role'] for a in self.report['assets']],['ssh','ftp','smb'])
    def test_03_29_catalogue_candidates(self):
        self.assertEqual(len(self.report['case_planning_candidates']),29)
    def test_04_25_distinct_family_ids(self):
        self.assertEqual(len({x['family_id'] for x in self.report['case_planning_candidates']}),25)
    def test_05_8_10_11_variants_by_asset(self):
        counts={a['asset_anchor_id']:sum(x['asset_anchor_id']==a['asset_anchor_id']
                for x in self.report['case_planning_candidates']) for a in self.report['assets']}
        self.assertEqual(list(counts.values()),[8,10,11])
    def test_06_three_unique_asset_anchors(self):
        self.assertEqual(len({a['asset_anchor_id'] for a in self.report['assets']}),3)
    def test_07_29_unique_planning_ids(self):
        self.assertEqual(len({x['candidate_planning_id'] for x in self.report['case_planning_candidates']}),29)
    def test_08_no_created_a5_case_id(self):
        self.assertTrue(all(x['case_id_a5'] is None and x['derived_case_id'] is None
                            for x in self.report['case_planning_candidates']))
    def test_09_no_attempt_or_assessment_index(self):
        self.assertTrue(all(x['assessment_index'] is None and x['attempt_id'] is None
                            for x in self.report['case_planning_candidates']))
    def test_10_no_a5_execution(self):
        self.assertEqual((self.report['a5_case_bindings_accredited'],self.report['a5_starts']),(0,0))
    def test_11_a6_stays_nd(self):
        self.assertEqual(self.report['a6_classification'],'ND')
        self.assertTrue(all(x['a6_classification']=='ND' for x in self.report['case_planning_candidates']))
    def test_12_no_risk(self):
        self.assertIsNone(self.report['confirmed_final_risk'])
        self.assertFalse(self.report['a7_risk_recalculated'])
    def test_13_no_state_transition(self):
        self.assertEqual(self.report['a8_transitions_applied'],0)
    def test_14_no_publication(self):
        self.assertIsNone(self.report['a9_published_generation'])
    def test_15_no_operational_algorithm_executions(self):
        self.assertEqual(self.report['algorithms_operationally_executed'],[])
        self.assertEqual(set(self.report['a1_to_a10_authority_boundaries']),set(c.ALGORITHM_CODES))
    def test_16_no_root_qga_tcp(self):
        self.assertEqual([self.report[k] for k in ('new_guest_exec','new_network_calls','new_root_calls')],[0,0,0])
    def test_17_ip_mac_pairs_real(self):
        self.assertEqual(self.report['assets'][0]['runner_mac'],'52:54:00:ad:30:01')
        self.assertEqual(self.report['assets'][0]['target_mac'],'52:54:00:ad:30:02')
    def test_18_bridge_scope_exact(self):
        self.assertEqual([a['bridge'] for a in self.report['assets']],['br33d30','br33d31','br33d32'])
    def test_19_port_scope_exact(self):
        self.assertEqual([a['tcp_port'] for a in self.report['assets']],[22,21,445])
    def test_20_smb_zero_bytes(self):
        self.assertEqual(self.report['assets'][2]['response_bytes'],0)
        self.assertFalse(self.report['assets'][2]['protocol_negotiation_admitted'])
    def test_21_ftp_does_not_admit_greeting_as_a6(self):
        row=next(x for x in self.report['case_planning_candidates'] if x['family_id']=='FTP-T01')
        self.assertIn('CONTROL_CHANNEL_RESPONSE',row['catalogue_required_supports_not_admitted'])
    def test_22_ssh_requires_host_key(self):
        row=next(x for x in self.report['case_planning_candidates'] if x['family_id']=='SSH-T01')
        self.assertIn('HOST_KEY_MATCH',row['catalogue_required_supports_not_admitted'])
    def test_23_smb_requires_dialect(self):
        row=next(x for x in self.report['case_planning_candidates'] if x['family_id']=='SMB-T01')
        self.assertIn('SMB_DIALECT',row['catalogue_required_supports_not_admitted'])
    def test_24_fail_false_identity_mac(self):
        self.bad_identity(lambda x:x['endpoints']['ssh']['ssh'].update(mac='52:54:00:00:00:00'))
    def test_25_fail_false_identity_ip(self):
        self.bad_identity(lambda x:x['endpoints']['runner']['ftp'].update(ipv4_cidr='10.203.31.4/28'))
    def test_26_fail_false_identity_bridge(self):
        self.bad_identity(lambda x:x['endpoints']['smb']['smb'].update(bridge='br999'))
    def test_27_fail_promoted_identity_p8(self):
        self.bad_identity(lambda x:x.update(p8_operational='GO'))
    def test_28_fail_source_hash_pin(self):
        with self.assertRaisesRegex(c.AnchorError,'PINNED_SOURCE'):
            make(report_sha='0'*64)
    def test_29_fail_f2_matrix_a5_case(self):
        self.bad_matrix(lambda x:x['family_requirements'][0].update(derived_case_id='SSH-T01-S01-01'))
    def test_30_fail_f2_matrix_smb_fake_dialect(self):
        self.bad_matrix(lambda x:x['real_observations'][2].update(classification='SMB2_NEGOTIATED'))
    def test_31_fail_f2_matrix_a7_risk(self):
        self.bad_matrix(lambda x:x.update(confirmed_final_risk='0.1'))
    def test_32_fail_f2_matrix_catalog_change(self):
        self.bad_matrix(lambda x:x.update(source_catalog_sha256='0'*64))
    def test_33_fail_f2_matrix_new_network_call(self):
        self.bad_matrix(lambda x:x.update(network_operations=1))
    def test_34_replay_recomputes_report_exact(self):
        self.assertTrue(c.verify(self.report,self.matrix,self.ident,
             matrix_manifest_sha256=c.F2_MATRIX_MANIFEST_PIN,
             identity_manifest_sha256=c.R113_F2_IDENTITY_MANIFEST_PIN,
             matrix_report_sha256=c.F2_MATRIX_REPORT_PIN))
    def test_35_replay_rejects_forged_a5(self):
        report=copy.deepcopy(self.report)
        report['a5_starts']=1
        with self.assertRaisesRegex(c.AnchorError,'F3_REPORT_NOT_REPRODUCIBLE'):
            c.verify(report,self.matrix,self.ident,
                matrix_manifest_sha256=c.F2_MATRIX_MANIFEST_PIN,
                identity_manifest_sha256=c.R113_F2_IDENTITY_MANIFEST_PIN,
                matrix_report_sha256=c.F2_MATRIX_REPORT_PIN)
    def test_36_replay_rejects_forged_smb2(self):
        report=copy.deepcopy(self.report)
        report['assets'][2]['protocol_negotiation_admitted']=True
        with self.assertRaises(c.AnchorError):
            c.verify(report,self.matrix,self.ident,
                matrix_manifest_sha256=c.F2_MATRIX_MANIFEST_PIN,
                identity_manifest_sha256=c.R113_F2_IDENTITY_MANIFEST_PIN,
                matrix_report_sha256=c.F2_MATRIX_REPORT_PIN)

if __name__=='__main__':unittest.main()
