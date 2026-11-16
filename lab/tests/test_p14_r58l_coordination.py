"""R58-L: adversarial A4-A5 synthetic coordination over 25 family preview."""
from __future__ import annotations

from copy import deepcopy
from io import StringIO
import json
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr

from ardrec.coordination import r58l_a4_a5_family_review as m
from ardrec.coordination import r58k_unified_family_bridge as k
from ardrec.evidence import r58h_ssh_family_logic as ssh
from ardrec.evidence import r58i_ftp_family_logic as ftp
from ardrec.evidence import r58j_smb_family_logic as smb
from scripts import ardrec_p14_r58k_unified_family_demo as demo_k
from scripts import ardrec_p14_r58l_a4_a5_review_demo as demo_l


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patches=[]
        if not ssh.CATALOG_PATH.exists():
            # Explicit test-spec substitution exists only in this test fixture.
            # Production has no catalogue fallback.
            from test_p14_r58h_ssh_family_logic import specs as ssh_specs
            from test_p14_r58i_ftp_family_logic import specs as ftp_specs
            from test_p14_r58j_smb_family_logic import specs as smb_specs
            bindings=(
                (ssh,'load_pinned_catalog',lambda: ssh._specs(ssh_specs())),
                (ftp,'load_pinned_ftp_catalog',lambda: ftp._specs(ftp_specs())),
                (smb,'load_pinned_smb_catalog',lambda: smb._specs(smb_specs())),
                (demo_k,'load_pinned_catalog',lambda: ssh._specs(ssh_specs())),
                (demo_k,'load_pinned_ftp_catalog',lambda: ftp._specs(ftp_specs())),
                (demo_k,'load_pinned_smb_catalog',lambda: smb._specs(smb_specs())),
            )
            for obj,name,value in bindings:
                p=patch.object(obj,name,side_effect=value)
                p.start();cls.patches.append(p)
        cls.entries=demo_l.synthetic_entries()

    @classmethod
    def tearDownClass(cls):
        for p in reversed(cls.patches):p.stop()

    def entry(self,service='SSH_DEV'):
        return deepcopy(next(e for e in self.entries if e['service_id']==service))

    def build(self, entries=None, **kwargs):
        return m.build_a4_a5_review(deepcopy(self.entries if entries is None else entries),**kwargs)

    def single(self,service='SSH_DEV', **kwargs):
        return self.build([self.entry(service)],**kwargs)

    def intent(self, preview):
        return {**preview['a4_selected_identity'], 'attempt_id':'ATT_SAMPLE_01',
                'action':'SYNTHETIC_REVIEW_ONLY'}

    def bad(self,mutator,expected=None):
        entries=[self.entry()];mutator(entries)
        with self.assertRaises(m.CoordinationError if expected is not None else (ValueError,TypeError,KeyError)) as ctx:
            self.build(entries)
        if expected is not None:self.assertEqual(str(ctx.exception),expected)

    def test_real_pinned_catalog_when_present(self):
        if not ssh.CATALOG_PATH.exists():
            self.skipTest('TEST_ONLY_FIXTURE_NOT_PINNED')
        self.assertEqual(len(ssh.load_pinned_catalog()),8)
        self.assertEqual(len(ftp.load_pinned_ftp_catalog()),8)
        self.assertEqual(len(smb.load_pinned_smb_catalog()),9)
        r=self.build()
        self.assertEqual(r['covered_family_count'],25)
        self.assertEqual(r['source_catalog_sha256'],ssh.CATALOG_SHA256)

    def test_all_25_and_29(self):
        r=self.build()
        self.assertEqual((r['covered_family_count'],r['unit_count']),(25,29))
        self.assertEqual(r['count_by_service'],{'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11})
        self.assertEqual(len(r['a4']['candidates']),29)
        self.assertEqual(r['a4']['eligible_count'],29)

    def test_no_operational_authority(self):
        r=self.build()
        self.assertEqual(r['a6_classification'],'ND')
        self.assertIs(r['technical_truth_accredited'],False)
        self.assertIs(r['operational_dispatch'],False)
        self.assertIs(r['vm_checks_executed'],False)
        self.assertEqual(r['host_mutations'],0)
        self.assertEqual(r['p8_operational'],'NO-GO')
        self.assertIsNone(r['confirmed_final_risk'])
        self.assertIsNone(r['published_generation'])
        self.assertIsNone(r['applied_state_transition'])
        self.assertIsNone(r['a4_operational_selection'])
        self.assertEqual(r['a5']['actual_attempts_started'],0)
        self.assertEqual(r['a5']['actual_attempt_reservations'],0)

    def test_a4_selection_and_precedence(self):
        r=self.build()
        self.assertIsNotNone(r['a4']['selected'])
        self.assertTrue(r['a4_selected_identity'])
        selected=[d for d in r['decisions'] if d['a4_selected_simulated']]
        self.assertEqual(len(selected),1)
        self.assertEqual(r['a4']['selected']['precedence'],1)
        self.assertEqual(r['a4']['maximum_priority_ties'],29)

    def test_a4_no_evidence_promotion(self):
        r=self.single()
        self.assertEqual(r['a4']['selected']['priority'],'1/4')
        self.assertEqual(r['a4']['source_kind'],'SYNTHETIC_PROJECTION_ONLY')
        self.assertEqual(r['unified']['a6_classification'],'ND')

    def test_a7_full_uncertainty(self):
        r=self.single()
        d=r['decisions'][0]
        self.assertEqual((d['a7_rf_lower'],d['a7_rf_upper']),('1/4','7/12'))
        self.assertEqual(d['a8_recommendation'],'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
        self.assertEqual(d['a6_classification'],'ND')
        self.assertIsNone(d['confirmed_rf'])

    def test_intent_review_only(self):
        seed=self.single()
        r=self.single(attempt_intent=self.intent(seed))
        self.assertEqual(r['a5']['disposition'],'SYNTHETIC_INTENT_REVIEWED_NO_RESERVATION')
        self.assertFalse(r['a5']['real_attempt_budget_attested'])
        self.assertEqual(r['a5']['actual_attempts_started'],0)
        self.assertEqual(r['a5']['ordinary_attempt_budget'],1)

    def test_without_intent_does_not_propose_attempt(self):
        r=self.single()
        self.assertEqual(r['a5']['disposition'],'NO_ATTEMPT_INTENT')
        self.assertFalse(r['a5']['attempt_intent_seen'])
        self.assertEqual(r['attempt_history'],[])

    def test_history_blocks_second_intent(self):
        seed=self.single(); intent=self.intent(seed)
        history=[{**seed['a4_selected_identity'],'attempt_id':'ATT_PRIOR_001',
                  'state':'RECOVERY_UNCERTAIN'}]
        r=self.single(attempt_history=history,attempt_intent=intent)
        self.assertEqual(r['a5']['disposition'],'BLOCKED_ORDINARY_BUDGET_CONSUMED_NO_RETRY')
        self.assertEqual(r['a5']['actual_attempts_started'],0)

    def test_all_prior_states_block_retries(self):
        seed=self.single(); intent=self.intent(seed)
        for state in m.HISTORY_STATES:
            with self.subTest(state=state):
                h=[{**seed['a4_selected_identity'],'attempt_id':'ATT_PRIOR_001',
                    'state':state}]
                self.assertEqual(self.single(attempt_intent=intent,
                    attempt_history=h)['a5']['disposition'],
                    'BLOCKED_ORDINARY_BUDGET_CONSUMED_NO_RETRY')

    def test_forged_real_authorization_rejected(self):
        seed=self.single(); intent=self.intent(seed)
        intent['action']='EXECUTE_VM'
        with self.assertRaisesRegex(ValueError,'INTENT_MUST_BE_REVIEW_ONLY'):
            self.single(attempt_intent=intent)

    def test_intent_nonwinner_rejected(self):
        seed=self.single(); intent=self.intent(seed)
        intent['derived_case_id']='SSH-T02-S01-01'
        with self.assertRaisesRegex(ValueError,'INTENT_NOT_A4_WINNER'):
            self.single(attempt_intent=intent)

    def test_intent_with_no_candidate_rejected(self):
        entry=self.entry();entry['applicable']=False
        intent={'service_id':'SSH_DEV','session_id':entry['unit']['session_id'],
                'derived_case_id':entry['unit']['derived_case_id'],
                'assessment_index':0,'attempt_id':'ATT_DEMO_001',
                'action':'SYNTHETIC_REVIEW_ONLY'}
        with self.assertRaisesRegex(ValueError,'INTENT_WITHOUT_A4_WINNER'):
            self.build([entry],attempt_intent=intent)

    def test_no_candidate_is_not_execution(self):
        entry=self.entry();entry['applicable']=False
        r=self.build([entry])
        self.assertIsNone(r['a4']['selected'])
        self.assertEqual(r['a5']['disposition'],'NO_ELIGIBLE_CASE')

    def test_non_pending_ineligible(self):
        entry=self.entry();entry['unit']['phase']='PREPARADO'
        r=self.build([entry]);self.assertIsNone(r['a4']['selected'])
        self.assertEqual(r['decisions'][0]['a4_blocker'],'STATE_NOT_PENDING')

    def test_nd_guard_ineligible(self):
        entry=self.entry();entry['unit']['preconditions']['SCOPE_APPROVED']='ND'
        r=self.build([entry]);self.assertIsNone(r['a4']['selected'])
        self.assertEqual(r['decisions'][0]['a4_blocker'],'GUARD_NOT_TRUE')

    def test_false_guard_ineligible(self):
        entry=self.entry();entry['unit']['preconditions']['SCOPE_APPROVED']='FALSO'
        r=self.build([entry]);self.assertIsNone(r['a4']['selected'])
        self.assertEqual(r['decisions'][0]['a4_blocker'],'GUARD_NOT_TRUE')

    def test_hypothetical_positive_never_grants_execution(self):
        entry=self.entry();entry['unit']['outcome']='OBSERVADO_POSITIVO'
        r=self.build([entry])
        self.assertEqual(r['decisions'][0]['a6_hypothetical_result'],'POSITIVO_VALIDO')
        self.assertEqual(r['a6_classification'],'ND')
        self.assertIsNone(r['confirmed_final_risk'])

    def test_hypothetical_negative_never_means_zero(self):
        entry=self.entry();entry['unit']['outcome']='OBSERVADO_NEGATIVO'
        r=self.build([entry])
        self.assertEqual(r['decisions'][0]['a6_hypothetical_result'],'NEGATIVO_VALIDO')
        self.assertEqual(r['decisions'][0]['a7_rf_upper'],'7/12')

    def test_permutation_invariant(self):
        self.assertEqual(self.build(),self.build(list(reversed(self.entries))))

    def test_distinct_ftp_variants(self):
        r=self.build()
        a=[x for x in r['decisions'] if x['family_id']=='FTP-T02']
        self.assertEqual({x['variant'] for x in a},{'CONTROL','DATA'})
        self.assertEqual(len({x['case_id_a7'] for x in a}),2)
        self.assertEqual({x['a4_precedence'] for x in a},{1,3})

    def test_distinct_smb_variants(self):
        r=self.build()
        a=[x for x in r['decisions'] if x['family_id']=='SMB-T03']
        self.assertEqual({x['variant'] for x in a},{'SIGNING','ENCRYPTION'})
        self.assertEqual(len({x['case_id_a7'] for x in a}),2)
        self.assertEqual({x['a4_precedence'] for x in a},{3})

    def test_distinct_read_write(self):
        r=self.build()
        for fid in ('FTP-T08','SMB-T09'):
            a=[x for x in r['decisions'] if x['family_id']==fid]
            self.assertEqual({x['variant'] for x in a},{'READ','WRITE'})
            self.assertEqual({x['a4_precedence'] for x in a},{3,4})

    def test_sparse_ssh(self):
        self.assertEqual(self.single()['count_by_service'],{'SSH_DEV':1,'FTP_DEV':0,'SMB_DEV':0})

    def test_sparse_ftp(self):
        self.assertEqual(self.single('FTP_DEV')['a4']['eligible_count'],1)

    def test_sparse_smb(self):
        self.assertEqual(self.single('SMB_DEV')['a4']['eligible_count'],1)

    def test_54_allowed(self):
        extra=deepcopy(self.entries)
        for row in self.entries[:25]:
            v=deepcopy(row);v['unit']['assessment_index']=1;extra.append(v)
        self.assertEqual(self.build(extra)['unit_count'],54)

    def test_55_refused(self):
        extra=deepcopy(self.entries)
        for row in self.entries[:26]:
            v=deepcopy(row);v['unit']['assessment_index']=1;extra.append(v)
        with self.assertRaisesRegex(ValueError,'ENTRY_COUNT'):
            self.build(extra)

    def test_reject_empty(self):
        with self.assertRaisesRegex(ValueError,'ENTRY_COUNT'):self.build([])

    def test_reject_nonlist(self):
        with self.assertRaisesRegex(ValueError,'ENTRY_COUNT'):self.build({})

    def test_reject_applicability_string(self):
        self.bad(lambda x:x[0].update(applicable='VERDADERO'),'APPLICABILITY_MUST_BE_BOOLEAN')

    def test_reject_extra_entry_field(self):
        self.bad(lambda x:x[0].update(authorized=True),'ENTRY_SCHEMA')

    def test_reject_missing_entry_field(self):
        self.bad(lambda x:x[0].pop('applicable'),'ENTRY_SCHEMA')

    def test_reject_duplicate_entry(self):
        self.bad(lambda x:x.append(deepcopy(x[0])),'DUPLICATE_APPLICABILITY')

    def test_reject_mixed_sessions(self):
        rows=[self.entry('SSH_DEV'),self.entry('FTP_DEV')]
        rows[1]['unit']['session_id']='DIFFERENT_SESSION'
        with self.assertRaisesRegex(ValueError,'MIXED_SESSIONS'):
            self.build(rows)

    def test_reject_invalid_risk(self):
        self.bad(lambda x:x[0]['risk'].update(initial_risk='7/4'))

    def test_reject_injected_evidence(self):
        self.bad(lambda x:x[0].update(evidence={'evil':1}),'ENTRY_SCHEMA')

    def test_reject_forged_support(self):
        self.bad(lambda x:x[0]['unit']['supports'].update(EVIL='VERDADERO'))

    def test_reject_unknown_service(self):
        self.bad(lambda x:x[0].update(service_id='HTTP_DEV'))

    def test_reject_history_not_list(self):
        with self.assertRaisesRegex(ValueError,'HISTORY_COUNT'):
            self.single(attempt_history={})

    def test_reject_history_missing_field(self):
        with self.assertRaisesRegex(ValueError,'ATTEMPT_RECORD_SCHEMA'):
            self.single(attempt_history=[{'attempt_id':'ATT_PRIOR'}])

    def test_reject_history_unbound_case(self):
        r=self.single();h={**r['a4_selected_identity'],'attempt_id':'ATT_PRIOR',
                           'state':'RESERVED','derived_case_id':'SSH-T02-S01-01'}
        with self.assertRaisesRegex(ValueError,'HISTORY_UNBOUND_CASE'):
            self.single(attempt_history=[h])

    def test_reject_history_duplicate_case_budget(self):
        r=self.single();key=r['a4_selected_identity']
        h=[{**key,'attempt_id':'ATT_ONE','state':'RESERVED'},
           {**key,'attempt_id':'ATT_TWO','state':'RECORDED_LIMITED'}]
        with self.assertRaisesRegex(ValueError,'ORDINARY_BUDGET_EXCEEDED_NO_RETRY'):
            self.single(attempt_history=h)

    def test_reject_duplicate_history_id(self):
        r=self.build([self.entry('SSH_DEV'),self.entry('FTP_DEV')])
        a=r['decisions']
        h=[{**{k:d[k] for k in m.IDENTITY_FIELDS},'attempt_id':'ATT_SAME',
            'state':'RESERVED'} for d in a]
        with self.assertRaisesRegex(ValueError,'DUPLICATE_ATTEMPT_ID'):
            self.build([self.entry('SSH_DEV'),self.entry('FTP_DEV')],attempt_history=h)

    def test_reject_intent_replayed_id(self):
        r=self.single();key=r['a4_selected_identity']; intent=self.intent(r)
        history=[{**key,'attempt_id':intent['attempt_id'],'state':'RESERVED'}]
        with self.assertRaisesRegex(ValueError,'ATTEMPT_ID_REPLAY'):
            self.single(attempt_intent=intent,attempt_history=history)

    def test_reject_intent_extra_field(self):
        seed=self.single();intent=self.intent(seed);intent['authorized']=True
        with self.assertRaisesRegex(ValueError,'ATTEMPT_RECORD_SCHEMA'):
            self.single(attempt_intent=intent)

    def test_reject_intent_invalid_id(self):
        seed=self.single();intent=self.intent(seed);intent['attempt_id']='../PATH'
        with self.assertRaisesRegex(ValueError,'ATTEMPT_ID'):
            self.single(attempt_intent=intent)

    def test_reject_intent_other_session(self):
        seed=self.single();intent=self.intent(seed);intent['session_id']='DIFFERENT_SESSION'
        with self.assertRaisesRegex(ValueError,'INTENT_NOT_A4_WINNER'):
            self.single(attempt_intent=intent)

    def test_reject_history_invalid_state(self):
        seed=self.single();h=[{**seed['a4_selected_identity'],
                                'attempt_id':'ATT_OLD','state':'EXECUTED_ON_VM'}]
        with self.assertRaisesRegex(ValueError,'HISTORY_STATE_INVALID'):
            self.single(attempt_history=h)

    def test_reject_boolean_assessment_index(self):
        self.bad(lambda x:x[0]['unit'].update(assessment_index=True))

    def test_reject_noncanonical_priority(self):
        rows=[self.entry()];rows[0]['risk']['normalized_criticality']='2/4'
        with self.assertRaises((ValueError,TypeError)):self.build(rows)

    def test_input_is_not_aliased_to_report(self):
        entry=self.entry()
        report=self.build([entry])
        entry['unit']['session_id']='LATER_MUTATION'
        entry['risk']['initial_risk']='0'
        self.assertEqual(report['inputs'][0]['unit']['session_id'],'DEV_TUTOR_001')
        self.assertEqual(report['inputs'][0]['risk']['initial_risk'],'1/4')
        self.assertTrue(m.verify_a4_a5_review(report))

    def test_report_reproducible(self):
        report=self.single();self.assertTrue(m.verify_a4_a5_review(report))
        self.assertEqual(report,self.single())

    def test_report_tampered_digest(self):
        report=self.single();report['sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_report_rehashed_fake_risk(self):
        report=self.single();report['confirmed_final_risk']='0'
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_report_rehashed_fake_dispatch(self):
        report=self.single();report['operational_dispatch']=True
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_report_rehashed_fake_selected(self):
        report=self.single();report['a4']['selected']['case_id']='CASE_FAKE'
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_report_rehashed_fake_a5(self):
        report=self.single();report['a5']['actual_attempts_started']=1
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_report_rehashed_fake_nested_a6(self):
        report=self.single();report['unified']['a6_classification']='POSITIVO_VALIDO'
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_report_rehashed_fake_a9_generation(self):
        report=self.single();report['published_generation']=1
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'REPORT_NOT_REPRODUCIBLE'):
            m.verify_a4_a5_review(report)

    def test_cli_needs_explicit_flag(self):
        with patch('sys.argv',['demo']):
            out=StringIO()
            with redirect_stderr(out):
                rc=demo_l.main()
        self.assertEqual(rc,23)
        self.assertIn('EXPLICIT_OFFLINE',out.getvalue())

    def test_cli_summary(self):
        if not ssh.CATALOG_PATH.exists():
            self.skipTest('CLI_SOURCE_REAL_PIN_NOT_AVAILABLE_IN_TEMPORARY_FIXTURE')
        with patch('sys.argv',['demo','--synthetic-offline']):
            out=StringIO()
            with redirect_stdout(out):
                rc=demo_l.main()
        self.assertEqual(rc,0)
        d=json.loads(out.getvalue())
        self.assertEqual(d['unit_count'],29)
        self.assertEqual(d['covered_family_count'],25)
        self.assertEqual(d['a5_actual_starts'],0)
        self.assertEqual(d['a6_classification'],'ND')


if __name__ == '__main__':
    unittest.main()
