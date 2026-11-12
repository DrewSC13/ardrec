"""R34 synthetic-only adversarial tests. Zero real private evidence or clients."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import p8_r33_human_adjudication as r33
import p8_r34_review_navigation as m
from test_p8_r33_human_adjudication import synthetic_queue


class ReviewNavigationTests(unittest.TestCase):
    def setUp(self):
        self.queue = synthetic_queue()
        self.ledger = r33.new_ledger(self.queue)
        self.events = []
        self.term = self.queue['review_rows'][0]['term_id']
        self.note = 'Revisar cláusula íntegra en fuente autenticada antes de concluir.'
    def get(self):
        return m.review_index(self.queue,self.ledger,self.events)
    def add(self, term=None, question=None, disposition=None):
        self.events.append(r33.make_event(self.ledger,self.events,term or self.term,
                          question or r33.QUESTIONS[0],disposition or r33.DISPOSITIONS[0],self.note))
    def test_01_empty_312(self):
        self.assertEqual(self.get()['questions_untriaged'],312)
    def test_02_empty_39(self):
        self.assertEqual(len(self.get()['entries']),39)
    def test_03_no_approval(self):
        self.assertFalse(self.get()['dispatch_allowed'])
    def test_04_no_semantic_reviews(self):
        self.assertEqual(self.get()['semantic_reviews_completed'],0)
    def test_05_per_question_initial_counts(self):
        self.assertEqual(list(self.get()['questions_untriaged_by_kind'].values()),[39]*8)
    def test_06_all_initial_untriaged(self):
        self.assertTrue(all(v==m.STATES[0] for e in self.get()['entries'] for v in e['question_states'].values()))
    def test_07_single_documentary_disposition(self):
        self.add(); self.assertEqual(self.get()['documentary_dispositions_recorded'],1)
    def test_08_single_count_311(self):
        self.add(); self.assertEqual(self.get()['questions_untriaged'],311)
    def test_09_note_never_in_result(self):
        self.add(); self.assertNotIn(self.note,str(self.get()))
    def test_10_disposition_never_in_result(self):
        self.add(); self.assertNotIn(r33.DISPOSITIONS[0],str(self.get()))
    def test_11_no_excerpt_bytes(self):
        self.assertNotIn('context_b64_private',str(self.get()))
    def test_12_row_source_window_not_clause(self):
        self.assertFalse(self.get()['entries'][0]['full_clause_certified'])
    def test_13_documentary_record_not_authority(self):
        self.add(); self.assertEqual(self.get()['approved_cli_options'],0)
    def test_14_focus(self):
        self.assertEqual(m.one_term(self.get(),self.term)['term_id'],self.term)
    def test_15_focus_unknown(self):
        with self.assertRaises(r33.Denied):m.one_term(self.get(),'curl.1.gz:--absent')
    def test_16_page_five(self):
        self.assertEqual(len(m.page(self.get())),5)
    def test_17_page_last(self):
        self.assertEqual(len(m.page(self.get(),38,5)),1)
    def test_18_page_10(self):
        self.assertEqual(len(m.page(self.get(),0,10)),10)
    def test_19_page_11_denied(self):
        with self.assertRaises(r33.Denied):m.page(self.get(),0,11)
    def test_20_page_negative_denied(self):
        with self.assertRaises(r33.Denied):m.page(self.get(),-1,5)
    def test_21_page_offset_39_denied(self):
        with self.assertRaises(r33.Denied):m.page(self.get(),39,5)
    def test_22_page_bool_denied(self):
        with self.assertRaises(r33.Denied):m.page(self.get(),False,5)
    def test_23_page_limit_zero_denied(self):
        with self.assertRaises(r33.Denied):m.page(self.get(),0,0)
    def test_24_focus_nonstring_denied(self):
        with self.assertRaises(r33.Denied):m.one_term(self.get(),None)
    def test_25_duplicate_term_denied(self):
        q=copy.deepcopy(self.queue);q['review_rows'][1]['term_id']=q['review_rows'][0]['term_id']
        with self.assertRaises(r33.Denied):m.review_index(q,self.ledger,[])
    def test_26_source_context_tamper_denied(self):
        q=copy.deepcopy(self.queue);q['review_rows'][0]['context_sha256']='0'*64
        with self.assertRaises(r33.Denied):m.review_index(q,self.ledger,[])
    def test_27_ledger_tamper_denied(self):
        l=copy.deepcopy(self.ledger);l['authorized_cases']=1
        with self.assertRaises(r33.Denied):m.review_index(self.queue,l,[])
    def test_28_duplicate_event_denied(self):
        self.add(); self.events.append(copy.deepcopy(self.events[0]))
        with self.assertRaises(r33.Denied):self.get()
    def test_29_broken_event_chain_denied(self):
        self.add();self.events[0]['previous_event_sha256']='0'*64
        with self.assertRaises(r33.Denied):self.get()
    def test_30_unapproved_record_denied(self):
        self.add();self.events[0]['approved_cli_option']=True
        with self.assertRaises(r33.Denied):self.get()
    def test_31_no_unknown_question(self):
        q=copy.deepcopy(self.queue);q['review_rows'][0]['review_questions']['FAKE']='pass'
        with self.assertRaises(r33.Denied):m.review_index(q,self.ledger,[])
    def test_32_no_claim_complete_clause(self):
        q=copy.deepcopy(self.queue);q['review_rows'][0]['context_status']='COMPLETE'
        with self.assertRaises(r33.Denied):m.review_index(q,self.ledger,[])
    def test_33_order_preserved(self):
        self.assertEqual([x['term_id'] for x in self.get()['entries']],
                         [x['term_id'] for x in self.queue['review_rows']])
    def test_34_multiple_distinct_questions(self):
        self.add();self.add(question=r33.QUESTIONS[1]);self.assertEqual(self.get()['questions_untriaged'],310)
    def test_35_different_terms(self):
        self.add();self.add(term=self.queue['review_rows'][1]['term_id']);self.assertEqual(self.get()['questions_untriaged'],310)
    def test_36_high_priority_is_only_priority(self):
        self.queue['review_rows'][0]['attention']='ELEVATED_REVIEW_PRIORITY_ONLY'
        result=self.get()['entries'][0]
        self.assertFalse(result['operational_approval'])
        self.assertEqual(result['priority'],'ELEVATED_REVIEW_PRIORITY_ONLY')
    def test_37_synthetic_marked_not_authentic(self):
        with self.assertRaises(r33.Denied):r33.source_queue(r33.canonical(self.queue))
    def test_38_sha_chain_visible_only(self):
        self.add();self.assertEqual(self.get()['latest_r33_event_sha256'],r33.sha(r33.canonical(self.events[-1])))
    def test_39_source_ids_retain_manual(self):
        self.assertEqual(self.get()['entries'][0]['manual_id'],'curl.1.gz')
    def test_40_no_automatic_event_creation(self):
        self.get();self.assertEqual(self.events,[])

if __name__=='__main__': unittest.main()
