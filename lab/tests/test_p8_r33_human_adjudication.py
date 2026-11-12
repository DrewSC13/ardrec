"""R33 synthetic-only adversarial tests. No private receipt, QCOW2 or client."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r33_human_adjudication as m


def synthetic_queue():
    rows=[]
    for n in range(39):
        rows.append({
            'term_id':f'curl.1.gz:--case{n}',
            'manual_path':'/usr/share/man/man1/curl.1.gz',
            'profile_refs':['FTP-01'],
            'source_line_start_1based':n+1,
            'source_line_end_1based':n+24,
            'context_sha256':hashlib.sha256(f'window{n}'.encode()).hexdigest(),
            'context_line_count':24,
            'context_status':'BOUNDED_ROFF_WINDOW_NOT_COMPLETE_SEMANTIC_CLAUSE',
            'lexical_signals_only_not_conclusions':[],
            'attention':'STANDARD_REVIEW_PRIORITY_ONLY',
            'review_questions':{q:m.UNANSWERED for q in m.QUESTIONS},
            'semantic_review_completed':False,
            'approved_cli_option':False,
            'argv_renderable':False,
            'capability_proven':False,
        })
    return dict(
        schema_version='1.0',
        scope='P8_R32_PRIVATE_SEMANTIC_REVIEW_QUEUE_NO_SEMANTIC_VERDICTS',
        source_main_sha=m.R32_BASE_SHA,
        r31_private_receipt_sha256=m.R31_PRIVATE_SHA,
        source_excerpt_bytes_copied=False,
        profiles=21,source_terms=39,questions_per_term=8,
        unanswered_review_questions=312,
        priority_totals={'STANDARD_REVIEW_PRIORITY_ONLY':39},
        lexical_signal_counts_not_authority={},review_rows=rows,
        semantic_reviews_completed=0,approved_cli_options=0,
        approved_argv_renderers=0,material_fields_unbound=348,
        runtime_proof_gates_unverified=261,authorized_cases=0,
        authorized_profiles=0,dispatch_allowed=False,p8_closed=False,
        p9_started=False,a1_to_a10_started=False,
    )


class AdjudicationTests(unittest.TestCase):
    def setUp(self):
        self.queue=synthetic_queue()
        self.ledger=m.new_ledger(self.queue)
        self.term=self.queue['review_rows'][0]['term_id']
        self.question=m.QUESTIONS[0]
        self.note='Se requiere revisar la cláusula completa antes de toda conclusión.'

    def event(self,events=None,term=None,question=None,disposition=None,note=None):
        return m.make_event(self.ledger,events if events is not None else [],
                            term or self.term,question or self.question,
                            disposition or m.DISPOSITIONS[0],note or self.note)

    def test_01_question_taxonomy(self):
        self.assertEqual(len(m.QUESTIONS),8)
        self.assertEqual(len(set(m.QUESTIONS)),8)
    def test_02_dispositions_cannot_approve(self):
        self.assertEqual(len(m.DISPOSITIONS),3)
        self.assertFalse(any('APPROVED' in d for d in m.DISPOSITIONS))
    def test_03_ledger_has_39_and_312_unanswered(self):
        self.assertEqual(self.ledger['source_terms'],39)
        self.assertEqual(self.ledger['unanswered_review_questions'],312)
    def test_04_ledger_has_no_text_excerpt(self):
        blob=m.canonical(self.ledger)
        self.assertNotIn(b'context_b64_private',blob)
        self.assertNotIn(b'raw_window',blob)
    def test_05_ledger_is_deny_all(self):
        self.assertFalse(self.ledger['dispatch_allowed'])
        self.assertEqual(self.ledger['approved_cli_options'],0)
    def test_06_initial_journal_has_312_untriaged(self):
        result=m.validate_journal(self.ledger,[])
        self.assertEqual(result['questions_still_untriaged'],312)
    def test_07_one_event_no_semantic_promotion(self):
        event=self.event()
        self.assertFalse(event['semantic_review_completed'])
        self.assertFalse(event['approved_cli_option'])
        self.assertFalse(event['capability_proven'])
    def test_08_one_event_only_311_pending(self):
        event=self.event()
        self.assertEqual(m.validate_journal(self.ledger,[event])['questions_still_untriaged'],311)
    def test_09_valid_second_event_chain(self):
        a=self.event()
        b=self.event([a],question=m.QUESTIONS[1])
        self.assertEqual(b['sequence'],2)
        self.assertEqual(b['previous_event_sha256'],m.sha(m.canonical(a)))
    def test_10_repeated_same_term_question_denied(self):
        first=self.event()
        with self.assertRaises(m.Denied):self.event([first])
    def test_11_unknown_term_denied(self):
        with self.assertRaises(m.Denied):self.event(term='evil.1.gz:--force')
    def test_12_unknown_question_denied(self):
        with self.assertRaises(m.Denied):self.event(question='RUNTIME_APPROVED')
    def test_13_invalid_disposition_denied(self):
        with self.assertRaises(m.Denied):self.event(disposition='APPROVED_FOR_EXECUTION')
    def test_14_short_note_denied(self):
        with self.assertRaises(m.Denied):self.event(note='corta')
    def test_15_long_note_denied(self):
        with self.assertRaises(m.Denied):self.event(note='z'*513)
    def test_16_control_character_note_denied(self):
        with self.assertRaises(m.Denied):self.event(note='texto con control\x00 en la nota que no es válida')
    def test_17_bad_previous_sha_denied(self):
        a=self.event()
        a['previous_event_sha256']='0'*64
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a])
    def test_18_bad_sequence_denied(self):
        a=self.event()
        a['sequence']=2
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a])
    def test_19_bad_source_context_denied(self):
        a=self.event()
        a['source_context_sha256']='0'*64
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a])
    def test_20_false_capability_field_not_mutable(self):
        a=self.event()
        a['capability_proven']=True
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a])
    def test_21_dispatch_always_denied(self):
        a=self.event()
        a['dispatch_allowed']=True
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a])
    def test_22_extra_untrusted_field_denied(self):
        a=self.event()
        a['argv']=['curl','target']
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a])
    def test_23_bad_ledger_count_denied(self):
        ledger=copy.deepcopy(self.ledger)
        ledger['approved_cli_options']=1
        with self.assertRaises(m.Denied):m.validate_journal(ledger,[])
    def test_24_bad_ledger_source_denied(self):
        ledger=copy.deepcopy(self.ledger)
        ledger['source_r32_receipt_sha256']='0'*64
        with self.assertRaises(m.Denied):m.validate_journal(ledger,[])
    def test_25_ledger_duplicate_id_denied(self):
        ledger=copy.deepcopy(self.ledger)
        ledger['review_items'][1]=copy.deepcopy(ledger['review_items'][0])
        with self.assertRaises(m.Denied):m.validate_journal(ledger,[])
    def test_26_ledger_context_is_immutable(self):
        ledger=copy.deepcopy(self.ledger)
        ledger['review_items'][0]['source_context_sha256']='bad'
        with self.assertRaises(m.Denied):m.validate_journal(ledger,[])
    def test_27_pinned_receipt_rejects_synthetic(self):
        with self.assertRaises(m.Denied):m.source_queue(m.canonical(self.queue))
    def test_28_pinned_receipt_rejects_override(self):
        with self.assertRaises(m.Denied):m.source_queue(m.canonical(self.queue),'0'*64)
    def test_29_duplicate_json_keys_rejected(self):
        with self.assertRaises(m.Denied):m.parse(b'{"x":1,"x":2}')
    def test_30_non_json_constant_rejected(self):
        with self.assertRaises(m.Denied):m.parse(b'{"x":NaN}')
    def test_31_canonical_serialization_stable(self):
        self.assertEqual(m.canonical(self.ledger),m.canonical(m.parse(m.canonical(self.ledger))))
    def test_32_denied_over_312_events(self):
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[{}]*313)
    def test_33_tampered_note_detected_by_chain(self):
        a=self.event()
        b=self.event([a],question=m.QUESTIONS[1])
        a['reviewer_note_private']='Texto cambiado para forzar desacuerdo en las evidencias.'
        with self.assertRaises(m.Denied):m.validate_journal(self.ledger,[a,b])
    def test_34_distinct_disposition_always_nonapproval(self):
        for disposition in m.DISPOSITIONS:
            row=self.event(disposition=disposition)
            self.assertFalse(row['approved_cli_option'])
            self.assertFalse(row['dispatch_allowed'])
    def test_35_different_terms_can_share_question(self):
        a=self.event()
        b=self.event([a],term=self.queue['review_rows'][1]['term_id'])
        self.assertEqual(m.validate_journal(self.ledger,[a,b])['dispositions_recorded'],2)
    def test_36_no_semantic_reviews_completed_after_events(self):
        a=self.event()
        result=m.validate_journal(self.ledger,[a])
        self.assertEqual(result['semantic_reviews_completed'],0)
    def test_37_deny_invalid_ledger_opaque_field(self):
        l=copy.deepcopy(self.ledger);l['extra']='override'
        with self.assertRaises(m.Denied):m.validate_ledger(l)
    def test_38_deny_json_too_large(self):
        with self.assertRaises(m.Denied):m.parse(b'0'*(m.MAX_QUEUE_SIZE+1))

if __name__=='__main__':unittest.main()
