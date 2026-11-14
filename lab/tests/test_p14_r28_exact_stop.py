"""P14-R28: oráculos exactos, incertidumbre y ausencia de autorización."""
from __future__ import annotations
import copy
from fractions import Fraction
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.analytics.exact_preview import preview_bounds,verify_bounds,ExactPreviewError
from ardrec.stopping.development_stop import preview_stop,verify_stop,StopPreviewError

class ExactA7Tests(unittest.TestCase):
    def test_prior_independent_oracle_file(self):
        import json
        o=json.loads((ROOT/'lab/p14-r28-oracles-v1/oracle.json').read_text(encoding='utf-8'))
        actual=preview_bounds(**o['input'])
        for name,value in o['expected'].items():
            self.assertEqual(actual[name],value)
        self.assertFalse(actual['technical_truth_accredited'])

    def test_zero_evidence_preserves_baseline(self):
        o=preview_bounds('1/4','1/2',[],'1/4')
        self.assertEqual(o['hypothetical_rf'],'1/4')
        self.assertEqual(o['evidence_max'],'0')
        self.assertTrue(verify_bounds(o))
    def test_positive_exact(self):
        o=preview_bounds('1/4','1/2',['1/2'],'1/4')
        self.assertEqual(o['upper'],'5/12')
        self.assertEqual(o['lower'],'1/4')
        self.assertEqual(o['hypothetical_rf'],'5/12')
    def test_contributions_max_not_sum(self):
        o=preview_bounds('1/4','1/2',['1/2','1/2','1/4'],'1/4')
        self.assertEqual(o['evidence_max'],'1/2')
        self.assertEqual(o['hypothetical_rf'],'5/12')
    def test_negative_substitution_exact(self):
        o=preview_bounds('3/4','0',[],'1/4')
        self.assertEqual(o['lower'],'1/3')
        self.assertEqual(o['hypothetical_rf'],'1/3')
    def test_no_negative_adjustment_without_substitution(self):
        self.assertEqual(preview_bounds('3/4','0',[],'3/4')['hypothetical_rf'],'3/4')
    def test_no_confirmation_from_oracle(self):
        d=preview_bounds('1/4','1/2',['1/2'],'1/4')
        self.assertIsNone(d['confirmed_rf'])
        self.assertFalse(d['technical_truth_accredited'])
        self.assertEqual(d['p8_operational'],'NO-GO')
    def test_reject_noncanonical(self):
        for v in ('0.25','2/8','01/4','-1/4','2','1/0','nan',''):
            with self.subTest(v=v),self.assertRaises(ExactPreviewError):
                preview_bounds(v,'1/2',[],'0')
    def test_reject_float(self):
        with self.assertRaises(ExactPreviewError): preview_bounds(0.25,'1/2',[],'0')
    def test_reject_increasing_replacement(self):
        with self.assertRaises(ExactPreviewError): preview_bounds('1/4','1/2',[],'1/2')
    def test_reject_weights(self):
        with self.assertRaises(ExactPreviewError):
            preview_bounds('1/4','1/2',[],'1/4',('0','1/2','1/2'))
    def test_tamper_not_accepted(self):
        d=preview_bounds('1/4','1/2',['1/2'],'1/4')
        d['hypothetical_rf']='1'
        with self.assertRaises(ExactPreviewError): verify_bounds(d)
    def test_same_input_same_sha(self):
        one=preview_bounds('1/4','1/2',['1/2'],'1/4')
        self.assertEqual(one,preview_bounds('1/4','1/2',['1/2'],'1/4'))

class A8Tests(unittest.TestCase):
    def setUp(self):
        self.kw={'a6_classification':'ND','accredited':False,'vm_checked':False,
                 'operational_dispatch':False,'source_sha256':'a'*64}
    def test_no_false_closed_status(self):
        d=preview_stop(**self.kw)
        self.assertIsNone(d['applied_transition'])
        self.assertIsNone(d['terminal_state'])
        self.assertEqual(d['criteria_es_sa_cv_le'],[])
        self.assertTrue(verify_stop(d))
    def test_reject_claimed_accreditation(self):
        q=dict(self.kw,accredited=True)
        with self.assertRaises(StopPreviewError): preview_stop(**q)
    def test_reject_vm_claim(self):
        q=dict(self.kw,vm_checked=True)
        with self.assertRaises(StopPreviewError): preview_stop(**q)
    def test_reject_false_classification(self):
        q=dict(self.kw,a6_classification='VERDADERO')
        with self.assertRaises(StopPreviewError): preview_stop(**q)
    def test_reject_tamper(self):
        doc=preview_stop(**self.kw)
        doc['applied_transition']='CERRADO'
        with self.assertRaises(StopPreviewError): verify_stop(doc)

if __name__=='__main__': unittest.main()
