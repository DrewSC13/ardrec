"""R27 A4: invariantes de seleccion exacta (tesis 3.2.6, 3.4.2)."""
from __future__ import annotations
import copy
from fractions import Fraction
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from ardrec.selection.greedy_development import (
    SelectionError, canon, select_development, verify_selection)

SID='a'*64

def sample():
    base=dict(phase='PENDIENTE',guard='VERDADERO',applicable=True,
              initial_risk='1/4',evidence='0',criticality='1/2')
    return [dict(base,service_id='SSH_DEV',case_id='CASE_POLICY',precedence=20),
            dict(base,service_id='SSH_DEV',case_id='CASE_REFERENCE',precedence=10),
            dict(base,service_id='FTP_DEV',case_id='CASE_POLICY',precedence=2,
                 phase='PREPARADO')]

class GreedyTests(unittest.TestCase):
    def test_exact_oracle(self):
        view=select_development(sample(),SID)
        self.assertEqual(view['selected'],dict(service_id='SSH_DEV',
            case_id='CASE_REFERENCE',priority='1/4',precedence=10))
        self.assertEqual(view['maximum_priority_ties'],2)
        self.assertEqual(view['eligible_count'],2)
        self.assertTrue(verify_selection(view,sample()))
    def test_permutation_stable(self):
        self.assertEqual(select_development(sample(),SID),
                         select_development(list(reversed(sample())),SID))
    def test_empty_returns_none(self):
        v=select_development([],SID)
        self.assertIsNone(v['selected'])
    def test_not_pending_not_eligible(self):
        a=sample()
        for x in a: x['phase']='PREPARADO'
        self.assertIsNone(select_development(a,SID)['selected'])
    def test_nd_is_not_true(self):
        a=sample()
        for x in a: x['guard']='ND'
        self.assertIsNone(select_development(a,SID)['selected'])
    def test_false_is_not_true(self):
        a=sample()
        for x in a: x['guard']='FALSO'
        self.assertIsNone(select_development(a,SID)['selected'])
    def test_inapplicable_no_priority_override(self):
        a=sample();a[0]['applicable']=False;a[1]['applicable']=False
        self.assertIsNone(select_development(a,SID)['selected'])
    def test_priority_takes_precedence_over_prec(self):
        a=sample();a[0]['evidence']='1'
        self.assertEqual(select_development(a,SID)['selected']['case_id'],'CASE_POLICY')
    def test_lexical_tiebreak(self):
        a=sample();a[0]['precedence']=10
        self.assertEqual(select_development(a,SID)['selected']['case_id'],'CASE_POLICY')
    def test_reject_duplicate(self):
        a=sample();a.append(a[0].copy())
        with self.assertRaisesRegex(SelectionError,'duplicate_candidate'):
            select_development(a,SID)
    def test_reject_noncanonical_and_float(self):
        for v in ('2/4',0.5,'1.0','-1','2'):
            a=sample();a[0]['evidence']=v
            with self.assertRaises(SelectionError): select_development(a,SID)
    def test_weights_invalid(self):
        for w in (('0','1/2','1/2'),('1/2','1/2','1/2')):
            with self.assertRaises(SelectionError):
                select_development(sample(),SID,weights=w)
    def test_digest_tampering(self):
        v=select_development(sample(),SID)
        v['selected']['service_id']='SMB_DEV'
        with self.assertRaises(SelectionError): verify_selection(v,sample())
    def test_no_operational_grant(self):
        v=select_development(sample(),SID)
        self.assertFalse(v['selection_is_operational'])
        self.assertFalse(v['operational_dispatch'])
        self.assertIsNone(v['published_generation'])

if __name__=='__main__': unittest.main()
