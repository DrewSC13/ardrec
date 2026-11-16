"""R58-C A6-A7-A9 real module integration on a synthetic SOURCE only."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import ardrec_p14_r58c_a6_a7_a9_chain as m
from ardrec.evidence.defensive_import import (read_observation,admit_defensive_observation)
from ardrec.analytics.exact_preview import digest
from ardrec.persistence.development_receipt import FILE_NAME

class TestDocumentaryChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rawdoc,raw=read_observation(m.SYNTHETIC_RECEIPT)
        cls.admission=admit_defensive_observation(rawdoc,raw,m.SYNTHETIC_SUPPORT,
                                                    as_of_utc=m.SYNTHETIC_ASOF)
        cls.scenario=m.read_fixed_scenario(m.SCENARIO)
        cls.report=m.build_documentary_chain(cls.admission,scenario=cls.scenario)

    def test_chain_validates(self):
        self.assertTrue(m.verify_documentary_chain(self.report,self.admission,
                                                   scenario=self.scenario))

    def test_a6_remains_nd(self):
        self.assertEqual(self.report['a6']['classification'],'ND')
        self.assertIs(self.report['a6']['technical_truth_accredited'],False)

    def test_a7_no_uncredited_contributions(self):
        self.assertEqual(self.report['a7']['evidence_contributions'],[])
        self.assertIsNone(self.report['a7']['confirmed_rf'])

    def test_a8_stays_conservative(self):
        self.assertEqual(self.report['a8']['recommendation'],'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
        self.assertIsNone(self.report['a8']['applied_transition'])

    def test_a9_never_publishes_generation(self):
        self.assertIs(self.report['a9']['technical_generation_published'],False)
        self.assertIsNone(self.report['a9']['published_generation'])

    def test_no_operational_execution(self):
        self.assertIs(self.report['vm_checks_executed'],False)
        self.assertIs(self.report['operational_dispatch'],False)
        self.assertEqual(self.report['p8'],'NO-GO')
        self.assertIsNone(self.report['final_risk'])

    def test_a8_source_binds_a6(self):
        self.assertIs(self.report['chain']['a8_source_is_a6'],True)
        self.assertEqual(self.report['chain']['a6_admission_sha256'],self.admission['sha256'])

    def test_report_is_deterministic(self):
        second=m.build_documentary_chain(self.admission,scenario=self.scenario)
        self.assertEqual(self.report,second)

    def test_a6_tamper_does_not_pass(self):
        bad=deepcopy(self.admission)
        bad['technical_truth_accredited']=True
        with self.assertRaises(ValueError):m.build_documentary_chain(bad,scenario=self.scenario)

    def test_invalid_case_does_not_pass(self):
        bad=deepcopy(self.admission)
        bad['case_id']='UNAUTHORIZED'
        with self.assertRaises(ValueError):m.build_documentary_chain(bad,scenario=self.scenario)

    def test_hash_tamper_report_rejected(self):
        doc=deepcopy(self.report)
        doc['a7']['confirmed_rf']='1'
        with self.assertRaises(m.ChainError):m.verify_documentary_chain(doc,self.admission,scenario=self.scenario)

    def test_forged_generation_not_accepted(self):
        doc=deepcopy(self.report)
        doc['a9']['technical_generation_published']=True
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(m.ChainError):m.verify_documentary_chain(doc,self.admission,scenario=self.scenario)

    def test_receipt_write_requires_explicit_optin(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.assertFalse((root/FILE_NAME).exists())
            m.build_documentary_chain(self.admission,scenario=self.scenario)
            self.assertFalse((root/FILE_NAME).exists())

    def test_idempotent_local_development_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            first=m.build_documentary_chain(self.admission,scenario=self.scenario,output_dir=root)
            original=(root/FILE_NAME).read_bytes()
            second=m.build_documentary_chain(self.admission,scenario=self.scenario,output_dir=root)
            self.assertEqual(first,second)
            self.assertEqual(original,(root/FILE_NAME).read_bytes())
            self.assertTrue(first['a9']['local_development_receipt_written'])

    def test_receipt_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            m.build_documentary_chain(self.admission,scenario=self.scenario,output_dir=root)
            (root/FILE_NAME).write_text('corrupted')
            with self.assertRaises(ValueError):
                m.build_documentary_chain(self.admission,scenario=self.scenario,output_dir=root)

    def test_session_mismatch_rejected(self):
        bad=deepcopy(self.scenario)
        bad['session_id']='OTHER'
        with self.assertRaises(ValueError):m.build_documentary_chain(self.admission,scenario=bad)
