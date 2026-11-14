"""P14-R28: recepción de desarrollo sin publicación; render legible sin TTY."""
from __future__ import annotations
from pathlib import Path
import copy
import json
import os
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.persistence.development_receipt import (
    build_receipt,verify_receipt,persist_receipt,ReceiptError,FILE_NAME)
from ardrec.coordination.terminal_view import lines_for_page,render_text
from ardrec.analytics.exact_preview import canonical

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.r=build_receipt(session_sha='a'*64,r27_sha='b'*64,
                             a7_sha='c'*64,a8_sha='d'*64)
    def test_exact_contents(self):
        self.assertTrue(verify_receipt(self.r))
        self.assertIsNone(self.r['published_generation'])
        self.assertFalse(self.r['technical_generation_published'])
    def test_idempotent_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            a=persist_receipt(p,self.r)
            before=a.read_bytes()
            b=persist_receipt(p,self.r)
            self.assertEqual(a,b)
            self.assertEqual(a.read_bytes(),before)
    def test_reject_tamper_disk(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            f=persist_receipt(p,self.r)
            f.write_text('{}')
            with self.assertRaises(ReceiptError):persist_receipt(p,self.r)
    def test_reject_symlink_target(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            other=p/'elsewhere'; other.write_text('x')
            (p/FILE_NAME).symlink_to(other)
            with self.assertRaises(ReceiptError): persist_receipt(p,self.r)
    def test_reject_symlink_root(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); link=p/'alias';link.symlink_to(p,target_is_directory=True)
            with self.assertRaises(ReceiptError):persist_receipt(link,self.r)
    def test_reject_source_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            persist_receipt(p,self.r)
            changed=build_receipt(session_sha='e'*64,r27_sha='b'*64,a7_sha='c'*64,a8_sha='d'*64)
            with self.assertRaises(ReceiptError):persist_receipt(p,changed)
    def test_reject_payload_tamper(self):
        doc=copy.deepcopy(self.r)
        doc['technical_generation_published']=True
        with self.assertRaises(ReceiptError):verify_receipt(doc)
    def test_reject_bad_sha(self):
        with self.assertRaises(ReceiptError):
            build_receipt(session_sha='z'*64,r27_sha='b'*64,a7_sha='c'*64,a8_sha='d'*64)
    def test_reject_world_writable_root(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); p.chmod(0o777)
            try:
                with self.assertRaises(ReceiptError):persist_receipt(p,self.r)
            finally:p.chmod(0o700)

class RenderTests(unittest.TestCase):
    @staticmethod
    def fake():
        return {
            'session_id':'DEV_TUTOR_001','sha256':'e'*64,
            'r26_units':[{'protocol':'SSH','service_id':'SSH_DEV','a1':'VERDADERO','a2':'PREPARADO','a3':'VERDADERO'}],
            'r27':{'selected_actual':None,'selected_hypothetical':{'case_id':'CASE_REFERENCE'},
                   'a5_state':'RECORDED_LIMITED','a6_classification':'ND'},
            'a7':{'hypothetical_rf':'5/12'},
            'a8':{'recommendation':'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'},
            'a9':{'receipt_sha256':'a'*64},
            'a10':{'stages':[{'algorithm':f'A{i}','source':'TEST','status':'PREVIEW','detail':'Solo prueba de interfaz'} for i in range(1,11)]},
        }
    def test_all_ten_pages(self):
        f=self.fake()
        txt=render_text(f)
        for i in range(1,11): self.assertIn(f'A{i} | PREVIEW',txt)
        self.assertIn('NO-GO',txt)
    def test_page_bounds(self):
        with self.assertRaises(ValueError):lines_for_page(self.fake(),10)
    def test_narrow_width(self):
        out=lines_for_page(self.fake(),9,width=40)
        self.assertTrue(all(len(s)<=40 for s in out))
    def test_no_network_and_no_execution_in_render(self):
        self.assertIn('VM OBSERVADAS: NO',render_text(self.fake()))

if __name__=='__main__': unittest.main()
