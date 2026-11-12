"""R31 negative/positive tests: synthetic bytes only; never guest or private data."""
from __future__ import annotations
import base64
import copy
import hashlib
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r31_manual_windows as m


def sha(s):return hashlib.sha256(s).hexdigest()


def synthetic():
    payload=(b'.IP "--proto"\nFirst description\nSecond description\n' +
             b'Further plain text\n' * 35)
    return payload, {'source_line_1based':1,
                     'exact_roff_line_sha256':sha(b'.IP "--proto"\n'),
                     'uncompressed_manual_sha256':sha(payload)}


class R31Tests(unittest.TestCase):
    def test_fixed_window_and_no_authorization(self):
        src,a=synthetic();r=m.window(src,a)
        self.assertEqual(r['source_line_start_1based'],1)
        self.assertEqual(r['source_line_end_1based'],24)
        self.assertEqual(r['context_line_count'],24)
        self.assertEqual(r['semantic_review_completed'],False)
        self.assertEqual(r['cli_option_approved'],False)
        self.assertEqual(len(base64.b64decode(r['context_b64_private']).splitlines()),24)
    def test_hash_matches_exact_window(self):
        src,a=synthetic();r=m.window(src,a)
        self.assertEqual(sha(base64.b64decode(r['context_b64_private'])),r['context_sha256'])
    def test_anchor_is_exact(self):
        src,a=synthetic();r=m.window(src,a)
        self.assertEqual(base64.b64decode(r['context_b64_private']).splitlines()[0],b'.IP "--proto"')
    def test_last_line_valid(self):
        src,a=synthetic();lines=src.splitlines(keepends=True)
        a['source_line_1based']=len(lines)
        a['exact_roff_line_sha256']=sha(lines[-1])
        r=m.window(src,a)
        self.assertEqual(r['context_line_count'],1)
    def test_negative_source_digest(self):
        src,a=synthetic();a['uncompressed_manual_sha256']='a'*64
        with self.assertRaises(m.Blocked):m.window(src,a)
    def test_negative_anchor_digest(self):
        src,a=synthetic();a['exact_roff_line_sha256']='a'*64
        with self.assertRaises(m.Blocked):m.window(src,a)
    def test_negative_anchor_line_out_of_bounds(self):
        src,a=synthetic();a['source_line_1based']=10000
        with self.assertRaises(m.Blocked):m.window(src,a)
    def test_negative_anchor_line_zero(self):
        src,a=synthetic();a['source_line_1based']=0
        with self.assertRaises(m.Blocked):m.window(src,a)
    def test_negative_anchor_boolean(self):
        src,a=synthetic();a['source_line_1based']=True
        with self.assertRaises(m.Blocked):m.window(src,a)
    def test_negative_empty_source(self):
        _,a=synthetic()
        with self.assertRaises(m.Blocked):m.window(b'',a)
    def test_negative_too_long_source(self):
        _,a=synthetic()
        with self.assertRaises(m.Blocked):m.window(b'x'*(m.MAX_SOURCE_BYTES+1),a)
    def test_negative_wrong_type(self):
        _,a=synthetic()
        with self.assertRaises(m.Blocked):m.window('text',a)
    def test_negative_oversize_window(self):
        src=b'.IP "--proto"\n'+b'X'*20000+b'\n'
        a={'source_line_1based':1,'exact_roff_line_sha256':sha(b'.IP "--proto"\n'),
           'uncompressed_manual_sha256':sha(src)}
        with self.assertRaises(m.Blocked):m.window(src,a)
    def test_negative_invalid_catalog_type(self):
        with self.assertRaises(m.Blocked):m.catalog([])
    def test_negative_invalid_catalog_source_authority(self):
        a={'increment':'P8-R14','private_report_sha256':m.R14_FULL_SHA,
           'approved_cli_options':1,'dispatch_allowed':False}
        with self.assertRaises(m.Blocked):m.catalog(a)
    def test_negative_invalid_catalog_dispatch(self):
        a={'increment':'P8-R14','private_report_sha256':m.R14_FULL_SHA,
           'approved_cli_options':0,'dispatch_allowed':True}
        with self.assertRaises(m.Blocked):m.catalog(a)
    def test_negative_unsigned_private_report(self):
        with self.assertRaises(m.Blocked):m.from_authenticated_report(b'{}',{},lambda a,b:None)
    def test_no_run_state(self):
        self.assertEqual(m.WINDOW_LINES,24)
        self.assertEqual(len(m.MANUALS),3)

if __name__=='__main__':unittest.main()
