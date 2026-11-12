"""R32 adversarial tests: synthetic evidence only, no real receipts or guest."""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import p8_r32_semantic_triage as m


def sha(raw): return hashlib.sha256(raw).hexdigest()


def synthetic(hint=b'TLS password shell upload proxy timeout'):
    anchors=[]
    rows=[]
    for i in range(39):
        term='curl.1.gz:--config' if i == 0 else 'curl.1.gz:--flag'+str(i)
        # For test fixtures, the catalog is injected; real catalog comes from R14.
        source=(b'.IP "--flag"\n'+hint+b'\n')
        anchor={'term_id':term,'manual_path':'/usr/share/man/man1/curl.1.gz',
            'source_line_1based':42+i,'exact_roff_line_sha256':sha(b'.IP "--flag"\n'),
            'uncompressed_manual_sha256':'a'*64,'profile_refs':['FTP-T01-BASE']}
        row={**anchor,'source_line_start_1based':42+i,'source_line_end_1based':43+i,
             'context_line_count':2,'context_sha256':sha(source),
             'context_b64_private':base64.b64encode(source).decode(),
             'context_completeness':'FIXED_WINDOW_NOT_A_CERTIFIED_COMPLETE_CLAUSE',
             'semantic_review_completed':False,'cli_option_approved':False}
        anchors.append(anchor);rows.append(row)
    doc={'schema_version':'1.0',
         'scope':'P8_R31_AUTHENTICATED_PRIVATE_MANPAGE_WINDOWS_NOT_SEMANTIC_APPROVAL',
         'source_main_sha':m.R31_BASE_SHA,'r14_private_report_sha256':m.R14_FULL_SHA,
         'r14_anchor_catalog_sha256':m.R14_ANCHOR_SHA,'profile_count':21,
         'unique_documentary_entry_count':39,'manuals_used':3,'source_windows':rows,
         'complete_semantic_reviews':0,'approved_cli_options':0,
         'approved_argv_renderers':0,'material_bindings_fulfilled':0,
         'runtime_proof_gates_fulfilled':0,'authorized_profiles':0,
         'authorized_cases':0,'dispatch_allowed':False,'p8_closed':False,
         'p9_started':False,'algorithms_started':False}
    return doc, tuple(anchors)


def encoded(doc): return (json.dumps(doc,sort_keys=True)+'\n').encode()


def checked(doc=None,anchors=None):
    if doc is None:doc,anchors=synthetic()
    raw=encoded(doc)
    with patch.object(m,'R31_PRIVATE_SHA',sha(raw)):
        return m.audit_r31(raw,anchors,sha(raw))


class R32Tests(unittest.TestCase):
    def test_expected_question_domains(self):
        self.assertEqual(len(m.QUESTIONS),8)
    def test_flags_are_not_approvals(self):
        queue=m.semantic_queue(checked())
        self.assertFalse(queue['dispatch_allowed'])
        self.assertEqual(queue['semantic_reviews_completed'],0)
        self.assertEqual(queue['approved_cli_options'],0)
    def test_exact_39_records(self):
        q=m.semantic_queue(checked())
        self.assertEqual(len(q['review_rows']),39)
        self.assertEqual(q['unanswered_review_questions'],312)
    def test_no_excerpt_base64_copied(self):
        q=m.semantic_queue(checked())
        self.assertFalse(q['source_excerpt_bytes_copied'])
        self.assertNotIn('context_b64_private',repr(q))
    def test_first_record_elevated_attention(self):
        q=m.semantic_queue(checked())
        self.assertEqual(q['review_rows'][0]['attention'],'ELEVATED_REVIEW_PRIORITY_ONLY')
    def test_no_assumptions_from_absence(self):
        doc,a=synthetic(b'neutral description')
        q=m.semantic_queue(checked(doc,a))
        self.assertEqual(q['review_rows'][0]['lexical_signals_only_not_conclusions'],[])
        self.assertFalse(q['review_rows'][0]['capability_proven'])
    def test_lexical_signals_only(self):
        q=m.semantic_queue(checked())
        found=q['review_rows'][0]['lexical_signals_only_not_conclusions']
        self.assertIn('TRANSPORT_PROTECTION',found)
        self.assertIn('AUTHENTICATION',found)
        self.assertIn('EXECUTION_SURFACE',found)
    def test_all_questions_open(self):
        q=m.semantic_queue(checked())
        self.assertTrue(all(set(r['review_questions'].values())=={'UNANSWERED_NEEDS_HUMAN_REVIEW'} for r in q['review_rows']))
    def test_identity_pinned(self):
        self.assertEqual(m.R32_BASE_SHA,'3a236a74da1b88f1e9485e3a6de82064592a04fa')
    def test_reject_real_expected_sha_override(self):
        doc,a=synthetic();raw=encoded(doc)
        with self.assertRaises(m.Denied):m.audit_r31(raw,a)
    def test_reject_raw_text_instead_bytes(self):
        doc,a=synthetic()
        with self.assertRaises(m.Denied):m.audit_r31(encoded(doc).decode(),a)
    def test_reject_wrong_type_anchors(self):
        doc,a=synthetic();raw=encoded(doc)
        with patch.object(m,'R31_PRIVATE_SHA',sha(raw)):
            with self.assertRaises(m.Denied):m.audit_r31(raw,list(a),sha(raw))
    def test_reject_json_duplicate_keys(self):
        raw=b'{"a":1,"a":2}'
        with patch.object(m,'R31_PRIVATE_SHA',sha(raw)):
            with self.assertRaises(m.Denied):m.clean_json(raw)
    def test_reject_nan(self):
        raw=b'{"a":NaN}'
        with patch.object(m,'R31_PRIVATE_SHA',sha(raw)):
            with self.assertRaises(m.Denied):m.clean_json(raw)
    def test_reject_bad_b64(self):
        doc,a=synthetic();doc['source_windows'][0]['context_b64_private']='!'
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_context_hash_drift(self):
        doc,a=synthetic();doc['source_windows'][0]['context_sha256']='0'*64
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_anchor_hash_drift(self):
        doc,a=synthetic();doc['source_windows'][0]['exact_roff_line_sha256']='0'*64
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_profile_mismatch(self):
        doc,a=synthetic();doc['source_windows'][0]['profile_refs']=['SMB-T01-BASE']
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_extra_context_field(self):
        doc,a=synthetic();doc['source_windows'][0]['new_approval']=True
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_extra_root_field(self):
        doc,a=synthetic();doc['unverified_flags']=False
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_authorization(self):
        doc,a=synthetic();doc['authorized_profiles']=1
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_boolean_as_count(self):
        doc,a=synthetic();doc['authorized_cases']=False
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_r31_source_main_changed(self):
        doc,a=synthetic();doc['source_main_sha']='0'*40
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_scope_changed(self):
        doc,a=synthetic();doc['scope']='PROOF_GRANTED'
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_38_rows(self):
        doc,a=synthetic();doc['source_windows'].pop()
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_25_lines(self):
        doc,a=synthetic();doc['source_windows'][0]['context_line_count']=25
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_line_end_drift(self):
        doc,a=synthetic();doc['source_windows'][0]['source_line_end_1based']+=2
        with self.assertRaises(m.Denied):checked(doc,a)
    def test_reject_more_than_39_semantic_queue(self):
        with self.assertRaises(m.Denied):m.semantic_queue(checked()[:38])
    def test_reject_duplicate_semantic_term(self):
        rows=list(checked());rows[1]=(rows[0][0],rows[1][1])
        with self.assertRaises(m.Denied):m.semantic_queue(tuple(rows))
    def test_no_private_file_imports(self):
        with open(Path(m.__file__),'rb') as f:src=f.read()
        self.assertNotIn(b'import subprocess',src)
        self.assertNotIn(b'import socket',src)
        self.assertNotIn(b'os.system',src)

if __name__=='__main__':unittest.main()
