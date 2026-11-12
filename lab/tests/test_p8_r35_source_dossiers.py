"""R35 adversarial offline-only tests; synthetic byte streams, no actual clients/VMs."""
from __future__ import annotations
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r31_manual_windows as r31
import p8_r33_human_adjudication as r33
import p8_r35_source_dossiers as m
from test_p8_r33_human_adjudication import synthetic_queue

MATRIX=Path(__file__).resolve().parents[1]/'p8-r35-source-dossiers-v1/developer_matrix.json'


def synthetic_fixture():
    matrix=json.loads(MATRIX.read_text(encoding='utf-8'))
    ids=[r['term_id'] for r in matrix['entries']]
    manual_ids={
        'curl':'/usr/share/man/man1/curl.1.gz',
        'smbclient':'/usr/share/man/man1/smbclient.1.gz',
        'rpcclient':'/usr/share/man/man1/rpcclient.1.gz',
    }
    bymanual={name:[] for name in manual_ids.values()}
    for term in ids:
        bymanual[manual_ids[term.split('.',1)[0]]].append(term)
    docs={}
    anchors=[]
    for name, terms in bymanual.items():
        lines=[('ANCHOR '+term+'\n').encode() for term in terms]
        lines.extend([b'context marker\n']*30)
        docs[name]=b''.join(lines)
        for i,term in enumerate(terms):
            anchors.append({
                'term_id':term,'manual_path':name,'source_line_1based':i+1,
                'exact_roff_line_sha256':hashlib.sha256(lines[i]).hexdigest(),
            })
    anchors.sort(key=lambda x:x['term_id'])
    manifests=[{
        'manual_path':name,'uncompressed_sha256':m.sha(raw),
        'uncompressed_bytes':len(raw),
    } for name,raw in docs.items()]
    catalog={'source_manifests':manifests,'term_anchors':anchors}
    receipt={'scope':'P8_R31_AUTHENTICATED_PRIVATE_MANPAGE_WINDOWS_NOT_SEMANTIC_APPROVAL',
             'complete_semantic_reviews':0,'dispatch_allowed':False,'source_windows':[]}
    queue=synthetic_queue()
    for row,anchor in zip(queue['review_rows'],anchors):
        name=anchor['manual_path']
        pos=anchor['source_line_1based']
        raw=b''.join(docs[name].splitlines(keepends=True)[pos-1:pos-1+r31.WINDOW_LINES])
        old={
            'term_id':anchor['term_id'],'manual_path':name,
            'source_line_start_1based':pos,
            'context_sha256':m.sha(raw),
            'context_b64_private':base64.b64encode(raw).decode(),
        }
        receipt['source_windows'].append(old)
        row['term_id']=anchor['term_id']
        row['manual_path']=name
        row['source_line_start_1based']=pos
        row['source_line_end_1based']=pos+23
        row['context_sha256']=old['context_sha256']
    ledger=r33.new_ledger(queue)
    return docs,catalog,receipt,queue,ledger,[],matrix,anchors


class R35Tests(unittest.TestCase):
    def setUp(self):
        self.docs,self.catalog,self.receipt,self.queue,self.ledger,self.events,self.matrix,self.anchors=synthetic_fixture()

    def evaluate(self):
        with patch.object(r31,'catalog',return_value=tuple(self.anchors)):
            return m.build(self.docs,self.catalog,self.receipt,self.queue,
                           self.ledger,self.events,self.matrix)

    def test_01_39_312(self):
        x=self.evaluate();self.assertEqual(x['terms'],39);self.assertEqual(x['question_count'],312)
    def test_02_exact_three_manuals(self):self.assertEqual(self.evaluate()['manuals'],3)
    def test_03_all_metadata_no_full_text(self):
        s=str(self.evaluate());self.assertNotIn('context marker',s)
    def test_04_no_base64_attachments(self):
        s=str(self.evaluate());self.assertNotIn('context_b64_private',s)
    def test_05_no_dispatch(self):self.assertFalse(self.evaluate()['dispatch_allowed'])
    def test_06_no_semantic(self):self.assertEqual(self.evaluate()['semantic_reviews_completed'],0)
    def test_07_no_full_clauses(self):self.assertEqual(self.evaluate()['full_clauses_certified'],0)
    def test_08_no_approval(self):self.assertEqual(self.evaluate()['approved_cli_options'],0)
    def test_09_all_candidates_non_certified(self):
        self.assertTrue(all(not x['full_clause_certified'] for x in self.evaluate()['candidates']))
    def test_10_all_questions(self):
        self.assertTrue(all(len(x['questions_in_scope'])==8 for x in self.evaluate()['candidates']))
    def test_11_all_anchors(self):
        self.assertEqual({x['term_id'] for x in self.evaluate()['candidates']},
                         {x['term_id'] for x in self.anchors})
    def test_12_crosschain_hash(self):
        self.assertEqual(self.evaluate()['r33_latest_event_sha256'],m.sha(r33.canonical(self.ledger)))
    def test_13_matrix_exact(self):self.assertEqual(len(m.validate_matrix(self.matrix,self.anchors)),39)
    def test_14_matrix_missing_term(self):
        self.matrix['entries'].pop()
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_15_matrix_duplicate_term(self):
        self.matrix['entries'][1]['term_id']=self.matrix['entries'][0]['term_id']
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_16_matrix_approve(self):
        self.matrix['entries'][0]['cli_approved']=True
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_17_matrix_semantic(self):
        self.matrix['entries'][0]['term_semantic_certified']=True
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_18_matrix_question_completed(self):
        self.matrix['entries'][0]['questions'][0]['review_status']='PASS'
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_19_matrix_foreign_question(self):
        self.matrix['entries'][0]['questions'][0]['question_id']='OTHER'
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_20_matrix_forged_proof(self):
        self.matrix['local_runtime_proofs_count']=1
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_21_matrix_foreign_document(self):
        self.matrix['official_sources'].append('https://invalid.example/')
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_22_manual_mutated(self):
        key=next(iter(self.docs));self.docs[key]+=b'EXTRA'
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_23_manual_missing(self):
        self.docs.pop(next(iter(self.docs)))
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_24_r31_mutated(self):
        self.receipt['source_windows'][0]['context_sha256']='0'*64
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_25_r31_source_mutated(self):
        self.receipt['source_windows'][0]['context_b64_private']='AA=='
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_26_r32_context_mutated(self):
        self.queue['review_rows'][0]['context_sha256']='f'*64
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_27_r33_ledger_modified(self):
        self.ledger['authorized_cases']=1
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_28_r33_forged_event(self):
        self.events.append({'fake':'event'})
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_29_r31_promoted(self):
        self.receipt['complete_semantic_reviews']=1
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_30_bounded_single_line(self):
        d=m.bounded_candidate(b'a\n',1)
        self.assertEqual(d['candidate_line_count'],1)
    def test_31_bounded_next_heading(self):
        d=m.bounded_candidate(b'a\nb\nc\n',1,3)
        self.assertEqual(d['candidate_line_count'],2)
    def test_32_bounded_not_whole_clause(self):
        self.assertFalse(m.bounded_candidate(b'abc\n',1)['full_clause_certified'])
    def test_33_bounded_120_lines(self):
        d=m.bounded_candidate(b'a\n'*200,1)
        self.assertEqual(d['candidate_line_count'],120)
    def test_34_bounded_20kb(self):
        d=m.bounded_candidate(b'x'*5000+b'\n'+b'y'*5000+b'\n'+b'z'*5000+b'\n'+b'w'*5000+b'\n',1)
        self.assertEqual(d['candidate_line_count'],3)
    def test_35_bounded_zero_line_rejected(self):
        with self.assertRaises(r33.Denied):m.bounded_candidate(b'abc\n',0)
    def test_36_bounded_backward_anchor_rejected(self):
        with self.assertRaises(r33.Denied):m.bounded_candidate(b'a\nb\n',1,1)
    def test_37_bounded_boolean_rejected(self):
        with self.assertRaises(r33.Denied):m.bounded_candidate(b'a\n',True)
    def test_38_bounded_giant_line_rejected(self):
        with self.assertRaises(r33.Denied):m.bounded_candidate(b'X'*20001+b'\n',1)
    def test_39_source_anchor_modified(self):
        self.anchors[0]['exact_roff_line_sha256']='0'*64
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_40_r32_no_dispatch(self):
        self.queue['dispatch_allowed']=True
        with self.assertRaises(r33.Denied):self.evaluate()
    def test_41_question_order_kept(self):
        self.assertEqual(self.evaluate()['candidates'][0]['questions_in_scope'],list(r33.QUESTIONS))
    def test_42_cannot_claim_completed(self):
        self.assertFalse(any(x['semantic_review_completed'] for x in self.evaluate()['candidates']))
    def test_43_no_argv_renderer(self):
        self.assertTrue(all(x['approved_argv_renderers']==0 for x in self.evaluate()['candidates']))
    def test_44_no_client_capability(self):
        self.assertTrue(all(x['client_capability_proven'] is False for x in self.evaluate()['candidates']))

if __name__=='__main__':unittest.main()
