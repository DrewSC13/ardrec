"""R116-F13 offline closure: exact source and rejection of false acceptance."""
from __future__ import annotations
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts'))
import ardrec_p14_r116_f13_merge_gate as gate

class TestR116F13Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=json.loads((REPO/gate.LOCK).read_text())
        cls.sources=sorted(cls.original['source_sha256'])
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='ardrec-r116-f13-')
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        for name in [*self.sources,gate.LOCK,gate.CATALOG,gate.CI,gate.DOC]:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(REPO/name,p)
    def rewrite(self,mutate):
        p=self.root/gate.LOCK
        v=json.loads(p.read_text())
        mutate(v)
        p.write_text(json.dumps(v),encoding='utf-8')
    def rejects(self,message):
        with self.assertRaises(gate.GateFailure) as ctx:
            gate.evaluate(self.root)
        self.assertIn(message,str(ctx.exception))
    def test_01_accept_source_only(self):
        o=gate.evaluate(self.root)
        self.assertEqual(o['source_integrity'],'PASS_87_PLUS_CI_SEPARATE')
        self.assertEqual(o['p8'],'NO-GO')
        self.assertEqual(o['a6'],'ND')
        self.assertEqual(o['host_mutations'],0)
    def test_02_missing_source(self):
        (self.root/self.sources[0]).unlink();self.rejects('FILE_MISSING')
    def test_03_mutated_source(self):
        with (self.root/self.sources[0]).open('ab') as f:f.write(b'alteration')
        self.rejects('SOURCE_DRIFT')
    def test_04_symlink_source(self):
        p=self.root/self.sources[0];p.unlink();p.symlink_to(self.root/gate.CATALOG)
        self.rejects('SYMLINK_FORBIDDEN')
    def test_05_catalog_drift(self):
        with (self.root/gate.CATALOG).open('ab') as f:f.write(b'\n')
        self.rejects('CATALOG_SHA_MISMATCH')
    def test_06_catalog_go_even_with_updated_pin(self):
        p=self.root/gate.CATALOG;v=json.loads(p.read_text());v['execution_enabled']=True
        raw=json.dumps(v).encode();p.write_bytes(raw)
        self.rewrite(lambda lock:lock.__setitem__('catalog_sha256',hashlib.sha256(raw).hexdigest()))
        self.rejects('CATALOG_NO_GO_VIOLATION')
    def test_07_count(self):
        self.rewrite(lambda d:d.__setitem__('source_count',86));self.rejects('SOURCE_COUNT_MISMATCH')
    def test_08_source_index_change(self):
        def change(d):
            k=self.sources[0];v=d['source_sha256'].pop(k);d['source_sha256']['docs/replaced.txt']=v
        self.rewrite(change);self.rejects('SOURCE_PATH_INDEX_MISMATCH')
    def test_09_p8_go(self):
        self.rewrite(lambda d:d.__setitem__('p8','GO'));self.rejects('UNSAFE_LOCK:p8')
    def test_10_physical_false_claim(self):
        self.rewrite(lambda d:d.__setitem__('new_a5_physical','ATTESTED'))
        self.rejects('UNSAFE_LOCK:new_a5_physical')
    def test_11_a6_false_claim(self):
        self.rewrite(lambda d:d.__setitem__('a6','ADMITTED'))
        self.rejects('UNSAFE_LOCK:a6')
    def test_12_p7_completed(self):
        self.rewrite(lambda d:d.__setitem__('p7_pilot_completed',True))
        self.rejects('UNSAFE_LOCK:p7_pilot_completed')
    def test_13_bad_timer(self):
        self.rewrite(lambda d:d.__setitem__('backup_scheduled_seconds',60))
        self.rejects('UNSAFE_LOCK:backup_scheduled_seconds')
    def test_14_false_root_deploy(self):
        self.rewrite(lambda d:d.__setitem__('root_redeploy_f12','PASS'))
        self.rejects('UNSAFE_LOCK:root_redeploy_f12')
    def test_15_duplicate_json_key(self):
        p=self.root/gate.LOCK
        p.write_text(p.read_text().replace('"schema":','"schema": "forged", "schema":',1))
        self.rejects('INVALID_JSON')
    def test_16_ci_required(self):
        (self.root/gate.CI).write_text('name: no ci\n');self.rejects('CLOSURE_CI_NOT_REGISTERED')
    def test_17_doc_required(self):
        (self.root/gate.DOC).write_text('document incomplete')
        self.rejects('DEFERRED_SCOPE_NOT_DOCUMENTED')

if __name__=='__main__':unittest.main()
