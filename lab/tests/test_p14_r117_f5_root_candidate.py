"""Pruebas deterministas R117-F5A; sin root ni VM."""
from io import BytesIO
import importlib.util
from pathlib import Path
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/ardrec_p14_r117_f5_root_candidate.py"

spec = importlib.util.spec_from_file_location("r117_f5a", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CandidateTests(unittest.TestCase):

    def test_historical_and_f4_source_counts(self):
        payload, lock = m.checked_sources(REPO)
        self.assertEqual(len(lock["files"]), 33)
        self.assertEqual(len(payload), 38)

    def test_root_transform_is_deterministic(self):
        raw = m.read_source(REPO, m.PILOT)
        a = m.transform(raw)
        self.assertEqual(a, m.transform(raw))
        self.assertIn(b"r117-f4-ftp-pilot-root-v1", a)

    def test_source_transform_drift_is_rejected(self):
        raw = m.read_source(REPO, m.PILOT)
        broken = raw.replace(
            b"r116-f3-ftp-pilot-root-v1",
            b"unknown-root-directory"
        )
        with self.assertRaises(m.Stop):
            m.transform(broken)

    def test_candidate_is_reproducible(self):
        first = m.candidate("a" * 40, REPO)
        second = m.candidate("a" * 40, REPO)
        self.assertEqual(first, second)
        self.assertEqual(
            m.audit(first, REPO)["head"], "a" * 40
        )

    def test_wrong_head_is_rejected(self):
        raw = m.candidate("a" * 40, REPO)
        with self.assertRaises(m.Stop):
            m.audit(raw, REPO, "b" * 40)

    def test_modified_root_source_is_rejected(self):
        original = m.candidate("a" * 40, REPO)
        with zipfile.ZipFile(BytesIO(original)) as archive:
            docs = {
                name: archive.read(name)
                for name in archive.namelist()
            }
        docs["root-pilot.py"] += b"# altered\n"
        with self.assertRaises(m.Stop):
            m.audit(m.pack(docs), REPO)

    def test_unexpected_member_is_rejected(self):
        original = m.candidate("a" * 40, REPO)
        with zipfile.ZipFile(BytesIO(original)) as archive:
            docs = {
                name: archive.read(name)
                for name in archive.namelist()
            }
        docs["unexpected.txt"] = b"untrusted"
        with self.assertRaises(m.Stop):
            m.audit(m.pack(docs), REPO)

if __name__ == "__main__":
    unittest.main()
