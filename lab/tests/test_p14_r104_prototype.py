"""R104 tests: actual fixture-to-risk execution, durable replay and negative gates."""
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts')]
from ardrec_p14_r104_prototype import build, fixtures, persist, verify, PrototypeError
from ardrec.coordination import r59d_a5_result_intake as a5


class R104PrototypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.small = build(29)
        cls.full = build(54)

    def test_29_existing_variants_run(self):
        self.assertEqual(self.small['unit_count'], 29)
        self.assertEqual(self.small['covered_family_count_in_batch'], 25)
        self.assertEqual(self.small['count_by_service'],
                         {'SSH_DEV': 8, 'FTP_DEV': 10, 'SMB_DEV': 11})

    def test_54_independent_case_windows_run(self):
        self.assertEqual(self.full['unit_count'], 54)
        self.assertEqual(len(self.full['decisions']), 54)
        self.assertEqual(len({d['case_id_a7'] for d in self.full['decisions']}), 54)
        self.assertEqual(self.full['covered_family_count_in_batch'], 25)

    def test_full_reproducibility(self):
        self.assertEqual(self.full['sha256'], build(54)['sha256'])
        self.assertEqual(self.full, build(54))

    def test_no_accreditation_or_execution(self):
        for d in self.full['decisions']:
            self.assertEqual(d['a6_classification'], 'ND')
            self.assertIsNone(d['confirmed_rf'])
            self.assertIsNone(d['applied_transition'])
            self.assertEqual(d['a8_recommendation'],
                             'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
        self.assertFalse(self.full['operational_dispatch'])
        self.assertEqual(self.full['p8_operational'], 'NO-GO')

    def test_private_durable_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session, manifest = persist(self.small, root)
            self.assertEqual(verify(session), manifest)
            self.assertEqual((session / 'report.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual((session / 'manifest.json').stat().st_mode & 0o777, 0o600)

    def test_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            session, _ = persist(self.small, Path(tmp))
            path = session / 'report.json'
            value = path.read_bytes()
            path.write_bytes(value.replace(b'"NO-GO"', b'"GO"', 1))
            with self.assertRaises((ValueError, OSError)):
                verify(session)

    def test_unsupported_case_count_rejected(self):
        for count in (0, 28, 30, 53, 55, True):
            with self.subTest(count=count):
                with self.assertRaises(PrototypeError):
                    fixtures(count)


if __name__ == '__main__':
    unittest.main()
