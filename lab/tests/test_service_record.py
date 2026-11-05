"""Guard against changed evidence, scope inflation and broken historical links."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('lab_service_record', ROOT / 'lab/verify_services.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class LaboratoryServiceRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in V.ARTIFACTS | {V.MANIFEST, 'docs/traceability/laboratory-design-v1.json',
                                   'lab/topology-v1.json', '.github/workflows/ci.yml'}:
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, dest)

    def mutate(self, path, edit, rehash=False):
        file = self.root / path
        data = json.loads(file.read_text())
        edit(data)
        file.write_text(json.dumps(data))
        if rehash:
            self.mutate(V.MANIFEST, lambda m: m['artifact_sha256'].update({path: V.sha(file.read_bytes())}))

    def test_reviewed_record(self):
        self.assertEqual(V.verify(self.root)['recorded_host_checks'], 17)

    def test_missing_check_even_when_rehashed(self):
        self.mutate(V.PREFIX + 'evidence.json', lambda e: e['checks'].pop(), True)
        with self.assertRaisesRegex(ValueError, 'check inventory'):
            V.verify(self.root)

    def test_denial_must_have_nonzero_code(self):
        self.mutate(V.PREFIX + 'evidence.json', lambda e: e['checks'][3].update(exit_code=0), True)
        with self.assertRaisesRegex(ValueError, 'result code'):
            V.verify(self.root)

    def test_scope_inflation_rejected(self):
        self.mutate(V.MANIFEST, lambda m: m.update(system_functional_acceptance='PASS'))
        with self.assertRaisesRegex(ValueError, 'scope'):
            V.verify(self.root)

    def test_obligation_removal_rejected(self):
        self.mutate(V.MANIFEST, lambda m: m['development_obligations'].pop())
        with self.assertRaisesRegex(ValueError, 'Obligations'):
            V.verify(self.root)

    def test_configuration_change_rejected_even_when_rehashed(self):
        path = V.PREFIX + 'config/ftp.conf'
        file = self.root / path
        file.write_text(file.read_text().replace('force_local_data_ssl=YES', 'force_local_data_ssl=NO'))
        digest = V.sha(file.read_bytes())
        self.mutate(V.MANIFEST, lambda m: (m['artifact_sha256'].update({path: digest}),
                                         m['configurations']['ftp'].update(sha256=digest)))
        with self.assertRaisesRegex(ValueError, 'physical run'):
            V.verify(self.root)

    def test_incomplete_cleanup_rejected(self):
        self.mutate(V.PREFIX + 'evidence.json', lambda e: e['cleanup'].update(created_networks_removed=False), True)
        with self.assertRaisesRegex(ValueError, 'cleanup'):
            V.verify(self.root)

    def test_unknown_artifact_path_rejected(self):
        self.mutate(V.MANIFEST, lambda m: m['artifact_sha256'].update({'../escape': '0' * 64}))
        with self.assertRaisesRegex(ValueError, 'inventory'):
            V.verify(self.root)

    def test_ci_link_required(self):
        path = self.root / '.github/workflows/ci.yml'
        original = path.read_text()
        for command in ['run: python3 lab/verify_services.py',
                        'run: python3 -m unittest discover -s lab/tests -p test_service_record.py -v']:
            with self.subTest(command=command):
                path.write_text(original.replace(command, 'run: true'))
                with self.assertRaisesRegex(ValueError, 'CI step'):
                    V.verify(self.root)


if __name__ == '__main__':
    unittest.main()
