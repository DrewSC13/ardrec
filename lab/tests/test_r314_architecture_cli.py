"""R314: declaración de arquitectura, sin ejecución técnica."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ArchitectureCLI(unittest.TestCase):
    def call(self, *args):
        with tempfile.TemporaryDirectory() as folder:
            env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([sys.executable, '-B', '-m', 'ardrec', *args],
                                    cwd=folder, env=env, capture_output=True, timeout=20)
            self.assertEqual(list(Path(folder).iterdir()), [])
            return result

    def test_declared_model(self):
        result = self.call('arquitectura', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['operator_model'], 'SINGLE_USER')
        self.assertEqual(data['human_operators'], 1)
        self.assertEqual(data['external_operational_actors'], 0)
        self.assertIs(data['logical_role_separation'], True)
        self.assertIs(data['privilege_separation_required'], True)

    def test_authority_boundary(self):
        data = json.loads(self.call('arquitectura', '--json').stdout)
        for key in ('operator_identity_attested', 'independent_human_attested',
                    'operational_authority_granted', 'experimental_validation_granted'):
            self.assertIs(data[key], False)
        self.assertEqual(data['security_contracts'], 'UNCHANGED')
        self.assertEqual(data['academic_validation'], 'SEPARATE_METHOD_REQUIREMENT')

    def test_paths(self):
        data = json.loads(self.call('arquitectura', '--json').stdout)
        self.assertEqual(data['working_directory'], 'REPOSITORY_ROOT')
        self.assertEqual(data['patch_archive'], 'SIBLING_ARCHIVE_ONLY')
        self.assertEqual(data['private_workspaces'],
                         ['experiments/raw/', 'lab/private/', 'runtime/', 'local-reports/'])

    def test_text_and_reproducibility(self):
        plain = self.call('arquitectura')
        self.assertEqual(plain.returncode, 0)
        self.assertEqual(plain.stdout, self.call('arquitectura', '--texto').stdout)
        self.assertIn(b'HUMAN_OPERATORS=1', plain.stdout)
        self.assertIn(b'OPERATIONAL_AUTHORITY_GRANTED=NO', plain.stdout)
        self.assertEqual(self.call('arquitectura', '--json').stdout,
                         self.call('arquitectura', '--json').stdout)

    def test_help_and_rejection(self):
        help_result = self.call('--help')
        self.assertEqual(help_result.returncode, 0)
        for route in (b'arquitectura', b'live', b'caso', b'familias', b'estudio'):
            self.assertIn(route, help_result.stdout)
        self.assertEqual(self.call('arquitectura', '--help').returncode, 0)
        for args in (('--authorize',), ('--json', '--texto')):
            self.assertEqual(self.call('arquitectura', *args).returncode, 2)
