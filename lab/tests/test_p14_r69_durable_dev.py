"""R69: pruebas de ruta R28, A2/A1/A9 y recuperación sin despacho físico."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.durable_dev import DurableDevError, open_or_create_dev
from ardrec.persistence import DurableStore
from ardrec.persistence.codec import StorageError, canonical, digest, parse

FIXTURE = ROOT / 'lab/p14-r26-session-v1/scenario.json'
SCRIPT = ROOT / 'scripts/demo_p14_r28_a1_a10_tui.py'
EXPECTED = {'SSH_DEV': ('VERDADERO', 'ALLOW', 'CASE_POLICY'),
            'SMB_DEV': ('VERDADERO', 'DENY', 'CASE_REFERENCE'),
            'FTP_DEV': ('ND', None, None)}

@unittest.skipIf(os.geteuid() == 0, 'La persistencia privada se ensaya sin root')
class SessionR69Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ardrec-r69-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'session'
        self.fixture = read_fixed_scenario(FIXTURE)

    def start(self, **kwargs):
        return open_or_create_dev(self.root, self.fixture, **kwargs)

    def cmd(self, module=False, extra=()):
        argv = ([sys.executable, '-B', '-m', 'ardrec'] if module else
                [sys.executable, '-B', str(SCRIPT)])
        argv += ['--durable-dev-root', str(self.root), '--json', *extra]
        return subprocess.run(argv, cwd=ROOT,
                              env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
                              capture_output=True, text=True, timeout=25)

    @staticmethod
    def overwrite(path, raw):
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)

    def test_01_generation_and_decisions_have_provenance_and_seven_fields(self):
        d = self.start()
        self.assertEqual((d['record_id'], d['generation'], d['source_kind']),
                         ('DEV_TUTOR_001', 0, 'SYNTHETIC_FIXTURE'))
        self.assertTrue(d['a9_initialization_durable'])
        for sid, expected in EXPECTED.items():
            record = d['a1_decisions'][sid]
            self.assertEqual(tuple(record['r68'][x] for x in
                                   ('status', 'selected_rule', 'declared_output')), expected)
            self.assertEqual(set(record['seven_field_context']),
                             {'estado', 'configuracion', 'origen', 'servicio',
                              'caso', 'condicion', 'contexto'})
            self.assertEqual(record['r68']['confirmed_configuration_sha256'],
                             d['configuration_sha256'])
            self.assertEqual(record['r68']['rules_source_sha256'], d['rules_sha256'])
            self.assertEqual(record['r68']['generation_reference'], d['generation_reference'])
        self.assertEqual(d['sha256'], digest(canonical({k: v for k, v in d.items()
                                                       if k != 'sha256'})))

    def test_02_reopen_is_idempotent_without_new_journal(self):
        a = self.start()
        journal = self.root / 'generational-store/journal'
        self.assertEqual(len(list(journal.glob('*.json'))), 1)
        self.assertEqual(a, self.start())
        self.assertEqual(len(list(journal.glob('*.json'))), 1)

    def test_03_entrypoint_r28_create_and_reopen(self):
        a, b = self.cmd(), self.cmd()
        self.assertEqual((a.returncode, b.returncode), (0, 0), (a.stderr, b.stderr))
        self.assertEqual(json.loads(a.stdout), json.loads(b.stdout))

    def test_04_python_module_entrypoint(self):
        a, b = self.cmd(module=True), self.cmd(module=True)
        self.assertEqual((a.returncode, b.returncode), (0, 0), (a.stderr, b.stderr))
        self.assertEqual(a.stdout, b.stdout)

    def test_05_changed_frozen_configuration_rejected(self):
        self.start()
        self.fixture['services'][0]['fact'] = 'VERDADERO'
        with self.assertRaisesRegex(DurableDevError, 'frozen_configuration_mismatch'):
            self.start()

    def test_06_bad_external_pin_is_fail_closed_before_create(self):
        with self.assertRaisesRegex(DurableDevError, 'external_config_pin_mismatch'):
            self.start(expected_config_sha256='0' * 64)
        self.assertFalse(self.root.exists())

    def test_07_pin_good_or_stale_head(self):
        a = self.start()
        self.assertEqual(a, self.start(expected_config_sha256=a['configuration_sha256'],
                                       expected_head_sha256=a['store_head_sha256']))
        with self.assertRaises(StorageError):
            self.start(expected_head_sha256='0' * 64)
        self.assertEqual(a, self.start())

    def test_08_missing_configuration_of_existing_store_fails(self):
        self.start()
        (self.root / 'configuration.json').unlink()
        with self.assertRaisesRegex(DurableDevError, 'configuration_missing_for_existing_store'):
            self.start()

    def test_09_corrupted_configuration_fails(self):
        self.start()
        (self.root / 'configuration.json').write_bytes(b'CORRUPT')
        with self.assertRaisesRegex(DurableDevError, 'frozen_configuration_mismatch'):
            self.start()

    def test_10_corrupt_journal_fails_replay(self):
        self.start()
        p = next((self.root / 'generational-store/journal').glob('*.json'))
        self.overwrite(p, b'X' + p.read_bytes()[1:])
        with self.assertRaises(StorageError): self.start()

    def test_11_corrupt_generation_fails_replay(self):
        self.start()
        p = next((self.root / 'generational-store/generations').glob('*.json'))
        self.overwrite(p, b'X' + p.read_bytes()[1:])
        with self.assertRaises(StorageError): self.start()

    def test_12_corrupt_head_fails_replay(self):
        self.start()
        p = self.root / 'generational-store/HEAD'
        self.overwrite(p, b'X' + p.read_bytes()[1:])
        with self.assertRaises(StorageError): self.start()

    def test_13_forged_obsolete_generation_fails_even_with_rehashed_head(self):
        self.start()
        p = self.root / 'generational-store/HEAD'
        head = parse(p.read_bytes())['head']
        head['generation'] = 1
        self.overwrite(p, canonical({'head': head, 'sha256': digest(canonical(head))}))
        with self.assertRaises(StorageError): self.start()

    def test_14_existing_a1_receipt_forgery_refused(self):
        self.start()
        (self.root / 'a1-generation-0.json').write_bytes(b'FORGED')
        with self.assertRaisesRegex(DurableDevError, 'existing_receipt_mismatch'):
            self.start()

    def test_15_root_symlink_refused(self):
        target = Path(self.tmp.name) / 'target'
        target.mkdir(mode=0o700)
        self.root.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(DurableDevError, 'symlink_in_path'): self.start()

    def test_16_directory_not_private_refused(self):
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(DurableDevError, 'root_not_private'): self.start()

    def test_17_relative_root_refused(self):
        with self.assertRaisesRegex(DurableDevError, 'root_must_be_absolute'):
            open_or_create_dev(Path('relative'), self.fixture)

    def test_18_no_physical_execution_or_fabricated_risk(self):
        d = self.start()
        self.assertFalse(d['physical_observation_attested'])
        self.assertFalse(d['a5_dispatch_performed'])
        self.assertFalse(d['a9_subsequent_publication_attested'])
        self.assertFalse(d['external_pin_authority_attested'])
        self.assertFalse(d['operational_dispatch'])
        self.assertIsNone(d['a7_confirmed_rf'])
        self.assertEqual(d['p8_operational'], 'NO-GO')

    def test_19_concurrent_writer_refused_without_changes(self):
        d = self.start()
        with DurableStore.open(self.root / 'generational-store',
                               record_id=d['record_id'],
                               configuration_sha256=d['configuration_sha256']):
            with self.assertRaises(StorageError): self.start()
        self.assertEqual(d, self.start())

    def test_20_cli_error_has_nonzero_exit_and_no_data_mutation(self):
        d = self.start()
        out = self.cmd(extra=['--expected-head-sha256', '0' * 64])
        self.assertEqual(out.returncode, 2)
        self.assertIn('R69_FAIL=', out.stderr)
        self.assertEqual(d, self.start())

    def test_21_lost_store_is_not_silently_recreated(self):
        self.start()
        shutil.rmtree(self.root / 'generational-store')
        with self.assertRaisesRegex(DurableDevError, 'store_missing_with_frozen_configuration'):
            self.start()

if __name__ == '__main__': unittest.main()
