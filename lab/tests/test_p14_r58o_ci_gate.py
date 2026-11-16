"""R58-O CI and real pinned-catalog direct-CLI gate."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / 'src/ardrec/coordination/r58o_a1_a10_cross_contract_trace.py'
DEMO = REPO / 'scripts/ardrec_p14_r58o_a1_a10_trace_demo.py'
TEST = REPO / 'lab/tests/test_p14_r58o_cross_contract.py'
DOC = REPO / 'docs/development/p14-r58o-a1-a10-cross-contract-audit.md'
CI = REPO / '.github/workflows/ci.yml'
CATALOG = REPO / 'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_CMD = "PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58o_*.py' -v"
DEMO_CMD = 'PYTHONPATH=src python3 -B scripts/ardrec_p14_r58o_a1_a10_trace_demo.py --synthetic-offline'


class R58OGates(unittest.TestCase):
    def test_files_exist(self):
        self.assertTrue(all(p.is_file() for p in (SRC, DEMO, TEST, DOC, CI)))

    def test_ci_one_test_command(self):
        self.assertEqual(CI.read_text().count(TEST_CMD), 1)

    def test_ci_one_demo_command(self):
        self.assertEqual(CI.read_text().count(DEMO_CMD), 1)

    def test_ci_steps_named_once(self):
        content = CI.read_text()
        self.assertEqual(content.count('Probar R58-O trazabilidad A1 A10'), 1)
        self.assertEqual(content.count('Demostrar R58-O cadena A1 A10'), 1)

    def test_prior_n_before_o(self):
        content = CI.read_text()
        self.assertLess(content.index('Demostrar R58-N recibo declarado'),
                        content.index('Probar R58-O trazabilidad A1 A10'))
        self.assertLess(content.index('Probar R58-O trazabilidad A1 A10'),
                        content.index('Demostrar R58-O cadena A1 A10'))
        self.assertLess(content.index('Demostrar R58-O cadena A1 A10'),
                        content.index('Verificar diseño del laboratorio'))

    def test_prerequisites_preserved(self):
        content = CI.read_text()
        for label in ('Probar R58-L A4 A5 revision sin despacho',
                      'Probar R58-M auditoria durable A5 offline',
                      'Probar R58-N vinculacion durable A4 A5'):
            self.assertEqual(content.count(label), 1)

    def test_ci_no_privileged_or_network(self):
        steps = CI.read_text().split('Probar R58-O trazabilidad A1 A10',1)[1].split(
            'Verificar diseño del laboratorio',1)[0]
        for bad in ('sudo ', 'libvirt', 'nmap ', 'ssh ', 'smbclient',
                    'docker run', 'apt install', '--privileged'):
            self.assertNotIn(bad, steps.lower())

    def test_python_only_no_rust_changes(self):
        self.assertIn('Rust - compilación / build', CI.read_text())

    def test_no_subprocess_in_audit_source(self):
        tree = ast.parse(SRC.read_text())
        imported = [x for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                    for x in ([a.name for a in node.names] if isinstance(node, ast.Import)
                              else [node.module or ''])]
        for forbidden in ('subprocess', 'socket', 'sqlite3', 'os',
                          'ardrec.benign_pipeline'):
            self.assertNotIn(forbidden, imported)

    def test_audit_never_persists(self):
        src = SRC.read_text()
        for token in ('persist_binding(', '.execute(', '.recover(',
                      '.submit(', '.accept(', 'Popen(', 'os.system('):
            self.assertNotIn(token, src)

    def test_cli_requires_explicit_flag(self):
        self.assertIn("--synthetic-offline", DEMO.read_text())
        self.assertIn('Path.cwd().resolve() != REPO', DEMO.read_text())

    def test_cli_no_process_launch(self):
        src = DEMO.read_text()
        for token in ('.execute(', '.recover(', 'Popen(', 'subprocess.run(',
                      'os.system(', 'socket.'):
            self.assertNotIn(token, src)
        self.assertIn('benign.accept(rid)', src)

    def test_audit_trace_requires_real_sources(self):
        src = SRC.read_text()
        for name in ('build_development_session', 'build_development_cycle',
                     'verify_a4_a5_review', 'verify_persisted', 'build_binding'):
            self.assertIn(name, src)

    def test_audit_explicit_gap(self):
        src = SRC.read_text()
        self.assertIn("'a1_a3_to_family_case_binding_attested': False", src)
        self.assertIn("'a1_a10_implementation_complete': False", src)
        self.assertIn("'experimental_hypothesis_validated': False", src)

    def test_p8_explicitly_denied(self):
        self.assertIn("'p8_operational': 'NO-GO'", SRC.read_text())

    def test_catalog_pin_if_present(self):
        if not CATALOG.is_file():
            self.skipTest('PINNED_CATALOG_NOT_MOUNTED_IN_TEMP_TEST')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(), CATALOG_SHA)

    def test_cli_denies_missing_flag(self):
        if not DEMO.exists() or not (REPO / 'src/ardrec/benign_pipeline.py').exists():
            self.skipTest('GITHUB_WORKTREE_REQUIRED')
        proc = subprocess.run([sys.executable, '-B', str(DEMO)], cwd=REPO,
                              env={**os.environ, 'PYTHONPATH':'src'},
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 23)
        self.assertIn('R58O=BLOCKED', proc.stderr)

    def test_real_direct_cli_a1_a10(self):
        if not CATALOG.is_file() or not (REPO / 'src/ardrec/benign_pipeline.py').exists():
            self.skipTest('FULL_GITHUB_WORKTREE_REQUIRED')
        proc = subprocess.run([sys.executable, '-B', str(DEMO),
                               '--synthetic-offline'],
                              cwd=REPO, env={**os.environ, 'PYTHONPATH':'src'},
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        d = json.loads(proc.stdout)
        self.assertEqual(d['stage_count'], 10)
        self.assertEqual(d['stages'], ['A'+str(i) for i in range(1,11)])
        self.assertEqual(d['a1_a3_service_count'], 3)
        self.assertEqual(d['a1_a3_event_count'], 9)
        self.assertEqual(d['a4_a8_case_count'], 29)
        self.assertEqual(d['a4_a8_family_count'], 25)
        self.assertEqual(d['a5_local_fixture_start_intent_count'], 0)
        self.assertFalse(d['a1_a3_to_family_case_binding_attested'])
        self.assertFalse(d['a1_a10_implementation_complete'])
        self.assertFalse(d['experimental_hypothesis_validated'])
        self.assertEqual(d['a6_classification'], 'ND')
        self.assertEqual(d['p8_operational'], 'NO-GO')
        self.assertIsNone(d['published_generation'])


if __name__ == '__main__':
    unittest.main()
