"""R58-C D1: deterministic CI portability with strictly pinned host-only boundary."""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch
import unittest

from scripts import ardrec_p14_r58c_f11_deployment_plan as f11
from scripts import ardrec_p14_r58c_a6_a7_a9_chain as chain

ROOT = Path(__file__).resolve().parents[2]


class TestR58CD1PortableCI(unittest.TestCase):
    def test_f11_checkout_is_dynamically_resolved(self):
        self.assertEqual(f11.REPO, ROOT)
        self.assertEqual(f11.REPO, Path(f11.__file__).resolve().parents[1])

    def test_chain_checkout_is_dynamically_resolved(self):
        self.assertEqual(chain.REPO, ROOT)
        self.assertEqual(chain.REPO, Path(chain.__file__).resolve().parents[1])

    def test_synthetic_fixtures_follow_checkout(self):
        self.assertEqual(chain.SCENARIO, ROOT/'lab/p14-r26-session-v1/scenario.json')
        self.assertEqual(chain.SYNTHETIC_RECEIPT, ROOT/'lab/p14-r37-a6-defensive-import-v1/synthetic-receipt.json')
        self.assertEqual(chain.SYNTHETIC_SUPPORT, ROOT/'lab/p14-r37-a6-defensive-import-v1/synthetic-support.txt')
        for source in (chain.SCENARIO, chain.SYNTHETIC_RECEIPT, chain.SYNTHETIC_SUPPORT):
            self.assertTrue(source.is_file())
            self.assertFalse(source.is_symlink())

    def test_f11_offline_source_hashes_still_pinned(self):
        self.assertEqual(f11.check_source(), f11.SOURCE)

    def test_host_mode_requires_canonical_prometheus_checkout(self):
        self.assertEqual(f11.HOST_REPO, Path('/home/cicada/Development/GitHub/ardrec'))
        with patch.object(f11, 'HOST_REPO', Path('/a/different/prometheus/checkout')):
            with patch.object(f11, 'check_source', side_effect=AssertionError('reached host reads')):
                with self.assertRaisesRegex(f11.PlanError, 'HOST_CANONICAL_REPOSITORY_REQUIRED'):
                    f11.host_audit()

    def test_checkout_relocation_resolves_paths_without_host_calls(self):
        for module_path in (ROOT/'scripts/ardrec_p14_r58c_f11_deployment_plan.py',
                            ROOT/'scripts/ardrec_p14_r58c_a6_a7_a9_chain.py'):
            script=ast.parse(module_path.read_text(encoding='utf-8'))
            assignments=[n for n in script.body if isinstance(n,ast.Assign) and
                         any(isinstance(t,ast.Name) and t.id=='REPO' for t in n.targets)]
            self.assertEqual(len(assignments),1)
            value=assignments[0].value
            for different_root in ('/home/runner/work/ardrec/ardrec',
                                   '/tmp/ardrec-ci-checkout'):
                mock_file=str(Path(different_root)/'scripts'/module_path.name)
                calculated=eval(compile(ast.Expression(value),str(module_path),'eval'),
                                {'Path':Path,'__file__':mock_file})
                self.assertEqual(calculated,Path(different_root))

    def test_offline_workflow_remains_non_privileged(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn("test_p14_r58c_*.py", workflow)
        self.assertIn('PYTHONPATH=src python3 -B -m unittest discover',workflow)
        self.assertNotIn('sudo -v', workflow)
