"""F10R root operator unit-only tests, never running a real root command."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ardrec.coordination import r113_f10_contract as contract
from ardrec.coordination import r113_f10r_filter_semantics as semantic

ROOT_SRC = Path(__file__).resolve().parents[2] / 'scripts' / 'ardrec_p14_r113_f10r_root_window.py'
STAGE_SRC = Path(__file__).resolve().parents[2] / 'scripts' / 'ardrec_p14_r113_f10r_root_stage.py'


def load_operator():
    import sys
    with patch.dict(sys.modules, {'contract': contract, 'semantic': semantic}):
        spec = importlib.util.spec_from_file_location('ardrec_f10r_root_unit_test', ROOT_SRC)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class RootFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.module = load_operator()

    def test_01_distinct_root_directory(self):
        self.assertEqual(str(self.module.ROOT), '/var/lib/ardrec/r113-f10r-window-v1')
    def test_02_six_roles_preserved(self):
        self.assertEqual(len(self.module.c.ROLES), 6)
    def test_03_no_filter_definition_operation(self):
        self.assertNotIn('nwfilter-define', ROOT_SRC.read_text())
    def test_04_original_f10_root_preserved(self):
        self.assertIn("OLD=Path('/var/lib/ardrec/r113-f10-window-v1')",STAGE_SRC.read_text())
        self.assertIn("NEW=Path('/var/lib/ardrec/r113-f10r-window-v1')",STAGE_SRC.read_text())
    def test_05_stage_rejects_previous_window_attempt(self):
        self.assertIn("window-attempted.once",STAGE_SRC.read_text())
        self.assertIn("ORIGINAL_F10_WINDOW_ALREADY_ATTEMPTED",STAGE_SRC.read_text())
    def test_06_self_contained_timer_restores_f6(self):
        text=ROOT_SRC.read_text()
        self.assertIn("'/usr/bin/python3',F6,'--restore-deny']",text)
        self.assertIn("f6('f6_restore_final','--restore-deny',folder)",text)
    def test_07_root_semantic_helper_exact(self):
        name=contract.name('ssh')
        a=f"<filter name='{name}'><rule action='drop' direction='inout'><all/></rule></filter>".encode()
        b=a.replace(b"<filter ",b"<filter chain='root' ")
        self.assertTrue(self.module.same_filter(b,a))
    def test_08_root_semantic_helper_rejects_rule_change(self):
        name=contract.name('ssh')
        a=f"<filter name='{name}'><rule action='drop' direction='inout'><all/></rule></filter>".encode()
        b=a.replace(b"action='drop'",b"action='accept'")
        self.assertFalse(self.module.same_filter(b,a))
    def test_09_adoption_writes_only_local_marker(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p)
            with patch.object(self.module,'ROOT',root),\
                 patch.object(self.module,'f6') as f6,\
                 patch.object(self.module,'invariant_f11_and_watchdog'),\
                 patch.object(self.module,'filters_ready') as ready,\
                 patch.object(self.module,'receipt'):
                result=self.module.adopt_filters({})
                self.assertEqual(result,0)
                self.assertEqual(f6.call_count,3)
                ready.assert_called_once()
                self.assertEqual((root/'filters-installed.once').read_bytes(),
                    b'R113_F10R_SIX_EXISTING_FILTERS_READONLY_ADOPTED\n')
    def test_10_adoption_precondition_does_not_repeat(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p)
            (root/'filters-installed.once').write_bytes(b'original')
            with patch.object(self.module,'ROOT',root):
                with self.assertRaises(contract.Stop):
                    self.module.adopt_filters({})


if __name__=='__main__': unittest.main()
