"""R117-F2: offline adversarial tests; never schedule or alter the host."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'scripts/ardrec_p14_r117_f2_deny_45s_verification.py'
SPEC = importlib.util.spec_from_file_location('ardrec_r117_f2', SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)

class R117F2Safety(unittest.TestCase):
    def test_interval_45_to_50(self):
        d=MOD.validate_timing(1000.0,1046_000_000,1047_000_000)
        self.assertTrue(d['within_60s']);self.assertTrue(d['not_before_40s'])
    def test_exact_60(self):
        self.assertTrue(MOD.validate_timing(1000.0,1050_000_000,1060_000_000)['within_60s'])
    def test_over_60(self):
        self.assertFalse(MOD.validate_timing(1000.0,1050_000_000,1060_001_000)['within_60s'])
    def test_too_early(self):
        self.assertFalse(MOD.validate_timing(1000.0,1035_000_000,1036_000_000)['not_before_40s'])
    def test_missing_start(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(1000.,0,1045_000_000)
    def test_missing_exit(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(1000.,1045_000_000,0)
    def test_reversed_times(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(1000.,1047_000_000,1046_000_000)
    def test_before_attempt(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(1000.,999_999_999,1045_000_000)
    def test_boolean_attempt(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(True,1045_000_000,1047_000_000)
    def test_zero_attempt(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(0.,1045_000_000,1047_000_000)
    def test_invalid_microsecond_types(self):
        with self.assertRaises(MOD.Stop):MOD.validate_timing(1000.,'1045000000',1047_000_000)
    def test_duration(self):
        d=MOD.validate_timing(1000.,1045_000_000,1047_400_000)
        self.assertEqual(d['duration_seconds'],2.4)
    def test_monotonic_missing_denies_but_preserves_evidence(self):
        status,timing=MOD.timing_assessment(1000.0,{})
        self.assertEqual(status,'NO_GO_MONOTONIC_NOT_ATTESTED')
        self.assertEqual(timing['attestation'],'UNAVAILABLE')
    def test_monotonic_malformed_denies(self):
        status,timing=MOD.timing_assessment(1000.0,{'ExecMainStartTimestampMonotonic':'n/a','ExecMainExitTimestampMonotonic':'1047000000'})
        self.assertEqual(status,'NO_GO_MONOTONIC_NOT_ATTESTED')
    def test_monotonic_elapsed_above_max_denies(self):
        status,timing=MOD.timing_assessment(1000.0,{'ExecMainStartTimestampMonotonic':'1045000000','ExecMainExitTimestampMonotonic':'1061000000'})
        self.assertEqual(status,'NO_GO_TIMING_NOT_WITHIN_40_TO_60S')
        self.assertFalse(timing['within_60s'])
    def test_source_identical(self):
        self.assertTrue(MOD.root_source_ok(b'source',b'source'))
    def test_source_modified(self):
        self.assertFalse(MOD.root_source_ok(b'source',b'source2'))
    def test_empty_source(self):
        self.assertFalse(MOD.root_source_ok(b'',b''))
    def test_canon_roundtrip(self):
        value={'abc':1,'state':'NO-GO'}
        self.assertEqual(MOD.strict_obj(MOD.canonical(value)),value)
    def test_duplicate_json_rejected(self):
        with self.assertRaises(MOD.Stop):MOD.strict_obj(b'{"x":1,"x":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(MOD.Stop):MOD.strict_obj(b'{"x":NaN}')
    def test_single_use_no_rearm(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'attempt-already-exists';base.mkdir()
            with patch.object(MOD,'BASE',base), patch.object(MOD,'physical_preflight',return_value='fake'):
                with self.assertRaises(MOD.Stop):MOD.main(['--run'])
    def test_readonly_inspect_with_no_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'no-attempt'
            with patch.object(MOD,'BASE',base), patch.object(MOD,'physical_preflight',return_value='fake'):
                self.assertEqual(MOD.main(['--inspect']),0)
                self.assertFalse(base.exists())
    def test_inspect_consumed_fails(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'attempt';base.mkdir()
            with patch.object(MOD,'BASE',base), patch.object(MOD,'physical_preflight',return_value='fake'):
                self.assertEqual(MOD.main(['--inspect']),23)
    def test_final_only_existing_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'absent'
            with patch.object(MOD,'BASE',base):
                with self.assertRaises(MOD.Stop):MOD.finalize()
    def test_attempt_written_before_systemd(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'test'
            fired=[]
            def fake_command(args,**kwargs):
                self.assertTrue((base/'attempt.json').is_file())
                self.assertEqual(args[0],'/usr/bin/systemd-run')
                self.assertIn('--on-active=45s',args)
                self.assertEqual(args[-1],'--restore-deny')
                self.assertNotIn('--arm-deny',args)
                self.assertNotIn('--execute-pilot',args)
                fired.append(args)
            with patch.object(MOD,'BASE',base), patch.object(MOD,'physical_preflight',return_value='fake'),\
                 patch.object(MOD,'git',return_value=b'0'*40), patch.object(MOD,'directory',return_value=None),\
                 patch.object(MOD,'command',side_effect=fake_command),\
                 patch.object(MOD,'service_receipt',return_value=(None,None,None)),\
                 patch.object(MOD,'finalize',return_value=0):
                self.assertEqual(MOD.main(['--run']),0)
                self.assertEqual(len(fired),1)
    def test_no_systemd_run_in_inspect(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'absent'
            with patch.object(MOD,'BASE',base), patch.object(MOD,'physical_preflight',return_value='fake'),\
                 patch.object(MOD,'command',side_effect=AssertionError('host change')):
                self.assertEqual(MOD.main(['--inspect']),0)
    def test_requires_explicit_mode(self):
        with self.assertRaises(SystemExit):MOD.main([])

if __name__=='__main__': unittest.main()
