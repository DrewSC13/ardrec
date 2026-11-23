"""R168-F2: source-pins and non-bypassable runner release gate."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from ardrec.coordination import r168_f2_runner_ftp_boot as core
from ardrec.coordination import r168_f2_runner_release_gate as gate
from ardrec.coordination import r167_f7d_controlled_boot as f7

class RunnerReleaseTests(unittest.TestCase):
    def test_source_pins(self):
        self.assertEqual(len(gate.source_admission()), 4)

    def test_chain_uses_r167_ssh(self):
        self.assertIs(core.f7, f7)
        self.assertEqual(core.SCHEMA, 'ARDREC-R168-F2-RUNNER-FTP-DENY-v1')

    def test_ftp_cannot_use_runner_release(self):
        from datetime import datetime, timezone
        plan={'role':'ftp','traffic_authorized':False,'p8':'NO-GO'}
        with self.assertRaisesRegex(gate.Stop,'RUNNER_RELEASE_PLAN_SCOPE'):
            gate.require(plan,now=datetime.now(timezone.utc))

    def test_boot_release_gate_precedes_host_capture_or_claim(self):
        with patch.object(core, '_check_sources', return_value='b'*40), \
             patch.object(core, '_read_plan', return_value=(
                 {'role':'runner','head':'b'*40}, {}, {})), \
             patch.object(gate, 'require', side_effect=gate.Stop('NO_SIGNED_RELEASE')), \
             patch.object(core, '_no_attempt', side_effect=AssertionError('HOST_STAGE_REACHED')):
            with self.assertRaisesRegex(gate.Stop,'NO_SIGNED_RELEASE'):
                core.boot(Path('/no-real-plan'),Path('/no-contract'),
                          Path('/no-auth'),Path('/no-permit'))

    def test_release_source_only_does_not_grant_p8(self):
        manifest=json.loads(gate.MANIFEST.read_bytes())
        self.assertFalse(manifest['traffic_authorized'])
        self.assertEqual(manifest['p8'],'NO-GO')
        self.assertEqual(manifest['role'],'runner')

    def test_f1_historical_source_intact(self):
        manifest=json.loads(gate.MANIFEST.read_bytes())
        f1=Path('/home/cicada/Development/GitHub/ardrec/src/ardrec/coordination/r168_f1_runner_ftp_boot.py')
        import hashlib
        self.assertEqual(hashlib.sha256(f1.read_bytes()).hexdigest(),
                         manifest['historical_source_sha256'])
