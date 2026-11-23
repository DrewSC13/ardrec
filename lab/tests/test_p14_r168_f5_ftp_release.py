"""R168-F5: FTP predecessor replay and fail-closed release checks."""
import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from ardrec.coordination import r168_f5_ftp_boot as ftp
from ardrec.coordination import r168_f5_ftp_release_gate as gate
from ardrec.coordination import r168_f2_runner_ftp_boot as prior_runner

REPO = Path('/home/cicada/Development/GitHub/ardrec')

class R168FTPSourceTests(unittest.TestCase):
    def test_source_pins(self):
        self.assertEqual(len(gate.source_admission()), 4)

    def test_ftp_only(self):
        self.assertEqual(ftp.ROLES, ('ftp',))
        self.assertIs(ftp.prior_runner, prior_runner)
        self.assertNotEqual(ftp.ROOT, prior_runner.ROOT)

    def test_manifest_provenance(self):
        doc = json.loads(gate.MANIFEST.read_bytes())
        h = hashlib.sha256((REPO / 'src/ardrec/coordination/r168_f2_runner_ftp_boot.py').read_bytes()).hexdigest()
        self.assertEqual(doc['historical_source_sha256'], h)
        self.assertEqual(doc['p8'], 'NO-GO')
        self.assertFalse(doc['traffic_authorized'])

    def test_runner_release_cannot_boot_ftp(self):
        plan = {'role':'runner', 'traffic_authorized':False, 'p8':'NO-GO'}
        with self.assertRaisesRegex(gate.Stop, 'FTP_RELEASE_PLAN_SCOPE'):
            gate.require(plan, now=datetime.now(timezone.utc))

    def test_release_check_precedes_claim_or_capture(self):
        with patch.object(ftp, '_check_sources', return_value='a'*40), \
             patch.object(ftp, '_read_plan', return_value=({'role':'ftp','head':'a'*40},{},{})), \
             patch.object(gate, 'require', side_effect=gate.Stop('NO_FTP_RELEASE')), \
             patch.object(ftp, '_no_attempt', side_effect=AssertionError('CLAIM_REACHED')):
            with self.assertRaisesRegex(gate.Stop,'NO_FTP_RELEASE'):
                ftp.boot(Path('/no-plan'), Path('/no-contract'), Path('/no-authorization'), Path('/no-permit'))

    def test_signed_predecessor_replay(self):
        rec = {'role':'runner', 'state':'RUNNER_RUNNING_DENY_ATTESTED',
               'traffic_authorized':False,'p8':'NO-GO'}
        plan = prior_runner.ROOT / 'plan-fake'
        boot = prior_runner.ROOT / 'boot-fake'
        with patch.object(ftp, '_receipt_dir', side_effect=lambda p,r,q:p), \
             patch.object(prior_runner, 'replay', return_value=rec):
            doc = ftp.predecessor('ftp',plan,boot)
        self.assertEqual(doc['receipt_sha256'], ftp.f7.digest(rec))
        self.assertEqual(doc['role'], 'runner')

    def test_untrusted_runner_predecessor_denied(self):
        rec = {'role':'runner', 'state':'RUNNER_RUNNING_DENY_ATTESTED',
               'traffic_authorized':True,'p8':'NO-GO'}
        with patch.object(ftp, '_receipt_dir', side_effect=lambda p,r,q:p), \
             patch.object(prior_runner, 'replay', return_value=rec):
            with self.assertRaisesRegex(ftp.Stop, 'RUNNER_PREDECESSOR_NOT_ATTESTED'):
                ftp.predecessor('ftp',prior_runner.ROOT / 'plan-fake',
                                prior_runner.ROOT / 'boot-fake')

    def test_no_attempt_marker_issued_by_test(self):
        self.assertEqual(ftp._claimed('ftp').name, 'one-ftp.once')

if __name__ == '__main__':
    unittest.main()
