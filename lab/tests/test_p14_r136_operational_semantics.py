"""R136: exact B4 and B9 signed operational semantics, source-only tests."""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from ardrec.coordination import r136_operational_semantics as admission
from ardrec.coordination import r135_root_transaction as transaction

REPO = Path(__file__).resolve().parents[2]
HEAD = 'f789fb16c5a3295220d17b30bd3f5ac5c1f353ec'
BOOT = '00000000-0000-4000-8000-000000000000'
NOW = datetime(2026, 11, 22, 3, 0, 5, tzinfo=timezone.utc)
SESSION = 'a' * 16
CASE = 'FTP-T01-S01-01'
TARGET = {'ip': '10.203.31.2', 'port': 21,
          'vm': 'ardrec-r33-dev-ftp', 'network': 'ardrec-r33-dev-net-ftp'}
START = '2026-11-22T03:00:00Z'
END = '2026-11-22T03:01:00Z'
REV_ISSUED = '2026-11-22T03:00:04Z'
REV_END = '2026-11-22T03:00:30Z'


def openssl(*args):
    r = subprocess.run(['/usr/bin/openssl', *map(str, args)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=10, check=False)
    if r.returncode != 0:
        raise RuntimeError('TEST_OPENSSL:' + r.stderr.decode(errors='replace')[:140])
    return r.stdout


class OperationalSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ardrec-r136-ephemeral-')
        cls.root = Path(cls.temp.name)
        cls.b4raw = (REPO / 'scripts/ardrec_p14_r130_b4_root_guard_v2.py').read_bytes()
        cls.b9raw = (REPO / 'scripts/ardrec_p14_r130_b9_ftp_executor_v2.py').read_bytes()
        cls.b4 = admission.pinned_module(cls.b4raw, transaction.B4_SHA, 'b4fixture')
        cls.b9 = admission.pinned_module(cls.b9raw, transaction.B9_SHA, 'b9fixture')
        cls.keys = {}
        for role in ('root_grant', 'root_rev', 'scope_auth', 'scope_rev',
                     'pilot_auth', 'pilot_rev', 'window_auth', 'window_rev',
                     'traffic_auth', 'traffic_rev'):
            sk, pk = cls.root / (role + '.key'), cls.root / (role + '.pub')
            openssl('genpkey', '-algorithm', 'ED25519', '-out', sk)
            openssl('pkey', '-in', sk, '-pubout', '-out', pk)
            cls.keys[role] = (sk, pk.read_text('ascii'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def key(self, role):
        return {'key_id': 'ardrec.r136.test.' + role,
                'public_key_pem': self.keys[role][1]}

    def sign(self, role, prefix, statement):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            msg = base / 'message'
            sig = base / 'signature'
            msg.write_bytes(prefix + self.b4.canonical(statement))
            openssl('pkeyutl', '-sign', '-inkey', self.keys[role][0],
                    '-rawin', '-in', msg, '-out', sig)
            return {'statement': copy.deepcopy(statement),
                    'signer_key_id': self.key(role)['key_id'],
                    'signature_b64': base64.b64encode(sig.read_bytes()).decode('ascii')}

    def rev(self, role, prefix, schema, id_name, ident, sha_name, value):
        return self.sign(role, prefix, {
            'schema': schema, id_name: ident, sha_name: value,
            'issued_at': REV_ISSUED, 'valid_until': REV_END,
            'revoked': False, 'reason_code': 'CURRENT_CLEAR',
        })

    def setUp(self):
        b4, b9 = self.b4, self.b9
        scope_statement = {
            'schema': 'ARDREC-R115-F3-FTP-T01-AUTHORIZATION-v1',
            'authorization_id': 'scope-r136-1', 'case_id': CASE,
            'target': TARGET, 'catalog_sha256': '1' * 64,
            'valid_from': START, 'valid_until': END,
        }
        scope = self.sign('scope_auth', b4.SCOPE_AUTH_PREFIX, scope_statement)
        contract = {'case_id': CASE, 'source_commit': HEAD,
                    'catalog_sha256': '1' * 64, 'target': TARGET}
        contract_hash = b4.sha(b4.canonical(contract))
        scope_hash = b4.sha(b4.canonical(scope))
        budget = {'ordinary_attempts': 1, 'additional_attempts': 0, 'max_connections': 1}
        pilot_statement = {
            'schema': 'ARDREC-R115-F15-FTP-T01-PILOT-PERMIT-v1',
            'pilot_id': 'pilot-r136-1', 'case_id': CASE, 'head': HEAD,
            'target': TARGET, 'contract_sha256': contract_hash,
            'scope_authorization_sha256': scope_hash,
            'pilot_only_no_production_p8': True,
            'action': 'ONE_ISOLATED_FTP_T01_CONTROL_GREETING',
            'budget': budget, 'valid_from': START, 'valid_until': END,
        }
        pilot = self.sign('pilot_auth', b4.PILOT_PREFIX, pilot_statement)
        window_statement = {
            'schema': 'ARDREC-R115-F11-FTP-T01-TRAFFIC-WINDOW-v1',
            'window_id': 'window-r136-1', 'case_id': CASE, 'head': HEAD,
            'target': TARGET, 'contract_sha256': contract_hash,
            'scope_authorization_sha256': scope_hash,
            'action': 'ONE_FTP_CONTROL_GREETING_READ_ONLY',
            'network_traffic_requested': True, 'budget': budget,
            'valid_from': START, 'valid_until': END,
        }
        window = self.sign('window_auth', b4.WINDOW_PREFIX, window_statement)
        budget_hash = b4.sha(b4.canonical(budget))
        grant_statement = {
            'schema': b4.GRANT_SCHEMA, 'session': SESSION,
            'head': HEAD, 'case_id': CASE, 'target': TARGET,
            'catalog_sha256': '1' * 64,
            'contract_sha256': contract_hash,
            'scope_authorization_sha256': scope_hash,
            'pilot_sha256': b4.sha(b4.canonical(pilot)),
            'window_sha256': b4.sha(b4.canonical(window)),
            'budget_sha256': budget_hash,
            'guard_sha256': transaction.GUARD_SHA,
            'boot_id': BOOT, 'valid_from': START, 'valid_until': END,
            'action': 'ARM_DENY_BACKUP_ONLY',
            'network_traffic_authorized': False,
            'one_shot': True, 'p8': 'NO-GO',
        }
        grant = self.sign('root_grant', b4.GRANT_PREFIX, grant_statement)
        self.b4docs = {
            'root_trust': {'schema': b4.TRUST_SCHEMA,
                           'grant_signer': self.key('root_grant'),
                           'revocation_signer': self.key('root_rev')},
            'scope_trust': {'schema': 'ARDREC-R115-F3-EXTERNAL-TRUST-PINS-v1',
                            'scope_signer': self.key('scope_auth'),
                            'revocation_signer': self.key('scope_rev')},
            'pilot_trust': {'schema': 'ARDREC-R115-F15-P7-EXTERNAL-TRUST-v1',
                            'pilot_signer': self.key('pilot_auth'),
                            'revocation_signer': self.key('pilot_rev')},
            'window_trust': {'schema': 'ARDREC-R115-F11-P8-EXTERNAL-TRUST-v1',
                             'window_signer': self.key('window_auth'),
                             'revocation_signer': self.key('window_rev')},
            'grant': grant, 'contract': contract,
            'scope_authorization': scope, 'pilot_permit': pilot,
            'traffic_window': window,
            'root_revocation': self.rev('root_rev', b4.REV_PREFIX, b4.REV_SCHEMA,
                                        'session', SESSION, 'grant_sha256',
                                        b4.sha(b4.canonical(grant))),
            'scope_revocation': self.rev('scope_rev', b4.SCOPE_REV_PREFIX,
                                         'ARDREC-R115-F3-REVOCATION-REVIEW-v1',
                                         'authorization_id', scope_statement['authorization_id'],
                                         'authorization_sha256', scope_hash),
            'pilot_revocation': self.rev('pilot_rev', b4.PILOT_REV_PREFIX,
                                         'ARDREC-R115-F15-P7-PILOT-REVOCATION-v1',
                                         'pilot_id', pilot_statement['pilot_id'],
                                         'pilot_sha256', b4.sha(b4.canonical(pilot))),
            'window_revocation': self.rev('window_rev', b4.WINDOW_REV_PREFIX,
                                          'ARDREC-R115-F11-P8-REVOCATION-v1',
                                          'window_id', window_statement['window_id'],
                                          'window_sha256', b4.sha(b4.canonical(window))),
        }
        handoff = {
            'schema': b9.HANDOFF_SCHEMA, 'head': HEAD, 'session': SESSION,
            'case_id': CASE, 'case_key': '2' * 64, 'assessment_index': 0,
            'attempt_id': 'ATT_R136_FTP_T01', 'contract_sha256': contract_hash,
            'scope_authorization_sha256': scope_hash,
            'window_sha256': b4.sha(b4.canonical(window)),
            'reservation_sha256': '3' * 64, 'spent_sha256': '4' * 64,
            'budget_sha256': budget_hash, 'target': {'ip': '10.203.31.2', 'port': 21},
            'once_consumed_without_physical_claim': True,
            'root_approval_issued': False, 'a6': 'ND', 'p8': 'NO-GO',
        }
        handoff['sha256'] = b9.digest(handoff)
        traffic_statement = {
            'schema': b9.GRANT_SCHEMA,
            'traffic_id': 'traffic-r136-1', 'session': SESSION,
            'case_id': CASE, 'head': HEAD, 'boot_id': BOOT,
            'f13_handoff_sha256': b9.digest(handoff),
            'root_deny_grant_sha256': b9.digest(grant),
            'window_sha256': grant_statement['window_sha256'],
            'budget_sha256': budget_hash,
            'valid_from': START, 'valid_until': END,
            'action': 'ONE_FTP_T01_GUEST_GREETING',
            'guest': 'ardrec-r33-dev-runner',
            'destination': {'ip': '10.203.31.2', 'port': 21},
            'one_shot': True, 'traffic_pilot_exception_only': True,
            'a6': 'ND', 'p8': 'NO-GO',
        }
        traffic = self.sign('traffic_auth', b9.GRANT_PREFIX, traffic_statement)
        self.external = {
            key: b4.canonical(doc) for key, doc in self.b4docs.items()
            if key.endswith('trust') or key.endswith('revocation')
        }
        self.external['traffic_trust'] = b4.canonical({
            'schema': b9.TRUST_SCHEMA,
            'traffic_signer': self.key('traffic_auth'),
            'revocation_signer': self.key('traffic_rev'),
        })
        self.external['traffic_revocation'] = b4.canonical(
            self.rev('traffic_rev', b9.REV_PREFIX, b9.REV_SCHEMA,
                     'traffic_id', traffic_statement['traffic_id'],
                     'traffic_grant_sha256', b9.digest(traffic)))
        self.payload = {}
        for label, names in (('B4', transaction.B4), ('B9', transaction.B9)):
            for name in names:
                if name.endswith('.json'):
                    self.payload[label + '/' + name] = b4.canonical({'schema':'TEST-ONLY'})
        self.payload.update({
            'B4/root-controller.py': self.b4raw,
            'B9/root-executor.py': self.b9raw,
            'B4/grant.json': b4.canonical(grant),
            'B4/contract.json': b4.canonical(contract),
            'B4/scope-authorization.json': b4.canonical(scope),
            'B4/pilot-permit.json': b4.canonical(pilot),
            'B4/traffic-window.json': b4.canonical(window),
            'B9/f13-handoff.json': b9.canon(handoff),
            'B9/traffic-grant.json': b9.canon(traffic),
            'B9/lock': b'ARDREC-R128-B9-ROOT-LOCK\n',
            'B4/manifest.json': transaction.canonical({
                'schema': 'ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle',
                'script_sha256': transaction.B4_SHA, 'guard_sha256': transaction.GUARD_SHA,
                'approved_head': HEAD, 'deny_only': True, 'root_install_independent': True,
            }),
            'B9/manifest.json': transaction.canonical({
                'schema': 'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle',
                'approved_head': HEAD, 'script_sha256': transaction.B9_SHA,
                'r126_deny_controller_sha256': transaction.B4_SHA,
                'legacy_f3_sha256': transaction.F3_SHA,
                'guard_sha256': transaction.GUARD_SHA,
                'root_staged_independently': True, 'automatic_network': False,
                'p8': 'NO-GO',
            }),
        })

    def check(self):
        return admission.validate(payload=self.payload, external=self.external,
                                  b4_source=self.b4raw, b9_source=self.b9raw,
                                  head=HEAD, boot_id=BOOT, now=NOW)

    def test_01_complete_signed_b4_b9(self):
        r = self.check()
        self.assertEqual(r['b4_signed_semantics'], 'PASS')
        self.assertEqual(r['b9_traffic_signed_semantics'], 'PASS')
        self.assertFalse(r['root_install_authorized'])

    def test_02_b4_source_tampered(self):
        with self.assertRaisesRegex(admission.Refusal, 'CONTROLLER_SOURCE_PIN_MISMATCH'):
            admission.validate(payload=self.payload, external=self.external,
                               b4_source=self.b4raw+b'x', b9_source=self.b9raw,
                               head=HEAD, boot_id=BOOT, now=NOW)

    def test_03_b9_source_tampered(self):
        with self.assertRaisesRegex(admission.Refusal, 'CONTROLLER_SOURCE_PIN_MISMATCH'):
            admission.validate(payload=self.payload, external=self.external,
                               b4_source=self.b4raw, b9_source=self.b9raw+b'x',
                               head=HEAD, boot_id=BOOT, now=NOW)

    def test_04_unbound_scope(self):
        doc = self.b4.parse(self.payload['B4/scope-authorization.json'])
        doc['signature_b64'] = base64.b64encode(bytes(64)).decode('ascii')
        self.payload['B4/scope-authorization.json'] = self.b4.canonical(doc)
        with self.assertRaisesRegex(ValueError, 'SIGNATURE_INVALID'):
            self.check()

    def test_05_grant_not_signed(self):
        doc = self.b4.parse(self.payload['B4/grant.json'])
        doc['signature_b64'] = base64.b64encode(bytes(64)).decode('ascii')
        self.payload['B4/grant.json'] = self.b4.canonical(doc)
        with self.assertRaisesRegex(ValueError, 'SIGNATURE_INVALID'):
            self.check()

    def test_06_upstream_trust_collision(self):
        r = self.b4.parse(self.external['scope_trust'])
        r['scope_signer'] = self.key('root_grant')
        self.external['scope_trust'] = self.b4.canonical(r)
        with self.assertRaisesRegex(ValueError, 'EIGHT_INDEPENDENT_SIGNERS_REQUIRED'):
            self.check()

    def test_07_traffic_trust_collision(self):
        r = self.b4.parse(self.external['traffic_trust'])
        r['traffic_signer'] = self.key('root_grant')
        self.external['traffic_trust'] = self.b4.canonical(r)
        with self.assertRaisesRegex(ValueError, 'TEN_SEPARATE_SIGNERS_REQUIRED'):
            self.check()

    def test_08_window_budget_outside_scope(self):
        window = self.b4.parse(self.payload['B4/traffic-window.json'])
        window['statement']['budget']['max_connections'] = 2
        self.payload['B4/traffic-window.json'] = self.b4.canonical(window)
        with self.assertRaisesRegex(ValueError, 'SIGNATURE_INVALID'):
            self.check()

    def test_09_traffic_grant_wrong_target(self):
        t = self.b9.parse(self.payload['B9/traffic-grant.json'])
        t['statement']['destination']['ip'] = '192.0.2.1'
        self.payload['B9/traffic-grant.json'] = self.b9.canon(t)
        with self.assertRaisesRegex(ValueError, 'SIGNATURE_INVALID'):
            self.check()

    def test_10_traffic_grant_wrong_head(self):
        t = self.b9.parse(self.payload['B9/traffic-grant.json'])
        t['statement']['head'] = '0'*40
        self.payload['B9/traffic-grant.json'] = self.b9.canon(t)
        with self.assertRaisesRegex(ValueError, 'SIGNATURE_INVALID'):
            self.check()

    def test_11_handoff_tamper(self):
        h = self.b9.parse(self.payload['B9/f13-handoff.json'])
        h['case_id'] = 'FTP-T01-S01-02'
        self.payload['B9/f13-handoff.json'] = self.b9.canon(h)
        with self.assertRaisesRegex(ValueError, 'F13_HANDOFF_NOT_BOUND'):
            self.check()

    def test_12_revoked_root_grant(self):
        doc = self.b4.parse(self.external['root_revocation'])
        doc['statement']['revoked'] = True
        doc = self.sign('root_rev', self.b4.REV_PREFIX, doc['statement'])
        self.external['root_revocation'] = self.b4.canonical(doc)
        with self.assertRaisesRegex(ValueError, 'REVOCATION_NOT_BOUND_OR_REVOKED'):
            self.check()

    def test_13_stale_traffic_revocation(self):
        doc = self.b4.parse(self.external['traffic_revocation'])
        doc['statement']['issued_at'] = '2026-11-22T02:59:00Z'
        doc = self.sign('traffic_rev', self.b9.REV_PREFIX, doc['statement'])
        self.external['traffic_revocation'] = self.b4.canonical(doc)
        with self.assertRaisesRegex(ValueError, 'REVOCATION_NOT_FRESH'):
            self.check()

    def test_14_missing_external_document(self):
        del self.external['traffic_trust']
        with self.assertRaisesRegex(admission.Refusal, 'EXTERNAL_DOCUMENT_SCOPE'):
            self.check()

    def test_15_future_boot_rejected(self):
        with self.assertRaisesRegex(ValueError, 'GRANT_SCOPE_OR_IDENTITY_INVALID'):
            admission.validate(payload=self.payload, external=self.external,
                               b4_source=self.b4raw, b9_source=self.b9raw,
                               head=HEAD, boot_id='11111111-1111-4111-8111-111111111111', now=NOW)

    def test_16_past_window_rejected(self):
        when = datetime(2026, 11, 22, 3, 2, 0, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, 'GRANT_TIME_BUDGET_TOO_SHORT'):
            admission.validate(payload=self.payload, external=self.external,
                               b4_source=self.b4raw, b9_source=self.b9raw,
                               head=HEAD, boot_id=BOOT, now=when)

    def test_17_unaware_clock_rejected(self):
        with self.assertRaisesRegex(admission.Refusal, 'CLOCK_NOT_AWARE'):
            admission.validate(payload=self.payload, external=self.external,
                               b4_source=self.b4raw, b9_source=self.b9raw,
                               head=HEAD, boot_id=BOOT,
                               now=datetime(2026, 11, 22, 3, 0, 5))

    def test_18_caps(self):
        caps = admission.capabilities()
        self.assertFalse(caps['root_installer'])
        self.assertFalse(caps['trust_provenance_attested'])


if __name__ == '__main__':
    unittest.main()
