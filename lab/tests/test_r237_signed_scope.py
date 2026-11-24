"""Real signature verification with synthetic test identities."""

import base64
import unittest

import test_p14_r163_single_operator_install_policy as fixtures

from ardrec.coordination import r237_scope_review as m
from ardrec.experiments import prospective_attempt_journal as j

NOW = 1800000000


class SignedScopeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        fixtures.R163PolicyTests.setUpClass()

    @classmethod
    def tearDownClass(cls):

        fixtures.R163PolicyTests.tearDownClass()

    def setUp(self):

        self.signer = fixtures.R163PolicyTests()

        self.trust = {
            "schema": m.TRUST_SCHEMA,
            "authorization_signer": {
                "key_id": "r237-test-auth",
                "public_key_pem":
                    self.signer.keys["authorization"]["public"],
            },
            "revocation_signer": {
                "key_id": "r237-test-rev",
                "public_key_pem":
                    self.signer.keys["revocation"]["public"],
            },
        }

        self.signer.trust = self.trust

        self.plan = j.make_plan(
            plan_id="1"*32,
            protocol="SSH",
            head="a"*40,
            tree="b"*40,
            coverage_sha256="c"*64,
            runner_sha256="d"*64,
            fixture_sha256="e"*64,
            operator_uid=1000,
            created_at=NOW-10,
            expires_at=NOW+120,
            operation="FIXED_SYNTHETIC_SFTP_READ",
        )

        self.claim = m.authorization_statement(self.plan)

        self.issue()

    def issue(self):

        self.authorization = self.signer.sign(
            "authorization",
            m.AUTH_PREFIX,
            self.claim,
        )

        self.rev = {
            "schema": m.REV_SCHEMA,
            "authorization_sha256":
                m.sha(self.authorization),
            "plan_sha256": self.plan["sha256"],
            "sequence": 5,
            "issued_at": NOW,
            "valid_until": NOW+30,
            "revoked": False,
            "reason": "ACTIVE",
        }

        self.sign_revocation()

    def sign_revocation(self):

        self.revocation = self.signer.sign(
            "revocation",
            m.REV_PREFIX,
            self.rev,
        )

    def verify(self, **overrides):

        trust_raw = m.canonical(self.trust)

        values = {
            "plan": self.plan,
            "trust_raw": trust_raw,
            "authorization_raw": self.authorization,
            "revocation_raw": self.revocation,
            "expected_trust_sha256": m.sha(trust_raw),
            "expected_plan_sha256": self.plan["sha256"],
            "minimum_revocation_sequence": 5,
            "now": NOW,
        }

        values.update(overrides)

        return m.review(**values)

    def reject(self, **overrides):

        with self.assertRaises(ValueError):

            self.verify(**overrides)

    def test_01_valid_signatures(self):

        result = self.verify()

        self.assertTrue(
            result["cryptographic_signatures_verified"]
        )

        self.assertTrue(
            result["documentary_scope_verified"]
        )

    def test_02_reproducibility(self):

        self.assertEqual(
            self.verify(),
            self.verify(),
        )

    def test_03_wrong_trust_anchor(self):

        self.reject(
            expected_trust_sha256="0"*64
        )

    def test_04_wrong_plan_anchor(self):

        self.reject(
            expected_plan_sha256="0"*64
        )

    def test_05_tampered_signature(self):

        envelope = m.crypto.parse(
            self.authorization
        )

        envelope["signature_b64"] = (
            base64.b64encode(bytes(64)).decode("ascii")
        )

        self.reject(
            authorization_raw=m.canonical(envelope)
        )

    def test_06_scope_change_rejected_even_signed(self):

        self.claim["destination"] = "192.0.2.1"

        self.issue()
        self.reject()

    def test_07_false_independence_rejected(self):

        self.claim["human_independence_claimed"] = True

        self.issue()
        self.reject()

    def test_08_expired_plan(self):

        self.reject(now=NOW+121)

    def test_09_stale_revocation(self):

        self.reject(now=NOW+31)

    def test_10_revoked_authorization(self):

        self.rev["revoked"] = True
        self.rev["reason"] = "REVOKED"

        self.sign_revocation()
        self.reject()

    def test_11_wrong_revocation_binding(self):

        self.rev["authorization_sha256"] = "0"*64

        self.sign_revocation()
        self.reject()

    def test_12_revocation_rollback(self):

        self.reject(
            minimum_revocation_sequence=6
        )

    def test_13_key_reuse(self):

        self.trust["revocation_signer"]["public_key_pem"] = (
            self.trust["authorization_signer"]["public_key_pem"]
        )

        self.reject()

    def test_14_no_authority_promotion(self):

        result = self.verify()

        for name in (
            "operational_authorization",
            "operational_dispatch",
            "historical_authority_granted",
            "trust_provenance_attested",
            "durable_revocation_floor_attested",
            "human_independence_verified",
            "runtime_installed",
        ):

            self.assertIs(result[name], False)

        self.assertIsNone(result["confirmed_rf"])
        self.assertIsNone(result["a9_generation"])
        self.assertEqual(result["experimental_admitted"], 0)
        self.assertEqual(result["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
