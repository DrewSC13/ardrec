"""R270: counter normalization and original evidence tests."""

import unittest

from ardrec.coordination import (
    prospective_local_pilot as durable,
    pilot_observation as engine,
)


class PilotObservationTests(unittest.TestCase):

    def fixture(self):

        raw = b"ARDREC:PILOT:ssh:CONTROL:REFERENCE\n"

        pin = engine.sha(raw)

        smoke = durable.seal({
            "protocol": "ssh",
            "schema": "ARDREC-R260-SERVICE-SMOKE-v1",
            "scope": "PRIVATE_SYNTHETIC_CONTROL_READ",
            "client_invocations": 1,
            "functional_read_verified": True,
            "runner_deny_restored": True,
            "target_deny_restored": True,
            "target_account_locked": True,
            "target_service_masked": True,
            "client_credential_removed": True,
            "formal_pilot_admitted": False,
            "experimental_admitted": False,
            "a6": "ND",
            "confirmed_rf": None,
            "fixture_sha256": pin,
            "p8": "NO-GO",
            "observation": {
                "bytes_read": len(raw),
                "client_returncode": 0,
                "read_sha256": pin,
            },
        })

        return smoke, raw

    def modify(self, smoke, **changes):

        data = {
            key: value
            for key, value in smoke.items()
            if key != "sha256"
        }

        data.update(changes)

        return durable.seal(data)

    def test_01_attempt_list_normalized(self):

        self.assertEqual(
            engine.validate_attempts(
                ["ssh", "ftp", "smb"]
            ),
            3,
        )

    def test_02_integer_counter_rejected(self):

        with self.assertRaises(ValueError):
            engine.validate_attempts(3)

    def test_03_duplicate_protocol_rejected(self):

        with self.assertRaises(ValueError):
            engine.validate_attempts(
                ["ssh", "ftp", "ftp"]
            )

    def test_04_valid_original_bytes(self):

        smoke, raw = self.fixture()

        result = engine.validate_smoke(
            smoke, smoke, raw, "ssh"
        )

        self.assertEqual(
            result["read_bytes"], 35
        )

    def test_05_modified_original_rejected(self):

        smoke, raw = self.fixture()

        with self.assertRaises(ValueError):
            engine.validate_smoke(
                smoke, smoke, raw + b"x", "ssh"
            )

    def test_06_cleanup_failure_rejected(self):

        smoke, raw = self.fixture()

        changed = self.modify(
            smoke,
            runner_deny_restored=False,
        )

        with self.assertRaises(ValueError):
            engine.validate_smoke(
                changed, changed, raw, "ssh"
            )

    def test_07_experimental_promotion_rejected(self):

        smoke, raw = self.fixture()

        changed = self.modify(
            smoke,
            experimental_admitted=True,
        )

        with self.assertRaises(ValueError):
            engine.validate_smoke(
                changed, changed, raw, "ssh"
            )

    def test_08_missing_comparison_not_accredited(self):

        self.assertEqual(
            engine.support_status(
                "ACCESS_COMPARISON", True
            ),
            "MISSING_RESTRICTED_COMPARISON",
        )

        self.assertEqual(
            engine.support_status(
                "RESOURCE_READ", False
            ),
            "ND_NOT_OBSERVED",
        )


if __name__ == "__main__":
    unittest.main()
