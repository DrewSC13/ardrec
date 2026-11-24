"""R202: offline functional receipt validation."""
import copy
import unittest

from ardrec.experiments import functional_ftp_fixture as m
from ardrec.coordination import local_ssh_pilot as ssh


def sample():

    digest = ssh.digest(m.PAYLOAD)

    return {
        "host_namespace": "net:[100]",
        "child_namespace": "net:[200]",
        "interfaces": ["lo"],
        "endpoint": "127.0.0.1",
        "greeting_code": "220",
        "login_code": "230",
        "transfer_code": "226",
        "goodbye_code": "221",
        "bytes_received": len(m.PAYLOAD),
        "source_sha256": digest,
        "received_sha256": digest,
        "final_source_sha256": digest,
        "source_unchanged": True,
        "server_thread_stopped": True,
        "fixture_permissions": "er",
        "authentication_attempts": 1,
        "authorized_read_transfers": 1,
        "write_operations_requested": 0,
    }


class FunctionalFixtureTests(unittest.TestCase):

    def test_valid_software_receipt(self):

        self.assertTrue(
            m.verify_observation(
                sample(),
                "net:[100]",
            )
        )

    def test_same_namespace_rejected(self):

        value = sample()

        value["child_namespace"] = "net:[100]"

        with self.assertRaises(ValueError):

            m.verify_observation(
                value,
                "net:[100]",
            )

    def test_external_interface_rejected(self):

        value = sample()
        value["interfaces"] = ["eth0", "lo"]

        with self.assertRaises(ValueError):

            m.verify_observation(
                value,
                "net:[100]",
            )

    def test_invalid_integrity_or_codes_rejected(self):

        for key, changed in (
            ("received_sha256", "0" * 64),
            ("final_source_sha256", "0" * 64),
            ("bytes_received", 0),
            ("transfer_code", "550"),
            ("login_code", "530"),
            ("source_unchanged", False),
            ("server_thread_stopped", False),
        ):

            with self.subTest(key=key):

                value = copy.deepcopy(sample())
                value[key] = changed

                with self.assertRaises(ValueError):

                    m.verify_observation(
                        value,
                        "net:[100]",
                    )

    def test_scope_promotion_rejected(self):

        for key, changed in (
            ("authentication_attempts", 2),
            ("authorized_read_transfers", 2),
            ("write_operations_requested", 1),
            ("fixture_permissions", "elradfmw"),
            ("endpoint", "192.0.2.1"),
            ("experimental_admission", True),
        ):

            with self.subTest(key=key):

                value = sample()
                value[key] = changed

                with self.assertRaises(ValueError):

                    m.verify_observation(
                        value,
                        "net:[100]",
                    )


if __name__ == "__main__":
    unittest.main()
