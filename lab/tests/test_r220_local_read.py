"""Contract regression tests for the R220 local read fixtures."""

import copy
import unittest

from ardrec.experiments import r220_local_read as r220
from ardrec.experiments import functional_local_fixtures as old


def observation(protocol, profile):

    restricted = (
        b"" if profile == "CONTROL"
        else r220.RESTRICTED
    )

    status = (
        "ACCESS_DENIED"
        if profile == "CONTROL"
        else "READ_OK"
    )

    result = {
        "protocol": protocol,
        "profile": profile,
        "authenticated": True,
        "source_unchanged": True,
        "server_cleanup_verified": True,
        "operations_requested": 2,
        "authentication_requests_planned": 1,
        "write_operations_requested": 0,
        "arbitrary_commands_requested": 0,
        "effective_restricted_mode":
            0 if profile == "CONTROL" else 0o400,
        "versions": old.VERSIONS[protocol],
        "isolation": {
            "host_namespace": "net:[100]",
            "child_namespace": "net:[200]",
            "interfaces": ["lo"],
            "endpoint": "127.0.0.1",
            "effective_uid": 1000,
            "effective_capabilities": "00000000",
        },
        "resources": {
            "allowed.txt": {
                "status": "READ_OK",
                "bytes": len(r220.ALLOWED),
                "sha256": r220.digest(r220.ALLOWED),
            },
            "restricted.txt": {
                "status": status,
                "bytes": len(restricted),
                "sha256": r220.digest(restricted),
            },
        },
    }

    if protocol == "SSH":

        result.update({
            "backend": "PARAMIKO_SFTP_USERSPACE",
            "server_identity_verified": True,
            "operation": "FIXED_SYNTHETIC_SFTP_READ",
        })

    else:

        result.update({
            "backend": "IMPACKET_USERSPACE",
            "guest_session": False,
            "dialect": "0x202",
            "share_read_only_configured": True,
            "operation": "FIXED_SYNTHETIC_SMB_READ",
        })

    return result


class R220Tests(unittest.TestCase):

    def test_runner_compiles(self):

        compile(r220.RUNNER, "<r220-runner>", "exec")

    def test_four_contracts(self):

        for _, protocol, profile in r220.CASES:

            with self.subTest(
                protocol=protocol,
                profile=profile,
            ):

                self.assertTrue(
                    r220.verify_observation(
                        protocol,
                        profile,
                        observation(protocol, profile),
                        "net:[100]",
                    )
                )

    def test_wrong_content_rejected(self):

        for _, protocol, profile in r220.CASES:

            value = observation(protocol, profile)

            value["resources"]["allowed.txt"][
                "sha256"
            ] = "0" * 64

            with self.assertRaises(ValueError):

                r220.verify_observation(
                    protocol, profile, value, "net:[100]"
                )

    def test_external_endpoint_rejected(self):

        value = observation("SSH", "CONTROL")
        value["isolation"]["endpoint"] = "192.0.2.1"

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SSH", "CONTROL", value, "net:[100]"
            )

    def test_same_namespace_rejected(self):

        value = observation("SMB", "CONTROL")

        value["isolation"]["child_namespace"] = "net:[100]"

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SMB", "CONTROL", value, "net:[100]"
            )

    def test_partial_denial_rejected(self):

        value = observation("SMB", "CONTROL")

        value["resources"]["restricted.txt"]["bytes"] = 1

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SMB", "CONTROL", value, "net:[100]"
            )

    def test_write_rejected(self):

        value = observation("SSH", "CONTRAST")
        value["write_operations_requested"] = 1

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SSH", "CONTRAST", value, "net:[100]"
            )

    def test_guest_session_rejected(self):

        value = observation("SMB", "CONTRAST")
        value["guest_session"] = True

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SMB", "CONTRAST", value, "net:[100]"
            )

    def test_policy_mismatch_rejected(self):

        value = observation("SSH", "CONTROL")
        value["effective_restricted_mode"] = 0o400

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SSH", "CONTROL", value, "net:[100]"
            )

    def test_unclassified_response_rejected(self):

        value = observation("SMB", "CONTROL")

        value["resources"]["restricted.txt"][
            "status"
        ] = "UNKNOWN"

        with self.assertRaises(ValueError):

            r220.verify_observation(
                "SMB", "CONTROL", value, "net:[100]"
            )

    def test_input_not_modified(self):

        value = observation("SSH", "CONTRAST")
        before = copy.deepcopy(value)

        r220.verify_observation(
            "SSH", "CONTRAST", value, "net:[100]"
        )

        self.assertEqual(value, before)


if __name__ == "__main__":

    unittest.main()
