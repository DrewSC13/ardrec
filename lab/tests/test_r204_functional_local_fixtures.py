"""Offline verification tests; no protocol connections."""
import unittest

from ardrec.experiments import functional_local_fixtures as m
from ardrec.coordination import local_ssh_pilot as ssh


def sample(protocol):

    digest = ssh.digest(m.PAYLOAD[protocol])

    value = {
        "protocol": protocol,
        "host_namespace": "net:[100]",
        "child_namespace": "net:[200]",
        "interfaces": ["lo"],
        "endpoint": "127.0.0.1",
        "effective_uid": 1000,
        "effective_capabilities": "0000000000000000",
        "versions": m.VERSIONS[protocol],
        "authenticated": True,
        "operations_requested": 1,
        "authentication_requests_planned": 1,
        "arbitrary_commands_requested": 0,
        "write_operations_requested": 0,
        "bytes_received": len(m.PAYLOAD[protocol]),
        "expected_sha256": digest,
        "received_sha256": digest,
        "server_thread_stopped": True,
    }

    if protocol == "SSH":

        value.update({
            "backend": "PARAMIKO_USERSPACE",
            "server_identity_verified": True,
            "authentication_method": "PUBLIC_KEY",
            "operation": "FIXED_DIAGNOSTIC_SUBSYSTEM",
            "exit_status": 0,
        })

    else:

        value.update({
            "backend": "IMPACKET_USERSPACE",
            "guest_session": False,
            "dialect": "0x202",
            "operation": "AUTHORIZED_READ_ONLY_FILE",
            "final_source_sha256": digest,
            "source_unchanged": True,
            "share_read_only_configured": True,
        })

    return value


class FunctionalLocalTests(unittest.TestCase):

    def test_runner_syntax(self):

        compile(
            m.RUNNER,
            "fixture_runner.py",
            "exec",
        )

    def test_ssh_valid(self):

        self.assertTrue(
            m.verify_observation(
                "SSH", sample("SSH"), "net:[100]"
            )
        )

    def test_smb_valid(self):

        self.assertTrue(
            m.verify_observation(
                "SMB", sample("SMB"), "net:[100]"
            )
        )

    def test_isolation_rejected(self):

        for protocol in m.PROTOCOLS:

            for key, changed in (
                ("child_namespace", "net:[100]"),
                ("interfaces", ["lo", "eth0"]),
                ("effective_uid", 0),
                ("effective_capabilities", "1"),
                ("endpoint", "192.0.2.1"),
            ):

                document = sample(protocol)
                document[key] = changed

                with self.assertRaises(ValueError):

                    m.verify_observation(
                        protocol,
                        document,
                        "net:[100]",
                    )

    def test_integrity_rejected(self):

        for protocol in m.PROTOCOLS:

            document = sample(protocol)
            document["received_sha256"] = "0" * 64

            with self.assertRaises(ValueError):

                m.verify_observation(
                    protocol,
                    document,
                    "net:[100]",
                )

    def test_ssh_identity_rejected(self):

        document = sample("SSH")
        document["server_identity_verified"] = False

        with self.assertRaises(ValueError):

            m.verify_observation(
                "SSH",
                document,
                "net:[100]",
            )

    def test_smb_guest_rejected(self):

        document = sample("SMB")
        document["guest_session"] = True

        with self.assertRaises(ValueError):

            m.verify_observation(
                "SMB",
                document,
                "net:[100]",
            )

    def test_write_or_command_scope_rejected(self):

        for protocol in m.PROTOCOLS:

            for field in (
                "write_operations_requested",
                "arbitrary_commands_requested",
            ):

                document = sample(protocol)
                document[field] = 1

                with self.assertRaises(ValueError):

                    m.verify_observation(
                        protocol,
                        document,
                        "net:[100]",
                    )


if __name__ == "__main__":
    unittest.main()
