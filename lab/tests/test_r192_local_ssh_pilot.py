"""R192: bounded local transport regression tests."""
import os
import unittest
from unittest.mock import patch

from ardrec.coordination import local_ssh_pilot as m


class R192Tests(unittest.TestCase):

    def test_valid_banner(self):

        self.assertEqual(
            m.parse_banner(
                b"SSH-2.0-OpenSSH_TEST\r\n"
            ),
            "SSH-2.0-OpenSSH_TEST",
        )

    def test_invalid_protocol(self):

        for value in (
            b"FTP 220\r\n",
            b"SSH-1.0-TEST\r\n",
            b"SSH-2.0-TEST",
        ):

            with self.assertRaises(ValueError):
                m.parse_banner(value)

    def test_bounded_banner(self):

        with self.assertRaises(ValueError):

            m.parse_banner(
                b"SSH-2.0-" + b"A" * 300 + b"\r\n"
            )

    def test_local_pair(self):

        client, peer = m.local_pair()

        try:

            self.assertEqual(
                client.getpeername(),
                peer.getsockname(),
            )

            self.assertEqual(
                client.getsockname(),
                peer.getpeername(),
            )

            self.assertEqual(
                client.getpeername()[0],
                "127.0.0.1",
            )

        finally:

            client.close()
            peer.close()

    def test_explicit_consent_required(self):

        with patch.object(os, "geteuid", return_value=1000):

            with self.assertRaises(ValueError):
                m.run("INCORRECT")

    def test_root_rejected(self):

        with patch.object(os, "geteuid", return_value=0):

            with self.assertRaises(ValueError):
                m.run(m.CONFIRMATION)

    def test_configuration_restrictions(self):

        config = m.ssh_config(
            m.Path("/tmp/ardrec-test")
        )

        for required in (
            "PasswordAuthentication no",
            "PubkeyAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitRootLogin no",
            "AllowTcpForwarding no",
            "PermitTTY no",
            "MaxSessions 0",
        ):

            self.assertIn(required, config)


if __name__ == "__main__":
    unittest.main()
