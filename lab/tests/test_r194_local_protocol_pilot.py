"""R194 transport parser and boundary regressions."""

import struct
import unittest

from unittest.mock import patch

from ardrec.coordination import local_protocol_pilot as m


def smb_fixture():

    data = bytearray(128)

    data[:4] = b"\xfeSMB"

    struct.pack_into(
        "<H", data, 4, 64
    )

    struct.pack_into(
        "<I", data, 16, 1
    )

    struct.pack_into(
        "<HHH",
        data,
        64,
        65,
        1,
        0x0210,
    )

    return (
        len(data).to_bytes(4, "big")
        + data
    )


class LocalProtocolTests(unittest.TestCase):

    def test_ftp_single_line(self):

        result = m.parse_ftp(
            b"220 FTP ready\r\n"
        )

        self.assertEqual(
            result["reply_code"], 220
        )

    def test_ftp_multiline(self):

        result = m.parse_ftp(
            b"220-Welcome\r\n"
            b"220 Ready\r\n"
        )

        self.assertEqual(
            len(result["lines"]), 2
        )

    def test_ftp_invalid(self):

        for raw in (
            b"530 Denied\r\n",
            b"220 Ready",
            b"220-Welcome\r\n",
            b"220 " + b"A" * 5000 + b"\r\n",
        ):

            with self.assertRaises(ValueError):
                m.parse_ftp(raw)

    def test_smb_request(self):

        raw = m.smb_request()

        self.assertEqual(
            len(raw), 108
        )

        self.assertEqual(
            int.from_bytes(
                raw[:4], "big"
            ),
            104,
        )

        self.assertEqual(
            raw[4:8], b"\xfeSMB"
        )

        self.assertEqual(
            struct.unpack_from(
                "<H", raw, 16
            )[0],
            0,
        )

    def test_smb_response(self):

        result = m.parse_smb(
            smb_fixture()
        )

        self.assertEqual(
            result["dialect"],
            "0x0210",
        )

    def test_smb_invalid(self):

        with self.assertRaises(ValueError):

            m.parse_smb(
                smb_fixture()[:-1]
            )

        raw = bytearray(smb_fixture())

        struct.pack_into(
            "<H",
            raw,
            16,
            1,
        )

        with self.assertRaises(ValueError):

            m.parse_smb(bytes(raw))

    def test_consent_and_root(self):

        with self.assertRaises(ValueError):

            m.run("INCORRECT")

        with patch.object(
            m.os,
            "geteuid",
            return_value=0,
        ):

            with self.assertRaises(ValueError):

                m.run(m.CONFIRM)

    def test_configuration_restrictions(self):

        for entry in (
            "listen=NO",
            "anonymous_enable=NO",
            "local_enable=NO",
            "write_enable=NO",
            "port_enable=NO",
            "pasv_enable=NO",
        ):

            self.assertIn(
                entry,
                m.ftp_config(),
            )

        for entry in (
            "interfaces = 127.0.0.1",
            "bind interfaces only = yes",
            "disable netbios = yes",
            "map to guest = Never",
            "usershare max shares = 0",
        ):

            self.assertIn(
                entry,
                m.smb_config(),
            )



class R194CorrectionTests(unittest.TestCase):

    def test_minimal_sandbox_mounts(self):

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:

            with patch.object(
                m.ssh,
                "trusted_binary",
                return_value={"sha256": "DEV"},
            ), patch.object(
                m.os,
                "getuid",
                return_value=1000,
            ), patch.object(
                m.os,
                "getgid",
                return_value=1000,
            ):

                _, args = m.sandbox(
                    Path(tmp),
                    ["/usr/bin/true"],
                )

            mounts = [
                args[index:index + 3]
                for index, value in enumerate(args)
                if value == "--ro-bind"
            ]

            self.assertNotIn(
                ["--ro-bind", "/", "/"],
                mounts,
            )

            self.assertIn(
                ["--ro-bind", "/usr", "/usr"],
                mounts,
            )

            self.assertIn("--unshare-all", args)
            self.assertIn("--clearenv", args)
            self.assertNotIn("--share-net", args)

            self.assertTrue(
                (
                    Path(tmp)
                    / "sandbox-etc/passwd"
                ).is_file()
            )

    def test_unpinned_source_rejected(self):

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:

            folder = Path(tmp)
            archive = folder / "invalid.tar.gz"

            archive.write_bytes(
                b"not the pinned source"
            )

            with self.assertRaisesRegex(
                ValueError,
                "FTP_SOURCE_SHA256_INVALID",
            ):

                m.prepare_ftp_source(
                    archive,
                    folder,
                )

            self.assertFalse(
                (folder / "vendor").exists()
            )

    def test_ftp_runner_no_accounts(self):

        self.assertIn(
            "DummyAuthorizer()",
            m.FTP_RUNNER,
        )

        self.assertIn(
            "FTPHandler.proto_cmds = {}",
            m.FTP_RUNNER,
        )

        self.assertNotIn(
            "add_user(",
            m.FTP_RUNNER,
        )

        self.assertNotIn(
            "add_anonymous(",
            m.FTP_RUNNER,
        )

        self.assertEqual(
            len(m.FTP_SOURCE_SHA256),
            64,
        )



class R194CompatibilityTests(unittest.TestCase):

    def test_compatibility_wheels_are_pinned(self):

        self.assertEqual(
            len(m.FTP_COMPAT_WHEELS),
            2,
        )

        self.assertEqual(
            {
                entry[2]
                for entry in m.FTP_COMPAT_WHEELS
            },
            {"asyncore", "asynchat"},
        )

        for filename, digest, name in m.FTP_COMPAT_WHEELS:

            self.assertTrue(
                filename.endswith(
                    "-1.0.5-py3-none-any.whl"
                )
            )

            self.assertRegex(
                digest,
                r"^[0-9a-f]{64}$",
            )

    def test_missing_compatibility_dependency_rejected(self):

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:

            folder = Path(tmp)

            vendor = folder / "vendor"
            vendor.mkdir()

            with self.assertRaisesRegex(
                ValueError,
                "FTP_COMPAT_WHEEL_MISSING",
            ):

                m.prepare_ftp_compatibility(
                    folder,
                    vendor,
                )

            self.assertEqual(
                list(vendor.iterdir()),
                [],
            )

    def test_altered_compatibility_dependency_rejected(self):

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:

            folder = Path(tmp)

            vendor = folder / "vendor"
            vendor.mkdir()

            filename = m.FTP_COMPAT_WHEELS[0][0]

            (folder / filename).write_bytes(
                b"invalid synthetic wheel"
            )

            with self.assertRaisesRegex(
                ValueError,
                "FTP_COMPAT_WHEEL_SHA256_INVALID",
            ):

                m.prepare_ftp_compatibility(
                    folder,
                    vendor,
                )

            self.assertEqual(
                list(vendor.iterdir()),
                [],
            )

    def test_compatibility_import_origin_is_checked(self):

        self.assertIn(
            "import asyncore",
            m.FTP_RUNNER,
        )

        self.assertIn(
            "import asynchat",
            m.FTP_RUNNER,
        )

        self.assertIn(
            "FTP_COMPAT_IMPORT_ORIGIN_INVALID",
            m.FTP_RUNNER,
        )

        self.assertIn(
            "FTP_COMPAT_IMPORTS=PASS",
            m.FTP_RUNNER,
        )


if __name__ == "__main__":
    unittest.main()
