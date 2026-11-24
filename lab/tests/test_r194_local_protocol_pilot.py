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


if __name__ == "__main__":
    unittest.main()
