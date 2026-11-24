"""R211: exact trajectory regression and private replay."""
import tempfile
import unittest

from pathlib import Path

from ardrec.experiments import risk_trajectory as m
from ardrec.coordination import prospective_local_pilot as durable


class TrajectoryTests(unittest.TestCase):

    def test_three_protocols(self):

        expected = [
            ("5/12", "5/12"),
            ("5/9", "5/9"),
            ("5/9", "5/9"),
            ("1/2", "1/2"),
            ("1/2", "7/12"),
        ]

        for protocol in m.PROTOCOLS:

            report = m.demo(protocol)

            self.assertEqual(
                [
                    (w["rf_lower"], w["rf_upper"])
                    for w in report["windows"]
                ],
                expected,
            )

            self.assertTrue(m.verify(report))
            self.assertIsNone(report["confirmed_rf"])
            self.assertFalse(
                report["operational_a9_published"]
            )

    def test_negative_only(self):

        report = m.build("FTP", [{
            "kind": "NEGATIVE_MODEL",
            "value": "1/6",
        }])

        self.assertEqual(
            report["windows"][-1]["rf_lower"],
            "13/36",
        )

    def test_unknown_persists(self):

        report = m.build("SSH", [
            {"kind": "ND_MODEL", "value": None},
            {"kind": "POSITIVE_MODEL", "value": "1/4"},
        ])

        last = report["windows"][-1]

        self.assertEqual(last["evidence_lower"], "1/4")
        self.assertEqual(last["evidence_upper"], "1")
        self.assertEqual(last["evidence_count"], 2)

    def test_invalid_events(self):

        cases = [
            {"kind": "ND_MODEL", "value": "0"},
            {"kind": "POSITIVE_MODEL", "value": "0"},
            {"kind": "NEGATIVE_MODEL", "value": "1"},
            {"kind": "REAL_EVIDENCE", "value": "1"},
            {
                "kind": "POSITIVE_MODEL",
                "value": "1",
                "technical_truth_accredited": True,
            },
        ]

        for event in cases:

            with self.subTest(event=event):

                with self.assertRaises(ValueError):

                    m.build("SMB", [event])

    def test_resealed_tampering_rejected(self):

        report = m.demo("FTP")

        report.pop("sha256")
        report["confirmed_rf"] = "1/2"

        report = durable.seal(report)

        with self.assertRaises(ValueError):

            m.verify(report)

    def test_durable_replay(self):

        with tempfile.TemporaryDirectory() as folder:

            path = Path(folder) / "trajectory.json"

            report = m.demo("SMB")

            durable.write_once(path, report)

            self.assertTrue(
                m.verify(durable.load(path))
            )

            with self.assertRaises(FileExistsError):

                durable.write_once(path, report)


if __name__ == "__main__":
    unittest.main()
