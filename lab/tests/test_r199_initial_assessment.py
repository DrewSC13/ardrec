"""R199: exact ordinal arithmetic and preparation boundaries."""

import itertools
import tempfile
import unittest

from fractions import Fraction
from pathlib import Path

from ardrec.experiments import initial_assessment as m
from ardrec.coordination import local_ssh_pilot as ssh


class InitialAssessmentTests(unittest.TestCase):

    def test_static_domain_exhaustive(self):

        count = 0

        for x, p, i in itertools.product(
            range(1, 6), repeat=3
        ):

            result = m.compute(
                x, p, i, (1, 1, 1)
            )

            expected = (
                Fraction(x - 1, 4)
                + Fraction(p - 1, 4)
                + Fraction(i - 1, 4)
            ) / 3

            self.assertEqual(
                Fraction(result["initial_risk"]),
                expected,
            )

            count += 1

        self.assertEqual(count, 125)

    def test_criticality_domain_exhaustive(self):

        count = 0

        for values in itertools.product(
            range(1, 6), repeat=3
        ):

            a, b, c = sorted(values)

            result = m.compute(
                3, 3, 3, values
            )

            criticality = max(b, c - 1)

            self.assertEqual(
                result["criticality_ordinal"],
                criticality,
            )

            self.assertEqual(
                Fraction(
                    result["normalized_criticality"]
                ),
                Fraction(criticality - 1, 4),
            )

            self.assertLessEqual(b, criticality)
            self.assertLessEqual(criticality, c)

            count += 1

        self.assertEqual(count, 125)

    def test_extremes(self):

        for ordinal, expected in (
            (1, "0"),
            (5, "1"),
        ):

            result = m.compute(
                ordinal,
                ordinal,
                ordinal,
                (ordinal,) * 3,
            )

            self.assertEqual(
                result["initial_risk"],
                expected,
            )

            self.assertEqual(
                result["normalized_criticality"],
                expected,
            )

        self.assertEqual(
            m.compute(
                3, 3, 3, (1, 1, 5)
            )["criticality_ordinal"],
            4,
        )

    def test_invalid_ordinals(self):

        for invalid in (
            0, 6, -1, True, 1.5, "3", None
        ):

            with self.assertRaises(ValueError):

                m.compute(
                    invalid, 3, 3, (1, 1, 1)
                )

            with self.assertRaises(ValueError):

                m.compute(
                    3, 3, 3, (1, invalid, 1)
                )

    def test_materialization_and_tamper(self):

        with tempfile.TemporaryDirectory() as tmp:

            root = Path(tmp)

            for protocol in m.PROTOCOLS:

                folder = root / protocol

                result = m.materialize_case(
                    folder,
                    protocol,
                    "a" * 40,
                    {"implementation": "TEST_ONLY"},
                )

                self.assertFalse(
                    result["deployment_performed"]
                )

                self.assertFalse(
                    result["baseline_closed"]
                )

                self.assertEqual(
                    result,
                    m.verify_case(folder),
                )

                with self.assertRaises(
                    FileExistsError
                ):

                    m.materialize_case(
                        folder,
                        protocol,
                        "a" * 40,
                        {"implementation": "TEST_ONLY"},
                    )

                path = (
                    folder / m.CONFIG_NAMES[protocol]
                )

                path.write_bytes(b"ALTERED")

                with self.assertRaises(ValueError):

                    m.verify_case(folder)

    def test_candidate_assessment(self):

        config = m.config_bytes("FTP")
        inventory = {"implementation": "TEST_ONLY"}

        manifest = m.make_manifest(
            "FTP",
            "a" * 40,
            config,
            inventory,
        )

        raw = b"SYNTHETIC SOFTWARE TEST SUPPORT"
        digest = ssh.digest(raw)

        ratings = {
            name: {
                "ordinal": 1
                    if name == "exposure"
                    else 3,
                "support_sha256": digest,
                "justification":
                    "Synthetic software test only.",
            }
            for name in m.DIMENSIONS
        }

        result = m.draft_assessment(
            manifest,
            config,
            inventory,
            ratings,
            {digest: raw},
        )

        self.assertEqual(
            result["calculated"]["initial_risk"],
            "1/3",
        )

        self.assertEqual(
            result["calculated"][
                "normalized_criticality"
            ],
            "1/2",
        )

        self.assertFalse(
            result["baseline_closed"]
        )

        self.assertFalse(
            result["experimental_admission"]
        )

        with self.assertRaises(ValueError):

            m.draft_assessment(
                manifest,
                config,
                inventory,
                ratings,
                {digest: b"ALTERED"},
            )

        ratings["exposure"]["ordinal"] = 5

        with self.assertRaises(ValueError):

            m.draft_assessment(
                manifest,
                config,
                inventory,
                ratings,
                {digest: raw},
            )

    def test_authority_promotion_rejected(self):

        config = m.config_bytes("SSH")
        inventory = {"implementation": "TEST_ONLY"}

        manifest = m.make_manifest(
            "SSH",
            "a" * 40,
            config,
            inventory,
        )

        manifest.pop("sha256")
        manifest["execution_authorized"] = True

        manifest = m.durable.seal(manifest)

        with self.assertRaises(ValueError):

            m.verify_manifest(
                manifest,
                config,
                inventory,
            )


if __name__ == "__main__":
    unittest.main()
