"""R187: pruebas matematicas, no observaciones experimentales."""
import copy
import unittest
from fractions import Fraction as F

from ardrec.experiments import parameter_sensitivity as m


class R187Tests(unittest.TestCase):

    def test_configurations(self):

        configs = list(m.configurations())

        self.assertEqual(len(configs), 17)
        self.assertEqual(len({k for k, _ in configs}), 17)

        for name, config in configs:

            changed = sum(
                config[key] != m.BASE[key]
                for key in m.BASE
            )

            self.assertEqual(
                changed, 0 if name == "BASE" else 1
            )

            for key, values in config.items():
                self.assertEqual(sum(map(F, values)), 1)
                self.assertTrue(all(F(v) > 0 for v in values))

    def test_contribution(self):

        self.assertEqual(
            m.contribution(
                (3, 1, 4, 2),
                m.BASE["beta_ap"],
                m.BASE["beta_qf"],
            ),
            F(3, 8),
        )

    def test_baseline_exact(self):

        row = m.evaluate(
            m.mathematical_profiles()[0],
            m.BASE,
        )

        self.assertEqual(row["hypothetical_evidence"], "3/8")
        self.assertEqual(row["hypothetical_priority"], "3/8")
        self.assertEqual(row["hypothetical_rf"], "3/8")
        self.assertIsNone(row["confirmed_rf"])

    def test_beta_negative_zero(self):

        self.assertEqual(
            m.contribution(
                (0, 0, 3, 4),
                m.BASE["beta_ap"],
                m.BASE["beta_qf"],
            ),
            F(0),
        )

    def test_invalid_weights(self):

        with self.assertRaises(ValueError):
            m.weights(("0", "1"), 2)

        with self.assertRaises(ValueError):
            m.weights(("1/2", "1/3"), 2)

    def test_invalid_dimensions(self):

        for item in ((5, 1, 1, 1), (1, 1, 0, 1)):
            with self.assertRaises(ValueError):
                m.contribution(
                    item,
                    m.BASE["beta_ap"],
                    m.BASE["beta_qf"],
                )

    def test_lambda_only_priority(self):

        source = m.mathematical_profiles()[0]
        base = m.evaluate(source, m.BASE)

        changed = m.evaluate(source, {
            **m.BASE,
            "lambda": ("1/2", "1/4", "1/4"),
        })

        self.assertNotEqual(
            base["hypothetical_priority"],
            changed["hypothetical_priority"],
        )

        self.assertEqual(
            base["hypothetical_rf"],
            changed["hypothetical_rf"],
        )

    def test_w_only_risk(self):

        source = m.mathematical_profiles()[0]
        base = m.evaluate(source, m.BASE)

        changed = m.evaluate(source, {
            **m.BASE,
            "w": ("1/2", "1/4", "1/4"),
        })

        self.assertEqual(
            base["hypothetical_priority"],
            changed["hypothetical_priority"],
        )

        self.assertNotEqual(
            base["hypothetical_rf"],
            changed["hypothetical_rf"],
        )

    def test_all_bounds(self):

        doc = m.build()

        self.assertEqual(doc["configuration_count"], 17)
        self.assertEqual(doc["evaluation_count"], 51)

        for config in doc["configurations"]:
            for row in config["rows"]:

                self.assertTrue(
                    F(row["replacement"])
                    <= F(row["hypothetical_rf"]) <= 1
                )

                self.assertTrue(
                    0 <= F(row["hypothetical_priority"]) <= 1
                )

                self.assertIsNone(row["confirmed_rf"])

    def test_secondary_proposals(self):

        doc = m.build()

        for row in doc["secondary_comparators"]:

            self.assertEqual(
                row["static_r0"],
                row["without_both_evidence_components"],
            )

        self.assertFalse(doc["secondary_protocol_frozen"])

    def test_reproducibility_and_authority(self):

        doc = m.build()

        self.assertTrue(m.verify(doc))

        self.assertFalse(doc["reference_values_used"])
        self.assertFalse(doc["operational_dispatch"])
        self.assertEqual(doc["experimental_units_admitted"], 0)
        self.assertEqual(doc["p8"], "NO-GO")

        modified = copy.deepcopy(doc)
        modified["experimental_units_admitted"] = 54

        with self.assertRaises(ValueError):
            m.verify(modified)


if __name__ == "__main__":
    unittest.main()
