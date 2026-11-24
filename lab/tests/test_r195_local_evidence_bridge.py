"""R195: conservative local evidence bridge tests."""

import tempfile
import unittest

from pathlib import Path

from ardrec.coordination import local_evidence_bridge as m


CATALOG = Path(
    "lab/operational-catalog-v1/catalog.json"
)


class R195Tests(unittest.TestCase):

    def test_catalog_exact_families(self):

        selected = m.load_catalog(
            CATALOG.read_bytes()
        )

        self.assertEqual(
            [selected[p]["id"] for p in m.PROTOCOLS],
            ["SSH-T01", "FTP-T01", "SMB-T01"],
        )

    def test_modified_catalog_rejected(self):

        with self.assertRaisesRegex(
            ValueError,
            "CATALOG_PIN_INVALID",
        ):

            m.load_catalog(
                CATALOG.read_bytes() + b"\n"
            )

    def test_receipt_digest(self):

        receipt = {
            "status": "SYNTHETIC_TEST_ONLY",
        }

        receipt["sha256"] = m.digest(receipt)

        self.assertTrue(
            m.verify_digest(receipt)
        )

        receipt["status"] = "ALTERED"

        with self.assertRaises(ValueError):

            m.verify_digest(receipt)

    def test_missing_receipt_digest(self):

        with self.assertRaises(ValueError):

            m.verify_digest({})

    def test_reference_nd_all_protocols(self):

        for protocol in m.PROTOCOLS:

            result = m.reference_preview(
                protocol,
                "a" * 64,
            )["result"]

            self.assertEqual(
                result["classification"], "ND"
            )

            self.assertIsNone(
                result["candidate_reference_score"]
            )

            self.assertFalse(
                result["experimental_admission"]
            )

    def test_reference_reproducible(self):

        one = m.reference_preview(
            "SSH", "a" * 64
        )

        two = m.reference_preview(
            "SSH", "a" * 64
        )

        self.assertEqual(one, two)

    def test_stop_real_kernel(self):

        result = m.preview_stop(
            a6_classification=m.Truth.ND.value,
            accredited=False,
            vm_checked=False,
            operational_dispatch=False,
            source_sha256="a" * 64,
        )

        self.assertTrue(
            m.verify_stop(result)
        )

        self.assertEqual(
            result["recommendation"],
            "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA",
        )

        self.assertIsNone(
            result["applied_transition"]
        )

    def test_promoted_receipt_rejected(self):

        record = {
            "status": "LOCAL_SSH_IDENTIFICATION_OBSERVED",
            "authentication_attempts": 0,
            "historical_vm_access": False,
            "process_cleanup_verified": True,
            "a6": "VERDADERO",
            "confirmed_rf": "1/2",
        }

        record["sha256"] = m.digest(record)

        with self.assertRaisesRegex(
            ValueError,
            "TRANSPORT_AUTHORITY_OR_STATUS_INVALID",
        ):

            m.verify_transport("SSH", record)


if __name__ == "__main__":
    unittest.main()
