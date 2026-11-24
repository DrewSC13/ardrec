"""R261 synthetic ingestion and authority boundary tests."""

import copy
import hashlib
import unittest

from pathlib import Path

from ardrec.coordination import (
    prospective_local_pilot as durable,
)

from ardrec.experiments import (
    local_consolidation,
    vm_functional_evidence as engine,
)


class VmFunctionalEvidenceTests(unittest.TestCase):

    def setUp(self):

        self.artifacts = {}
        self.originals = {}

        for protocol in engine.FAMILIES:

            raw = (
                "ARDREC:PILOT:" + protocol
                + ":CONTROL:REFERENCE\n"
            ).encode()

            sha = hashlib.sha256(raw).hexdigest()

            self.artifacts[protocol] = raw

            self.originals[protocol] = durable.seal({
                "schema": engine.SMOKE_SCHEMA,
                "scope": "PRIVATE_SYNTHETIC_CONTROL_READ",
                "protocol": protocol,
                "client_invocations": 1,
                "functional_read_verified": True,
                "runner_deny_restored": True,
                "target_deny_restored": True,
                "target_service_masked": True,
                "target_account_locked": True,
                "client_credential_removed": True,
                "fixture_sha256": sha,
                "observation": {
                    "bytes_read": len(raw),
                    "client_returncode": 0,
                    "read_sha256": sha,
                },
                "formal_pilot_admitted": False,
                "experimental_admitted": False,
                "a6": "ND",
                "confirmed_rf": None,
                "p8": "NO-GO",
            })

        self.source = durable.seal({
            "schema": engine.SOURCE_SCHEMA,
            "code_head": "a" * 40,
            "status": "PRIVATE_SERVICE_SMOKE_PASS",
            "transport": "QEMU_PRIVATE_UNIX_STREAM",
            "private_vms_started": 4,
            "connected_roles_verified": 4,
            "connected_interfaces_verified": 6,
            "connected_firewalls_verified": 4,
            "private_links_verified": 3,
            "functional_services_verified": 3,
            "positive_service_connectivity_verified": True,
            "protocol_service_attempts": 3,
            "restricted_resource_attempts": 0,
            "graceful_shutdowns_verified": 4,
            "original_baselines_preserved": 4,
            "host_firewall_writes": 0,
            "functional_smokes": list(
                self.originals.values()
            ),
            "formal_pilot_admitted": 0,
            "experimental_admitted": 0,
            "p7": "DRAFT_NOT_FROZEN",
            "p8": "NO-GO",
        })

        self.catalog = local_consolidation.load_families(
            Path("lab/operational-catalog-v1/catalog.json")
        )

    def build(self, **kwargs):

        fields = {
            "source": self.source,
            "expected_sha256": self.source["sha256"],
            "originals": self.originals,
            "artifacts": self.artifacts,
            "catalog": self.catalog,
        }

        fields.update(kwargs)

        return engine.build(**fields)

    def reseal(self, value):

        return durable.seal({
            key: item for key, item in value.items()
            if key != "sha256"
        })

    def test_01_complete_replay(self):

        report = self.build()

        self.assertEqual(
            report["functional_reads_verified"], 3
        )

        self.assertEqual(
            report["raw_bytes_verified"], 105
        )

        self.assertEqual(
            report["native_a8_replays"], 3
        )

        self.assertEqual(report, self.build())

    def test_02_raw_tampering(self):

        self.artifacts["ssh"] += b"x"

        with self.assertRaisesRegex(
            ValueError, "TRANSFER_CONTENT_INVALID"
        ):
            self.build()

    def test_03_invalid_source_pin(self):

        with self.assertRaisesRegex(
            ValueError, "SOURCE_PIN_MISMATCH"
        ):
            self.build(expected_sha256="0" * 64)

    def test_04_missing_artifact(self):

        del self.artifacts["ftp"]

        with self.assertRaisesRegex(
            ValueError, "ARTIFACT_SET_INVALID"
        ):
            self.build()

    def test_05_duplicate_protocol(self):

        source = copy.deepcopy(self.source)

        source["functional_smokes"][2] = (
            source["functional_smokes"][0]
        )

        source = self.reseal(source)

        with self.assertRaisesRegex(
            ValueError, "SMOKE_SET_INVALID"
        ):
            self.build(
                source=source,
                expected_sha256=source["sha256"],
            )

    def test_06_wrong_original(self):

        self.originals["ssh"] = self.originals["ftp"]

        with self.assertRaisesRegex(
            ValueError, "INDIVIDUAL_RECEIPT_MISMATCH"
        ):
            self.build()

    def test_07_scope_promotion_refused(self):

        source = copy.deepcopy(self.source)
        source["formal_pilot_admitted"] = 3
        source = self.reseal(source)

        with self.assertRaisesRegex(
            ValueError, "SOURCE_SCOPE_INVALID"
        ):
            self.build(
                source=source,
                expected_sha256=source["sha256"],
            )

    def test_08_nd_and_no_publication(self):

        report = self.build()

        self.assertEqual(
            report["operational_supports_accredited"], 0
        )

        self.assertEqual(
            report["operational_a9_publications"], 0
        )

        self.assertEqual(
            report["experimental_admitted"], 0
        )

        for row in report["rows"]:

            self.assertEqual(row["a6"], "ND")
            self.assertIsNone(row["confirmed_rf"])
            self.assertIsNone(row["reference_i4"])


if __name__ == "__main__":
    unittest.main()
