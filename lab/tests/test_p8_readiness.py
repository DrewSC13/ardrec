"""Independent synthetic adversarial tests for P8 R3; no subprocess/network/VM."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "verify_p8_readiness.py"
spec = importlib.util.spec_from_file_location("ardrec_p8_r3", SOURCE)
assert spec is not None and spec.loader is not None
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

FAMILY_NAMES = (
    [f"SSH-T{i:02d}" for i in range(1, 9)] +
    [f"FTP-T{i:02d}" for i in range(1, 9)] +
    [f"SMB-T{i:02d}" for i in range(1, 10)]
)
MUTATIONS = {"SSH-T07", "FTP-T07", "SMB-T08", "FTP-T08-WRITE", "SMB-T09-WRITE"}
# Independent written reference, intentionally not imported from production.
FIXED_SPLITS = {
    "FTP-T02": ("CONTROL", "DATA"),
    "FTP-T08": ("READ", "WRITE"),
    "SMB-T03": ("SIGNING", "ENCRYPTION"),
    "SMB-T09": ("READ", "WRITE"),
}
FIXED_COMMON_GUARDS = ["SCOPE_APPROVED", "LAB_ISOLATION_CONFIRMED",
                       "DESTINATION_AUTHORIZED", "CLIENT_COMPATIBLE"]


def fixture():
    families, profiles = [], []
    for family in FAMILY_NAMES:
        protocol = family.split("-")[0].lower()
        families.append({"id": family, "protocol": protocol,
                         "minimum_action_es": "Acción técnica delimitada y sintética"})
        options = FIXED_SPLITS.get(family, ("BASE",))
        for option in options:
            profile_id = f"{family}-{option}"
            supports = ["TARGET_ATTESTATION", "INTEGRITY_PROVENANCE", "TECHNICAL_SUPPORT"]
            clean = "VERIFY_THEN_REMOVE_MARKER" if family in MUTATIONS or profile_id in MUTATIONS else "NO_MUTATION"
            if clean != "NO_MUTATION":
                supports += ["MARKER_CREATED", "MARKER_VERIFIED", "CLEANUP_CONFIRMED"]
            profiles.append({
                "profile_id": profile_id, "family_id": family, "protocol": protocol,
                "variant": None if option == "BASE" else option,
                "precedence": 1,
                "required_material_parameter_slots": ["target_ref"],
                "required_preconditions": FIXED_COMMON_GUARDS + ["SERVICE_READY"],
                "required_supports": supports,
                "required_acceptance_supports": ["TECHNICAL_SUPPORT"],
                "cleanup": clean,
                "status": V.NO_DISPATCH,
                "binding": {name: None for name in V.ALL_BINDINGS},
            })
    p7 = {"thesis_sha256": V.THESIS_SHA256, "execution_enabled": False, "families": families}
    p8 = {"thesis_sha256": V.THESIS_SHA256, "execution_enabled": False,
          "profile_frozen": False, "physical_isolation_verified": False,
          "pilot_limits_frozen": False, "cases_authorized": 0, "real_cases": 0,
          "profiles": profiles}
    stages = {name: {"stage": name, **{key: [] for key in (
        "services", "scenarios", "cases", "executions", "attempts", "artifacts", "units")}}
        for name in V.REQUIRED_STAGES}
    return p7, p8, stages


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.p7, self.p8, self.stages = fixture()

    def ok(self):
        return V.check_inventory(self.p7, self.p8, self.stages)

    def reject(self, msg):
        with self.assertRaisesRegex(V.ContractError, msg):
            self.ok()

    def test_independent_inventory_oracle(self):
        report = self.ok()
        self.assertEqual((report["counts"]["families"], report["counts"]["profiles"]), (25, 29))
        self.assertEqual(report["counts"]["by_protocol"], {"ssh": 8, "ftp": 10, "smb": 11})
        self.assertEqual(report["counts"]["authorized_profiles"], 0)
        self.assertEqual(len({r["profile_id"] for r in report["profiles"]}), 29)
        self.assertTrue(all(p["dispatch"] == "DENIED" for p in report["profiles"]))

    def test_receipt_is_post_execution_not_approval(self):
        data = self.ok()
        self.assertEqual(data["post_execution_receipt_fields"], ["cleanup_receipt_ref"])
        self.assertNotIn("cleanup_receipt_ref", data["pre_execution_binding_fields"])
        self.assertFalse(data["gate"]["dispatch_allowed"])

    def test_markdown_has_29_rows_and_no_dispatch(self):
        md = V.format_markdown(self.ok())
        self.assertEqual(md.count(" | BLOQUEADO |"), 29)
        self.assertIn("SMB-T03-ENCRYPTION", md)
        self.assertIn("FTP-T02-CONTROL", md)

    def test_execution_flag_denied(self):
        self.p8["execution_enabled"] = True
        self.reject("execution flag")

    def test_p7_execution_flag_denied(self):
        self.p7["execution_enabled"] = True
        self.reject("execution flag")

    def test_false_case_count_denied(self):
        self.p8["cases_authorized"] = 1
        self.reject("unauthorized case count")

    def test_bool_count_denied(self):
        self.p8["cases_authorized"] = False
        self.reject("unauthorized case count")

    def test_frozen_profile_denied(self):
        self.p8["profile_frozen"] = True
        self.reject("readiness promotion")

    def test_real_scenario_must_not_be_laundered_into_zero_baseline(self):
        self.stages["dev"]["scenarios"].append({"id": "dev-001"})
        self.reject("material inventory changed")

    def test_experiment_unit_must_not_be_fabricated(self):
        self.stages["exp"]["units"].append({"id": "exp-001"})
        self.reject("material inventory changed")

    def test_stage_spoofing_denied(self):
        self.stages["pilot"]["stage"] = "dev"
        self.reject("stage identity mismatch")

    def test_profile_count_denied(self):
        self.p8["profiles"].pop()
        self.reject("P8 slots")

    def test_duplicate_profile_denied(self):
        self.p8["profiles"][1] = copy.deepcopy(self.p8["profiles"][0])
        self.reject("duplicate/missing P8 profile id")

    def test_wrong_protocol_denied(self):
        self.p8["profiles"][0]["protocol"] = "ftp"
        self.reject("foreign family or protocol")

    def test_wrong_variant_denied(self):
        target = next(p for p in self.p8["profiles"] if p["profile_id"] == "FTP-T02-DATA")
        target["variant"] = "CONTROL"
        self.reject("inconsistent variant identity")

    def test_missing_common_guard_denied(self):
        self.p8["profiles"][0]["required_preconditions"].remove("SCOPE_APPROVED")
        self.reject("missing common guards")

    def test_acceptance_without_support_denied(self):
        self.p8["profiles"][0]["required_acceptance_supports"].append("INVENTED")
        self.reject("acceptance supports")

    def test_write_without_cleanup_denied(self):
        target = next(p for p in self.p8["profiles"] if p["profile_id"] == "SMB-T09-WRITE")
        target["cleanup"] = "NO_MUTATION"
        self.reject("mutation must require cleanup")

    def test_write_without_cleanup_support_denied(self):
        target = next(p for p in self.p8["profiles"] if p["profile_id"] == "FTP-T08-WRITE")
        target["required_supports"].remove("CLEANUP_CONFIRMED")
        self.reject("mutation must require cleanup")

    def test_early_binary_binding_denied(self):
        self.p8["profiles"][0]["binding"]["executable_sha256"] = "a" * 64
        self.reject("attempted binding promotion")

    def test_early_cleanup_receipt_denied(self):
        self.p8["profiles"][0]["binding"]["cleanup_receipt_ref"] = "ref:fake"
        self.reject("attempted binding promotion")

    def test_extra_binding_key_denied(self):
        self.p8["profiles"][0]["binding"]["password"] = "opaque"
        self.reject("changed/missing keys")

    def test_removed_split_denied(self):
        x = next(p for p in self.p8["profiles"] if p["profile_id"] == "SMB-T03-ENCRYPTION")
        x["family_id"] = "SMB-T02"
        self.reject("inconsistent variant identity")

    def test_thesis_sha_mismatch_denied(self):
        self.p7["thesis_sha256"] = "0" * 64
        self.reject("thesis version mismatch")

    def test_duplicate_json_keys_denied(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "test.json").write_text('{"a":1,"a":2}')
            with self.assertRaisesRegex(V.ContractError, "duplicate JSON key"):
                V.load_strict(root, "test.json")

    def test_path_traversal_denied(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(V.ContractError, "path traversal"):
                V.load_strict(Path(t), "../other")

    def test_symlink_denied(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "real.json").write_text('{}')
            (root / "link.json").symlink_to(root / "real.json")
            with self.assertRaisesRegex(V.ContractError, "symlink"):
                V.load_strict(root, "link.json")


if __name__ == "__main__":
    unittest.main()
