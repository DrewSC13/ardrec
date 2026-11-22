"""R130/B17-R6A negative tests; never touch privileged destinations."""
import copy
from pathlib import Path
import unittest

from ardrec.coordination import r130_b17_r6_install_contract as m

REPO = Path(__file__).resolve().parents[2]

class R130InstallContract(unittest.TestCase):
    def setUp(self):
        self.entries = {
            "root-controller.py.source-only":
                (REPO / "scripts/ardrec_p14_r126_root_session_guard.py").read_bytes(),
            "root-executor.py.source-only":
                (REPO / "scripts/ardrec_p14_r128_root_v2_executor.py").read_bytes(),
            "manifest-b4.draft.json": m.canon(m.EXPECTED_B4),
            "manifest-b9.draft.json": m.canon(m.EXPECTED_B9),
            "source-provenance.json": m.canon(m.EXPECTED_PROVENANCE),
        }

    def denied(self, code):
        with self.assertRaisesRegex(m.Stop, code):
            m.review_entries(self.entries)

    def test_01_positive_source_only(self):
        report = m.review_entries(self.entries)
        self.assertFalse(report["root_install_authorized"])
        self.assertFalse(report["root_install_executed"])
        self.assertEqual(report["p8"], "NO-GO")

    def test_02_missing_entry(self):
        self.entries.pop("manifest-b4.draft.json")
        self.denied("SOURCE_ENTRY_SCOPE")

    def test_03_unexpected_entry(self):
        self.entries["unexpected"] = b"bad"
        self.denied("SOURCE_ENTRY_SCOPE")

    def test_04_b4_tamper(self):
        self.entries["root-controller.py.source-only"] += b"\n# drift"
        self.denied("SOURCE_B4_SHA_MISMATCH")

    def test_05_b9_tamper(self):
        self.entries["root-executor.py.source-only"] += b"\n# drift"
        self.denied("SOURCE_B9_SHA_MISMATCH")

    def test_06_b4_fake_approval(self):
        data = copy.deepcopy(m.EXPECTED_B4)
        data["root_install_independent"] = True
        self.entries["manifest-b4.draft.json"] = m.canon(data)
        self.denied("B4_DRAFT_CONTRACT_CHANGED")

    def test_07_b9_fake_approval(self):
        data = copy.deepcopy(m.EXPECTED_B9)
        data["root_staged_independently"] = True
        self.entries["manifest-b9.draft.json"] = m.canon(data)
        self.denied("B9_DRAFT_CONTRACT_CHANGED")

    def test_08_forged_install_authorization(self):
        data = copy.deepcopy(m.EXPECTED_PROVENANCE)
        data["install_authorized"] = True
        self.entries["source-provenance.json"] = m.canon(data)
        self.denied("SOURCE_PROVENANCE_CHANGED")

    def test_09_wrong_commit(self):
        data = copy.deepcopy(m.EXPECTED_PROVENANCE)
        data["source_commit"] = "0" * 40
        self.entries["source-provenance.json"] = m.canon(data)
        self.denied("SOURCE_PROVENANCE_CHANGED")

    def test_10_fake_physical_evidence(self):
        data = copy.deepcopy(m.EXPECTED_PROVENANCE)
        data["physical_pilot_performed"] = True
        self.entries["source-provenance.json"] = m.canon(data)
        self.denied("SOURCE_PROVENANCE_CHANGED")

    def test_11_noncanonical_json(self):
        self.entries["manifest-b4.draft.json"] = b'{"schema":"fake"}'
        self.denied("DOCUMENT_NONCANONICAL")

    def test_12_duplicate_json_key(self):
        self.entries["manifest-b4.draft.json"] = b'{"a":1,"a":2}\n'
        self.denied("DUPLICATE_JSON_KEY")

    def test_13_invalid_entry_type(self):
        self.entries["root-controller.py.source-only"] = "not bytes"
        self.denied("SOURCE_ENTRY_BYTES")

    def test_14_invalid_archive_digest(self):
        with self.assertRaisesRegex(m.Stop, "ARCHIVE_SHA256_MISMATCH"):
            m.review_archive(b"not the approved archive")

    def test_15_capabilities_fail_closed(self):
        c = m.capabilities()
        self.assertFalse(c["can_install_root"])
        self.assertFalse(c["can_enable_traffic"])
        self.assertFalse(c["can_sign_authority"])
        self.assertEqual(c["p8"], "NO-GO")


    def test_16_private_path_valid(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="ardrec-r130-") as folder:
            path = Path(folder) / "review.zip"
            path.write_bytes(b"controlled-private-source")
            path.chmod(0o600)
            self.assertEqual(
                m.read_private(path),
                b"controlled-private-source",
            )

    def test_17_symlink_denied(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="ardrec-r130-") as folder:
            path = Path(folder) / "review.zip"
            path.write_bytes(b"fixture")
            path.chmod(0o600)
            link = Path(folder) / "link.zip"
            link.symlink_to(path)
            with self.assertRaisesRegex(
                m.Stop, "ARCHIVE_PATH_UNSAFE"
            ):
                m.read_private(link)

    def test_18_insecure_file_mode_denied(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="ardrec-r130-") as folder:
            path = Path(folder) / "review.zip"
            path.write_bytes(b"fixture")
            path.chmod(0o644)
            with self.assertRaisesRegex(
                m.Stop, "PRIVATE_ARCHIVE_REQUIRED"
            ):
                m.read_private(path)

    def test_19_hardlink_denied(self):
        import os
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="ardrec-r130-") as folder:
            path = Path(folder) / "review.zip"
            path.write_bytes(b"fixture")
            path.chmod(0o600)
            alias = Path(folder) / "second-link.zip"
            os.link(path, alias)
            with self.assertRaisesRegex(
                m.Stop, "PRIVATE_ARCHIVE_REQUIRED"
            ):
                m.read_private(path)

    def test_20_insecure_parent_denied(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="ardrec-r130-") as folder:
            parent = Path(folder)
            path = parent / "review.zip"
            path.write_bytes(b"fixture")
            path.chmod(0o600)
            parent.chmod(0o755)
            with self.assertRaisesRegex(
                m.Stop, "PRIVATE_PARENT_REQUIRED"
            ):
                m.read_private(path)

if __name__ == "__main__":
    unittest.main()
