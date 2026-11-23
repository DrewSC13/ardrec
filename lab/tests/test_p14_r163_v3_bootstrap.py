"""R163-F7: offline bootstrap checks, no root operations."""

from __future__ import annotations

import io
from pathlib import Path
import unittest
import warnings
import zipfile

import ardrec_p14_r163_v3_bootstrap as bootstrap
import ardrec_p14_r163_v3_root_stage_agent as agent

ROOT = Path(__file__).resolve().parents[2]

SOURCE = {
    "installer.py":
        "scripts/ardrec_p14_r163_v3_root_stage_agent.py",

    "runtime/r146_independent_install.py":
        "src/ardrec/coordination/r146_independent_install.py",

    "runtime/r163_single_operator_install_policy.py":
        "src/ardrec/coordination/r163_single_operator_install_policy.py",

    "runtime/r163_install_phase_gate.py":
        "src/ardrec/coordination/r163_install_phase_gate.py",

    "runtime/r163_single_operator_stage.py":
        "src/ardrec/coordination/r163_single_operator_stage.py",

    "source/B4/source.py":
        "scripts/ardrec_p14_r130_b4_root_guard_v2.py",

    "source/B9/source.py":
        "scripts/ardrec_p14_r130_b9_ftp_executor_v2.py",
}


def make_zip(files, duplicate=None, symbolic=None):
    output = io.BytesIO()

    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:

        for name, raw in sorted(files.items()):
            member = zipfile.ZipInfo(
                name,
                (2020, 1, 1, 0, 0, 0),
            )

            member.compress_type = zipfile.ZIP_DEFLATED

            member.external_attr = (
                (
                    0o120777
                    if name == symbolic
                    else 0o100644
                ) << 16
            )

            archive.writestr(
                member,
                raw,
            )

        if duplicate is not None:
            member = zipfile.ZipInfo(
                duplicate,
                (2020, 1, 1, 0, 0, 0),
            )

            member.external_attr = 0o100644 << 16

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)

                archive.writestr(
                    member,
                    files[duplicate],
                )

    return output.getvalue()


class R163BootstrapTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.source = {
            name: (ROOT / path).read_bytes()
            for name, path in SOURCE.items()
        }

        cls.manifest = agent.bundle_manifest(
            cls.source,
            head=bootstrap.HEAD,
            tree=bootstrap.TREE,
            operator_uid=1000,
            operator_id="test-operator",
        )

    def setUp(self):
        self.files = dict(self.source)

        self.files["manifest.json"] = self.manifest

    def verify(self):
        raw = make_zip(self.files)

        return bootstrap.audit_bytes(
            raw,
            bootstrap.sha(raw),
        )

    def deny(self, raw=None):
        if raw is None:
            raw = make_zip(self.files)

        with self.assertRaises(bootstrap.Refusal):
            bootstrap.audit_bytes(
                raw,
                bootstrap.sha(raw),
            )

    def test_01_valid_bundle(self):
        files, document = self.verify()

        self.assertEqual(
            set(files),
            bootstrap.ENTRIES,
        )

        self.assertFalse(
            document["independent_authority"]
        )

    def test_02_wrong_archive_hash(self):
        raw = make_zip(self.files)

        with self.assertRaises(bootstrap.Refusal):
            bootstrap.audit_bytes(
                raw,
                "f" * 64,
            )

    def test_03_modified_b4(self):
        self.files["source/B4/source.py"] += b"x"
        self.deny()

    def test_04_modified_b9(self):
        self.files["source/B9/source.py"] += b"x"
        self.deny()

    def test_05_extra_entry(self):
        self.files["extra.py"] = b"x"
        self.deny()

    def test_06_missing_entry(self):
        self.files.pop(
            "runtime/r163_install_phase_gate.py"
        )
        self.deny()

    def test_07_symbolic_link(self):
        raw = make_zip(
            self.files,
            symbolic="installer.py",
        )
        self.deny(raw)

    def test_08_duplicate_entry(self):
        raw = make_zip(
            self.files,
            duplicate="installer.py",
        )
        self.deny(raw)

    def test_09_wrong_git_head(self):
        document = agent.parse(self.manifest)
        document["approved_head"] = "f" * 40

        self.files["manifest.json"] = agent.canonical(
            document
        )

        self.deny()

    def test_10_wrong_git_tree(self):
        document = agent.parse(self.manifest)
        document["approved_tree"] = "f" * 40

        self.files["manifest.json"] = agent.canonical(
            document
        )

        self.deny()

    def test_11_false_independent_authority(self):
        document = agent.parse(self.manifest)
        document["independent_authority"] = True

        self.files["manifest.json"] = agent.canonical(
            document
        )

        self.deny()

    def test_12_no_checkout_root_authority(self):
        import os

        if os.geteuid() != 0:
            with self.assertRaises(
                bootstrap.Refusal
            ):
                bootstrap.root_entry()

        self.assertEqual(
            bootstrap.HEAD,
            "db23e9927e6a8c6f78ef7dde6ebedc7843a2e769",
        )
