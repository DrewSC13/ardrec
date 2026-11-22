"""R163 V3 root bundle: offline source-only tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

import ardrec_p14_r163_v3_root_stage_agent as agent

REPO = Path(__file__).resolve().parents[2]

SOURCES = {
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


class R163V3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {
            name: (REPO / path).read_bytes()
            for name, path in SOURCES.items()
        }

    def setUp(self):
        self.items = dict(self.files)
        self.raw = agent.bundle_manifest(
            self.items,
            head="a" * 40,
            tree="b" * 40,
            operator_uid=1000,
            operator_id="test-operator",
        )

    def denied(self, files=None, raw=None):
        with self.assertRaises(agent.Refusal):
            agent.verify_bundle(
                self.raw if raw is None else raw,
                self.items if files is None else files,
            )

    def test_01_valid_canonical_bundle(self):
        doc = agent.verify_bundle(self.raw, self.items)
        self.assertFalse(doc["independent_authority"])
        self.assertFalse(doc["operational_activation"])

    def test_02_b4_pin_changed(self):
        self.items["source/B4/source.py"] += b"x"
        self.denied()

    def test_03_b9_pin_changed(self):
        self.items["source/B9/source.py"] += b"x"
        self.denied()

    def test_04_extra_file(self):
        self.items["unexpected.py"] = b"test"
        self.denied()

    def test_05_missing_file(self):
        self.items.pop("runtime/r163_install_phase_gate.py")
        self.denied()

    def test_06_wrong_head(self):
        doc = agent.parse(self.raw)
        doc["approved_head"] = "z" * 40
        self.denied(raw=agent.canonical(doc))

    def test_07_wrong_tree(self):
        doc = agent.parse(self.raw)
        doc["approved_tree"] = "z" * 40
        self.denied(raw=agent.canonical(doc))

    def test_08_zero_operator_uid(self):
        doc = agent.parse(self.raw)
        doc["operator_uid"] = 0
        self.denied(raw=agent.canonical(doc))

    def test_09_invalid_operator_id(self):
        doc = agent.parse(self.raw)
        doc["operator_id"] = "../unsafe"
        self.denied(raw=agent.canonical(doc))

    def test_10_noncanonical_manifest(self):
        self.denied(raw=self.raw[:-1] + b" ")

    def test_11_false_independence(self):
        doc = agent.parse(self.raw)
        doc["independent_authority"] = True
        self.denied(raw=agent.canonical(doc))

    def test_12_checkout_has_no_root_stage_authority(self):
        result = subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts/"
                    "ardrec_p14_r163_v3_root_stage_agent.py"),
                "--preflight",
            ],
            capture_output=True, text=True,
            timeout=20, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
