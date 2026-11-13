"""R14: oráculos fail-closed sin systemd activo en CI."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "p9_r14_active_stop_probe.py"
spec = importlib.util.spec_from_file_location("ardrec_r14_test_subject", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class StopProbeTests(unittest.TestCase):
    def setUp(self):
        self.success = {
            "scope": "one_owned_benign_transient_user_service",
            "p8_operational": "NO-GO",
            "general_tree_cleanup_proven": False,
            "live_group_verified": True,
            "prestop_is_active_rc": 0,
            "prestop_two_identities_alive": True,
            "targeted_stop_rc": 0,
            "two_identities_absent": True,
            "poststop_cgroup_absent_or_unpopulated": True,
            "systemd_run_wrapper_rc": 0,
            "effective_limits": {
                "pids.max": "16", "memory.max": "134217728", "cpu.max": "100000 100000"
            },
        }

    def test_full_evidence_is_scoped_success(self):
        self.assertTrue(mod._assess(self.success))

    def test_missing_field_never_passes(self):
        for key in self.success:
            with self.subTest(key=key):
                value = self.success.copy()
                value.pop(key)
                self.assertFalse(mod._assess(value))

    def test_failed_stop_cannot_pass_with_absent_identites(self):
        value = self.success.copy()
        value["targeted_stop_rc"] = 5
        self.assertFalse(mod._assess(value))

    def test_stop_before_active_unit_is_not_proven(self):
        value = self.success.copy()
        value["prestop_is_active_rc"] = 3
        self.assertFalse(mod._assess(value))

    def test_process_disappeared_before_command_denies(self):
        value = self.success.copy()
        value["prestop_two_identities_alive"] = False
        self.assertFalse(mod._assess(value))

    def test_cgroup_populated_after_stop_denies(self):
        value = self.success.copy()
        value["poststop_cgroup_absent_or_unpopulated"] = False
        self.assertFalse(mod._assess(value))

    def test_wrapper_nonzero_denies(self):
        value = self.success.copy()
        value["systemd_run_wrapper_rc"] = 1
        self.assertFalse(mod._assess(value))

    def test_wrong_resource_limits_denied(self):
        for name, wrong in (("pids.max", "max"), ("memory.max", "max"),
                            ("cpu.max", "max 100000")):
            with self.subTest(limit=name):
                value = self.success.copy()
                value["effective_limits"] = dict(self.success["effective_limits"])
                value["effective_limits"][name] = wrong
                self.assertFalse(mod._assess(value))

    def test_p8_authority_can_never_be_inferred(self):
        value = self.success.copy()
        value["p8_operational"] = "GO"
        self.assertFalse(mod._assess(value))

    def test_global_cleanup_claim_is_forbidden(self):
        value = self.success.copy()
        value["general_tree_cleanup_proven"] = True
        self.assertFalse(mod._assess(value))

    def test_own_unit_name_is_unique_and_exact(self):
        names = {mod._unit_name() for _ in range(3)}
        self.assertEqual(len(names), 3)
        self.assertTrue(all(s.startswith("ardrec-p9r12-") and s.endswith(".service")
                            and len(s) == 33 for s in names))

    def test_stop_uses_own_unit_and_no_shell(self):
        with mock.patch.object(mod.subprocess, "run", return_value=mock.Mock(returncode=0)) as call:
            mod._stop_own_unit("ardrec-p9r12-012345abcdef.service")
        args, kwargs = call.call_args
        self.assertEqual(args[0], ["systemctl", "--user", "--no-ask-password",
                                   "stop", "ardrec-p9r12-012345abcdef.service"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 5)
        self.assertNotIn("shell", kwargs)

    def test_stop_rejects_unowned_names_without_running_command(self):
        for unit in ("ssh.service", "konsole.scope", "ardrec-p9r12-xxx.service",
                     "ardrec-p9r12-012345abcdef.service/../bad", "", "ardrec-p9r12-012345abcdef.service;sh"):
            with self.subTest(unit=unit), mock.patch.object(mod.subprocess, "run", side_effect=AssertionError("must not run")):
                with self.assertRaises(ValueError):
                    mod._stop_own_unit(unit)

    def test_cgroup_populated_0_is_accepted_only_for_own_observation(self):
        class Cg:
            def __init__(self, path):
                self.path = path
            def _cgpath(self, relative):
                return self.path
            def _read(self, path):
                return path.read_text()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "cgroup.events").write_text("populated 0\nfrozen 0\n")
            present, events = mod._cgroup_absent_or_empty(Cg(p), "/own.service")
            self.assertTrue(present)
            self.assertIn("populated 0", events)
            (p / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            present, events = mod._cgroup_absent_or_empty(Cg(p), "/own.service")
            self.assertFalse(present)

    def test_missing_events_is_not_empty_proof(self):
        class Cg:
            def __init__(self, path):
                self.path = path
            def _cgpath(self, relative):
                return self.path
            def _read(self, path):
                return None
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(mod._cgroup_absent_or_empty(Cg(Path(tmp)), "/own.service"), (False, None))

    def test_invalid_or_inaccessible_cgroup_must_not_pass_as_absent(self):
        class Missing:
            def _cgpath(self, relative):
                return None
        self.assertEqual(mod._cgroup_absent_or_empty(Missing(), "/../../../etc"), (False, None))
        self.assertEqual(mod._cgroup_absent_or_empty(Missing(), "relative"), (False, None))
        with mock.patch.object(Path, "stat", side_effect=PermissionError):
            self.assertEqual(mod._cgroup_absent_or_empty(Missing(), "/own.service"), (False, None))

    def test_evidence_directory_requires_empty_private_owned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            os.chmod(path, 0o700)
            mod._safe_evidence(path)
            (path / "existing").write_text("x")
            with self.assertRaises(ValueError):
                mod._safe_evidence(path)
            (path / "existing").unlink()
            os.chmod(path, 0o777)
            with self.assertRaises(ValueError):
                mod._safe_evidence(path)

    def test_denies_unavailable_systemd_before_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (mock.patch.object(mod.shutil, "which", return_value=None),
                  mock.patch.object(mod.subprocess, "Popen", side_effect=AssertionError("must not spawn"))):
                r, code = mod._run(Path(tmp), object())
        self.assertEqual(code, 3)
        self.assertEqual(r["result"], "UNSUPPORTED")
        self.assertEqual(r["p8_operational"], "NO-GO")

    def test_fixed_source_digest_matches_actual_fixture(self):
        repo = Path(__file__).resolve().parents[2]
        import hashlib
        data = (repo / mod.R12_PATH).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), mod.R12_SHA256)
        self.assertIsNotNone(mod._source(repo))

    def test_altered_r12_is_never_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            target = repo / mod.R12_PATH
            target.parent.mkdir(parents=True)
            target.write_text("# not pinned\n")
            with self.assertRaises(ValueError):
                mod._source(repo)


if __name__ == "__main__":
    unittest.main()
