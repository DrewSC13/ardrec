"""R12: oráculos puros y pruebas negativas, SIN crear servicios en CI."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "p9_r12_systemd_user_probe.py"
spec = importlib.util.spec_from_file_location("ardrec_r12_probe", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class R12ProbeTests(unittest.TestCase):
    def setUp(self):
        self.unit = "ardrec-p9r12-012345abcdef.service"
        self.worker = {"pid": 29001, "ppid": 77, "pgid": 29001, "start_ticks": 12345, "state": "S", "uid": os.getuid()}
        self.witness = {"pid": 29002, "ppid": 29001, "pgid": 29002, "start_ticks": 12455, "state": "S", "uid": os.getuid()}
        self.ready = {"unit": self.unit, "p8_operational": "NO-GO",
                      "witness_escaped_pgid": True, "worker_uid": os.getuid(),
                      "worker": self.worker, "witness": self.witness,
                      "worker_cgroup": "/user.slice/app.slice/" + self.unit,
                      "witness_cgroup": "/user.slice/app.slice/" + self.unit}
        self.live = {"pids.max": module.PIDS_MAX,
                     "memory.max": module.MEMORY_MAX,
                     "cpu.max": "100000 100000",
                     "cgroup.procs": "29001\n29002"}

    def test_exact_limits_and_two_processes_pass_only_a_benign_observation(self):
        self.assertTrue(module._observation_pass(self.ready, self.unit, self.live))

    def test_wrong_parent_cannot_be_attributed(self):
        self.ready["witness"]["ppid"] = 99999
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_wrong_uid_cannot_be_attributed(self):
        self.ready["witness"]["uid"] = 0 if os.getuid() != 0 else 8888
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_wrong_cgroup_cannot_be_attributed(self):
        self.ready["witness_cgroup"] = "/user.slice/another.service"
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_escape_of_process_group_is_required(self):
        self.ready["witness_escaped_pgid"] = False
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_one_process_not_present_denies_ownership(self):
        self.live["cgroup.procs"] = "29001"
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_identity_cannot_have_zero_start_ticks(self):
        self.ready["witness"]["start_ticks"] = 0
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_pids_limit_must_be_effective(self):
        self.live["pids.max"] = "max"
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_memory_limit_must_be_effective(self):
        self.live["memory.max"] = "max"
        self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_cpu_quota_must_be_effective(self):
        for value in ["max 100000", "200000 100000", "bad", None]:
            with self.subTest(value=value):
                self.live["cpu.max"] = value
                self.assertFalse(module._observation_pass(self.ready, self.unit, self.live))

    def test_no_fake_ownership_by_changing_unit(self):
        self.assertFalse(module._observation_pass(self.ready, "unrelated.service", self.live))

    def test_command_is_fixed_unprivileged_and_limits_are_declared(self):
        with tempfile.TemporaryDirectory() as temp:
            cmd = module._command(self.unit, Path(temp))
        self.assertIn("--user", cmd)
        self.assertIn("--wait", cmd)
        self.assertIn("--collect", cmd)
        self.assertIn("--property=KillMode=control-group", cmd)
        self.assertIn("--property=TasksMax=16", cmd)
        self.assertIn("--property=MemoryMax=134217728", cmd)
        self.assertIn("--property=CPUQuota=100%", cmd)
        self.assertIn("--property=NoNewPrivileges=yes", cmd)
        self.assertNotIn("--scope", cmd)
        self.assertNotIn("sudo", cmd)
        self.assertEqual(cmd[-4], "--worker")
        self.assertEqual(cmd[-2:], ["--unit", self.unit])

    def test_worker_rejects_call_outside_own_transient_unit_before_spawn(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(module, "_cgroup_relative", return_value="/user.slice/tab.scope"):
            self.assertEqual(module._worker(Path(temp), self.unit), 26)

    def test_absence_is_scoped_to_pid_and_start_ticks(self):
        with mock.patch.object(module, "_proc_identity", return_value=None):
            self.assertTrue(module._identity_absent(self.worker))
        with mock.patch.object(module, "_proc_identity", return_value=self.worker.copy()):
            self.assertFalse(module._identity_absent(self.worker))
        with mock.patch.object(module, "_proc_identity", return_value={**self.worker, "start_ticks": 999}):
            self.assertTrue(module._identity_absent(self.worker))

    def test_output_directory_rejects_nonempty_and_unsafe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.chmod(root, 0o700)
            module._outdir_check(root)
            (root / "existing").write_text("x")
            with self.assertRaises(ValueError):
                module._outdir_check(root)
            (root / "existing").unlink()
            os.chmod(root, 0o777)
            with self.assertRaises(ValueError):
                module._outdir_check(root)

    def test_unavailable_systemd_denies_without_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.chmod(root, 0o700)
            with mock.patch.object(module.shutil, "which", return_value=None):
                with mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("must not launch")):
                    record, rc = module._probe(root)
            self.assertEqual(rc, 3)
            self.assertEqual(record["result"], "UNSUPPORTED")
            self.assertEqual(record["p8_operational"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
